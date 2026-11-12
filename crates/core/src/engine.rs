//! The check cycle: pull what changed upstream, match it against subscriptions, apply each
//! subscription's filter, de-duplicate, and record alerts.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::matcher::{Compiled, Target};
use crate::model::{merge_all, Advisory};
use crate::notify::{self, Notification};
use crate::settings::Settings;
use crate::sources::{cvelist, epss, kev, nvd, osv, parse_time};
use crate::store::{Alert, AlertKind};
use crate::Core;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PollReport {
    /// Alerts created by this check.
    pub alerts: Vec<Alert>,
    /// What to show the user for them (deduplicated, subscriptions with notifications on only).
    pub notifications: Vec<Notification>,
    /// Advisories examined.
    pub checked: usize,
    pub errors: Vec<String>,
    /// Set when the check did not run (another one in progress).
    pub skipped: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KevState {
    etag: Option<String>,
    checked_at: Option<DateTime<Utc>>,
    entries: BTreeMap<String, String>,
}

impl Core {
    /// Run one check. Never fails: problems are reported in `errors` and retried next time.
    pub fn poll(&self) -> PollReport {
        let Ok(_guard) = self.poll_lock.try_lock() else {
            return PollReport { skipped: true, ..Default::default() };
        };
        let settings = self.settings();
        let mut report = if settings.remote.enabled {
            self.poll_remote(&settings).unwrap_or_else(|e| PollReport { errors: vec![format!("server: {e:#}")], ..Default::default() })
        } else {
            let mut r = self.poll_local(&settings);
            self.announce(&settings, &mut r);
            r
        };
        report.errors.dedup();
        let now = Utc::now();
        let db = self.db();
        let mut status: Value = db.get("status").ok().flatten().unwrap_or_else(|| json!({}));
        status["last_check"] = json!(now);
        status["last_errors"] = json!(report.errors);
        status["last_checked"] = json!(report.checked);
        status["last_new"] = json!(report.alerts.len());
        if report.errors.is_empty() {
            status["last_ok"] = json!(now);
        }
        db.set("status", &status).ok();
        report
    }

    /// Build the notifications for a report's alerts and send them to the push channels.
    fn announce(&self, settings: &Settings, r: &mut PollReport) {
        if r.alerts.is_empty() {
            return;
        }
        let notify_subs: HashSet<i64> =
            self.db().subscriptions().unwrap_or_default().into_iter().filter(|s| s.notify).map(|s| s.id).collect();
        let wanted: Vec<&Alert> = r.alerts.iter().filter(|a| notify_subs.contains(&a.sub_id)).collect();
        r.notifications = notify::build(&wanted);
        let push_errors = notify::push(&self.net, settings, &r.notifications, &r.alerts);
        r.errors.extend(push_errors);
    }

    /// A target's list was just loaded (someone opened or refreshed its page, or a subscription
    /// is catching up): raise alerts for what in it is recent and not yet alerted. Product pages
    /// draw on more sources than the change feed the checks follow, so they can be ahead of it.
    /// `only` limits this to one subscription. Returns the alerts created.
    pub(crate) fn alerts_from_listing(&self, settings: &Settings, target: &Target, items: &[Advisory], only: Option<i64>) -> PollReport {
        let mut report = PollReport::default();
        let subs: Vec<Compiled> = self
            .db()
            .subscriptions()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.enabled && only.is_none_or(|id| id == s.id) && same_target(&s.target, target))
            .filter_map(|s| Compiled::new(s).ok())
            .collect();
        if subs.is_empty() {
            return report;
        }
        let now = Utc::now();
        // Not the whole `max_age_days`: a long-standing subscription has seen the older ones go by.
        let floor = now - Duration::days(settings.lookback_days.max(7) as i64);
        for sub in &subs {
            for adv in items {
                self.consider(sub, adv, &[], settings, now, Some(floor), &mut report);
            }
        }
        // Oldest first, like the alerts of a check.
        report.alerts.reverse();
        report
    }

    /// As `alerts_from_listing`, for a page the user is looking at: push channels are told too.
    pub(crate) fn alert_on_view(&self, settings: &Settings, target: &Target, items: &[Advisory]) -> usize {
        let mut report = self.alerts_from_listing(settings, target, items, None);
        self.announce(settings, &mut report);
        report.alerts.len()
    }

    /// Paired with a server: it does the checking; we only collect what is new since last time.
    fn poll_remote(&self, settings: &Settings) -> Result<PollReport> {
        let last: Option<i64> = self.db().get("remote_last_alert")?;
        let v = self.remote_call(settings, "alerts.since", json!({ "after_id": last }))?;
        let report = PollReport {
            alerts: serde_json::from_value(v["alerts"].clone()).unwrap_or_default(),
            notifications: serde_json::from_value(v["notifications"].clone()).unwrap_or_default(),
            ..Default::default()
        };
        if let Some(max) = v["max_id"].as_i64() {
            self.db().set("remote_last_alert", &max)?;
        }
        Ok(report)
    }

    fn poll_local(&self, settings: &Settings) -> PollReport {
        let mut report = PollReport::default();
        let subs: Vec<Compiled> = match self.db().subscriptions() {
            Ok(list) => list.into_iter().filter(|s| s.enabled).filter_map(|s| Compiled::new(s).ok()).collect(),
            Err(e) => {
                report.errors.push(format!("database: {e:#}"));
                return report;
            }
        };
        if subs.is_empty() {
            // Nothing to watch: forget the cursor so a later first subscription starts fresh.
            self.db().delete("nvd_cursor").ok();
            return report;
        }
        let now = Utc::now();
        let key = settings.nvd_key();

        // The change feed only says what happened since the last check. A subscription that has
        // not been through one yet first gets what its target's page lists from the days before.
        for sub in &subs {
            let done = format!("caught_up:{}", sub.sub.id);
            if self.db().get::<bool>(&done).ok().flatten().is_some() {
                continue;
            }
            match self.newest(settings, &sub.sub.target) {
                Ok(items) => {
                    report.checked += items.len();
                    let found = self.alerts_from_listing(settings, &sub.sub.target, &items, Some(sub.sub.id));
                    report.alerts.extend(found.alerts);
                    report.errors.extend(found.errors);
                    self.db().set(&done, &true).ok();
                }
                Err(e) => report.errors.push(format!("{}: {e:#}", sub.sub.name)),
            }
        }

        let (kev, newly_exploited) = match self.refresh_kev(false) {
            Ok(x) => x,
            Err(e) => {
                report.errors.push(format!("CISA KEV: {e:#}"));
                (self.kev(), vec![])
            }
        };

        let feed: Vec<&Compiled> = subs.iter().filter(|s| !matches!(s.sub.target, Target::Package { .. })).collect();
        if !feed.is_empty() {
            let cursor: Option<DateTime<Utc>> = self.db().get("nvd_cursor").ok().flatten();
            let from = match cursor {
                // Small overlap so nothing published during the previous request is missed.
                Some(c) => (c - Duration::minutes(3)).max(now - Duration::days(7)),
                None => now - Duration::hours(2),
            };
            let mut advisories = vec![];
            match nvd::modified_between(&self.net, key, from, now) {
                Ok(list) => {
                    advisories.extend(list);
                    self.db().set("nvd_cursor", &now).ok();
                }
                Err(e) => report.errors.push(format!("{e:#}")),
            }
            if settings.use_cvelist {
                let since: Option<String> = self.db().get("cvelist_cursor").ok().flatten();
                match cvelist::poll(&self.net, since.as_deref()) {
                    Ok(delta) => {
                        advisories.extend(delta.advisories);
                        if let Some(c) = delta.cursor {
                            self.db().set("cvelist_cursor", &c).ok();
                        }
                    }
                    Err(e) => report.errors.push(format!("cve.org: {e:#}")),
                }
            }
            // CVEs that just landed on KEV may be old and otherwise untouched: fetch them explicitly.
            for id in newly_exploited.iter().take(25) {
                if advisories.iter().any(|a| &a.id == id) {
                    continue;
                }
                match nvd::by_id(&self.net, key, id) {
                    Ok(found) => advisories.extend(found),
                    Err(e) => report.errors.push(format!("{e:#}")),
                }
            }
            let mut advisories = merge_all(advisories);
            report.checked += advisories.len();
            for a in &mut advisories {
                flag_kev(a, &kev);
            }
            let mut candidates: Vec<(Advisory, Vec<&Compiled>)> = advisories
                .into_iter()
                .filter_map(|a| {
                    let hits: Vec<&Compiled> = feed.iter().copied().filter(|s| s.matches(&a)).collect();
                    (!hits.is_empty()).then_some((a, hits))
                })
                .collect();
            if settings.use_epss {
                let mut refs: Vec<&mut Advisory> = candidates.iter_mut().map(|c| &mut c.0).collect();
                if let Err(e) = self.add_epss(&mut refs) {
                    report.errors.push(format!("EPSS: {e:#}"));
                }
            }
            for (adv, hits) in &candidates {
                for sub in hits {
                    self.consider(sub, adv, &newly_exploited, settings, now, None, &mut report);
                }
            }
        }

        let packages: Vec<&Compiled> = subs.iter().filter(|s| matches!(s.sub.target, Target::Package { .. })).collect();
        if !packages.is_empty() {
            if let Err(e) = self.poll_packages(&packages, &kev, &newly_exploited, settings, now, &mut report) {
                report.errors.push(format!("OSV: {e:#}"));
            }
        }
        report
    }

    fn poll_packages(
        &self,
        subs: &[&Compiled],
        kev: &BTreeMap<String, String>,
        newly_exploited: &[String],
        settings: &Settings,
        now: DateTime<Utc>,
        report: &mut PollReport,
    ) -> Result<()> {
        let names: Vec<(String, String)> = subs
            .iter()
            .map(|s| match &s.sub.target {
                Target::Package { ecosystem, name } => (ecosystem.clone(), name.clone()),
                _ => unreachable!(),
            })
            .collect();
        let listings = osv::batch(&self.net, &names)?;
        for (sub, listing) in subs.iter().zip(listings) {
            let cursor_key = format!("osv_cursor:{}", sub.sub.id);
            let cursor: Option<DateTime<Utc>> = self.db().get(&cursor_key)?;
            let newest = listing.iter().filter_map(|(_, m)| parse_time(m)).max();
            if let Some(cursor) = cursor {
                let changed = listing.iter().filter(|(_, m)| parse_time(m).is_some_and(|t| t > cursor));
                for (id, _) in changed.take(20) {
                    let Some(mut adv) = osv::by_id(&self.net, id)? else { continue };
                    report.checked += 1;
                    flag_kev(&mut adv, kev);
                    if settings.use_epss {
                        self.add_epss(&mut [&mut adv]).ok();
                    }
                    self.consider(sub, &adv, newly_exploited, settings, now, None, report);
                }
            }
            // First sight of a package only records where we are; its history is on the package page.
            self.db().set(&cursor_key, &newest.or(cursor).unwrap_or(now))?;
        }
        Ok(())
    }

    /// Decide whether a matching advisory becomes an alert for this subscription.
    fn consider(
        &self,
        sub: &Compiled,
        adv: &Advisory,
        newly_exploited: &[String],
        settings: &Settings,
        now: DateTime<Utc>,
        floor: Option<DateTime<Utc>>,
        report: &mut PollReport,
    ) {
        if !sub.passes_filter(adv) {
            return;
        }
        let ids: Vec<&str> = adv.all_ids().collect();
        let db = self.db();
        let prior = db.prior_alert(sub.sub.id, &ids).unwrap_or(None);
        let just_exploited = adv.exploited && ids.iter().any(|i| newly_exploited.iter().any(|n| n == i));
        let kind = match prior {
            // Already told the user; only speak again if it has since become exploited.
            Some(was_exploited) if adv.exploited && !was_exploited => AlertKind::Exploited,
            Some(_) => return,
            None if just_exploited => AlertKind::Exploited,
            None => {
                // Upstreams keep touching old records. Only recent publications count as "new".
                let mut horizon = now - Duration::days(settings.max_age_days as i64);
                if let Some(created) = sub.sub.created_at {
                    horizon = horizon.max(created - Duration::days(settings.lookback_days as i64));
                }
                if let Some(floor) = floor {
                    horizon = horizon.max(floor);
                }
                if adv.published.is_some_and(|p| p < horizon) {
                    return;
                }
                AlertKind::New
            }
        };
        match db.insert_alert(sub.sub.id, &sub.sub.name, &adv.id, kind, adv.exploited, &adv.view(true)) {
            Ok(Some(alert)) => report.alerts.push(alert),
            Ok(None) => {}
            Err(e) => report.errors.push(format!("database: {e:#}")),
        }
    }

    /// The KEV list as last fetched (empty if never).
    pub fn kev(&self) -> Arc<BTreeMap<String, String>> {
        if let Some(k) = self.kev.lock().unwrap().as_ref() {
            return k.clone();
        }
        let state: KevState = self.db().get("kev").ok().flatten().unwrap_or_default();
        let entries = Arc::new(state.entries);
        *self.kev.lock().unwrap() = Some(entries.clone());
        entries
    }

    /// Refresh the KEV list if it is over an hour old (or `force`). Returns the list and the ids
    /// added since the previous copy (empty on the very first load).
    pub fn refresh_kev(&self, force: bool) -> Result<(Arc<BTreeMap<String, String>>, Vec<String>)> {
        let mut state: KevState = self.db().get("kev")?.unwrap_or_default();
        let fresh = state.checked_at.is_some_and(|t| Utc::now() - t < Duration::hours(1));
        if fresh && !force && !state.entries.is_empty() {
            return Ok((self.kev(), vec![]));
        }
        let mut added = vec![];
        if let Some(catalog) = kev::fetch(&self.net, state.etag.as_deref().filter(|_| !state.entries.is_empty()))? {
            if !state.entries.is_empty() {
                added = catalog.entries.keys().filter(|k| !state.entries.contains_key(*k)).cloned().collect();
            }
            state.entries = catalog.entries;
            state.etag = catalog.etag;
        }
        state.checked_at = Some(Utc::now());
        self.db().set("kev", &state)?;
        let entries = Arc::new(state.entries);
        *self.kev.lock().unwrap() = Some(entries.clone());
        Ok((entries, added))
    }

    /// The KEV list, fetching it if we have never had one. Errors are swallowed (flag stays off).
    pub fn kev_ready(&self) -> Arc<BTreeMap<String, String>> {
        let current = self.kev();
        if !current.is_empty() {
            return current;
        }
        self.refresh_kev(true).map(|x| x.0).unwrap_or(current)
    }

    pub fn add_epss(&self, advisories: &mut [&mut Advisory]) -> Result<()> {
        let mut ids: Vec<String> = advisories.iter().filter_map(|a| a.cve_id().map(str::to_string)).collect();
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return Ok(());
        }
        let scores = epss::lookup(&self.net, &ids)?;
        for a in advisories.iter_mut() {
            if let Some((p, pct)) = a.cve_id().and_then(|id| scores.get(id)) {
                a.epss = Some(*p);
                a.epss_percentile = Some(*pct);
            }
        }
        Ok(())
    }
}

/// Do two targets name the same thing? A product's extra keywords are not part of what it is.
fn same_target(a: &Target, b: &Target) -> bool {
    match (a, b) {
        (Target::Product { vendor: v1, product: p1, .. }, Target::Product { vendor: v2, product: p2, .. }) => v1 == v2 && p1 == p2,
        _ => a == b,
    }
}

pub fn flag_kev(a: &mut Advisory, kev: &BTreeMap<String, String>) {
    let hit = a.all_ids().find_map(|id| kev.get(id)).cloned();
    if let Some(date) = hit {
        a.exploited = true;
        a.kev_added.get_or_insert(date);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{Filter, Subscription};
    use crate::model::Severity;
    use crate::sources::nvd;
    use crate::store::Store;

    fn setup(filter: Filter) -> (Core, Compiled) {
        let core = Core::with_store(Store::in_memory().unwrap(), false);
        let mut sub = Subscription {
            id: 0,
            name: "polkit".into(),
            target: Target::Product { vendor: "redhat".into(), product: "polkit".into(), keywords: vec!["polkit".into()] },
            filter,
            enabled: true,
            notify: true,
            created_at: None,
        };
        sub.id = core.db().save_subscription(&sub).unwrap();
        let sub = core.db().subscriptions().unwrap().remove(0);
        (core, Compiled::new(sub).unwrap())
    }

    fn polkit() -> Advisory {
        let v: Value = serde_json::from_str(include_str!("../testdata/nvd-cve.json")).unwrap();
        let mut a = nvd::parse_cve(&v).unwrap();
        a.published = Some(Utc::now() - Duration::hours(1));
        a
    }

    #[test]
    fn alerts_once_then_again_when_exploited() {
        let (core, sub) = setup(Filter::default());
        let settings = Settings::default();
        let mut report = PollReport::default();
        let mut adv = polkit();
        assert!(sub.matches(&adv));
        core.consider(&sub, &adv, &[], &settings, Utc::now(), None, &mut report);
        core.consider(&sub, &adv, &[], &settings, Utc::now(), None, &mut report);
        assert_eq!(report.alerts.len(), 1);
        assert_eq!(report.alerts[0].kind, AlertKind::New);

        adv.exploited = true;
        core.consider(&sub, &adv, &[], &settings, Utc::now(), None, &mut report);
        core.consider(&sub, &adv, &[], &settings, Utc::now(), None, &mut report);
        assert_eq!(report.alerts.len(), 2);
        assert_eq!(report.alerts[1].kind, AlertKind::Exploited);
        assert_eq!(core.db().unread_count().unwrap(), 2);
    }

    #[test]
    fn old_publications_are_not_news_unless_newly_exploited() {
        let (core, sub) = setup(Filter::default());
        let settings = Settings::default();
        let mut report = PollReport::default();
        let mut adv = polkit();
        adv.published = Some(Utc::now() - Duration::days(400));
        core.consider(&sub, &adv, &[], &settings, Utc::now(), None, &mut report);
        assert!(report.alerts.is_empty());

        adv.exploited = true;
        core.consider(&sub, &adv, &[adv.id.clone()], &settings, Utc::now(), None, &mut report);
        assert_eq!(report.alerts.len(), 1);
        assert_eq!(report.alerts[0].kind, AlertKind::Exploited);
    }

    #[test]
    fn a_new_subscription_reaches_back_the_configured_days() {
        let (core, sub) = setup(Filter::default());
        let mut settings = Settings::default();
        let mut report = PollReport::default();
        let mut adv = polkit();
        adv.published = Some(Utc::now() - Duration::days(5));
        settings.lookback_days = 3;
        core.consider(&sub, &adv, &[], &settings, Utc::now(), None, &mut report);
        assert!(report.alerts.is_empty());
        settings.lookback_days = 7;
        core.consider(&sub, &adv, &[], &settings, Utc::now(), None, &mut report);
        assert_eq!(report.alerts.len(), 1);
    }

    #[test]
    fn a_loaded_list_alerts_once_and_deleted_alerts_stay_gone() {
        let (core, sub) = setup(Filter::default());
        let settings = Settings::default();
        let target = Target::Product { vendor: "redhat".into(), product: "polkit".into(), keywords: vec![] };
        let mut old = polkit();
        old.id = "CVE-2020-0001".into();
        old.aliases.clear();
        old.published = Some(Utc::now() - Duration::days(20));
        let items = vec![polkit(), old];
        let found = core.alerts_from_listing(&settings, &target, &items, None);
        assert_eq!(found.alerts.len(), 1);
        assert!(core.alerts_from_listing(&settings, &target, &items, None).alerts.is_empty());
        // Another product's page says nothing about this subscription.
        let other = Target::Product { vendor: "redhat".into(), product: "other".into(), keywords: vec![] };
        assert!(core.alerts_from_listing(&settings, &other, &items, Some(sub.sub.id)).alerts.is_empty());

        core.db().delete_alerts(Some(&[found.alerts[0].id]), None).unwrap();
        assert!(core.db().alerts(None, false, None, None, 10).unwrap().is_empty());
        assert_eq!(core.db().unread_count().unwrap(), 0);
        assert!(core.alerts_from_listing(&settings, &target, &items, None).alerts.is_empty());
    }

    #[test]
    fn filter_holds_back_and_notifications_follow() {
        let (core, sub) = setup(Filter { min_severity: Some(Severity::Critical), ..Default::default() });
        let mut report = PollReport::default();
        let adv = polkit(); // CVSS 5.5
        core.consider(&sub, &adv, &[], &Settings::default(), Utc::now(), None, &mut report);
        assert!(report.alerts.is_empty());

        let (core, sub) = setup(Filter { min_severity: Some(Severity::Medium), ..Default::default() });
        core.consider(&sub, &adv, &[], &Settings::default(), Utc::now(), None, &mut report);
        let refs: Vec<&Alert> = report.alerts.iter().collect();
        let notes = notify::build(&refs);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].title.contains("CVE-2026-4897") || notes[0].body.contains("CVE-2026-4897"));
    }
}
