//! The check cycle: pull what changed upstream, match it against subscriptions, apply each
//! subscription's filter, de-duplicate, and record alerts.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration as Elapsed, Instant},
};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::matcher::{Compiled, Target};
use crate::model::{merge_all, Advisory};
use crate::notify::{self, Notification};
use crate::settings::Settings;
use crate::sources::{cvelist, epss, kev, nvd, osv, parse_time};
use crate::store::{Alert, AlertKind};
use crate::track::Step;
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

/// How the check in progress (or the last one) is getting on, for the UI to show.
#[derive(Default)]
pub(crate) struct Progress {
    running: bool,
    started: Option<Instant>,
    /// How long the whole check took, once it is over.
    took: Option<Elapsed>,
    new_alerts: usize,
    steps: Vec<Step>,
}

/// Marks the check as over when dropped, however `poll` is left.
struct Running<'a>(&'a Core);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut p = self.0.progress();
        p.running = false;
        p.took = p.started.map(|t| t.elapsed());
    }
}

/// How many past checks `check_history` remembers.
const HISTORY: usize = 60;

#[derive(Debug, Default, Serialize, Deserialize)]
struct KevState {
    etag: Option<String>,
    checked_at: Option<DateTime<Utc>>,
    entries: BTreeMap<String, String>,
}

impl Core {
    /// Run one check. Never fails: problems are reported in `errors` and retried next time.
    pub fn poll(&self) -> PollReport {
        self.poll_by("schedule")
    }

    /// A check, noting who asked for it ("schedule" or "manual") in the history.
    pub fn poll_by(&self, by: &str) -> PollReport {
        let _guard = match self.poll_lock.try_lock() {
            Ok(guard) => guard,
            // An earlier check crashed while holding the lock. That must not stop every later one.
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            // Another check is running (two triggers at once, say). Its result covers this one.
            Err(std::sync::TryLockError::WouldBlock) => {
                return PollReport { skipped: true, ..Default::default() };
            }
        };
        let started = Instant::now();
        // A check that never gets to its end (the system killed the app, say) leaves this behind.
        let lost: Option<Value> = self.db().get("check_started").ok().flatten();
        if let Some(mut lost) = lost {
            lost["unfinished"] = json!(true);
            self.remember(lost);
        }
        self.db().set("check_started", &json!({ "at": Utc::now(), "by": by })).ok();
        *self.progress() = Progress { running: true, started: Some(started), ..Default::default() };
        let _running = Running(self);
        // A crash in one check is reported like any other error, and the next check runs as usual.
        let mut report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.poll_once())).unwrap_or_else(|p| {
            let why = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
            PollReport { errors: vec![format!("the check crashed: {why}")], ..Default::default() }
        });
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
        db.delete("check_started").ok();
        drop(db);
        self.remember(json!({ "at": now, "by": by, "ms": started.elapsed().as_millis() as u64, "new": report.alerts.len(), "errors": report.errors }));
        report
    }

    /// Add to what this device itself did and when, so that a gap in background checks can be
    /// told apart: not started by the system, failed, or never finished.
    fn remember(&self, entry: Value) {
        let db = self.db();
        let mut history: Vec<Value> = db.get("history").ok().flatten().unwrap_or_default();
        history.insert(0, entry);
        history.truncate(HISTORY);
        db.set("history", &history).ok();
    }

    /// Seconds since this device last finished a check of its own, or -1 if it has not yet.
    pub fn since_last_check(&self) -> i64 {
        let history: Vec<Value> = self.db().get("history").ok().flatten().unwrap_or_default();
        history
            .iter()
            .filter(|c| c["ms"].is_u64())
            .find_map(|c| serde_json::from_value::<DateTime<Utc>>(c["at"].clone()).ok())
            .map_or(-1, |at| (Utc::now() - at).num_seconds().max(0))
    }

    /// The last checks this device ran, newest first.
    pub fn check_history(&self) -> Value {
        let db = self.db();
        let mut history: Vec<Value> = db.get("history").ok().flatten().unwrap_or_default();
        drop(db);
        history.retain(|c| c["skipped"] != json!(true));
        if !self.checking() {
            if let Some(mut lost) = self.db().get::<Value>("check_started").ok().flatten() {
                lost["unfinished"] = json!(true);
                history.insert(0, lost);
            }
        }
        json!({ "checks": history })
    }

    fn poll_once(&self) -> PollReport {
        let settings = self.settings();
        self.db().offline_purge(settings.offline_days).ok();
        // Alerts from before copies were kept (an update, or the setting was off).
        if self.db().get::<bool>("offline_filled").ok().flatten().is_none() {
            self.keep_recent_alerts(settings.offline_days).ok();
        }
        let report = if settings.remote.enabled {
            let report = self
                .step("vulnwatch server", || self.poll_remote(&settings))
                .unwrap_or_else(|e| PollReport { errors: vec![format!("server: {e:#}")], ..Default::default() });
            self.progress().new_alerts = report.alerts.len();
            if settings.offline_days > 0 {
                // The server may be out of reach later: keep what it just told us about.
                self.db().offline_put_all(&report.alerts).ok();
            }
            report
        } else {
            let mut r = self.poll_local(&settings);
            self.announce(&settings, &mut r);
            r
        };
        report
    }

    /// Keep the alerts of the last `days` days for offline reading, as far as they are not already.
    pub(crate) fn keep_recent_alerts(&self, days: u32) -> Result<()> {
        let db = self.db();
        if days > 0 {
            let horizon = Utc::now() - Duration::days(days as i64);
            let kept: HashSet<(String, i64)> = db.offline_alerts(None, false)?.into_iter().map(|a| (a.vuln_id, a.sub_id)).collect();
            let recent: Vec<_> = db
                .alerts(None, false, None, None, 2000)?
                .into_iter()
                .filter(|a| a.created_at >= horizon && !kept.contains(&(a.vuln_id.clone(), a.sub_id)))
                .collect();
            db.offline_put_all(&recent)?;
        }
        db.set("offline_filled", &true)
    }

    fn progress(&self) -> std::sync::MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Do one part of a check, keeping time for `check_progress`. Outside a check it only runs `work`.
    fn step<T>(&self, name: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
        let slot = {
            let mut p = self.progress();
            p.running.then(|| {
                let step = Step::new(name);
                let started = step.started;
                p.steps.push(step);
                (p.steps.len() - 1, started)
            })
        };
        let out = work();
        if let Some((i, started)) = slot {
            let mut p = self.progress();
            if let Some(s) = p.steps.get_mut(i).filter(|s| s.started == started) {
                s.finish(&out);
            }
        }
        out
    }

    /// The check in progress, or the last one: each step with how long it took or has been
    /// running, and how many alerts it has raised so far.
    pub fn check_progress(&self) -> Value {
        let p = self.progress();
        let ms = |d: Elapsed| d.as_millis() as u64;
        let steps: Vec<Value> = p.steps.iter().map(Step::view).collect();
        json!({
            "running": p.running,
            "ms": p.took.or(p.started.map(|t| t.elapsed())).map(ms),
            "new": p.new_alerts,
            "steps": steps,
        })
    }

    pub fn checking(&self) -> bool {
        self.progress().running
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
        if !(settings.ntfy.enabled || settings.webhook.enabled) || r.notifications.is_empty() {
            return;
        }
        let pushed = self.step("Sending notifications", || {
            let errors = notify::push(&self.net, settings, &r.notifications, &r.alerts);
            match errors.first() {
                Some(e) => Err(anyhow!("{e}")),
                None => Ok(()),
            }
        });
        r.errors.extend(pushed.err().map(|e| format!("{e:#}")));
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

        let (kev, newly_exploited) = match self.step("CISA KEV", || self.refresh_kev(false)) {
            Ok(x) => x,
            Err(e) => {
                report.errors.push(format!("CISA KEV: {e:#}"));
                (self.kev(), vec![])
            }
        };

        // The rest does not depend on each other, so it runs side by side and each raises its
        // alerts as soon as it has them: a slow NVD does not hold back what OSV found.
        let feed: Vec<&Compiled> = subs.iter().filter(|s| !matches!(s.sub.target, Target::Package { .. })).collect();
        let packages: Vec<&Compiled> = subs.iter().filter(|s| matches!(s.sub.target, Target::Package { .. })).collect();
        let parts = std::thread::scope(|s| {
            let catch_up = s.spawn(|| self.catch_up(settings, &subs));
            let feed = s.spawn(|| self.poll_feed(settings, &feed, &kev, &newly_exploited, now));
            let mut osv = PollReport::default();
            if !packages.is_empty() {
                if let Err(e) = self.step("OSV", || self.poll_packages(&packages, &kev, &newly_exploited, settings, now, &mut osv)) {
                    osv.errors.push(format!("OSV: {e:#}"));
                }
            }
            [catch_up.join(), feed.join(), Ok(osv)]
        });
        for part in parts {
            match part {
                Ok(part) => {
                    report.alerts.extend(part.alerts);
                    report.errors.extend(part.errors);
                    report.checked += part.checked;
                }
                Err(_) => report.errors.push("part of the check crashed".into()),
            }
        }
        report
    }

    /// The change feed only says what happened since the last check. A subscription that has
    /// not been through one yet first gets what its target's page lists from the days before.
    fn catch_up(&self, settings: &Settings, subs: &[Compiled]) -> PollReport {
        let mut report = PollReport::default();
        for sub in subs {
            let done = format!("caught_up:{}", sub.sub.id);
            if self.db().get::<bool>(&done).ok().flatten().is_some() {
                continue;
            }
            match self.step(&format!("New subscription: {} (last {} days)", sub.sub.name, settings.lookback_days.max(7)), || self.newest(settings, &sub.sub.target)) {
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
        report
    }

    /// What changed in the CVE feeds since the last check, for product, vendor and keyword subscriptions.
    fn poll_feed(
        &self,
        settings: &Settings,
        feed: &[&Compiled],
        kev: &BTreeMap<String, String>,
        newly_exploited: &[String],
        now: DateTime<Utc>,
    ) -> PollReport {
        let mut report = PollReport::default();
        if feed.is_empty() {
            return report;
        }
        let key = settings.nvd_key();
        let cursor: Option<DateTime<Utc>> = self.db().get("nvd_cursor").ok().flatten();
        let from = match cursor {
            // Small overlap so nothing published during the previous request is missed.
            Some(c) => (c - Duration::minutes(3)).max(now - Duration::days(7)),
            None => now - Duration::hours(2),
        };
        let mut advisories = vec![];
        // The two feeds describe the same CVEs, so they are asked together and merged before
        // anything is matched: a record judged on half of what is known could alert wrongly.
        let (from_nvd, from_cvelist) = std::thread::scope(|s| {
            let cvelist = settings.use_cvelist.then(|| {
                s.spawn(|| {
                    let since: Option<String> = self.db().get("cvelist_cursor").ok().flatten();
                    self.step("CVE.org changes", || cvelist::poll(&self.net, since.as_deref()))
                })
            });
            let nvd = self.step("NVD changes", || nvd::modified_between(&self.net, key, from, now));
            (nvd, cvelist.map(|j| j.join().unwrap_or_else(|_| Err(anyhow!("the lookup crashed")))))
        });
        match from_nvd {
            Ok(list) => {
                advisories.extend(list);
                self.db().set("nvd_cursor", &now).ok();
            }
            Err(e) => report.errors.push(format!("{e:#}")),
        }
        match from_cvelist {
            Some(Ok(delta)) => {
                advisories.extend(delta.advisories);
                if let Some(c) = delta.cursor {
                    self.db().set("cvelist_cursor", &c).ok();
                }
            }
            Some(Err(e)) => report.errors.push(format!("cve.org: {e:#}")),
            None => {}
        }
        // CVEs that just landed on KEV may be old and otherwise untouched: fetch them explicitly.
        let missing: Vec<&String> = newly_exploited.iter().take(25).filter(|id| !advisories.iter().any(|a| &a.id == *id)).collect();
        if !missing.is_empty() {
            let _ = self.step("NVD: newly exploited CVEs", || {
                for id in missing {
                    match nvd::by_id(&self.net, key, id) {
                        Ok(found) => advisories.extend(found),
                        Err(e) => report.errors.push(format!("{e:#}")),
                    }
                }
                Ok(())
            });
        }
        let mut advisories = merge_all(advisories);
        report.checked += advisories.len();
        for a in &mut advisories {
            flag_kev(a, kev);
        }
        let mut candidates: Vec<(Advisory, Vec<&Compiled>)> = advisories
            .into_iter()
            .filter_map(|a| {
                let hits: Vec<&Compiled> = feed.iter().copied().filter(|s| s.matches(&a)).collect();
                (!hits.is_empty()).then_some((a, hits))
            })
            .collect();
        if settings.use_epss && !candidates.is_empty() {
            let mut refs: Vec<&mut Advisory> = candidates.iter_mut().map(|c| &mut c.0).collect();
            if let Err(e) = self.step("EPSS", || self.add_epss(&mut refs)) {
                report.errors.push(format!("EPSS: {e:#}"));
            }
        }
        for (adv, hits) in &candidates {
            for sub in hits {
                self.consider(sub, adv, newly_exploited, settings, now, None, &mut report);
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
            Ok(Some(alert)) => {
                if settings.offline_days > 0 {
                    db.offline_put(&alert).ok();
                }
                report.alerts.push(alert);
                drop(db);
                self.progress().new_alerts += 1;
            }
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
        crate::track::step("CISA KEV", || self.refresh_kev(true)).map(|x| x.0).unwrap_or(current)
    }

    pub fn add_epss(&self, advisories: &mut [&mut Advisory]) -> Result<()> {
        let mut ids: Vec<String> = advisories.iter().filter_map(|a| a.cve_id().map(str::to_string)).collect();
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return Ok(());
        }
        let scores = crate::track::step("EPSS", || epss::lookup(&self.net, &ids))?;
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
pub(crate) fn same_target(a: &Target, b: &Target) -> bool {
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

    #[test]
    fn a_check_reports_each_step_and_what_it_found() {
        let (core, sub) = setup(Filter::default());
        // Outside a check nothing is recorded.
        core.step("idle", || Ok(())).unwrap();
        assert_eq!(core.check_progress()["steps"].as_array().unwrap().len(), 0);

        *core.progress() = Progress { running: true, started: Some(Instant::now()), ..Default::default() };
        {
            let _running = Running(&core);
            core.step("fast", || Ok(())).unwrap();
            core.step("broken", || Err::<(), _>(anyhow!("no answer"))).unwrap_err();
            core.step("slow", || {
                let p = core.check_progress();
                assert_eq!(p["running"], true);
                assert_eq!(p["steps"][0]["state"], "done");
                assert_eq!(p["steps"][1]["state"], "failed");
                assert_eq!(p["steps"][1]["error"], "no answer");
                assert_eq!(p["steps"][2]["name"], "slow");
                assert_eq!(p["steps"][2]["state"], "running");
                Ok(())
            })
            .unwrap();
            let mut report = PollReport::default();
            core.consider(&sub, &polkit(), &[], &core.settings(), Utc::now(), None, &mut report);
            core.consider(&sub, &polkit(), &[], &core.settings(), Utc::now(), None, &mut report);
            assert_eq!(report.alerts.len(), 1);
        }
        let p = core.check_progress();
        assert_eq!(p["running"], false);
        assert_eq!(p["new"], 1);
        assert_eq!(p["steps"][2]["state"], "done");
        assert!(p["ms"].is_u64());
    }

    #[test]
    fn a_crashed_check_does_not_stop_later_ones() {
        let (core, _) = setup(Filter::default());
        assert_eq!(core.since_last_check(), -1);
        // What a check that panicked leaves behind: its lock, poisoned.
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _held = core.poll_lock.lock().unwrap();
                    panic!("boom");
                })
                .join();
        });
        assert!(core.poll_lock.is_poisoned());
        let mut s = core.settings();
        s.remote = crate::settings::Remote { enabled: true, url: "http://127.0.0.1:9".into(), ..Default::default() };
        core.db().set("settings", &s).unwrap();
        let report = core.poll_by("manual");
        assert!(!report.skipped);
        let history = core.check_history();
        assert_eq!(history["checks"].as_array().unwrap().len(), 1);
        assert_eq!(history["checks"][0]["by"], "manual");
        assert!((0..5).contains(&core.since_last_check()));
        assert!(history["checks"][0]["errors"][0].as_str().unwrap().starts_with("server:"));

        // A check cut short (the app was killed) shows up, and is kept once the next one runs.
        core.db().set("check_started", &json!({ "at": Utc::now(), "by": "schedule" })).unwrap();
        assert_eq!(core.check_history()["checks"][0]["unfinished"], true);
        core.poll();
        let history = core.check_history();
        assert_eq!(history["checks"][0]["by"], "schedule");
        assert_eq!(history["checks"][1]["unfinished"], true);
        assert_eq!(history["checks"].as_array().unwrap().len(), 3);
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
