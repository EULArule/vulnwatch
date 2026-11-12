//! The one API every front end uses: `call(method, params) -> JSON`.
//!
//! The web UI reaches it over HTTP (`POST /api/rpc`), the app through a Tauri command. When the
//! app is paired with a server, most methods are forwarded there.

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::engine::flag_kev;
use crate::matcher::{cpe_vendor_product, suggest_keywords, Compiled, Filter, Subscription, Target};
use crate::model::{merge_all, Advisory};
use crate::notify::{self, Notification};
use crate::settings::Settings;
use crate::sources::{circl, cve5, cvedetails, euvd, nvd, osv};
use crate::{catalog, Core, VERSION};

/// Vulnerabilities per page on product pages.
const PAGE: usize = 100;
/// How long fetched lists/details are reused.
const CACHE_SECS: i64 = 30 * 60;
/// How long CIRCL's last answer may stand in for it while it is down (the cache keeps a week).
const STALE_SECS: i64 = 7 * 86400;

const CIRCL_DOWN: &str = "circl-down";

fn circl_key(vendor: &str, product: &str) -> String {
    format!("circl:{vendor}:{product}")
}

#[derive(Serialize, Deserialize)]
struct Listing {
    total: usize,
    /// Pass back as `end` to get the next (older) page.
    next_end: Option<usize>,
    items: Vec<Advisory>,
    #[serde(default)]
    notes: Vec<String>,
    /// `total` is NVD's count before unrelated entries were dropped, so an upper bound.
    #[serde(default)]
    approx: bool,
}

fn arg<T: serde::de::DeserializeOwned>(params: &Value, name: &str) -> Result<T> {
    serde_json::from_value(params[name].clone()).map_err(|e| anyhow!("bad parameter `{name}`: {e}"))
}

fn text(params: &Value, name: &str) -> Result<String> {
    let s = params[name].as_str().unwrap_or_default().trim().to_string();
    if s.is_empty() {
        bail!("missing parameter `{name}`");
    }
    Ok(s)
}

/// `CVE-2024-1234`, `GHSA-xxxx-xxxx-xxxx`, `PYSEC-2024-1`, ... typed into the search box.
pub fn looks_like_vuln_id(q: &str) -> Option<String> {
    let q = q.trim();
    let upper = q.to_uppercase();
    let cve = upper.strip_prefix("CVE-").is_some_and(|r| {
        let mut p = r.split('-');
        matches!((p.next(), p.next(), p.next()), (Some(y), Some(n), None)
            if y.len() == 4 && n.len() >= 4 && y.chars().chain(n.chars()).all(|c| c.is_ascii_digit()))
    });
    if cve {
        return Some(upper);
    }
    if upper.starts_with("GHSA-") && q.len() == 19 {
        return Some(format!("GHSA-{}", q[5..].to_lowercase()));
    }
    const PREFIXES: &[&str] = &["PYSEC-", "RUSTSEC-", "GO-", "OSV-", "MAL-", "DSA-", "DLA-", "USN-", "RHSA-", "ALSA-", "RLSA-"];
    (PREFIXES.iter().any(|p| upper.starts_with(p)) && q.len() > 6 && !q.contains(' ')).then_some(upper)
}

impl Core {
    /// Dispatch one API call.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let settings = self.settings();
        if settings.remote.enabled && self.mobile {
            match method {
                // Device-local state.
                "settings.get" | "settings.set" | "poll" | "remote.test" | "search" => {}
                "status" => {
                    let mut local = self.status(&settings);
                    match self.remote_call(&settings, "status", json!({})) {
                        Ok(remote) => {
                            for k in ["unread", "subscriptions", "last_check", "last_ok", "last_errors", "last_new"] {
                                local[k] = remote[k].clone();
                            }
                            local["server_version"] = remote["version"].clone();
                        }
                        Err(e) => local["last_errors"] = json!([format!("server: {e:#}")]),
                    }
                    return Ok(local);
                }
                _ => return self.remote_call(&settings, method, params),
            }
        }
        match method {
            "search" => {
                let q = params["q"].as_str().unwrap_or_default();
                Ok(json!({ "products": catalog::search(q, 40), "vuln_id": looks_like_vuln_id(q) }))
            }
            "search.online" => {
                let q = text(&params, "q")?;
                let hits = nvd::search_products(&self.net, settings.nvd_key(), &q)?;
                let products: Vec<Value> = hits
                    .iter()
                    .take(60)
                    .map(|h| json!({ "part": h.part, "vendor": h.vendor, "product": h.product, "title": h.title, "versions": h.versions }))
                    .collect();
                Ok(json!({ "products": products }))
            }
            "search.packages" => {
                let q = text(&params, "q")?;
                let found = osv::find_package(&self.net, &q)?;
                let packages: Vec<Value> =
                    found.into_iter().map(|(ecosystem, count)| json!({ "ecosystem": ecosystem, "name": q, "count": count })).collect();
                Ok(json!({ "packages": packages }))
            }
            "product.info" => {
                let (vendor, product) = (text(&params, "vendor")?, text(&params, "product")?);
                Ok(json!({
                    "product": catalog::find(&vendor, &product),
                    "vendor_products": catalog::vendor_size(&vendor),
                    "keywords": suggest_keywords(&vendor, &product),
                }))
            }
            "vulns.list" => {
                let target: Target = arg(&params, "target")?;
                let end: Option<usize> = arg(&params, "end")?;
                let refresh = params["refresh"].as_bool().unwrap_or(false);
                // `quick`: whatever can be shown at once (a cached list, or CIRCL's newest
                // records), so the page is not blank while NVD answers. `partial` tells the UI
                // that the full list is still worth asking for.
                let quick = params["quick"].as_bool().unwrap_or(false);
                let listing = if quick { self.quick_listing(&settings, &target)? } else { self.listing(&settings, &target, end, refresh)? };
                // What is on a page the user watches belongs in their alerts too.
                let new_alerts = if quick { 0 } else { self.alert_on_view(&settings, &target, &listing.items) };
                Ok(json!({
                    "new_alerts": new_alerts,
                    "partial": quick && listing.next_end == Some(usize::MAX),
                    "total": listing.total,
                    "approx": listing.approx,
                    "next_end": listing.next_end.filter(|e| *e != usize::MAX),
                    "notes": listing.notes,
                    "items": listing.items.iter().map(|a| a.view(false)).collect::<Vec<_>>(),
                }))
            }
            "vulns.get" => {
                let id = text(&params, "id")?;
                let id = looks_like_vuln_id(&id).unwrap_or(id);
                Ok(self.advisory(&settings, &id, params["refresh"].as_bool().unwrap_or(false))?.view(true))
            }
            "subs.list" => {
                let db = self.db();
                let counts = db.alert_counts()?;
                let subs: Vec<Value> = db
                    .subscriptions()?
                    .into_iter()
                    .map(|s| {
                        let (total, unread) = counts.get(&s.id).copied().unwrap_or((0, 0));
                        let mut v = json!(s);
                        v["alerts"] = json!(total);
                        v["unread"] = json!(unread);
                        v
                    })
                    .collect();
                Ok(json!({ "subscriptions": subs }))
            }
            "subs.save" => {
                let mut sub: Subscription = arg(&params, "subscription")?;
                sub.name = sub.name.trim().to_string();
                if sub.name.is_empty() {
                    sub.name = default_name(&sub.target);
                }
                clean_target(&mut sub.target)?;
                clean_filter(&mut sub.filter);
                // Compiling validates the keyword phrases.
                Compiled::new(sub.clone())?;
                let db = self.db();
                if sub.id == 0 {
                    let same = db.subscriptions()?.into_iter().find(|s| s.target == sub.target && s.filter == sub.filter);
                    if let Some(existing) = same {
                        bail!("you already have this subscription (\"{}\")", existing.name);
                    }
                }
                sub.id = db.save_subscription(&sub)?;
                let saved = db.subscriptions()?.into_iter().find(|s| s.id == sub.id);
                Ok(json!({ "subscription": saved }))
            }
            "subs.delete" => {
                self.db().delete_subscription(arg(&params, "id")?)?;
                Ok(json!({}))
            }
            "subs.preview" => {
                // "What would this filter have let through?" judged on the newest page of history.
                let target: Target = arg(&params, "target")?;
                let filter: Filter = arg(&params, "filter")?;
                let listing = self.listing(&settings, &target, None, false)?;
                let sub = Subscription { id: 0, name: String::new(), target, filter, enabled: true, notify: true, created_at: None };
                let compiled = Compiled::new(sub)?;
                let passing: Vec<&Advisory> = listing.items.iter().filter(|a| compiled.passes_filter(a)).collect();
                Ok(json!({
                    "checked": listing.items.len(),
                    "passing": passing.len(),
                    "sample": passing.iter().take(5).map(|a| a.view(false)).collect::<Vec<_>>(),
                }))
            }
            "alerts.list" => {
                let limit = params["limit"].as_u64().unwrap_or(50).clamp(1, 500) as u32;
                let db = self.db();
                let alerts = db.alerts(
                    arg(&params, "sub_id")?,
                    params["unread_only"].as_bool().unwrap_or(false),
                    arg(&params, "before_id")?,
                    None,
                    limit,
                )?;
                Ok(json!({ "more": alerts.len() as u32 == limit, "alerts": alerts, "unread": db.unread_count()? }))
            }
            "alerts.mark" => {
                let ids: Option<Vec<i64>> = arg(&params, "ids")?;
                let db = self.db();
                db.mark_read(ids.as_deref(), arg(&params, "sub_id")?, params["read"].as_bool().unwrap_or(true))?;
                Ok(json!({ "unread": db.unread_count()? }))
            }
            "alerts.delete" => {
                let ids: Option<Vec<i64>> = arg(&params, "ids")?;
                let db = self.db();
                db.delete_alerts(ids.as_deref(), arg(&params, "sub_id")?)?;
                Ok(json!({ "unread": db.unread_count()? }))
            }
            "alerts.since" => {
                // Used by paired apps. Without `after_id` only the high-water mark is returned, so
                // a freshly paired phone is not flooded with history.
                let db = self.db();
                let after: Option<i64> = arg(&params, "after_id")?;
                let max_id = db.max_alert_id()?;
                let Some(after) = after else { return Ok(json!({ "alerts": [], "notifications": [], "max_id": max_id })) };
                let alerts = db.alerts(None, false, None, Some(after), 200)?;
                let notifying: Vec<i64> = db.subscriptions()?.into_iter().filter(|s| s.notify).map(|s| s.id).collect();
                let wanted: Vec<_> = alerts.iter().filter(|a| notifying.contains(&a.sub_id)).collect();
                let notifications = notify::build(&wanted);
                // Nothing newer: report the real high-water mark (lower than `after` if the server was reset).
                let max_id = alerts.last().map(|a| a.id).unwrap_or(max_id);
                Ok(json!({ "alerts": alerts, "notifications": notifications, "max_id": max_id }))
            }
            "settings.get" => Ok(json!({ "settings": settings })),
            "settings.set" => {
                let new: Settings = arg(&params, "settings")?;
                let new = new.sanitize();
                let db = self.db();
                if new.remote != settings.remote {
                    db.delete("remote_last_alert")?;
                }
                if new.nvd_api_key != settings.nvd_api_key
                    || new.use_circl != settings.use_circl
                    || new.use_euvd != settings.use_euvd
                    || new.cvedetails_token != settings.cvedetails_token
                {
                    db.cache_clear()?;
                }
                db.set("settings", &new)?;
                Ok(json!({ "settings": new }))
            }
            "remote.test" => {
                let probe = Settings {
                    remote: crate::settings::Remote { enabled: true, url: text(&params, "url")?, token: params["token"].as_str().unwrap_or_default().into() },
                    ..Default::default()
                }
                .sanitize();
                let status = self.remote_call(&probe, "status", json!({}))?;
                Ok(json!({ "version": status["version"], "subscriptions": status["subscriptions"] }))
            }
            "status" => Ok(self.status(&settings)),
            "poll" => {
                let report = self.poll();
                Ok(json!({
                    "new": report.alerts.len(),
                    "checked": report.checked,
                    "errors": report.errors,
                    "skipped": report.skipped,
                    "notifications": report.notifications,
                }))
            }
            "notify.test" => {
                let n = Notification {
                    id: 0,
                    title: "vulnwatch test notification".into(),
                    body: "If you can read this, alerts will reach you here.".into(),
                    url: None,
                    priority: 3,
                    vuln_id: String::new(),
                };
                let errors = notify::push(&self.net, &settings, std::slice::from_ref(&n), &[]);
                Ok(json!({
                    "notification": n,
                    "errors": errors,
                    "channels": { "ntfy": settings.ntfy.enabled, "webhook": settings.webhook.enabled },
                }))
            }
            _ => bail!("unknown method `{method}`"),
        }
    }

    fn status(&self, settings: &Settings) -> Value {
        let db = self.db();
        let mut v: Value = db.get("status").ok().flatten().unwrap_or_else(|| json!({}));
        v["version"] = json!(VERSION);
        v["mobile"] = json!(self.mobile);
        v["remote"] = json!(settings.remote.enabled && self.mobile);
        v["unread"] = json!(db.unread_count().unwrap_or(0));
        v["subscriptions"] = json!(db.subscriptions().map(|s| s.len()).unwrap_or(0));
        v["interval_minutes"] = json!(settings.interval_minutes);
        v["background"] = json!(settings.background);
        v["nvd_key"] = json!(settings.nvd_key().is_some());
        v["now"] = json!(Utc::now());
        v
    }

    /// Call the paired server.
    pub(crate) fn remote_call(&self, settings: &Settings, method: &str, params: Value) -> Result<Value> {
        let url = &settings.remote.url;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            bail!("server address must start with http:// or https://");
        }
        let auth = format!("Bearer {}", settings.remote.token);
        let reply = self
            .net
            .post_json(&format!("{url}/api/rpc"), &[("Authorization", auth.as_str())], &json!({ "method": method, "params": params }))
            .map_err(|e| match crate::net::status_of(&e) {
                Some(401 | 403) => anyhow!("the server rejected the access token"),
                _ => e.context("could not reach the vulnwatch server"),
            })?;
        if let Some(err) = reply["error"].as_str() {
            bail!("{err}");
        }
        Ok(reply["result"].clone())
    }

    /// One page of a target's vulnerability history, newest first.
    /// A first look that needs no slow request: the cached full list if there is one, otherwise
    /// CIRCL's newest records for a product (about a second). `next_end == usize::MAX` marks it partial.
    fn quick_listing(&self, settings: &Settings, target: &Target) -> Result<Listing> {
        let cache_key = format!("list:{}:", serde_json::to_string(target)?);
        if let Some(hit) = self.db().cache_get(&cache_key, CACHE_SECS)?.and_then(|v| serde_json::from_value(v).ok()) {
            return Ok(hit);
        }
        let mut items = match target {
            Target::Product { vendor, product, .. } if settings.use_circl => {
                let alias_key = format!("alias:{}", serde_json::to_string(target)?);
                let alias: Option<(String, String)> =
                    self.db().cache_get(&alias_key, 30 * 86400)?.and_then(|v| serde_json::from_value(v).ok());
                let (v, p) = alias.as_ref().map(|(v, p)| (v.as_str(), p.as_str())).unwrap_or((vendor, product));
                // No waiting here: CIRCL right now, or else what it said last time.
                let live = match self.circl_down() {
                    None => circl::by_product_page(&self.net, v, p, PAGE, 1, false).ok(),
                    Some(_) => None,
                };
                match live {
                    Some(list) => list,
                    None => self.db().cache_get(&circl_key(v, p), STALE_SECS)?.and_then(|c| serde_json::from_value(c).ok()).unwrap_or_default(),
                }
            }
            _ => vec![],
        };
        let kev = self.kev();
        for a in &mut items {
            flag_kev(a, &kev);
        }
        items.sort_by(|a, b| b.published.cmp(&a.published).then_with(|| b.id.cmp(&a.id)));
        Ok(Listing { total: items.len(), next_end: Some(usize::MAX), items, notes: vec![], approx: false })
    }

    /// Page `k` (from 1, newest first) of the CVEs published under a vendor/product name, as the
    /// publishers spell it. CIRCL answers this; when it is switched off or down, EUVD does (for
    /// the CVEs published around or after `newest_nvd`, the ones NVD cannot supply yet); failing
    /// that, CIRCL's last answer. What had to be substituted is added to `notes`.
    fn by_publisher_name(
        &self,
        settings: &Settings,
        vendor: &str,
        product: &str,
        k: usize,
        newest_nvd: Option<DateTime<Utc>>,
        notes: &mut Vec<String>,
    ) -> Vec<Advisory> {
        let key = circl_key(vendor, product);
        let mut down = self.circl_down();
        if settings.use_circl && down.is_none() {
            match circl::by_product_page(&self.net, vendor, product, PAGE, k, true) {
                Ok(list) => {
                    if k == 1 {
                        self.db().cache_put(&key, &json!(list)).ok();
                    }
                    return list;
                }
                Err(e) => {
                    let msg = format!("CIRCL is not answering ({e:#})");
                    self.db().cache_put(CIRCL_DOWN, &json!(msg)).ok();
                    down = Some(msg);
                }
            }
        }
        if settings.use_euvd {
            match self.euvd_since(vendor, product, newest_nvd) {
                Ok(found) => {
                    if let Some(down) = &down {
                        notes.push(format!("{down}. The newest CVEs come from ENISA's EUVD instead."));
                    }
                    if found.truncated {
                        notes.push("EUVD has more recent CVEs for this product than could be loaded; some from before the newest may be missing.".into());
                    }
                    return found.items.into_iter().skip((k - 1) * PAGE).take(PAGE).collect();
                }
                Err(e) => match &mut down {
                    Some(down) => down.push_str(&format!(", and neither is EUVD ({e:#})")),
                    None => down = Some(format!("EUVD is not answering ({e:#})")),
                },
            }
        }
        let Some(down) = down else { return vec![] };
        let saved: Option<(i64, Vec<Advisory>)> = match k {
            1 => self.db().cache_entry(&key, STALE_SECS).ok().flatten().and_then(|(at, v)| Some((at, serde_json::from_value(v).ok()?))),
            _ => None,
        };
        match saved {
            Some((at, list)) => {
                let hours = (Utc::now().timestamp() - at) / 3600;
                let age = match hours {
                    0 => "less than an hour ago".to_string(),
                    1..=47 => format!("{hours} h ago"),
                    _ => format!("{} days ago", hours / 24),
                };
                notes.push(format!("{down}. Showing what CIRCL listed {age}; newer CVEs may be missing."));
                list
            }
            None => {
                notes.push(format!("{down}. CVEs that NVD has not analysed yet may be missing."));
                vec![]
            }
        }
    }

    /// Set for a couple of minutes after CIRCL failed, so that the other lookups of the same page,
    /// and the pages after it, do not each wait for it again. Refreshing a list asks it anew.
    fn circl_down(&self) -> Option<String> {
        self.db().cache_get(CIRCL_DOWN, 120).ok().flatten().and_then(|v| v.as_str().map(str::to_string))
    }

    /// EUVD's records for a name since shortly before `newest_nvd`, kept for a while: every page
    /// of a listing is cut from the same download.
    fn euvd_since(&self, vendor: &str, product: &str, newest_nvd: Option<DateTime<Utc>>) -> Result<euvd::Found> {
        // A week of overlap: NVD does not analyse in order of publication.
        let floor = Utc::now() - chrono::Duration::days(120);
        let from = newest_nvd.map(|d| d - chrono::Duration::days(7)).unwrap_or(floor).max(floor).date_naive();
        let key = format!("euvd:{vendor}:{product}:{from}");
        if let Some((items, truncated)) = self.db().cache_get(&key, CACHE_SECS)?.and_then(|v| serde_json::from_value(v).ok()) {
            return Ok(euvd::Found { items, truncated });
        }
        let found = euvd::since(&self.net, vendor, product, from)?;
        self.db().cache_put(&key, &json!((&found.items, found.truncated)))?;
        Ok(found)
    }

    /// The newest page of a target's list (reusing a recent copy).
    pub(crate) fn newest(&self, settings: &Settings, target: &Target) -> Result<Vec<Advisory>> {
        Ok(self.listing(settings, target, None, false)?.items)
    }

    fn listing(&self, settings: &Settings, target: &Target, end: Option<usize>, refresh: bool) -> Result<Listing> {
        let cache_key = format!("list:{}:{}", serde_json::to_string(target)?, end.map(|e| e.to_string()).unwrap_or_default());
        if !refresh {
            if let Some(hit) = self.db().cache_get(&cache_key, CACHE_SECS)?.and_then(|v| serde_json::from_value(v).ok()) {
                return Ok(hit);
            }
        }
        if refresh {
            self.db().cache_put(CIRCL_DOWN, &Value::Null)?;
        }
        let key = settings.nvd_key();
        let mut notes: Vec<String> = vec![];
        // How many NVD had last time (kept for a week): lets the newest page skip the counting request.
        let total_key = format!("nvd-total:{}", serde_json::to_string(target)?);
        // `end` values from AHEAD up are not NVD positions: AHEAD + k is page k of the CVEs that
        // are newer than anything NVD lists for a product (see below).
        let ahead_page = end.filter(|e| *e >= AHEAD).map(|e| e - AHEAD);
        let end = end.filter(|e| *e < AHEAD);
        let hint: Option<usize> = match end {
            None => self.db().cache_get(&total_key, 7 * 86400)?.and_then(|v| v.as_u64()).map(|n| n as usize),
            Some(_) => None,
        };
        let mut nvd_total = None;
        let mut approx = false;
        let mut from_page = |p: nvd::Page| {
            nvd_total = Some(p.total);
            (p.total, (p.start > 0).then_some(p.start), p.items)
        };
        let (total, next_end, mut items) = match target {
            Target::Product { vendor, product, .. } => {
                let first_key = format!("nvd-first:{}", serde_json::to_string(target)?);
                let cached: Option<(usize, Option<usize>, Vec<Advisory>, bool)> = match ahead_page {
                    Some(_) => self.db().cache_get(&first_key, CACHE_SECS)?.and_then(|v| serde_json::from_value(v).ok()),
                    None => None,
                };
                let fresh = cached.is_none();
                let (mut total, mut next, mut items) = match cached {
                    Some((t, n, i, a)) => {
                        approx = a;
                        (t, n, i)
                    }
                    None => from_page(nvd::by_product(&self.net, key, vendor, product, end, PAGE, hint)?),
                };
                // NVD also returns CVEs that merely list this product as the platform something
                // else runs on ("IBM Foo running on Linux"). Keep only those where it is the
                // vulnerable product, and read further back if that leaves the page thin.
                let about = |a: &Advisory| {
                    a.affected.iter().flat_map(|x| &x.cpes).filter_map(|c| cpe_vendor_product(c)).any(|(v, p)| v == *vendor && p == *product)
                };
                let fetched = items.len();
                items.retain(about);
                approx |= items.len() < fetched;
                for _ in 0..2 {
                    let Some(e) = next.filter(|_| fresh && items.len() < PAGE / 4) else { break };
                    let older = nvd::by_product(&self.net, key, vendor, product, Some(e), PAGE, None)?;
                    next = (older.start > 0).then_some(older.start);
                    approx = true;
                    items.extend(older.items.into_iter().filter(about));
                }
                if fresh && end.is_none() {
                    self.db().cache_put(&first_key, &json!((total, next, &items, approx)))?;
                }
                if end.is_none() && (settings.use_circl || settings.use_euvd || settings.cvedetails_key().is_some()) {
                    // CIRCL indexes vendor-assigned product names too, so it knows CVEs NVD has
                    // not analysed yet. Only merge what belongs on this (newest) page.
                    // NVD takes weeks to attach its product name to a new CVE. Until then a CVE
                    // only carries the name its publisher uses ("Linux Linux" for the kernel),
                    // so learn that name from the CVEs we do have and ask CIRCL for it as well.
                    let alias_key = format!("alias:{}", serde_json::to_string(target)?);
                    let alias = publisher_name(&items, vendor, product);
                    if let Some(a) = &alias {
                        self.db().cache_put(&alias_key, &json!(a))?;
                    }
                    let alias: Option<(String, String)> = match alias {
                        Some(a) => Some(a),
                        None => self.db().cache_get(&alias_key, 30 * 86400)?.and_then(|v| serde_json::from_value(v).ok()),
                    };
                    let k = ahead_page.unwrap_or(1);
                    let newest_nvd = items.iter().filter_map(|a| a.published).max();
                    let ahead = match &alias {
                        Some((v, p)) => self.by_publisher_name(settings, v, p, k, newest_nvd, &mut notes),
                        None => vec![],
                    };
                    // A whole page newer than NVD's newest: show it by itself and continue with
                    // the next such page, so no stretch of recent CVEs is skipped.
                    let gap = k < 200
                        && !ahead.is_empty()
                        && newest_nvd.is_some_and(|d| ahead.iter().all(|a| a.published.is_some_and(|p| p > d)));
                    let mut extra = ahead;
                    if gap {
                        items = std::mem::take(&mut extra);
                        next = Some(AHEAD + k + 1);
                        approx = true;
                    } else if k == 1 {
                        extra.extend(self.by_publisher_name(settings, vendor, product, 1, newest_nvd, &mut notes));
                    }
                    if let (1, Some(token)) = (k, settings.cvedetails_key()) {
                        match cvedetails::by_product(&self.net, token, vendor, product, PAGE, 1) {
                            Ok(list) => extra.extend(list),
                            Err(e) => notes.push(format!("CVEdetails lookup failed: {e:#}")),
                        }
                    }
                    let oldest = items.iter().filter_map(|a| a.published).min();
                    let before = items.len();
                    let keep = extra.into_iter().filter(|a| {
                        items.iter().any(|i| i.id == a.id) || next.is_none() || matches!((a.published, oldest), (Some(p), Some(o)) if p >= o)
                    });
                    let merged: Vec<Advisory> = keep.collect();
                    items = merge_all(items.into_iter().chain(merged));
                    total += items.len() - before;
                }
                (total, next, items)
            }
            Target::Vendor { vendor } => {
                let (total, next, mut items) = from_page(nvd::by_vendor(&self.net, key, vendor, end, PAGE, hint)?);
                items.retain(|a| a.affected.iter().flat_map(|x| &x.cpes).filter_map(|c| cpe_vendor_product(c)).any(|(v, _)| v == *vendor));
                (total, next, items)
            }
            Target::Keyword { keywords } => {
                let words: Vec<&String> = keywords.iter().filter(|k| !k.trim().is_empty()).take(3).collect();
                match words.as_slice() {
                    [] => bail!("enter at least one keyword"),
                    [one] => from_page(nvd::by_keyword(&self.net, key, one, end, PAGE, hint)?),
                    many => {
                        let mut all = vec![];
                        let mut total = 0;
                        for w in many {
                            let page = nvd::by_keyword(&self.net, key, w, None, PAGE, None)?;
                            total += page.total;
                            all.extend(page.items);
                        }
                        notes.push("Showing the newest matches for each keyword.".into());
                        (total, None, merge_all(all))
                    }
                }
            }
            Target::Package { ecosystem, name } => {
                let items = osv::by_package(&self.net, ecosystem, name)?;
                (items.len(), None, items)
            }
            Target::Everything => from_page(nvd::latest(&self.net, key, end, PAGE, hint)?),
        };
        let kev = self.kev_ready();
        for a in &mut items {
            flag_kev(a, &kev);
        }
        if settings.use_epss {
            let mut refs: Vec<&mut Advisory> = items.iter_mut().collect();
            if let Err(e) = self.add_epss(&mut refs) {
                notes.push(format!("EPSS lookup failed: {e:#}"));
            }
        }
        items.sort_by(|a, b| b.published.cmp(&a.published).then_with(|| b.id.cmp(&a.id)));
        let mut seen = std::collections::HashSet::new();
        notes.retain(|n| seen.insert(n.clone()));
        let listing = Listing { total, next_end, items, notes, approx };
        self.db().cache_put(&cache_key, &json!(listing))?;
        if let (None, Some(n)) = (end, nvd_total) {
            self.db().cache_put(&total_key, &json!(n))?;
        }
        Ok(listing)
    }

    /// Full detail for one vulnerability, merged from every source that knows it.
    fn advisory(&self, settings: &Settings, id: &str, refresh: bool) -> Result<Advisory> {
        let cache_key = format!("vuln:{id}");
        if !refresh {
            if let Some(hit) = self.db().cache_get(&cache_key, CACHE_SECS)?.and_then(|v| serde_json::from_value(v).ok()) {
                return Ok(hit);
            }
        }
        let mut found: Vec<Advisory> = vec![];
        let mut failure = None;
        if id.starts_with("CVE-") {
            match nvd::by_id(&self.net, settings.nvd_key(), id) {
                Ok(a) => found.extend(a),
                Err(e) => failure = Some(e),
            }
            // The CVE record itself: has the vendor's own product names, fix versions and score,
            // and exists before NVD has processed the CVE.
            match self.net.get_json(&format!("https://cveawg.mitre.org/api/cve/{id}"), &[], &[]) {
                Ok(v) => found.extend(cve5::parse(&v)),
                Err(e) if found.is_empty() => failure = Some(e),
                Err(_) => {}
            }
        } else {
            match osv::by_id(&self.net, id) {
                Ok(a) => found.extend(a),
                Err(e) => failure = Some(e),
            }
        }
        let Some(mut adv) = merge_all(found).into_iter().next() else {
            return match failure {
                Some(e) if crate::net::status_of(&e) != Some(404) => Err(e).context(format!("could not load {id}")),
                _ => Err(anyhow!("{id} was not found")),
            };
        };
        flag_kev(&mut adv, &self.kev_ready());
        if settings.use_epss {
            self.add_epss(&mut [&mut adv]).ok();
        }
        self.db().cache_put(&cache_key, &json!(adv))?;
        Ok(adv)
    }
}

fn default_name(target: &Target) -> String {
    match target {
        Target::Product { vendor, product, .. } => {
            catalog::find(vendor, product).map(|p| p.title).unwrap_or_else(|| format!("{vendor} {product}").replace('_', " "))
        }
        Target::Vendor { vendor } => format!("Everything from {}", vendor.replace('_', " ")),
        Target::Package { ecosystem, name } => format!("{name} ({ecosystem})"),
        Target::Keyword { keywords } => keywords.join(", "),
        Target::Everything => "All vulnerabilities".into(),
    }
}

fn clean_list(list: &mut Vec<String>) {
    *list = list.iter().map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect();
    list.dedup();
}

fn clean_target(target: &mut Target) -> Result<()> {
    match target {
        Target::Product { vendor, product, keywords } => {
            *vendor = vendor.trim().to_lowercase();
            *product = product.trim().to_lowercase();
            clean_list(keywords);
            if vendor.is_empty() || product.is_empty() {
                bail!("a product subscription needs a vendor and a product");
            }
        }
        Target::Vendor { vendor } => {
            *vendor = vendor.trim().to_lowercase();
            if vendor.is_empty() {
                bail!("a vendor subscription needs a vendor");
            }
        }
        Target::Package { ecosystem, name } => {
            *name = name.trim().to_string();
            let known = osv::ECOSYSTEMS.iter().find(|e| crate::matcher::ecosystem_eq(e, ecosystem));
            *ecosystem = known.map(|e| e.to_string()).unwrap_or_else(|| ecosystem.trim().to_string());
            if name.is_empty() || ecosystem.is_empty() {
                bail!("a package subscription needs an ecosystem and a package name");
            }
        }
        Target::Keyword { keywords } => {
            clean_list(keywords);
            if keywords.is_empty() {
                bail!("enter at least one keyword");
            }
            if keywords.iter().any(|k| k.chars().count() < 3) {
                bail!("keywords must be at least 3 characters");
            }
        }
        Target::Everything => {}
    }
    Ok(())
}

fn clean_filter(filter: &mut Filter) {
    clean_list(&mut filter.include_keywords);
    clean_list(&mut filter.exclude_keywords);
    filter.min_cvss = filter.min_cvss.filter(|c| *c > 0.0).map(|c| (c.min(10.0) * 10.0).round() / 10.0);
    filter.min_epss = filter.min_epss.filter(|p| *p > 0.0).map(|p| p.min(1.0));
    filter.attack_vectors.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn core() -> Core {
        Core::with_store(Store::in_memory().unwrap(), false)
    }

    #[test]
    fn recognises_ids() {
        assert_eq!(looks_like_vuln_id(" cve-2024-3094 ").as_deref(), Some("CVE-2024-3094"));
        assert_eq!(looks_like_vuln_id("GHSA-462W-V97R-4M45").as_deref(), Some("GHSA-462w-v97r-4m45"));
        assert_eq!(looks_like_vuln_id("openssl"), None);
        assert_eq!(looks_like_vuln_id("cve-2024"), None);
        assert_eq!(looks_like_vuln_id("go lang"), None);
    }

    #[test]
    fn subscription_lifecycle() {
        let c = core();
        let saved = c
            .call("subs.save", json!({ "subscription": { "name": "", "target": { "kind": "product", "vendor": "OpenBSD", "product": "openssh", "keywords": [" OpenSSH ", ""] } } }))
            .unwrap();
        let sub = &saved["subscription"];
        assert_eq!(sub["target"]["vendor"], "openbsd");
        assert_eq!(sub["target"]["keywords"], json!(["OpenSSH"]));
        assert!(sub["name"].as_str().unwrap().to_lowercase().contains("openssh"));
        assert!(sub["created_at"].is_string());
        let id = sub["id"].as_i64().unwrap();

        // The same thing twice is refused; editing is fine.
        assert!(c.call("subs.save", json!({ "subscription": { "name": "x", "target": sub["target"] } })).is_err());
        let mut edited = sub.clone();
        edited["filter"]["min_severity"] = json!("high");
        edited["name"] = json!("SSH");
        c.call("subs.save", json!({ "subscription": edited })).unwrap();

        let list = c.call("subs.list", json!({})).unwrap();
        assert_eq!(list["subscriptions"].as_array().unwrap().len(), 1);
        assert_eq!(list["subscriptions"][0]["name"], "SSH");
        assert_eq!(list["subscriptions"][0]["filter"]["min_severity"], "high");
        assert_eq!(list["subscriptions"][0]["alerts"], 0);

        c.call("subs.delete", json!({ "id": id })).unwrap();
        assert!(c.call("subs.list", json!({})).unwrap()["subscriptions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        let c = core();
        assert!(c.call("subs.save", json!({ "subscription": { "name": "k", "target": { "kind": "keyword", "keywords": ["ab"] } } })).is_err());
        assert!(c.call("subs.save", json!({ "subscription": { "name": "k", "target": { "kind": "vendor", "vendor": " " } } })).is_err());
        assert!(c.call("nope", json!({})).is_err());
    }

    #[test]
    fn settings_round_trip_and_status() {
        let c = core();
        let mut s = c.call("settings.get", json!({})).unwrap()["settings"].clone();
        assert_eq!(s["interval_minutes"], 5);
        s["interval_minutes"] = json!(0);
        s["ntfy"]["topic"] = json!(" my-topic ");
        let saved = c.call("settings.set", json!({ "settings": s })).unwrap();
        assert_eq!(saved["settings"]["interval_minutes"], 1);
        assert_eq!(saved["settings"]["ntfy"]["topic"], "my-topic");
        let status = c.call("status", json!({})).unwrap();
        assert_eq!(status["version"], VERSION);
        assert_eq!(status["unread"], 0);
    }

    #[test]
    fn search_uses_the_bundled_catalog() {
        let c = core();
        let r = c.call("search", json!({ "q": "openssh" })).unwrap();
        let first = &r["products"][0];
        assert_eq!(first["vendor"], "openbsd");
        assert_eq!(first["product"], "openssh");
        let r = c.call("search", json!({ "q": "CVE-2024-3094" })).unwrap();
        assert_eq!(r["vuln_id"], "CVE-2024-3094");
    }
}

/// The vendor/product name CVE publishers most often use for a product, when it differs from
/// NVD's: taken from the publisher-declared names on CVEs already known to be about it.
// Far above any NVD position, and still fits a 32-bit usize (armv7 phones).
const AHEAD: usize = 1 << 30;

fn publisher_name(items: &[Advisory], vendor: &str, product: &str) -> Option<(String, String)> {
    use crate::matcher::norm;
    let mut counts: std::collections::HashMap<(String, String), usize> = Default::default();
    let mut declared = 0;
    for a in items {
        let mut names: Vec<(String, String)> = a
            .affected
            .iter()
            .filter_map(|x| Some((norm(x.vendor.as_deref()?), norm(x.product.as_deref()?))))
            .filter(|(v, p)| !v.is_empty() && !p.is_empty() && v != "n_a" && p != "n_a")
            .collect();
        names.sort();
        names.dedup();
        declared += usize::from(!names.is_empty());
        for n in names {
            *counts.entry(n).or_default() += 1;
        }
    }
    let (name, n) = counts.into_iter().max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))?;
    (declared >= 5 && n * 2 > declared && name != (norm(vendor), norm(product))).then_some(name)
}
