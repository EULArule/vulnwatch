//! Export and import: the settings, what is watched, and the alerts received so far, as one JSON
//! document. It can be kept as a backup, moved to another device, or handed to someone else.
//!
//! Importing adds to what is there: a subscription that is already watched (same target, same
//! filter) is left alone, an alert that is already listed is not listed twice, and settings the
//! document does not mention keep their value.

use std::collections::HashMap;

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::api::clean_subscription;
use crate::matcher::Subscription;
use crate::settings::Settings;
use crate::store::AlertKind;
use crate::{Core, VERSION};

/// The layout of the document. Raised only when an older vulnwatch could no longer read it.
const FORMAT: u64 = 1;

/// Settings that are credentials, or lead to the owner's own channels and server. They are left
/// out of an export unless asked for, so that a file can be passed on without a second thought.
const PRIVATE: [&str; 5] = ["nvd_api_key", "cvedetails_token", "ntfy", "webhook", "remote"];

/// An alert as it travels: without its number here, and tied to a subscription of the same document.
#[derive(Debug, Serialize, Deserialize)]
struct Past {
    sub_id: i64,
    vuln_id: String,
    kind: AlertKind,
    created_at: DateTime<Utc>,
    #[serde(default)]
    read: bool,
    #[serde(default)]
    vuln: Value,
}

impl Core {
    /// A paired app keeps only its settings; what it watches and its alerts are its server's.
    fn paired(&self, settings: &Settings) -> bool {
        settings.remote.enabled && self.mobile
    }

    /// `params`: which of `settings`, `subscriptions`, `alerts` to put in, and whether the
    /// settings come with their `secrets`. Alerts bring the subscriptions they belong to.
    pub(crate) fn export_data(&self, settings: &Settings, params: &Value) -> Result<Value> {
        let want = |what: &str| params[what].as_bool().unwrap_or(false);
        let alerts = want("alerts");
        let subs = want("subscriptions") || alerts;
        ensure!(want("settings") || subs, "choose what to export");

        let now = Utc::now();
        let mut doc = Map::new();
        doc.insert("vulnwatch_export".into(), json!(FORMAT));
        doc.insert("version".into(), json!(VERSION));
        doc.insert("exported_at".into(), json!(now));
        if want("settings") {
            let mut own = json!(settings);
            if !want("secrets") {
                for key in PRIVATE {
                    own.as_object_mut().map(|o| o.remove(key));
                }
            }
            doc.insert("settings".into(), own);
        }
        if subs && self.paired(settings) {
            let mut theirs = self.remote_call(settings, "data.export", json!({ "subscriptions": true, "alerts": alerts }))?;
            for part in ["subscriptions", "alerts"] {
                if let Some(v) = theirs["export"].get_mut(part) {
                    doc.insert(part.into(), v.take());
                }
            }
        } else if subs {
            let db = self.db();
            doc.insert("subscriptions".into(), json!(db.subscriptions()?));
            if alerts {
                // Oldest first, the order they were raised in.
                let past: Vec<Past> = db
                    .alerts(None, false, None, None, u32::MAX)?
                    .into_iter()
                    .rev()
                    .map(|a| Past { sub_id: a.sub_id, vuln_id: a.vuln_id, kind: a.kind, created_at: a.created_at, read: a.read, vuln: a.vuln })
                    .collect();
                doc.insert("alerts".into(), json!(past));
            }
        }
        Ok(json!({ "export": doc, "name": format!("vulnwatch-{}.json", now.format("%Y-%m-%d")) }))
    }

    /// `params`: `data` (an exported document) and, optionally, which of `settings`,
    /// `subscriptions`, `alerts` to take from it (default: everything it has).
    pub(crate) fn import_data(&self, settings: &Settings, params: &Value) -> Result<Value> {
        let data = &params["data"];
        let format = data["vulnwatch_export"].as_u64().context("that is not a vulnwatch export")?;
        ensure!(format <= FORMAT, "that export was made by a newer vulnwatch; update this one to import it");
        let want = |what: &str| params[what].as_bool().unwrap_or(true) && !data[what].is_null();
        let alerts = want("alerts");
        let subs = want("subscriptions") || alerts;
        ensure!(want("settings") || subs, "there is nothing to import");

        // Everything is read before anything is changed, so a bad document changes nothing.
        let new_settings = if want("settings") { Some(merged(settings, &data["settings"])?) } else { None };
        let mut out = json!({ "settings": false });
        if subs && self.paired(settings) {
            let part = json!({
                "vulnwatch_export": format,
                "subscriptions": data["subscriptions"],
                "alerts": if alerts { data["alerts"].clone() } else { Value::Null },
            });
            let done = self.remote_call(settings, "data.import", json!({ "data": part }))?;
            out["subscriptions"] = done["subscriptions"].clone();
            out["alerts"] = done["alerts"].clone();
        } else if subs {
            let mut incoming: Vec<Subscription> = list(&data["subscriptions"]).context("the watch list in that export cannot be read")?;
            for sub in &mut incoming {
                let name = sub.name.clone();
                clean_subscription(sub).with_context(|| format!("\"{name}\" in that export cannot be used"))?;
            }
            let mut past: Vec<Past> = if alerts { list(&data["alerts"]).context("the alerts in that export cannot be read")? } else { vec![] };
            past.sort_by_key(|p| p.created_at);

            let db = self.db();
            let counts = db.all_or_nothing(|| {
                let mut mine = db.subscriptions()?;
                // Their number in the document -> the number and name here.
                let mut here: HashMap<i64, (i64, String)> = HashMap::new();
                let (mut added, mut known) = (0, 0);
                for mut sub in incoming {
                    let theirs = sub.id;
                    let same = mine.iter().find(|m| m.target == sub.target && m.filter == sub.filter).map(|m| (m.id, m.name.clone()));
                    let place = match same {
                        Some(place) => {
                            known += 1;
                            place
                        }
                        None => {
                            sub.id = 0;
                            sub.id = db.save_subscription(&sub)?;
                            added += 1;
                            let place = (sub.id, sub.name.clone());
                            mine.push(sub);
                            place
                        }
                    };
                    here.insert(theirs, place);
                }
                let (mut listed, mut had) = (0, 0);
                for p in &past {
                    // Alerts of a subscription the document does not carry have nowhere to go.
                    let Some((id, name)) = here.get(&p.sub_id) else { continue };
                    if db.import_alert(*id, name, &p.vuln_id, p.kind, p.created_at, p.read, &p.vuln)? {
                        listed += 1;
                    } else {
                        had += 1;
                    }
                }
                Ok([added, known, listed, had])
            })?;
            drop(db);
            if counts[2] > 0 {
                self.keep_recent_alerts(settings.offline_days)?;
            }
            out["subscriptions"] = json!({ "added": counts[0], "existing": counts[1] });
            if alerts {
                out["alerts"] = json!({ "added": counts[2], "existing": counts[3] });
            }
        }
        if let Some(new) = new_settings {
            self.apply_settings(settings, new)?;
            out["settings"] = json!(true);
        }
        Ok(out)
    }
}

fn list<T: serde::de::DeserializeOwned>(v: &Value) -> Result<Vec<T>> {
    if v.is_null() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_value(v.clone())?)
}

/// The current settings with those of an export laid over them.
fn merged(current: &Settings, theirs: &Value) -> Result<Settings> {
    if !theirs.is_object() {
        bail!("the settings in that export cannot be read");
    }
    let mut all = json!(current);
    overlay(&mut all, theirs);
    let new: Settings = serde_json::from_value(all).context("the settings in that export cannot be read")?;
    Ok(new.sanitize())
}

fn overlay(base: &mut Value, over: &Value) {
    match (base, over) {
        (Value::Object(base), Value::Object(over)) => {
            for (key, value) in over {
                overlay(base.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        (base, over) => *base = over.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn core() -> Core {
        Core::with_store(Store::in_memory().unwrap(), false)
    }

    /// A core that watches two things, has two alerts for the first, and its own settings.
    fn filled() -> Core {
        let c = core();
        let ssh = c
            .call("subs.save", json!({ "subscription": { "name": "SSH", "target": { "kind": "product", "vendor": "openbsd", "product": "openssh" }, "filter": { "min_severity": "high" } } }))
            .unwrap()["subscription"]["id"]
            .as_i64()
            .unwrap();
        c.call("subs.save", json!({ "subscription": { "name": "Exploited", "target": { "kind": "everything" }, "filter": { "exploited_only": true }, "notify": false } })).unwrap();
        let db = c.db();
        let first = db.insert_alert(ssh, "SSH", "CVE-2026-0001", AlertKind::New, false, &json!({ "id": "CVE-2026-0001" })).unwrap().unwrap();
        db.insert_alert(ssh, "SSH", "CVE-2026-0002", AlertKind::Exploited, true, &json!({ "id": "CVE-2026-0002", "exploited": true })).unwrap();
        db.mark_read(Some(&[first.id]), None, true).unwrap();
        drop(db);
        let mut s = c.call("settings.get", json!({})).unwrap()["settings"].clone();
        s["interval_minutes"] = json!(60);
        s["use_cvelist"] = json!(true);
        s["nvd_api_key"] = json!("secret-key");
        s["ntfy"] = json!({ "enabled": true, "server": "https://ntfy.example", "topic": "my-topic", "token": "tk" });
        c.call("settings.set", json!({ "settings": s })).unwrap();
        c
    }

    #[test]
    fn everything_moves_to_another_device() {
        let from = filled();
        let file = from.call("data.export", json!({ "settings": true, "secrets": true, "subscriptions": true, "alerts": true })).unwrap();
        assert!(file["name"].as_str().unwrap().ends_with(".json"));
        // Through text, as it would travel.
        let data: Value = serde_json::from_str(&file["export"].to_string()).unwrap();

        let to = core();
        let done = to.call("data.import", json!({ "data": data })).unwrap();
        assert_eq!(done, json!({ "settings": true, "subscriptions": { "added": 2, "existing": 0 }, "alerts": { "added": 2, "existing": 0 } }));
        assert_eq!(to.settings(), from.settings());

        let subs = to.call("subs.list", json!({})).unwrap()["subscriptions"].clone();
        let ssh = subs.as_array().unwrap().iter().find(|s| s["name"] == "SSH").unwrap();
        assert_eq!(ssh["filter"]["min_severity"], "high");
        assert_eq!((ssh["alerts"].as_i64(), ssh["unread"].as_i64()), (Some(2), Some(1)));
        assert_eq!(subs.as_array().unwrap().iter().find(|s| s["name"] == "Exploited").unwrap()["notify"], false);

        let theirs = from.call("alerts.list", json!({})).unwrap()["alerts"].clone();
        let ours = to.call("alerts.list", json!({})).unwrap()["alerts"].clone();
        for (a, b) in theirs.as_array().unwrap().iter().zip(ours.as_array().unwrap()) {
            for field in ["vuln_id", "kind", "created_at", "read", "vuln", "sub_name"] {
                assert_eq!(a[field], b[field]);
            }
        }
        // They are kept for offline reading like any other, and a check will not raise them again.
        assert_eq!(to.db().offline_alerts(None, false).unwrap().len(), 2);
        assert_eq!(to.db().prior_alert(ssh["id"].as_i64().unwrap(), &["CVE-2026-0002"]).unwrap(), Some(true));

        // A second time changes nothing.
        let again = to.call("data.import", json!({ "data": data })).unwrap();
        assert_eq!(again["subscriptions"], json!({ "added": 0, "existing": 2 }));
        assert_eq!(again["alerts"], json!({ "added": 0, "existing": 2 }));
        assert_eq!(to.call("alerts.list", json!({})).unwrap()["alerts"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_shared_export_leaves_secrets_at_home() {
        let from = filled();
        let file = from.call("data.export", json!({ "settings": true, "subscriptions": true })).unwrap()["export"].clone();
        let text = file.to_string();
        for private in ["secret-key", "my-topic", "ntfy", "webhook", "remote", "alerts"] {
            assert!(!text.contains(private), "{private} is in the export");
        }

        // The other side keeps its own keys and channels, and takes the rest.
        let to = core();
        let mut s = to.call("settings.get", json!({})).unwrap()["settings"].clone();
        s["nvd_api_key"] = json!("their-key");
        s["webhook"] = json!({ "enabled": true, "url": "https://hook.example" });
        to.call("settings.set", json!({ "settings": s })).unwrap();
        to.call("data.import", json!({ "data": file })).unwrap();
        let now = to.settings();
        assert_eq!(now.nvd_api_key, "their-key");
        assert_eq!(now.webhook.url, "https://hook.example");
        assert!(!now.ntfy.enabled);
        assert_eq!((now.interval_minutes, now.use_cvelist), (60, true));
    }

    #[test]
    fn only_the_chosen_parts_are_taken() {
        let file = filled().call("data.export", json!({ "settings": true, "alerts": true })).unwrap()["export"].clone();
        // Alerts bring their subscriptions.
        assert_eq!(file["subscriptions"].as_array().unwrap().len(), 2);

        let to = core();
        let done = to.call("data.import", json!({ "data": file, "settings": false, "alerts": false })).unwrap();
        assert_eq!(done, json!({ "settings": false, "subscriptions": { "added": 2, "existing": 0 } }));
        assert_eq!(to.settings(), Settings::default());
        assert!(to.call("alerts.list", json!({})).unwrap()["alerts"].as_array().unwrap().is_empty());

        let to = core();
        let done = to.call("data.import", json!({ "data": file, "subscriptions": false, "alerts": false })).unwrap();
        assert_eq!(done, json!({ "settings": true }));
        assert_eq!(to.settings().interval_minutes, 60);
        assert!(to.call("subs.list", json!({})).unwrap()["subscriptions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn what_is_already_watched_is_kept_as_it_is() {
        let file = filled().call("data.export", json!({ "alerts": true })).unwrap()["export"].clone();
        let to = core();
        // The same subscription under another name, with one of the alerts already there.
        let id = to
            .call("subs.save", json!({ "subscription": { "name": "My SSH", "target": { "kind": "product", "vendor": "openbsd", "product": "openssh" }, "filter": { "min_severity": "high" } } }))
            .unwrap()["subscription"]["id"]
            .as_i64()
            .unwrap();
        to.db().insert_alert(id, "My SSH", "CVE-2026-0001", AlertKind::New, false, &json!({})).unwrap();

        let done = to.call("data.import", json!({ "data": file })).unwrap();
        assert_eq!(done["subscriptions"], json!({ "added": 1, "existing": 1 }));
        assert_eq!(done["alerts"], json!({ "added": 1, "existing": 1 }));
        let alerts = to.call("alerts.list", json!({ "sub_id": id })).unwrap()["alerts"].clone();
        assert_eq!(alerts.as_array().unwrap().len(), 2);
        assert!(alerts.as_array().unwrap().iter().all(|a| a["sub_name"] == "My SSH"));
    }

    #[test]
    fn a_bad_document_changes_nothing() {
        let c = core();
        assert!(c.call("data.export", json!({})).is_err());
        assert!(c.call("data.import", json!({ "data": { "subscriptions": [] } })).is_err());
        assert!(c.call("data.import", json!({ "data": { "vulnwatch_export": 99, "subscriptions": [] } })).is_err());
        assert!(c.call("data.import", json!({ "data": { "vulnwatch_export": 1 } })).is_err());
        // One subscription that cannot work stops the rest, and the settings with it.
        let bad = json!({
            "vulnwatch_export": 1,
            "settings": { "interval_minutes": 5 },
            "subscriptions": [
                { "id": 1, "name": "ok", "target": { "kind": "everything" } },
                { "id": 2, "name": "bad", "target": { "kind": "vendor", "vendor": " " } },
            ],
        });
        let e = c.call("data.import", json!({ "data": bad })).unwrap_err();
        assert!(format!("{e:#}").contains("\"bad\""));
        assert!(c.call("subs.list", json!({})).unwrap()["subscriptions"].as_array().unwrap().is_empty());
        assert_eq!(c.settings(), Settings::default());
        // Settings of the wrong shape are refused; out-of-range ones are brought into range.
        assert!(c.call("data.import", json!({ "data": { "vulnwatch_export": 1, "settings": { "interval_minutes": "often" } } })).is_err());
        c.call("data.import", json!({ "data": { "vulnwatch_export": 1, "settings": { "theme": "pink", "max_age_days": 0 } } })).unwrap();
        assert_eq!((c.settings().theme.as_str(), c.settings().max_age_days), ("system", 1));
    }
}
