//! Turning alerts into notifications, and the network push channels (ntfy, webhook).
//! On Android the host app shows `Notification`s locally; these channels are for servers
//! (and work on the phone too).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::net::Net;
use crate::settings::Settings;
use crate::store::{Alert, AlertKind};

/// A rendered, channel-neutral notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// Alert row id (0 for summaries/tests); doubles as the Android notification id.
    pub id: i64,
    pub title: String,
    pub body: String,
    pub url: Option<String>,
    /// 1 (min) .. 5 (urgent).
    pub priority: u8,
    pub vuln_id: String,
}

const MAX_INDIVIDUAL: usize = 5;

pub fn render(alert: &Alert) -> Notification {
    let v = &alert.vuln;
    let cvss = v["cvss"].as_f64();
    let exploited = v["exploited"].as_bool().unwrap_or(false);
    let mut bits: Vec<String> = vec![];
    match (v["severity"].as_str(), cvss) {
        (Some(s), Some(c)) => bits.push(format!("{} {c:.1}", capitalize(s))),
        (Some(s), None) => bits.push(capitalize(s)),
        _ => bits.push("Not yet scored".into()),
    }
    if exploited {
        bits.push("Exploited in the wild".into());
    }
    match v["attack_vector"].as_str() {
        Some("network") => bits.push("Remote".into()),
        Some("adjacent") => bits.push("Adjacent network".into()),
        Some("local") => bits.push("Local".into()),
        Some("physical") => bits.push("Physical".into()),
        _ => {}
    }
    let mut body = format!("{}\n{}", bits.join(" · "), v["summary"].as_str().unwrap_or_default());
    let fixed: Vec<&str> = v["fixed_in"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).take(3).collect();
    if !fixed.is_empty() {
        body.push_str(&format!("\nFixed in {}", fixed.join(", ")));
    }
    let title = match alert.kind {
        AlertKind::New => format!("{}: {}", alert.sub_name, alert.vuln_id),
        AlertKind::Exploited => format!("{}: {} is now being exploited", alert.sub_name, alert.vuln_id),
    };
    let priority = match cvss.unwrap_or(0.0) {
        _ if exploited => 5,
        c if c >= 9.0 => 5,
        c if c >= 7.0 => 4,
        _ => 3,
    };
    Notification { id: alert.id, title, body, url: v["url"].as_str().map(str::to_string), priority, vuln_id: alert.vuln_id.clone() }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// One notification per vulnerability (a CVE matching two subscriptions notifies once), most
/// urgent first, with the tail collapsed into a summary so a busy day cannot flood the phone.
pub fn build(alerts: &[&Alert]) -> Vec<Notification> {
    let mut list: Vec<Notification> = vec![];
    for a in alerts {
        if !list.iter().any(|n| n.vuln_id == a.vuln_id) {
            list.push(render(a));
        }
    }
    list.sort_by(|a, b| b.priority.cmp(&a.priority));
    if list.len() > MAX_INDIVIDUAL + 1 {
        let rest = list.split_off(MAX_INDIVIDUAL);
        let ids: Vec<&str> = rest.iter().take(8).map(|n| n.vuln_id.as_str()).collect();
        list.push(Notification {
            id: 0,
            title: format!("{} more new vulnerabilities", rest.len()),
            body: format!("{}{}", ids.join(", "), if rest.len() > ids.len() { ", …" } else { "" }),
            url: None,
            priority: rest.iter().map(|n| n.priority).max().unwrap_or(3),
            vuln_id: String::new(),
        });
    }
    list
}

pub fn send_ntfy(net: &Net, s: &Settings, n: &Notification) -> Result<()> {
    anyhow::ensure!(!s.ntfy.topic.is_empty(), "ntfy topic is not set");
    let url = format!("{}/{}", s.ntfy.server, s.ntfy.topic);
    // Header values must be ASCII; ntfy accepts RFC 2047 for anything else.
    let title = if n.title.is_ascii() { n.title.clone() } else { n.title.chars().filter(char::is_ascii).collect() };
    let priority = n.priority.to_string();
    let auth = format!("Bearer {}", s.ntfy.token);
    let mut headers = vec![("Title", title.as_str()), ("Priority", priority.as_str()), ("Tags", "shield")];
    if let Some(u) = &n.url {
        headers.push(("Click", u.as_str()));
    }
    if !s.ntfy.token.is_empty() {
        headers.push(("Authorization", auth.as_str()));
    }
    net.post_text(&url, &headers, &n.body)
}

pub fn send_webhook(net: &Net, s: &Settings, n: &Notification, alert: Option<&Alert>) -> Result<()> {
    anyhow::ensure!(s.webhook.url.starts_with("http"), "webhook URL is not set");
    // `text`/`content` make the same payload work for Slack-, Mattermost- and Discord-style hooks.
    let text = format!("{}\n{}{}", n.title, n.body, n.url.as_deref().map(|u| format!("\n{u}")).unwrap_or_default());
    let body = json!({ "text": text, "content": text, "notification": n, "alert": alert });
    net.post_text(&s.webhook.url, &[("Content-Type", "application/json")], &body.to_string())
}

/// Push notifications through every enabled channel. Returns error messages.
pub fn push(net: &Net, s: &Settings, list: &[Notification], alerts: &[Alert]) -> Vec<String> {
    let mut errors = vec![];
    for n in list {
        if s.ntfy.enabled {
            if let Err(e) = send_ntfy(net, s, n) {
                errors.push(format!("ntfy: {e:#}"));
            }
        }
        if s.webhook.enabled {
            let alert = alerts.iter().find(|a| a.id == n.id && n.id != 0);
            if let Err(e) = send_webhook(net, s, n, alert) {
                errors.push(format!("webhook: {e:#}"));
            }
        }
    }
    errors.dedup();
    errors
}
