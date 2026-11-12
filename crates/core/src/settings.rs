//! User settings, stored as one JSON document.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Ntfy {
    pub enabled: bool,
    pub server: String,
    pub topic: String,
    pub token: String,
}

impl Default for Ntfy {
    fn default() -> Self {
        Self { enabled: false, server: "https://ntfy.sh".into(), topic: String::new(), token: String::new() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Webhook {
    pub enabled: bool,
    pub url: String,
}

/// App only: use a vulnwatch server instead of checking on-device.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Remote {
    pub enabled: bool,
    pub url: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// Android background mode: "periodic" (WorkManager), "realtime" (foreground service), "off".
    pub background: String,
    /// Minutes between checks. Android's periodic mode cannot go below 15.
    pub interval_minutes: u32,
    /// Vulnerabilities published longer ago than this never raise a "new" alert.
    pub max_age_days: u32,
    /// Optional free NVD API key (10x rate limit).
    pub nvd_api_key: String,
    /// Merge CIRCL Vulnerability-Lookup results into product pages.
    pub use_circl: bool,
    /// Ask ENISA's EUVD for those CVEs when CIRCL is switched off or not answering.
    pub use_euvd: bool,
    /// Optional CVEdetails.com API token; with one, its listing is merged into product pages.
    pub cvedetails_token: String,
    /// Also follow the cve.org delta feed (faster first sight, more requests).
    pub use_cvelist: bool,
    /// Fetch EPSS exploit-probability scores.
    pub use_epss: bool,
    pub ntfy: Ntfy,
    pub webhook: Webhook,
    pub remote: Remote,
    /// "system", "light" or "dark".
    pub theme: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            background: "periodic".into(),
            interval_minutes: 15,
            max_age_days: 30,
            nvd_api_key: String::new(),
            use_circl: true,
            use_euvd: true,
            cvedetails_token: String::new(),
            use_cvelist: false,
            use_epss: true,
            ntfy: Ntfy::default(),
            webhook: Webhook::default(),
            remote: Remote::default(),
            theme: "system".into(),
        }
    }
}

impl Settings {
    pub fn sanitize(mut self) -> Self {
        self.interval_minutes = self.interval_minutes.clamp(1, 24 * 60);
        self.max_age_days = self.max_age_days.clamp(1, 365);
        if !matches!(self.background.as_str(), "periodic" | "realtime" | "off") {
            self.background = "periodic".into();
        }
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            self.theme = "system".into();
        }
        self.nvd_api_key = self.nvd_api_key.trim().to_string();
        self.cvedetails_token = self.cvedetails_token.trim().trim_start_matches("Bearer ").trim().to_string();
        self.ntfy.server = self.ntfy.server.trim().trim_end_matches('/').to_string();
        self.ntfy.topic = self.ntfy.topic.trim().to_string();
        self.webhook.url = self.webhook.url.trim().to_string();
        self.remote.url = self.remote.url.trim().trim_end_matches('/').to_string();
        self.remote.token = self.remote.token.trim().to_string();
        self
    }

    pub fn cvedetails_key(&self) -> Option<&str> {
        Some(self.cvedetails_token.as_str()).filter(|k| !k.is_empty())
    }

    pub fn nvd_key(&self) -> Option<&str> {
        Some(self.nvd_api_key.as_str()).filter(|k| !k.is_empty())
    }
}
