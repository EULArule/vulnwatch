//! Shared blocking HTTP client, with NVD's rolling-window rate limit built in.

use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use serde_json::Value;

pub struct Net {
    agent: ureq::Agent,
    nvd_calls: Mutex<VecDeque<Instant>>,
}

/// An HTTP error status, kept distinguishable so callers can treat 404/304 specially.
#[derive(Debug)]
pub struct HttpStatus(pub u16, pub String);

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {} from {}", self.0, self.1)
    }
}
impl std::error::Error for HttpStatus {}

fn host(url: &str) -> String {
    url.split('/').nth(2).unwrap_or(url).to_string()
}

fn convert(url: &str, e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(code, _) => HttpStatus(code, host(url)).into(),
        // Not `t` itself: its text repeats the whole URL, query string and all.
        ureq::Error::Transport(t) => {
            let offline = matches!(t.kind(), ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed);
            let e = match t.message() {
                Some(m) => anyhow!("{}: {} ({})", host(url), t.kind(), m),
                None => anyhow!("{}: {}", host(url), t.kind()),
            };
            if offline {
                e.context(NoConnection)
            } else {
                e
            }
        }
    }
}

/// Marks an error as "the host could not even be connected to": most likely there is no network.
#[derive(Debug)]
struct NoConnection;

impl std::fmt::Display for NoConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no connection")
    }
}

/// Whether a request failed before reaching the host. Trying again at once is pointless then.
pub fn no_connection(e: &anyhow::Error) -> bool {
    e.downcast_ref::<NoConnection>().is_some()
}

impl Default for Net {
    fn default() -> Self {
        Self::new()
    }
}

impl Net {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout(Duration::from_secs(90))
            .user_agent(concat!("vulnwatch/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { agent, nvd_calls: Mutex::new(VecDeque::new()) }
    }

    pub fn get(&self, url: &str, query: &[(&str, &str)], headers: &[(&str, &str)]) -> Result<ureq::Response> {
        let call = || {
            let mut req = self.agent.get(url);
            for (k, v) in query {
                req = req.query(k, v);
            }
            for (k, v) in headers {
                req = req.set(k, v);
            }
            req.call()
        };
        match call() {
            // A phone drops idle connections when it sleeps or changes network; the pooled one
            // then fails on first use. One retry gets a fresh connection.
            Err(ureq::Error::Transport(_)) => call(),
            other => other,
        }
        .map_err(|e| convert(url, e))
    }

    pub fn get_json(&self, url: &str, query: &[(&str, &str)], headers: &[(&str, &str)]) -> Result<Value> {
        Ok(self.get(url, query, headers)?.into_json()?)
    }

    pub fn post_json(&self, url: &str, headers: &[(&str, &str)], body: &Value) -> Result<Value> {
        let mut req = self.agent.post(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let sent = match req.clone().send_json(body) {
            Err(ureq::Error::Transport(_)) => req.send_json(body),
            other => other,
        };
        Ok(sent.map_err(|e| convert(url, e))?.into_json()?)
    }

    pub fn post_text(&self, url: &str, headers: &[(&str, &str)], body: &str) -> Result<()> {
        let mut req = self.agent.post(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        req.send_string(body).map_err(|e| convert(url, e))?;
        Ok(())
    }

    /// Block until an NVD request is allowed: 5 per rolling 30 s without a key, 50 with one.
    pub fn nvd_throttle(&self, has_key: bool) {
        let limit = if has_key { 45 } else { 5 };
        let window = Duration::from_secs(31);
        loop {
            let wait = {
                let mut calls = self.nvd_calls.lock().unwrap();
                let now = Instant::now();
                while calls.front().is_some_and(|t| now.duration_since(*t) > window) {
                    calls.pop_front();
                }
                if calls.len() < limit {
                    calls.push_back(now);
                    return;
                }
                window - now.duration_since(*calls.front().unwrap())
            };
            std::thread::sleep(wait + Duration::from_millis(50));
        }
    }
}

pub fn status_of(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<HttpStatus>().map(|s| s.0)
}
