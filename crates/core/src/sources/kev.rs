//! CISA Known Exploited Vulnerabilities catalog (~2 MB JSON, conditional GET by ETag).

use std::collections::BTreeMap;

use anyhow::Result;
use serde_json::Value;

use crate::net::{status_of, Net};

const URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub struct Catalog {
    /// CVE id -> date added (YYYY-MM-DD).
    pub entries: BTreeMap<String, String>,
    pub etag: Option<String>,
}

/// `Ok(None)` when the catalog has not changed since `etag`.
pub fn fetch(net: &Net, etag: Option<&str>) -> Result<Option<Catalog>> {
    let headers: Vec<(&str, &str)> = etag.map(|e| ("If-None-Match", e)).into_iter().collect();
    let resp = match net.get(URL, &[], &headers) {
        Ok(r) => r,
        Err(e) if status_of(&e) == Some(304) => return Ok(None),
        Err(e) => return Err(e),
    };
    if resp.status() == 304 {
        return Ok(None);
    }
    let etag = resp.header("ETag").map(str::to_string);
    let body: Value = resp.into_json()?;
    let mut entries = BTreeMap::new();
    for v in body["vulnerabilities"].as_array().into_iter().flatten() {
        if let Some(id) = v["cveID"].as_str() {
            entries.insert(id.to_string(), v["dateAdded"].as_str().unwrap_or_default().to_string());
        }
    }
    anyhow::ensure!(!entries.is_empty(), "KEV catalog came back empty");
    Ok(Some(Catalog { entries, etag }))
}
