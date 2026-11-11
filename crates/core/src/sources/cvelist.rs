//! cve.org's cvelistV5 repository: `delta.json` lists the CVEs published or updated in the last
//! few minutes, typically ahead of NVD. Optional, since each changed record is a separate download
//! and the delta only covers a short window (so it suits check intervals of ~10 minutes or less).

use anyhow::Result;
use chrono::{DateTime, Utc};

use super::{cve5, parse_time};
use crate::model::Advisory;
use crate::net::Net;

const DELTA: &str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json";
const MAX_RECORDS: usize = 150;

pub struct Delta {
    pub advisories: Vec<Advisory>,
    /// `fetchTime` of the delta; pass back as `since` next time.
    pub cursor: Option<String>,
}

pub fn poll(net: &Net, since: Option<&str>) -> Result<Delta> {
    let delta = net.get_json(DELTA, &[], &[])?;
    let cursor = delta["fetchTime"].as_str().map(str::to_string);
    if cursor.as_deref() == since && since.is_some() {
        return Ok(Delta { advisories: vec![], cursor });
    }
    let since: Option<DateTime<Utc>> = since.and_then(parse_time);
    let mut advisories = vec![];
    let entries = ["new", "updated"].into_iter().flat_map(|k| delta[k].as_array().into_iter().flatten());
    for e in entries.take(MAX_RECORDS) {
        let updated = e["dateUpdated"].as_str().and_then(parse_time);
        if let (Some(u), Some(s)) = (updated, since) {
            // Entries older than the previous delta were already handled.
            if u < s - chrono::Duration::minutes(30) {
                continue;
            }
        }
        let Some(link) = e["githubLink"].as_str().filter(|l| l.starts_with("https://raw.githubusercontent.com/CVEProject/")) else {
            continue;
        };
        match net.get_json(link, &[], &[]) {
            Ok(rec) => advisories.extend(cve5::parse(&rec)),
            Err(err) => log::warn!("cvelist: {err:#}"),
        }
    }
    Ok(Delta { advisories, cursor })
}
