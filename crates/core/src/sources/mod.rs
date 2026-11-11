//! Upstream adapters. Each one fetches from a public API and normalizes into `Advisory`.
//!
//! | module    | upstream                         | used for                                      |
//! |-----------|----------------------------------|-----------------------------------------------|
//! | `nvd`     | NVD CVE/CPE API 2.0              | product pages, live product search, alert feed |
//! | `circl`   | CIRCL Vulnerability-Lookup       | product pages (CVE records NVD has not analysed) |
//! | `cvelist` | cve.org cvelistV5 delta          | optional faster alert feed                    |
//! | `osv`     | OSV.dev (GHSA, PyPA, RustSec, …) | package search, package pages, package alerts |
//! | `kev`     | CISA Known Exploited Vulns       | "exploited in the wild" flag                  |
//! | `epss`    | FIRST EPSS                       | exploit-probability score                     |

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

pub mod circl;
pub mod cve5;
pub mod cvelist;
pub mod epss;
pub mod kev;
pub mod nvd;
pub mod osv;

/// Parse the assorted timestamp formats the feeds use (RFC 3339, NVD's zone-less form, bare dates).
pub fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    if let Ok(t) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(t.and_utc());
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)).map(|t| t.and_utc())
}

/// A version string worth showing as "fixed in" (not a wildcard, placeholder or git hash).
pub fn plausible_version(v: &str) -> bool {
    let v = v.trim();
    !(v.is_empty()
        || v == "*"
        || v == "0"
        || v.eq_ignore_ascii_case("n/a")
        || v.eq_ignore_ascii_case("unspecified")
        || (v.len() >= 12 && v.chars().all(|c| c.is_ascii_hexdigit())))
}

pub fn push_unique(list: &mut Vec<String>, v: impl Into<String>, cap: usize) {
    let v = v.into();
    if list.len() < cap && !list.contains(&v) {
        list.push(v);
    }
}
