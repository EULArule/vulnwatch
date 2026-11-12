//! CIRCL Vulnerability-Lookup (https://vulnerability.circl.lu): full CVE records searchable by the
//! vendor/product names CNAs publish. Fills the gap for CVEs NVD has not yet given a CPE.

use std::time::Duration;

use anyhow::Result;
use serde_json::Value;

use super::cve5;
use crate::model::Advisory;
use crate::net::{status_of, Net};

const BASE: &str = "https://vulnerability.circl.lu/api/vulnerability/search";

fn seg(s: &str) -> String {
    // Path segment: keep it simple and safe.
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') { c.to_string() } else { format!("%{:02X}", c as u32 & 0xff) })
        .collect()
}

/// One request, or with `patient` up to three: the service answers 502/503 for a few seconds at a
/// time when it is busy, and a second try usually gets through.
fn fetch(net: &Net, url: &str, query: &[(&str, &str)], patient: bool) -> Result<Value> {
    let mut delay = Duration::from_millis(800);
    for attempt in 0.. {
        match net.get_json(url, query, &[]) {
            Ok(v) => return Ok(v),
            Err(e) => {
                let busy = matches!(status_of(&e), Some(429 | 500..=599));
                if !patient || !busy || attempt == 2 {
                    return Err(e);
                }
                log::warn!("CIRCL: {e:#}; retrying in {delay:?}");
                std::thread::sleep(delay);
                delay *= 3;
            }
        }
    }
    unreachable!()
}

/// Page `page` (from 1, newest first) of the records for a vendor/product. `patient` retries
/// while the service is busy (a few seconds at most).
pub fn by_product_page(net: &Net, vendor: &str, product: &str, count: usize, page: usize, patient: bool) -> Result<Vec<Advisory>> {
    let url = format!("{BASE}/{}/{}", seg(vendor), seg(product));
    let v = match fetch(net, &url, &[("per_page", &count.to_string()), ("page", &page.to_string())], patient) {
        Ok(v) => v,
        Err(e) if status_of(&e) == Some(404) => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut out = vec![];
    // One page is split over several buckets ("cvelistv5", "nvd", ...), all holding `[id, record]`
    // pairs in CVE record format.
    for rec in v["results"].as_object().into_iter().flat_map(|o| o.values()).flat_map(|b| b.as_array().into_iter().flatten()) {
        if let Some(a) = cve5::parse(&rec[1]) {
            out.push(a);
        }
    }
    Ok(crate::model::merge_all(out))
}
