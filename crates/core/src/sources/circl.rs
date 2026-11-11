//! CIRCL Vulnerability-Lookup (https://vulnerability.circl.lu): full CVE records searchable by the
//! vendor/product names CNAs publish. Fills the gap for CVEs NVD has not yet given a CPE.

use anyhow::Result;

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

/// Most recent records for a vendor/product (one page).
pub fn by_product(net: &Net, vendor: &str, product: &str, count: usize) -> Result<Vec<Advisory>> {
    by_product_page(net, vendor, product, count, 1)
}

/// Page `page` (from 1, newest first) of the records for a vendor/product.
pub fn by_product_page(net: &Net, vendor: &str, product: &str, count: usize, page: usize) -> Result<Vec<Advisory>> {
    let url = format!("{BASE}/{}/{}", seg(vendor), seg(product));
    let v = match net.get_json(&url, &[("per_page", &count.to_string()), ("page", &page.to_string())], &[]) {
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
