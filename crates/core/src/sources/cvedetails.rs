//! CVEdetails.com (https://www.cvedetails.com/documentation/apis): optional, needs the API token
//! of a cvedetails account. The site itself sits behind a browser check, so there is no way to
//! use it without one.
//!
//! Lists a product's CVEs by publication date with cvedetails' own score, EPSS and KEV flag.

use anyhow::{Context, Result};
use serde_json::Value;

use super::parse_time;
use crate::model::{Advisory, Score, ScoreOrigin};
use crate::net::Net;

const SEARCH: &str = "https://www.cvedetails.com/api/v1/vulnerability/search";

fn number(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn flag(v: &Value) -> bool {
    v.as_bool().unwrap_or_else(|| number(v).is_some_and(|n| n != 0.0))
}

pub fn parse(item: &Value) -> Option<Advisory> {
    let id = item["cveId"].as_str().filter(|i| i.starts_with("CVE-"))?;
    let mut a = Advisory::new(id, "cvedetails");
    a.url = Some(format!("https://www.cvedetails.com/cve/{id}/"));
    a.title = item["title"].as_str().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
    a.description = item["summary"].as_str().unwrap_or_default().trim().to_string();
    // "2026-11-10 18:16:54"
    let time = |k: &str| item[k].as_str().and_then(|s| parse_time(&s.trim().replacen(' ', "T", 1)));
    a.published = time("publishDate");
    a.modified = time("updateDate");
    if let Some(base) = number(&item["maxCvssBaseScore"]).filter(|b| *b > 0.0) {
        // The highest of all scores on record, with no vector; ranked below NVD's and the vendor's.
        a.scores.push(Score { origin: ScoreOrigin::Adp, version: "3.1".into(), base: base as f32, vector: None, attack_vector: None });
    }
    a.epss = number(&item["epssScore"]).map(|e| e as f32).filter(|e| (0.0..=1.0).contains(e));
    a.epss_percentile = number(&item["epssPercentile"]).map(|e| e as f32).filter(|e| (0.0..=1.0).contains(e));
    a.exploited = flag(&item["isInCISAKEV"]);
    Some(a)
}

/// Page `page` (from 1) of a product's CVEs, newest first. cvedetails names products the way
/// NVD does, spelled with spaces (`linux` / `linux kernel`).
pub fn by_product(net: &Net, token: &str, vendor: &str, product: &str, count: usize, page: usize) -> Result<Vec<Advisory>> {
    let (v, p) = (vendor.replace('_', " "), product.replace('_', " "));
    let query = [
        ("outputFormat", "json"),
        ("vendorName", v.as_str()),
        ("productName", p.as_str()),
        ("orderBy", "publishDate"),
        ("sort", "DESC"),
        ("pageNumber", &page.to_string()),
        ("resultsPerPage", &count.clamp(1, 50).to_string()),
    ];
    let auth = format!("Bearer {token}");
    let body = net.get_json(SEARCH, &query, &[("Authorization", &auth), ("Accept", "application/json")]).context("cvedetails request failed")?;
    let results = body["results"].as_array().or(body.as_array());
    Ok(results.into_iter().flatten().filter_map(parse).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_search_result() {
        let item = json!({
            "cveId": "CVE-2026-99287", "summary": " In the Linux kernel, ... ", "publishDate": "2026-11-10 18:16:54",
            "updateDate": "2026-11-10 21:05:27", "maxCvssBaseScore": "7.8", "epssScore": "0.00170", "epssPercentile": 0.38, "isInCISAKEV": 0
        });
        let a = parse(&item).unwrap();
        assert_eq!(a.id, "CVE-2026-99287");
        assert_eq!(a.published.unwrap().to_rfc3339(), "2026-11-10T18:16:54+00:00");
        assert_eq!(a.best_score().unwrap().base, 7.8);
        assert_eq!(a.epss, Some(0.0017));
        assert!(!a.exploited);
        assert!(parse(&json!({ "summary": "no id" })).is_none());
    }
}
