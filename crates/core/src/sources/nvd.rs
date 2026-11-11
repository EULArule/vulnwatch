//! NVD CVE API 2.0 and CPE API 2.0.
//!
//! Docs: https://nvd.nist.gov/developers/vulnerabilities. Without a (free) API key the limit is
//! 5 requests per rolling 30 s; `Net::nvd_throttle` enforces it. NVD returns 403/429/503 under
//! load, so every request retries with backoff.

use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{parse_time, plausible_version, push_unique};
use crate::matcher::cpe_vendor_product;
use crate::model::{Advisory, Affected, AttackVector, Score, ScoreOrigin};
use crate::net::{status_of, Net};

const CVES: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CPES: &str = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
const CISA_ADP: &str = "134c704f-9b21-4f2e-91b3-4a467353bcc0";
pub const PAGE_MAX: usize = 2000;

pub struct Page {
    pub total: usize,
    pub start: usize,
    pub items: Vec<Advisory>,
}

fn request(net: &Net, key: Option<&str>, url: &str, query: &[(&str, &str)]) -> Result<Value> {
    let headers: Vec<(&str, &str)> = key.map(|k| ("apiKey", k)).into_iter().collect();
    let mut delay = Duration::from_secs(3);
    for attempt in 0..4 {
        net.nvd_throttle(key.is_some());
        match net.get_json(url, query, &headers) {
            Ok(v) => return Ok(v),
            Err(e) => {
                let retryable = matches!(status_of(&e), Some(403 | 429 | 500..=599) | None);
                if attempt == 3 || !retryable {
                    return Err(e).context("NVD request failed");
                }
                log::warn!("NVD: {e:#}; retrying in {delay:?}");
                std::thread::sleep(delay);
                delay *= 2;
            }
        }
    }
    unreachable!()
}

fn cves(net: &Net, key: Option<&str>, query: &[(&str, &str)], start: usize, count: usize) -> Result<Page> {
    let (start_s, count_s) = (start.to_string(), count.clamp(1, PAGE_MAX).to_string());
    let mut q = query.to_vec();
    q.push(("startIndex", &start_s));
    q.push(("resultsPerPage", &count_s));
    let v = request(net, key, CVES, &q)?;
    let items = v["vulnerabilities"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| parse_cve(&x["cve"])).collect())
        .unwrap_or_default();
    Ok(Page { total: v["totalResults"].as_u64().unwrap_or(0) as usize, start, items })
}

/// The newest `count` results ending at `end` (exclusive index into NVD's oldest-first ordering;
/// `None` = the very newest). NVD has no sort option, so the newest page is addressed from the end.
///
/// `hint` is the total seen last time. With it the newest page usually costs one request instead
/// of two (one to learn the total, one to fetch the tail), which matters for products with
/// thousands of CVEs where every NVD request takes several seconds.
fn newest(net: &Net, key: Option<&str>, query: &[(&str, &str)], end: Option<usize>, count: usize, hint: Option<usize>) -> Result<Page> {
    let mut page = match (end, hint.filter(|h| *h > count)) {
        (Some(end), _) => {
            let start = end.saturating_sub(count);
            cves(net, key, query, start, end - start)?
        }
        (None, Some(hint)) => {
            let mut page = cves(net, key, query, hint - count, count)?;
            if page.total > hint && page.total - hint <= count {
                // A few were published since: fetch just those.
                page.items.extend(cves(net, key, query, hint, page.total - hint)?.items);
            } else if page.total != hint {
                // Shrunk (rejected CVEs) or grew a lot: address the tail afresh.
                page = cves(net, key, query, page.total.saturating_sub(count), count)?;
            }
            page
        }
        (None, None) => {
            let first = cves(net, key, query, 0, count)?;
            if first.total <= count {
                first
            } else {
                cves(net, key, query, first.total - count, count)?
            }
        }
    };
    page.items.reverse();
    Ok(page)
}

/// Quote a CPE component for use in a formatted-string binding.
fn cpe_quote(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// CVEs whose NVD configuration lists this product.
pub fn by_product(net: &Net, key: Option<&str>, vendor: &str, product: &str, end: Option<usize>, count: usize, hint: Option<usize>) -> Result<Page> {
    let cpe = format!("cpe:2.3:*:{}:{}", cpe_quote(vendor), cpe_quote(product));
    newest(net, key, &[("virtualMatchString", &cpe)], end, count, hint)
}

/// CVEs listing any product of this vendor.
pub fn by_vendor(net: &Net, key: Option<&str>, vendor: &str, end: Option<usize>, count: usize, hint: Option<usize>) -> Result<Page> {
    let cpe = format!("cpe:2.3:*:{}", cpe_quote(vendor));
    newest(net, key, &[("virtualMatchString", &cpe)], end, count, hint)
}

/// CVEs whose description contains all the words.
pub fn by_keyword(net: &Net, key: Option<&str>, words: &str, end: Option<usize>, count: usize, hint: Option<usize>) -> Result<Page> {
    newest(net, key, &[("keywordSearch", words)], end, count, hint)
}

/// The most recently published CVEs of all.
pub fn latest(net: &Net, key: Option<&str>, end: Option<usize>, count: usize, hint: Option<usize>) -> Result<Page> {
    newest(net, key, &[], end, count, hint)
}

pub fn by_id(net: &Net, key: Option<&str>, id: &str) -> Result<Option<Advisory>> {
    Ok(cves(net, key, &[("cveId", id)], 0, 1)?.items.into_iter().next())
}

/// Every CVE added or changed in the window (the alert firehose). Windows over 120 days are rejected by NVD.
pub fn modified_between(net: &Net, key: Option<&str>, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<Vec<Advisory>> {
    let fmt = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
    let (a, b) = (fmt(from), fmt(to));
    let query = [("lastModStartDate", a.as_str()), ("lastModEndDate", b.as_str())];
    let mut out = vec![];
    let mut start = 0;
    loop {
        let page = cves(net, key, &query, start, PAGE_MAX)?;
        let got = page.items.len();
        out.extend(page.items);
        start += PAGE_MAX;
        if got == 0 || start >= page.total {
            return Ok(out);
        }
    }
}

/// A product found by live CPE dictionary search.
pub struct CpeHit {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub title: String,
    pub versions: u32,
}

/// Live product search in the CPE dictionary (complements the bundled catalog for new products).
pub fn search_products(net: &Net, key: Option<&str>, words: &str) -> Result<Vec<CpeHit>> {
    let v = request(net, key, CPES, &[("keywordSearch", words), ("resultsPerPage", "2000")])?;
    let mut hits: Vec<CpeHit> = vec![];
    for p in v["products"].as_array().into_iter().flatten() {
        let cpe = &p["cpe"];
        if cpe["deprecated"].as_bool() == Some(true) {
            continue;
        }
        let name = cpe["cpeName"].as_str().unwrap_or_default();
        let Some((vendor, product)) = cpe_vendor_product(name) else { continue };
        if let Some(h) = hits.iter_mut().find(|h| h.vendor == vendor && h.product == product) {
            h.versions += 1;
            continue;
        }
        let version = name.split(':').nth(5).unwrap_or("");
        let mut title = cpe["titles"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|t| t["lang"] == "en")
            .and_then(|t| t["title"].as_str())
            .unwrap_or_default()
            .to_string();
        if let Some(i) = title.find(&format!(" {version}")).filter(|_| !matches!(version, "-" | "*" | "")) {
            title.truncate(i);
        }
        if title.is_empty() {
            title = format!("{vendor} {product}").replace('_', " ");
        }
        hits.push(CpeHit { part: name.split(':').nth(2).unwrap_or("a").to_string(), vendor, product, title, versions: 1 });
    }
    hits.sort_by(|a, b| b.versions.cmp(&a.versions));
    Ok(hits)
}

fn metric_scores(metrics: &Value, out: &mut Vec<Score>) {
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        for m in metrics[key].as_array().into_iter().flatten() {
            let data = &m["cvssData"];
            let Some(base) = data["baseScore"].as_f64() else { continue };
            let source = m["source"].as_str().unwrap_or_default();
            let origin = if source == "nvd@nist.gov" {
                ScoreOrigin::Nvd
            } else if source == CISA_ADP {
                ScoreOrigin::Adp
            } else {
                ScoreOrigin::Vendor
            };
            let vector = data["vectorString"].as_str().map(str::to_string);
            let attack_vector = data["attackVector"]
                .as_str()
                .or(data["accessVector"].as_str())
                .and_then(AttackVector::parse)
                .or_else(|| vector.as_deref().and_then(AttackVector::from_vector));
            out.push(Score {
                origin,
                version: data["version"].as_str().unwrap_or("3.1").to_string(),
                base: base as f32,
                vector,
                attack_vector,
            });
        }
    }
}

/// Normalize one `vulnerabilities[].cve` object.
pub fn parse_cve(cve: &Value) -> Option<Advisory> {
    let id = cve["id"].as_str()?;
    let mut a = Advisory::new(id, "nvd");
    a.url = Some(format!("https://nvd.nist.gov/vuln/detail/{id}"));
    a.published = cve["published"].as_str().and_then(parse_time);
    a.modified = cve["lastModified"].as_str().and_then(parse_time);
    a.status = cve["vulnStatus"].as_str().map(str::to_string);
    a.description = cve["descriptions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["lang"] == "en")
        .and_then(|d| d["value"].as_str())
        .unwrap_or_default()
        .to_string();
    if a.status.as_deref() == Some("Rejected") {
        return None;
    }

    metric_scores(&cve["metrics"], &mut a.scores);
    for (name, ssvc) in cve["metrics"].as_object().into_iter().flatten() {
        if !name.starts_with("ssvc") {
            continue;
        }
        for opt in ssvc.as_array().into_iter().flatten().flat_map(|s| s["ssvcData"]["options"].as_array().into_iter().flatten()) {
            if opt["exploitation"].as_str().is_some_and(|e| e.eq_ignore_ascii_case("active")) {
                a.exploited = true;
            }
        }
    }
    if let Some(added) = cve["cisaExploitAdd"].as_str() {
        a.exploited = true;
        a.kev_added = Some(added.to_string());
    }

    // CNA-declared affected products (present long before NVD assigns CPEs).
    for data in cve["affected"].as_array().into_iter().flatten().flat_map(|x| x["affectedData"].as_array().into_iter().flatten()) {
        let text = |k: &str| data[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let mut aff = Affected { vendor: text("vendor"), product: text("product"), package: text("packageName"), ..Default::default() };
        for c in data["cpes"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            if let Some((v, p)) = cpe_vendor_product(c) {
                push_unique(&mut aff.cpes, format!("cpe:2.3:*:{v}:{p}"), 8);
            }
        }
        for ver in data["versions"].as_array().into_iter().flatten() {
            let status = ver["status"].as_str().unwrap_or_default();
            let version = ver["version"].as_str().unwrap_or_default();
            let less = ver["lessThan"].as_str().unwrap_or_default();
            if ver["versionType"].as_str() == Some("git") {
                continue;
            }
            if status == "affected" && plausible_version(less) {
                push_unique(&mut aff.fixed_in, less, 6);
            } else if status == "unaffected" && plausible_version(version) {
                push_unique(&mut aff.fixed_in, version, 6);
            }
        }
        if aff.vendor.is_some() || aff.product.is_some() || aff.package.is_some() || !aff.cpes.is_empty() {
            a.affected.push(aff);
        }
        if a.affected.len() >= 60 {
            break;
        }
    }

    // NVD-assigned CPE configurations, collapsed to one entry per vendor:product.
    let matches = cve["configurations"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| c["nodes"].as_array().into_iter().flatten())
        .flat_map(|n| n["cpeMatch"].as_array().into_iter().flatten());
    let mut by_product: Vec<Affected> = vec![];
    for m in matches {
        if m["vulnerable"].as_bool() == Some(false) {
            continue;
        }
        let Some((v, p)) = m["criteria"].as_str().and_then(cpe_vendor_product) else { continue };
        let part = m["criteria"].as_str().and_then(|c| c.split(':').nth(2)).unwrap_or("a");
        let name = format!("cpe:2.3:{part}:{v}:{p}");
        let idx = match by_product.iter().position(|a| a.cpes[0] == name) {
            Some(i) => i,
            None if by_product.len() < 60 => {
                by_product.push(Affected { cpes: vec![name], ..Default::default() });
                by_product.len() - 1
            }
            None => continue,
        };
        if let Some(fix) = m["versionEndExcluding"].as_str().filter(|f| plausible_version(f)) {
            push_unique(&mut by_product[idx].fixed_in, fix, 6);
        }
    }
    a.affected.extend(by_product);

    for w in cve["weaknesses"].as_array().into_iter().flatten().flat_map(|w| w["description"].as_array().into_iter().flatten()) {
        if let Some(c) = w["value"].as_str().filter(|c| c.starts_with("CWE-")) {
            push_unique(&mut a.cwes, c, 10);
        }
    }
    for r in cve["references"].as_array().into_iter().flatten().filter_map(|r| r["url"].as_str()) {
        push_unique(&mut a.references, r, 30);
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn parses_nvd_record() {
        let cve: Value = serde_json::from_str(include_str!("../../testdata/nvd-cve.json")).unwrap();
        let a = parse_cve(&cve).unwrap();
        assert_eq!(a.id, "CVE-2026-4897");
        assert!(a.description.starts_with("A flaw was found in polkit"));
        assert_eq!(a.published.unwrap().to_rfc3339(), "2026-03-26T15:16:43.017+00:00");
        assert!(a.affected.iter().any(|x| x.vendor.as_deref() == Some("Red Hat") && x.package.as_deref() == Some("polkit")));
        assert!(a.affected.iter().any(|x| x.cpes.iter().any(|c| c == "cpe:2.3:*:redhat:enterprise_linux")));
        assert!(a.best_score().is_some());
        assert!(a.effective_severity().unwrap() >= Severity::Low);
        assert!(!a.exploited);
    }

    #[test]
    fn quotes_cpe_components() {
        assert_eq!(cpe_quote("llama.cpp"), "llama.cpp");
        assert_eq!(cpe_quote("c++"), "c\\+\\+");
    }
}
