//! ENISA's European Vulnerability Database (https://euvd.enisa.europa.eu). Like CIRCL it lists
//! CVEs under the vendor/product names their publishers use, so it can stand in when CIRCL is
//! down. No key needed.
//!
//! Its search matches names as substrings and returns results by last update, not by publication,
//! so this fetches everything published since a date, keeps the exact name matches and sorts.

use anyhow::Result;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde_json::Value;

use super::{plausible_version, push_unique};
use crate::matcher::norm;
use crate::model::{Advisory, Affected, AttackVector, Score, ScoreOrigin};
use crate::net::Net;

const SEARCH: &str = "https://euvdservices.enisa.europa.eu/api/search";
/// The API's largest page.
const PAGE: usize = 100;
/// Most pages fetched for one product (the Linux kernel gets ~800 CVEs a month).
const MAX_PAGES: usize = 10;

pub struct Found {
    /// Newest first.
    pub items: Vec<Advisory>,
    /// More were published since `from` than `MAX_PAGES` holds; the oldest ones may be missing.
    pub truncated: bool,
}

/// `Nov 10, 2026, 6:16:54 PM` (some Java versions put a narrow no-break space before AM/PM).
fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    let s: String = s.trim().chars().map(|c| if c.is_whitespace() { ' ' } else { c }).collect();
    NaiveDateTime::parse_from_str(&s, "%b %d, %Y, %I:%M:%S %p").ok().map(|t| t.and_utc()).or_else(|| super::parse_time(&s))
}

fn lines(v: &Value) -> impl Iterator<Item = &str> {
    v.as_str().unwrap_or_default().lines().map(str::trim).filter(|l| !l.is_empty())
}

pub fn parse(item: &Value) -> Option<Advisory> {
    let euvd_id = item["id"].as_str()?;
    let ids: Vec<&str> = lines(&item["aliases"]).collect();
    let id = ids.iter().find(|i| i.starts_with("CVE-")).copied().unwrap_or(euvd_id);
    let mut a = Advisory::new(id, "euvd");
    a.aliases = ids.iter().copied().chain([euvd_id]).filter(|i| *i != id).map(str::to_string).collect();
    a.url = Some(format!("https://euvd.enisa.europa.eu/vulnerability/{euvd_id}"));
    a.description = item["description"].as_str().unwrap_or_default().trim().to_string();
    a.published = item["datePublished"].as_str().and_then(parse_date);
    a.modified = item["dateUpdated"].as_str().and_then(parse_date);
    // No score is sent as 0 (or -1) without a version.
    if let (Some(base), Some(version)) = (item["baseScore"].as_f64().filter(|b| *b > 0.0), item["baseScoreVersion"].as_str()) {
        let vector = item["baseScoreVector"].as_str().map(str::to_string);
        let attack_vector = vector.as_deref().and_then(AttackVector::from_vector);
        a.scores.push(Score { origin: ScoreOrigin::Vendor, version: version.to_string(), base: base as f32, vector, attack_vector });
    }
    for r in lines(&item["references"]) {
        push_unique(&mut a.references, r, 30);
    }
    for p in item["enisaIdProduct"].as_array().into_iter().flatten() {
        let name = |v: &Value| v["name"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let (vendor, product) = (name(&p["product"]["vendor"]), name(&p["product"]));
        if product.is_none() {
            continue;
        }
        let i = match a.affected.iter().position(|x| x.vendor == vendor && x.product == product) {
            Some(i) => i,
            None => {
                a.affected.push(Affected { vendor, product, ..Default::default() });
                a.affected.len() - 1
            }
        };
        // "patch: 6.12.117" is a version marked unaffected, "5.5 <6.1.2" a range up to its fix.
        let version = p["product_version"].as_str().unwrap_or_default();
        let fixed = version.strip_prefix("patch:").or_else(|| version.split_once('<').map(|(_, f)| f)).map(|f| f.trim_start_matches('=').trim());
        if let Some(f) = fixed.filter(|f| plausible_version(f) && !f.contains(' ')) {
            push_unique(&mut a.affected[i].fixed_in, f, 6);
        }
    }
    // Vendors with no product attached (rare) still say whose it is.
    if a.affected.is_empty() {
        for v in item["enisaIdVendor"].as_array().into_iter().flatten().filter_map(|v| v["vendor"]["name"].as_str()) {
            a.affected.push(Affected { vendor: Some(v.to_string()), ..Default::default() });
        }
    }
    Some(a)
}

fn page(net: &Net, vendor: &str, product: &str, from: NaiveDate, n: usize) -> Result<(usize, Vec<Advisory>)> {
    // The names are `norm`ed (`red_hat`); EUVD stores them as published (`Red Hat`).
    let (v, p) = (vendor.replace('_', " "), product.replace('_', " "));
    let query = [("vendor", v.as_str()), ("product", p.as_str()), ("fromDate", &from.to_string()), ("size", &PAGE.to_string()), ("page", &n.to_string())];
    let body = net.get_json(SEARCH, &query, &[])?;
    let items = body["items"].as_array().map(|l| l.iter().filter_map(parse).collect()).unwrap_or_default();
    Ok((body["total"].as_u64().unwrap_or(0) as usize, items))
}

/// Everything published since `from` under this vendor/product name: exactly (compared
/// `norm`ed), or as `belongs` decides, since EUVD's search also returns near names.
pub fn since(net: &Net, vendor: &str, product: &str, from: NaiveDate, belongs: &dyn Fn(&Advisory) -> bool) -> Result<Found> {
    let (vendor, product) = (norm(vendor), norm(product));
    let (vendor, product) = (vendor.as_str(), product.as_str());
    let (total, mut items) = page(net, vendor, product, from, 0)?;
    let pages = total.div_ceil(PAGE).min(MAX_PAGES);
    // The rest side by side: each page takes a couple of seconds.
    let rest: Vec<Result<(usize, Vec<Advisory>)>> = std::thread::scope(|s| {
        let mut out = vec![];
        for chunk in (1..pages).collect::<Vec<_>>().chunks(3) {
            let handles: Vec<_> = chunk.iter().map(|&n| s.spawn(move || page(net, vendor, product, from, n))).collect();
            out.extend(handles.into_iter().map(|h| h.join().expect("EUVD request panicked")));
        }
        out
    });
    for r in rest {
        items.extend(r?.1);
    }
    let named = |a: &Advisory| {
        a.affected.iter().any(|x| x.vendor.as_deref().map(norm).as_deref() == Some(vendor) && x.product.as_deref().map(norm).as_deref() == Some(product))
    };
    let mut items = crate::model::merge_all(items.into_iter().filter(|a| named(a) || belongs(a)));
    items.sort_by(|a, b| b.published.cmp(&a.published).then_with(|| b.id.cmp(&a.id)));
    Ok(Found { items, truncated: total > pages * PAGE })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_euvd_item() {
        let list: Value = serde_json::from_str(include_str!("../../testdata/euvd.json")).unwrap();
        let a = parse(&list["items"][0]).unwrap();
        assert_eq!(a.id, "CVE-2026-99287");
        assert!(a.aliases.contains(&"EUVD-2026-121531".to_string()));
        assert!(a.aliases.iter().any(|i| i.starts_with("GHSA-")));
        assert_eq!(a.published.unwrap().to_rfc3339(), "2026-11-10T18:16:54+00:00");
        assert!(a.description.starts_with("In the Linux kernel"));
        assert!(a.best_score().is_none());
        assert_eq!(a.affected.len(), 1);
        assert_eq!(a.affected[0].product.as_deref(), Some("Linux"));
        // Git hashes and the "0" placeholder are not versions.
        assert_eq!(a.fixed_in(), vec!["6.12.117", "6.18.63", "7.3.4"]);
        assert!(a.references[0].starts_with("https://git.kernel.org/"));

        let scored = list["items"].as_array().unwrap().iter().filter_map(parse).find(|a| a.best_score().is_some()).unwrap();
        let s = scored.best_score().unwrap();
        assert!(s.base > 0.0 && s.vector.as_deref().is_some_and(|v| v.starts_with("CVSS:")));
        assert!(scored.attack_vector().is_some());
    }

    #[test]
    fn parses_both_date_spellings() {
        assert!(parse_date("Nov 4, 2022, 12:00:00 AM").is_some());
        assert_eq!(parse_date("Jan 31, 2020, 7:50:14\u{202f}PM").unwrap().to_rfc3339(), "2020-01-31T19:50:14+00:00");
    }
}
