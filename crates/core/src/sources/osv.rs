//! OSV.dev: package-level advisories aggregated from GitHub Security Advisories, PyPA, RustSec,
//! Go, distro trackers and more. https://google.github.io/osv.dev/api/

use anyhow::Result;
use serde_json::{json, Value};

use super::{parse_time, plausible_version, push_unique};
use crate::model::{cvss3_base, Advisory, Affected, AttackVector, Score, ScoreOrigin, Severity};
use crate::net::Net;

const API: &str = "https://api.osv.dev/v1";

/// Ecosystems probed when searching for a package by name.
pub const ECOSYSTEMS: &[&str] = &[
    "npm", "PyPI", "Go", "crates.io", "Maven", "NuGet", "RubyGems", "Packagist", "Hex", "Pub", "SwiftURL",
    "GitHub Actions", "Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "Red Hat", "SUSE",
];

pub fn parse(v: &Value) -> Option<Advisory> {
    let osv_id = v["id"].as_str()?;
    if !v["withdrawn"].is_null() {
        return None;
    }
    let aliases: Vec<String> =
        v["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
    // Use the CVE id as canonical so records from different databases merge.
    let cve = std::iter::once(osv_id).chain(aliases.iter().map(String::as_str)).find(|i| i.starts_with("CVE-"));
    let mut a = Advisory::new(cve.unwrap_or(osv_id), "osv");
    for id in std::iter::once(osv_id.to_string()).chain(aliases) {
        if id != a.id {
            push_unique(&mut a.aliases, id, 12);
        }
    }
    a.url = Some(format!("https://osv.dev/vulnerability/{osv_id}"));
    a.title = v["summary"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    a.description = v["details"].as_str().unwrap_or_default().to_string();
    a.published = v["published"].as_str().and_then(parse_time);
    a.modified = v["modified"].as_str().and_then(parse_time);

    let add_severity = |list: &Value, a: &mut Advisory| {
        for s in list.as_array().into_iter().flatten() {
            let (Some(kind), Some(vector)) = (s["type"].as_str(), s["score"].as_str()) else { continue };
            let version = match kind {
                "CVSS_V3" if vector.starts_with("CVSS:3.0") => "3.0",
                "CVSS_V3" => "3.1",
                _ => continue, // v4 vectors need the full lookup tables; fall back to the qualitative label
            };
            if let Some(base) = cvss3_base(vector) {
                if !a.scores.iter().any(|x| x.version == version) {
                    a.scores.push(Score {
                        origin: ScoreOrigin::Vendor,
                        version: version.into(),
                        base,
                        vector: Some(vector.to_string()),
                        attack_vector: AttackVector::from_vector(vector),
                    });
                }
            }
        }
    };
    add_severity(&v["severity"], &mut a);
    a.severity = v["database_specific"]["severity"].as_str().and_then(Severity::parse);
    for c in v["database_specific"]["cwe_ids"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        push_unique(&mut a.cwes, c, 10);
    }

    for aff in v["affected"].as_array().into_iter().flatten().take(40) {
        add_severity(&aff["severity"], &mut a);
        if a.severity.is_none() {
            a.severity = aff["ecosystem_specific"]["severity"].as_str().and_then(Severity::parse);
        }
        let (Some(name), Some(eco)) = (aff["package"]["name"].as_str(), aff["package"]["ecosystem"].as_str()) else {
            continue;
        };
        let mut fixed = vec![];
        for r in aff["ranges"].as_array().into_iter().flatten() {
            if r["type"] == "GIT" {
                continue;
            }
            for e in r["events"].as_array().into_iter().flatten() {
                if let Some(f) = e["fixed"].as_str().filter(|f| plausible_version(f)) {
                    push_unique(&mut fixed, f, 6);
                }
            }
        }
        match a.affected.iter_mut().find(|x| x.package.as_deref() == Some(name) && x.ecosystem.as_deref() == Some(eco)) {
            Some(existing) => fixed.into_iter().for_each(|f| push_unique(&mut existing.fixed_in, f, 6)),
            None => a.affected.push(Affected {
                package: Some(name.to_string()),
                ecosystem: Some(eco.to_string()),
                fixed_in: fixed,
                ..Default::default()
            }),
        }
    }
    for r in v["references"].as_array().into_iter().flatten().filter_map(|r| r["url"].as_str()) {
        push_unique(&mut a.references, r, 30);
    }
    Some(a)
}

/// All advisories for a package.
pub fn by_package(net: &Net, ecosystem: &str, name: &str) -> Result<Vec<Advisory>> {
    let mut out = vec![];
    let mut token: Option<String> = None;
    for _ in 0..10 {
        let mut body = json!({ "package": { "name": name, "ecosystem": ecosystem } });
        if let Some(t) = &token {
            body["page_token"] = json!(t);
        }
        let v = net.post_json(&format!("{API}/query"), &[], &body)?;
        out.extend(v["vulns"].as_array().into_iter().flatten().filter_map(parse));
        token = v["next_page_token"].as_str().map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    Ok(out)
}

pub fn by_id(net: &Net, id: &str) -> Result<Option<Advisory>> {
    Ok(parse(&net.get_json(&format!("{API}/vulns/{id}"), &[], &[])?))
}

/// For each `(ecosystem, name)`: the `(id, modified)` of every advisory. One request for all packages.
pub fn batch(net: &Net, packages: &[(String, String)]) -> Result<Vec<Vec<(String, String)>>> {
    let queries: Vec<Value> =
        packages.iter().map(|(eco, name)| json!({ "package": { "name": name, "ecosystem": eco } })).collect();
    let v = net.post_json(&format!("{API}/querybatch"), &[], &json!({ "queries": queries }))?;
    let mut out = vec![];
    for i in 0..packages.len() {
        let list = v["results"][i]["vulns"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| Some((x["id"].as_str()?.to_string(), x["modified"].as_str().unwrap_or_default().to_string())))
            .collect();
        out.push(list);
    }
    Ok(out)
}

/// Which ecosystems have a package with exactly this name, and how many advisories each has.
pub fn find_package(net: &Net, name: &str) -> Result<Vec<(String, usize)>> {
    let packages: Vec<(String, String)> = ECOSYSTEMS.iter().map(|e| (e.to_string(), name.to_string())).collect();
    let results = batch(net, &packages)?;
    Ok(packages
        .into_iter()
        .zip(results)
        .filter(|(_, vulns)| !vulns.is_empty())
        .map(|((eco, _), vulns)| (eco, vulns.len()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn parses_osv_record() {
        let v: Value = serde_json::from_str(include_str!("../../testdata/osv.json")).unwrap();
        let a = parse(&v).unwrap();
        assert!(a.all_ids().any(|i| i == "GHSA-462w-v97r-4m45"));
        assert!(a.affected.iter().any(|x| x.package.as_deref().is_some_and(|p| p.eq_ignore_ascii_case("jinja2"))));
        assert_eq!(a.effective_severity(), Some(Severity::High));
        assert!(a.best_score().is_some_and(|s| s.base >= 7.0));
        assert!(!a.fixed_in().is_empty());
    }
}
