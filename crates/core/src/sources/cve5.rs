//! CVE Record Format v5 (cve.org / cvelistV5), as served by CIRCL and the cvelistV5 repository.

use serde_json::Value;

use super::{parse_time, plausible_version, push_unique};
use crate::matcher::cpe_vendor_product;
use crate::model::{Advisory, Affected, AttackVector, Score, ScoreOrigin};

fn scores(metrics: &Value, origin: ScoreOrigin, a: &mut Advisory) {
    for m in metrics.as_array().into_iter().flatten() {
        for (key, version) in [("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0")] {
            let data = &m[key];
            let Some(base) = data["baseScore"].as_f64() else { continue };
            let vector = data["vectorString"].as_str().map(str::to_string);
            let attack_vector = data["attackVector"]
                .as_str()
                .or(data["accessVector"].as_str())
                .and_then(AttackVector::parse)
                .or_else(|| vector.as_deref().and_then(AttackVector::from_vector));
            if !a.scores.iter().any(|s| s.origin == origin && s.version == version) {
                a.scores.push(Score { origin, version: version.into(), base: base as f32, vector, attack_vector });
            }
        }
        // CISA Vulnrichment: SSVC decision points and KEV membership ride along as "other" metrics.
        let other = &m["other"];
        match other["type"].as_str() {
            Some("ssvc") => {
                for opt in other["content"]["options"].as_array().into_iter().flatten() {
                    if opt["Exploitation"].as_str().is_some_and(|e| e.eq_ignore_ascii_case("active")) {
                        a.exploited = true;
                    }
                }
            }
            Some("kev") => {
                a.exploited = true;
                a.kev_added = other["content"]["dateAdded"].as_str().map(str::to_string);
            }
            _ => {}
        }
    }
}

pub fn parse(record: &Value) -> Option<Advisory> {
    let meta = &record["cveMetadata"];
    let id = meta["cveId"].as_str()?;
    if meta["state"].as_str().is_some_and(|s| s != "PUBLISHED") {
        return None;
    }
    let mut a = Advisory::new(id, "cve.org");
    a.url = Some(format!("https://www.cve.org/CVERecord?id={id}"));
    a.published = meta["datePublished"].as_str().and_then(parse_time);
    a.modified = meta["dateUpdated"].as_str().and_then(parse_time);

    let cna = &record["containers"]["cna"];
    a.title = cna["title"].as_str().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
    a.description = cna["descriptions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["lang"].as_str().is_some_and(|l| l.starts_with("en")))
        .and_then(|d| d["value"].as_str())
        .unwrap_or_default()
        .to_string();

    for data in cna["affected"].as_array().into_iter().flatten().take(60) {
        let text = |k: &str| data[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let mut aff = Affected { vendor: text("vendor"), product: text("product"), package: text("packageName"), ..Default::default() };
        for c in data["cpes"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            if let Some((v, p)) = cpe_vendor_product(c) {
                push_unique(&mut aff.cpes, format!("cpe:2.3:*:{v}:{p}"), 8);
            }
        }
        for ver in data["versions"].as_array().into_iter().flatten() {
            if ver["versionType"].as_str() == Some("git") {
                continue;
            }
            let status = ver["status"].as_str().unwrap_or_default();
            let version = ver["version"].as_str().unwrap_or_default();
            let less = ver["lessThan"].as_str().unwrap_or_default();
            if status == "affected" && plausible_version(less) {
                push_unique(&mut aff.fixed_in, less, 6);
            } else if status == "unaffected" && plausible_version(version) {
                push_unique(&mut aff.fixed_in, version, 6);
            }
        }
        a.affected.push(aff);
    }
    let cpe_nodes = cna["cpeApplicability"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| c["nodes"].as_array().into_iter().flatten())
        .flat_map(|n| n["cpeMatch"].as_array().into_iter().flatten());
    for m in cpe_nodes.take(60) {
        if let Some((v, p)) = m["criteria"].as_str().and_then(cpe_vendor_product) {
            let name = format!("cpe:2.3:*:{v}:{p}");
            if !a.affected.iter().any(|x| x.cpes.contains(&name)) {
                a.affected.push(Affected { cpes: vec![name], ..Default::default() });
            }
        }
    }

    scores(&cna["metrics"], ScoreOrigin::Vendor, &mut a);
    for adp in record["containers"]["adp"].as_array().into_iter().flatten() {
        scores(&adp["metrics"], ScoreOrigin::Adp, &mut a);
        for r in adp["references"].as_array().into_iter().flatten().filter_map(|r| r["url"].as_str()) {
            push_unique(&mut a.references, r, 30);
        }
    }
    for p in cna["problemTypes"].as_array().into_iter().flatten().flat_map(|p| p["descriptions"].as_array().into_iter().flatten()) {
        if let Some(c) = p["cweId"].as_str() {
            push_unique(&mut a.cwes, c, 10);
        }
    }
    for r in cna["references"].as_array().into_iter().flatten().filter_map(|r| r["url"].as_str()) {
        push_unique(&mut a.references, r, 30);
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cve5_record() {
        let rec: Value = serde_json::from_str(include_str!("../../testdata/cve5.json")).unwrap();
        let a = parse(&rec).unwrap();
        assert_eq!(a.id, "CVE-2026-123158");
        assert!(a.description.starts_with("sshd in OpenSSH before 10.6p2"));
        assert_eq!(a.best_score().unwrap().base, 8.1);
        assert_eq!(a.attack_vector(), Some(AttackVector::Network));
        assert!(a.exploited);
        assert_eq!(a.kev_added.as_deref(), Some("2026-11-09"));
        assert_eq!(a.fixed_in(), vec!["10.6p2"]);
        assert_eq!(a.cwes, vec!["CWE-394"]);
        assert!(a.affected.iter().any(|x| x.cpes.contains(&"cpe:2.3:*:openbsd:openssh".to_string())));
    }
}
