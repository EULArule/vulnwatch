//! Source-neutral vulnerability model. Every source normalizes into `Advisory`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

impl AttackVector {
    /// Parse NVD (`NETWORK`, `ADJACENT_NETWORK`, ...) or vector-string (`N`, `A`, `L`, `P`) forms.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "N" | "NETWORK" => Some(Self::Network),
            "A" | "ADJACENT" | "ADJACENT_NETWORK" => Some(Self::Adjacent),
            "L" | "LOCAL" => Some(Self::Local),
            "P" | "PHYSICAL" => Some(Self::Physical),
            _ => None,
        }
    }

    /// Extract `AV:x` from a CVSS vector string.
    pub fn from_vector(vector: &str) -> Option<Self> {
        vector.split('/').find_map(|part| part.strip_prefix("AV:")).and_then(Self::parse)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "low" => Some(Self::Low),
            "medium" | "moderate" => Some(Self::Medium),
            "high" | "important" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn from_score(base: f32) -> Self {
        match base {
            b if b >= 9.0 => Self::Critical,
            b if b >= 7.0 => Self::High,
            b if b >= 4.0 => Self::Medium,
            b if b > 0.0 => Self::Low,
            _ => Self::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Where a score came from. Used to choose the "best" score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScoreOrigin {
    /// NVD's own analysis.
    Nvd,
    /// The CNA / vendor that published the CVE, or a GHSA/vendor bulletin.
    Vendor,
    /// Third-party enrichment such as CISA ADP (Vulnrichment).
    Adp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Score {
    pub origin: ScoreOrigin,
    /// "4.0", "3.1", "3.0", "2.0"
    pub version: String,
    pub base: f32,
    pub vector: Option<String>,
    pub attack_vector: Option<AttackVector>,
}

/// A product the advisory says is affected (CNA `affected[]`, CPE, OSV package, ...).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Affected {
    pub vendor: Option<String>,
    pub product: Option<String>,
    /// Package name, e.g. OSV `package.name` or CNA `packageName`.
    pub package: Option<String>,
    /// Ecosystem for package advisories (npm, PyPI, Go, ...).
    pub ecosystem: Option<String>,
    /// CPE names, truncated to `cpe:2.3:part:vendor:product`.
    #[serde(default)]
    pub cpes: Vec<String>,
    /// Versions that fix the issue, best effort.
    #[serde(default)]
    pub fixed_in: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    /// Canonical id: CVE preferred, else GHSA / other database id.
    pub id: String,
    /// Other ids for the same issue (GHSA <-> CVE, ...).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Which sources contributed to this record ("nvd", "cve.org", "osv", "kev", ...).
    #[serde(default)]
    pub sources: Vec<String>,
    pub title: Option<String>,
    #[serde(default)]
    pub description: String,
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub scores: Vec<Score>,
    /// Qualitative severity when no numeric score exists (GHSA "critical", vendor "High").
    pub severity: Option<Severity>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    /// Known exploited (CISA KEV, SSVC exploitation=active).
    #[serde(default)]
    pub exploited: bool,
    /// Date the CVE was added to CISA KEV, if it is on the list.
    pub kev_added: Option<String>,
    /// EPSS probability of exploitation in the next 30 days (0..1) and its percentile.
    pub epss: Option<f32>,
    pub epss_percentile: Option<f32>,
    #[serde(default)]
    pub cwes: Vec<String>,
    /// NVD analysis status ("Analyzed", "Awaiting Analysis", ...).
    pub status: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

impl Advisory {
    pub fn new(id: impl Into<String>, source: &str) -> Self {
        Self {
            id: id.into(),
            aliases: vec![],
            sources: vec![source.to_string()],
            title: None,
            description: String::new(),
            published: None,
            modified: None,
            scores: vec![],
            severity: None,
            affected: vec![],
            exploited: false,
            kev_added: None,
            epss: None,
            epss_percentile: None,
            cwes: vec![],
            status: None,
            url: None,
            references: vec![],
        }
    }

    /// All ids this advisory is known by (canonical first).
    pub fn all_ids(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.id.as_str()).chain(self.aliases.iter().map(String::as_str))
    }

    /// The CVE id, if this advisory has one.
    pub fn cve_id(&self) -> Option<&str> {
        self.all_ids().find(|i| i.starts_with("CVE-"))
    }

    /// Pick the score to judge by: NVD > vendor > ADP; within an origin prefer CVSS 3.1, 4.0, 3.0, 2.0.
    pub fn best_score(&self) -> Option<&Score> {
        fn version_rank(v: &str) -> u8 {
            match v {
                "3.1" => 0,
                "4.0" => 1,
                "3.0" => 2,
                _ => 3,
            }
        }
        self.scores.iter().min_by_key(|s| (s.origin, version_rank(&s.version)))
    }

    /// Severity to judge by: from the best numeric score, else the qualitative label.
    pub fn effective_severity(&self) -> Option<Severity> {
        self.best_score().map(|s| Severity::from_score(s.base)).or(self.severity)
    }

    /// Attack vector from the best score, falling back to any score that has one.
    pub fn attack_vector(&self) -> Option<AttackVector> {
        self.best_score()
            .and_then(|s| s.attack_vector)
            .or_else(|| self.scores.iter().find_map(|s| s.attack_vector))
    }

    pub fn fixed_in(&self) -> Vec<&str> {
        let mut v: Vec<&str> =
            self.affected.iter().flat_map(|a| a.fixed_in.iter().map(String::as_str)).collect();
        v.sort_unstable();
        v.dedup();
        v.truncate(8);
        v
    }

    /// Text the keyword matcher runs against.
    pub fn text(&self) -> String {
        match &self.title {
            Some(t) => format!("{t}\n{}", self.description),
            None => self.description.clone(),
        }
    }

    /// Title if present, else the first sentence of the description, truncated.
    pub fn summary(&self, max: usize) -> String {
        let src = match &self.title {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => self.description.split(". ").next().unwrap_or_default().trim().to_string(),
        };
        let src = src.trim_end_matches('.');
        if src.chars().count() <= max {
            src.to_string()
        } else {
            format!("{}…", src.chars().take(max).collect::<String>().trim_end())
        }
    }

    /// Fold another record for the same vulnerability into this one (multi-source merge).
    pub fn merge(&mut self, other: Advisory) {
        for s in other.sources {
            if !self.sources.contains(&s) {
                self.sources.push(s);
            }
        }
        for a in other.aliases.into_iter().chain(std::iter::once(other.id)) {
            if a != self.id && !self.aliases.contains(&a) {
                self.aliases.push(a);
            }
        }
        if self.title.is_none() {
            self.title = other.title;
        }
        if self.description.is_empty() {
            self.description = other.description;
        }
        self.published = match (self.published, other.published) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.modified = self.modified.max(other.modified);
        for s in other.scores {
            if !self.scores.iter().any(|x| x.origin == s.origin && x.version == s.version) {
                self.scores.push(s);
            }
        }
        self.severity = self.severity.or(other.severity);
        self.affected.extend(other.affected);
        self.exploited |= other.exploited;
        self.kev_added = self.kev_added.take().or(other.kev_added);
        self.epss = self.epss.or(other.epss);
        self.epss_percentile = self.epss_percentile.or(other.epss_percentile);
        for c in other.cwes {
            if !self.cwes.contains(&c) {
                self.cwes.push(c);
            }
        }
        self.status = self.status.take().or(other.status);
        self.url = self.url.take().or(other.url);
        for r in other.references {
            if !self.references.contains(&r) {
                self.references.push(r);
            }
        }
    }

    /// JSON for the UI: the judged score/severity flattened out, heavy fields dropped unless `full`.
    pub fn view(&self, full: bool) -> Value {
        let best = self.best_score();
        let mut v = json!({
            "id": self.id,
            "aliases": self.aliases,
            "sources": self.sources,
            "title": self.title,
            "summary": self.summary(160),
            "published": self.published,
            "modified": self.modified,
            "cvss": best.map(|s| s.base),
            "cvss_version": best.map(|s| s.version.clone()),
            "cvss_origin": best.map(|s| s.origin),
            "vector": best.and_then(|s| s.vector.clone()),
            "severity": self.effective_severity(),
            "attack_vector": self.attack_vector(),
            "exploited": self.exploited,
            "kev_added": self.kev_added,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "fixed_in": self.fixed_in(),
            "status": self.status,
            "url": self.url,
        });
        if full {
            let mut products: Vec<String> = vec![];
            for a in &self.affected {
                let name = match (&a.ecosystem, &a.package, &a.vendor, &a.product) {
                    (Some(e), Some(p), _, _) => format!("{e}: {p}"),
                    (_, _, Some(v), Some(p)) if !is_na(v) => format!("{v} {p}"),
                    (_, _, _, Some(p)) if !is_na(p) => p.clone(),
                    _ => match a.cpes.first() {
                        Some(c) => c.splitn(4, ':').nth(3).unwrap_or(c).replace(':', " "),
                        None => continue,
                    },
                };
                if !products.contains(&name) {
                    products.push(name);
                }
            }
            products.truncate(40);
            let o = v.as_object_mut().unwrap();
            o.insert("description".into(), json!(self.description));
            o.insert("scores".into(), json!(self.scores));
            o.insert("products".into(), json!(products));
            o.insert("cwes".into(), json!(self.cwes));
            o.insert("references".into(), json!(self.references));
        }
        v
    }
}

pub fn is_na(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "" | "n/a" | "na" | "unknown" | "unspecified" | "-")
}

/// Merge records that share any id, keeping first-seen order.
pub fn merge_all(lists: impl IntoIterator<Item = Advisory>) -> Vec<Advisory> {
    let mut out: Vec<Advisory> = vec![];
    let mut index: std::collections::HashMap<String, usize> = Default::default();
    for adv in lists {
        let hit = adv.all_ids().find_map(|i| index.get(i).copied());
        match hit {
            Some(i) => {
                out[i].merge(adv);
                for id in out[i].all_ids().map(str::to_string).collect::<Vec<_>>() {
                    index.insert(id, i);
                }
            }
            None => {
                for id in adv.all_ids() {
                    index.insert(id.to_string(), out.len());
                }
                out.push(adv);
            }
        }
    }
    out
}

/// CVSS v3.x base score from a vector string (OSV only ships vectors).
pub fn cvss3_base(vector: &str) -> Option<f32> {
    let mut m = std::collections::HashMap::new();
    for part in vector.split('/') {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k, v);
        }
    }
    let changed = *m.get("S")? == "C";
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*m.get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| -> Option<f64> {
        Some(match *m.get(k)? {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => return None,
        })
    };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact =
        if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15) } else { 6.42 * iss };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let expl = 8.22 * av * ac * pr * ui;
    let raw: f64 = if changed { (1.08 * (impact + expl)).min(10.0) } else { (impact + expl).min(10.0) };
    // CVSS "roundup": smallest one-decimal number >= raw, done in integers to dodge float noise.
    let i = (raw * 100_000.0).round() as i64;
    let up = if i % 10_000 == 0 { i / 10_000 } else { i / 10_000 + 1 };
    Some(up as f32 / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss3_scores() {
        assert_eq!(cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        assert_eq!(cvss3_base("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(8.1));
        assert_eq!(cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), Some(10.0));
        assert_eq!(cvss3_base("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), Some(7.8));
        assert_eq!(cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some(6.1));
        assert_eq!(cvss3_base("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), None);
    }

    #[test]
    fn merge_by_alias() {
        let mut a = Advisory::new("CVE-2026-1", "nvd");
        a.description = "desc".into();
        let mut b = Advisory::new("GHSA-xxxx", "osv");
        b.aliases.push("CVE-2026-1".into());
        b.title = Some("Title".into());
        let merged = merge_all([a, b]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].id, "CVE-2026-1");
        assert_eq!(merged[0].sources, vec!["nvd", "osv"]);
        assert_eq!(merged[0].title.as_deref(), Some("Title"));
        assert!(merged[0].aliases.contains(&"GHSA-xxxx".to_string()));
    }
}
