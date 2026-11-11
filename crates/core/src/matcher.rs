//! Subscriptions: what to watch (`Target`) and how bad it must be to alert (`Filter`).
//! Pure logic, no I/O.

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::model::{is_na, Advisory, AttackVector, Severity};

/// What a subscription watches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// A product from the catalog (CPE `vendor:product`).
    Product {
        vendor: String,
        product: String,
        /// Phrases that also count as a match when found in the title/description. Needed because
        /// most brand-new CVEs carry no CPE yet and vendors name their products inconsistently.
        #[serde(default)]
        keywords: Vec<String>,
    },
    /// Everything from one vendor.
    Vendor { vendor: String },
    /// A package in a language/distro ecosystem (OSV: npm, PyPI, Go, crates.io, Debian, ...).
    Package { ecosystem: String, name: String },
    /// Free-text watch: any phrase appearing in the title/description.
    Keyword { keywords: Vec<String> },
    /// Every vulnerability (pair with a strict filter, e.g. "exploited only").
    Everything,
}

/// Per-subscription alert filter. All set conditions must hold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Filter {
    /// Minimum severity (from CVSS, or the qualitative label). `None` = any.
    pub min_severity: Option<Severity>,
    /// Minimum CVSS base score (0.1..10). `None` = any.
    pub min_cvss: Option<f32>,
    /// Alert on vulnerabilities that have no score/vector/EPSS yet. New CVEs usually start unscored.
    pub include_unscored: bool,
    /// Only these attack vectors. Empty = any.
    pub attack_vectors: Vec<AttackVector>,
    /// Only vulnerabilities known to be exploited in the wild.
    pub exploited_only: bool,
    /// Known-exploited vulnerabilities alert even if they fail the severity/vector/EPSS conditions.
    pub always_if_exploited: bool,
    /// Minimum EPSS probability (0..1). `None` = any.
    pub min_epss: Option<f32>,
    /// If non-empty, the text must contain at least one of these phrases.
    pub include_keywords: Vec<String>,
    /// Never alert if the text contains any of these phrases.
    pub exclude_keywords: Vec<String>,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            min_severity: None,
            min_cvss: None,
            include_unscored: true,
            attack_vectors: vec![],
            exploited_only: false,
            always_if_exploited: true,
            min_epss: None,
            include_keywords: vec![],
            exclude_keywords: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    pub target: Target,
    #[serde(default)]
    pub filter: Filter,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Send push notifications for this subscription (alerts are always listed in the app).
    #[serde(default = "yes")]
    pub notify: bool,
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not about this subscription's target.
    NoMatch,
    /// About the target, but filtered out.
    Filtered,
    Alert,
}

/// Lowercase, with every run of non-alphanumerics collapsed to `_`.
pub fn norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.trim().chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// `(vendor, product)` from a CPE 2.3 name or a 2.2 URI (`cpe:/a:vendor:product:...`).
pub fn cpe_vendor_product(cpe: &str) -> Option<(String, String)> {
    let rest = cpe.strip_prefix("cpe:2.3:").or_else(|| cpe.strip_prefix("cpe:/"))?;
    // Components may contain "\:" escapes.
    let mut parts: Vec<String> = vec![String::new()];
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    parts.last_mut().unwrap().push(n);
                }
            }
            ':' => {
                if parts.len() == 3 {
                    break;
                }
                parts.push(String::new());
            }
            c => parts.last_mut().unwrap().push(c),
        }
    }
    (parts.len() >= 3).then(|| (parts[1].clone(), parts[2].clone()))
}

/// Case-insensitive whole-phrase regex; spaces in the phrase also match `_`/`-`.
fn phrase_regex(phrase: &str) -> Result<Regex> {
    let words: Vec<String> = phrase.split_whitespace().map(regex::escape).collect();
    let body = words.join(r"[\s_\-]+");
    RegexBuilder::new(&format!(r"(?:^|[^\p{{L}}\p{{N}}]){body}(?:$|[^\p{{L}}\p{{N}}])"))
        .case_insensitive(true)
        .build()
        .with_context(|| format!("bad keyword {phrase:?}"))
}

fn phrases(list: &[String]) -> Result<Vec<Regex>> {
    list.iter().filter(|p| !p.trim().is_empty()).map(|p| phrase_regex(p)).collect()
}

/// Keywords to suggest when subscribing to a catalog product.
pub fn suggest_keywords(vendor: &str, product: &str) -> Vec<String> {
    const GENERIC: &[&str] = &[
        "office", "server", "client", "core", "framework", "manager", "router", "firewall", "browser",
        "player", "portal", "gateway", "dashboard", "access", "windows", "kernel", "console", "agent",
        "connect", "cloud", "desktop", "mobile", "enterprise", "platform", "security", "viewer",
        "reader", "studio", "explorer", "exchange", "teams", "word", "excel", "outlook", "edge",
        "express", "request", "commerce", "forms", "notes", "backup", "storage", "search",
    ];
    let phrase = product.replace(['_', '-'], " ").trim().to_string();
    let single = !phrase.contains(' ');
    if single && GENERIC.contains(&phrase.to_lowercase().as_str()) {
        return vec![format!("{} {}", vendor.replace('_', " "), phrase)];
    }
    if single && phrase.chars().count() <= 4 {
        // Too short to search prose for ("git", "ios", "curl"): rely on structured product data.
        return vec![];
    }
    vec![phrase]
}

/// A subscription with its regexes compiled once.
pub struct Compiled {
    pub sub: Subscription,
    keywords: Vec<Regex>,
    include: Vec<Regex>,
    exclude: Vec<Regex>,
    vendor: String,
    product: String,
}

impl Compiled {
    pub fn new(sub: Subscription) -> Result<Self> {
        let (keywords, vendor, product) = match &sub.target {
            Target::Product { vendor, product, keywords } => (phrases(keywords)?, norm(vendor), norm(product)),
            Target::Vendor { vendor } => (vec![], norm(vendor), String::new()),
            Target::Keyword { keywords } => (phrases(keywords)?, String::new(), String::new()),
            Target::Package { .. } | Target::Everything => (vec![], String::new(), String::new()),
        };
        Ok(Self {
            include: phrases(&sub.filter.include_keywords)?,
            exclude: phrases(&sub.filter.exclude_keywords)?,
            keywords,
            vendor,
            product,
            sub,
        })
    }

    pub fn evaluate(&self, adv: &Advisory) -> Verdict {
        if !self.matches(adv) {
            Verdict::NoMatch
        } else if self.passes_filter(adv) {
            Verdict::Alert
        } else {
            Verdict::Filtered
        }
    }

    /// Is this advisory about the subscription's target?
    pub fn matches(&self, adv: &Advisory) -> bool {
        match &self.sub.target {
            Target::Everything => true,
            Target::Keyword { .. } => {
                let text = adv.text();
                self.keywords.iter().any(|r| r.is_match(&text))
            }
            Target::Package { ecosystem, name } => adv.affected.iter().any(|a| {
                a.package.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(name))
                    && a.ecosystem.as_deref().is_some_and(|e| ecosystem_eq(e, ecosystem))
            }),
            Target::Vendor { .. } => adv.affected.iter().any(|a| {
                a.cpes.iter().any(|c| cpe_vendor_product(c).is_some_and(|(v, _)| norm(&v) == self.vendor))
                    || a.vendor.as_deref().is_some_and(|v| self.vendor_ok(&norm(v)))
            }),
            Target::Product { .. } => {
                if adv.affected.iter().any(|a| self.affected_is_product(a)) {
                    return true;
                }
                if self.keywords.is_empty() {
                    return false;
                }
                let text = adv.text();
                self.keywords.iter().any(|r| r.is_match(&text))
            }
        }
    }

    /// Loose vendor comparison: CNAs write "Apache Software Foundation" where CPE says "apache".
    fn vendor_ok(&self, nv: &str) -> bool {
        if nv.is_empty() || self.vendor.is_empty() {
            return false;
        }
        nv == self.vendor
            || nv.split('_').any(|w| w == self.vendor)
            || (nv.len() >= 3 && self.vendor.split('_').any(|w| w == nv))
    }

    fn affected_is_product(&self, a: &crate::model::Affected) -> bool {
        for c in &a.cpes {
            if let Some((v, p)) = cpe_vendor_product(c) {
                if norm(&v) == self.vendor && norm(&p) == self.product {
                    return true;
                }
            }
        }
        let nv = a.vendor.as_deref().filter(|v| !is_na(v)).map(norm).unwrap_or_default();
        let vendor_ok = self.vendor_ok(&nv);
        let combined = format!("{}_{}", self.vendor, self.product);
        for name in [&a.product, &a.package].into_iter().flatten() {
            let np = norm(name);
            if np == combined || (vendor_ok && (np == self.product || np == format!("{nv}_{}", self.product))) {
                return true;
            }
            // Product field repeats the vendor: vendor "Apache Software Foundation", product "Apache Tomcat".
            if vendor_ok && np.strip_prefix(&format!("{}_", self.vendor)) == Some(self.product.as_str()) {
                return true;
            }
        }
        false
    }

    /// Does a matching advisory clear this subscription's filter?
    pub fn passes_filter(&self, adv: &Advisory) -> bool {
        let f = &self.sub.filter;
        let text = adv.text();
        if self.exclude.iter().any(|r| r.is_match(&text)) {
            return false;
        }
        if !self.include.is_empty() && !self.include.iter().any(|r| r.is_match(&text)) {
            return false;
        }
        if f.exploited_only && !adv.exploited {
            return false;
        }
        if f.always_if_exploited && adv.exploited {
            return true;
        }
        if let Some(min) = f.min_severity {
            match adv.effective_severity() {
                Some(s) if s >= min => {}
                Some(_) => return false,
                None if f.include_unscored => {}
                None => return false,
            }
        }
        if let Some(min) = f.min_cvss {
            match adv.best_score() {
                // Compare in tenths: scores have one decimal and f32 would turn 7.5 into 7.4999.
                Some(s) if (s.base * 10.0).round() >= (min * 10.0).round() => {}
                Some(_) => return false,
                None if f.include_unscored => {}
                None => return false,
            }
        }
        if !f.attack_vectors.is_empty() {
            match adv.attack_vector() {
                Some(av) if f.attack_vectors.contains(&av) => {}
                Some(_) => return false,
                None if f.include_unscored => {}
                None => return false,
            }
        }
        if let Some(min) = f.min_epss {
            match adv.epss {
                Some(e) if e >= min => {}
                Some(_) => return false,
                None if f.include_unscored => {}
                None => return false,
            }
        }
        true
    }
}

pub fn ecosystem_eq(a: &str, b: &str) -> bool {
    // OSV suffixes distro ecosystems with a release ("Debian:12", "Alpine:v3.20").
    let base = |s: &str| s.split(':').next().unwrap_or(s).to_ascii_lowercase();
    base(a) == base(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Affected, Score, ScoreOrigin};

    fn sub(target: Target, filter: Filter) -> Compiled {
        Compiled::new(Subscription {
            id: 1,
            name: "t".into(),
            target,
            filter,
            enabled: true,
            notify: true,
            created_at: None,
        })
        .unwrap()
    }

    fn product(vendor: &str, product: &str, keywords: &[&str]) -> Target {
        Target::Product {
            vendor: vendor.into(),
            product: product.into(),
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn adv(desc: &str) -> Advisory {
        let mut a = Advisory::new("CVE-2026-0001", "nvd");
        a.description = desc.into();
        a
    }

    fn scored(mut a: Advisory, base: f32, vector: &str) -> Advisory {
        a.scores.push(Score {
            origin: ScoreOrigin::Vendor,
            version: "3.1".into(),
            base,
            vector: Some(vector.into()),
            attack_vector: AttackVector::from_vector(vector),
        });
        a
    }

    #[test]
    fn normalizes() {
        assert_eq!(norm("Apache Software Foundation"), "apache_software_foundation");
        assert_eq!(norm("  Linux-Kernel!"), "linux_kernel");
        assert_eq!(norm("n/a"), "n_a");
    }

    #[test]
    fn cpe_parsing() {
        assert_eq!(
            cpe_vendor_product("cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*"),
            Some(("openbsd".into(), "openssh".into()))
        );
        assert_eq!(cpe_vendor_product("cpe:2.3:a:openbsd:openssh"), Some(("openbsd".into(), "openssh".into())));
        assert_eq!(
            cpe_vendor_product("cpe:/o:redhat:enterprise_linux:9::baseos"),
            Some(("redhat".into(), "enterprise_linux".into()))
        );
        assert_eq!(cpe_vendor_product("nonsense"), None);
    }

    #[test]
    fn product_matches_by_cpe_cna_and_keyword() {
        let s = sub(product("openbsd", "openssh", &["openssh"]), Filter::default());
        let mut by_cpe = adv("something");
        by_cpe.affected.push(Affected { cpes: vec!["cpe:2.3:a:openbsd:openssh".into()], ..Default::default() });
        assert!(s.matches(&by_cpe));

        let mut by_cna = adv("something");
        by_cna.affected.push(Affected {
            vendor: Some("OpenBSD".into()),
            product: Some("OpenSSH".into()),
            ..Default::default()
        });
        assert!(s.matches(&by_cna));

        assert!(s.matches(&adv("sshd in OpenSSH before 10.6p2 lacks a workaround")));
        assert!(!s.matches(&adv("A flaw in LibreSSH-like tool myopensshd")));

        let mut other = adv("unrelated");
        other.affected.push(Affected {
            vendor: Some("Other".into()),
            product: Some("OpenSSH".into()),
            ..Default::default()
        });
        assert!(!sub(product("openbsd", "openssh", &[]), Filter::default()).matches(&other));
    }

    #[test]
    fn vendor_spelling_variants() {
        let s = sub(product("apache", "tomcat", &[]), Filter::default());
        let mut a = adv("x");
        a.affected.push(Affected {
            vendor: Some("Apache Software Foundation".into()),
            product: Some("Apache Tomcat".into()),
            ..Default::default()
        });
        assert!(s.matches(&a));
        let k = sub(product("linux", "linux_kernel", &["linux kernel"]), Filter::default());
        assert!(k.matches(&adv("In the Linux kernel, the following vulnerability has been resolved")));
    }

    #[test]
    fn severity_and_unscored() {
        let strict = Filter { min_severity: Some(Severity::High), include_unscored: false, ..Default::default() };
        let s = sub(Target::Everything, strict);
        assert_eq!(s.evaluate(&adv("x")), Verdict::Filtered);
        assert_eq!(s.evaluate(&scored(adv("x"), 6.5, "CVSS:3.1/AV:N")), Verdict::Filtered);
        assert_eq!(s.evaluate(&scored(adv("x"), 7.5, "CVSS:3.1/AV:N")), Verdict::Alert);

        let lenient = Filter { min_severity: Some(Severity::High), ..Default::default() };
        assert_eq!(sub(Target::Everything, lenient).evaluate(&adv("x")), Verdict::Alert);

        let mut qualitative = adv("x");
        qualitative.severity = Some(Severity::Critical);
        assert_eq!(s.evaluate(&qualitative), Verdict::Alert);
    }

    #[test]
    fn exploited_rules() {
        let f = Filter { min_severity: Some(Severity::Critical), include_unscored: false, ..Default::default() };
        let s = sub(Target::Everything, f.clone());
        let mut a = scored(adv("x"), 5.0, "CVSS:3.1/AV:L");
        assert_eq!(s.evaluate(&a), Verdict::Filtered);
        a.exploited = true;
        assert_eq!(s.evaluate(&a), Verdict::Alert);

        let no_bypass = sub(Target::Everything, Filter { always_if_exploited: false, ..f });
        assert_eq!(no_bypass.evaluate(&a), Verdict::Filtered);

        let only = sub(Target::Everything, Filter { exploited_only: true, ..Default::default() });
        assert_eq!(only.evaluate(&adv("x")), Verdict::Filtered);
        assert_eq!(only.evaluate(&a), Verdict::Alert);
    }

    #[test]
    fn vector_epss_and_keywords() {
        let remote = Filter {
            attack_vectors: vec![AttackVector::Network, AttackVector::Adjacent],
            ..Default::default()
        };
        let s = sub(Target::Everything, remote);
        assert_eq!(s.evaluate(&scored(adv("x"), 7.8, "CVSS:3.1/AV:L/AC:L")), Verdict::Filtered);
        assert_eq!(s.evaluate(&scored(adv("x"), 7.8, "CVSS:3.1/AV:N/AC:L")), Verdict::Alert);

        let cvss = sub(Target::Everything, Filter { min_cvss: Some(7.5), include_unscored: false, ..Default::default() });
        assert_eq!(cvss.evaluate(&adv("x")), Verdict::Filtered);
        assert_eq!(cvss.evaluate(&scored(adv("x"), 7.4, "CVSS:3.1/AV:N/AC:L")), Verdict::Filtered);
        assert_eq!(cvss.evaluate(&scored(adv("x"), 7.5, "CVSS:3.1/AV:N/AC:L")), Verdict::Alert);
        let lenient = sub(Target::Everything, Filter { min_cvss: Some(7.5), ..Default::default() });
        assert_eq!(lenient.evaluate(&adv("x")), Verdict::Alert);

        let epss = sub(Target::Everything, Filter { min_epss: Some(0.1), include_unscored: false, ..Default::default() });
        let mut a = adv("x");
        assert_eq!(epss.evaluate(&a), Verdict::Filtered);
        a.epss = Some(0.5);
        assert_eq!(epss.evaluate(&a), Verdict::Alert);

        let kw = sub(
            Target::Everything,
            Filter { exclude_keywords: vec!["wordpress plugin".into()], include_keywords: vec!["sql".into()], ..Default::default() },
        );
        assert_eq!(kw.evaluate(&adv("SQL injection in the Foo WordPress plugin")), Verdict::Filtered);
        assert_eq!(kw.evaluate(&adv("SQL injection in Foo")), Verdict::Alert);
        assert_eq!(kw.evaluate(&adv("XSS in Foo")), Verdict::Filtered);
    }

    #[test]
    fn packages_and_suggestions() {
        let s = sub(Target::Package { ecosystem: "PyPI".into(), name: "Jinja2".into() }, Filter::default());
        let mut a = adv("x");
        a.affected.push(Affected { package: Some("jinja2".into()), ecosystem: Some("PyPI".into()), ..Default::default() });
        assert!(s.matches(&a));
        assert!(ecosystem_eq("Debian:12", "debian"));

        assert_eq!(suggest_keywords("openbsd", "openssh"), vec!["openssh"]);
        assert_eq!(suggest_keywords("linux", "linux_kernel"), vec!["linux kernel"]);
        assert_eq!(suggest_keywords("microsoft", "office"), vec!["microsoft office"]);
        assert!(suggest_keywords("git-scm", "git").is_empty());
    }
}
