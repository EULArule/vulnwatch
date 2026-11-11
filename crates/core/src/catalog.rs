//! Bundled product catalog (built from the NVD CPE dictionary by `tools/build-catalog.py`):
//! ~150k `vendor:product` pairs for instant, offline product search.

use std::{io::Read, sync::OnceLock};

use serde::Serialize;

static RAW: &[u8] = include_bytes!("../data/catalog.tsv.gz");

struct Catalog {
    text: String,
    /// Lowercased copy of `text` (same byte offsets are not guaranteed, so lines are indexed separately).
    lower: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Product {
    /// CPE part: `a` application, `o` operating system, `h` hardware.
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub title: String,
    /// Number of versions in the CPE dictionary; a rough popularity signal.
    pub versions: u32,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut text = String::new();
        flate2::read::GzDecoder::new(RAW).read_to_string(&mut text).expect("bundled catalog is valid gzip");
        let lower = text
            .lines()
            .map(|l| {
                // Searchable part: vendor, product, title (skip the part letter and the count).
                let body = l.split_once('\t').map_or(l, |x| x.1);
                let body = body.rsplit_once('\t').map_or(body, |x| x.0);
                body.to_lowercase().replace('_', " ")
            })
            .collect();
        Catalog { text, lower }
    })
}

fn parse(line: &str) -> Option<Product> {
    let mut f = line.split('\t');
    Some(Product {
        part: f.next()?.to_string(),
        vendor: f.next()?.to_string(),
        product: f.next()?.to_string(),
        title: f.next()?.to_string(),
        versions: f.next()?.parse().unwrap_or(1),
    })
}

/// Rank products matching every word of `query`.
pub fn search(query: &str, limit: usize) -> Vec<Product> {
    let q = query.trim().to_lowercase().replace(['_', ':'], " ");
    let words: Vec<&str> = q.split_whitespace().collect();
    if words.is_empty() || q.chars().count() < 2 {
        return vec![];
    }
    let cat = catalog();
    let mut hits: Vec<(f32, Product)> = vec![];
    for (line, lower) in cat.text.lines().zip(&cat.lower) {
        if !words.iter().all(|w| lower.contains(w)) {
            continue;
        }
        let Some(p) = parse(line) else { continue };
        let product = p.product.to_lowercase().replace('_', " ");
        let vendor = p.vendor.to_lowercase().replace('_', " ");
        let title = p.title.to_lowercase();
        let word_start = |hay: &str| hay.split(|c: char| !c.is_alphanumeric()).any(|w| w.starts_with(words[0]));
        let mut score = (p.versions as f32).ln_1p() * 12.0;
        if product == q || title == q {
            score += 200.0;
        } else if format!("{vendor} {product}") == q {
            score += 220.0;
        } else if product.starts_with(&q) || title.starts_with(&q) {
            score += 90.0;
        } else if vendor == q {
            score += 60.0;
        } else if word_start(&product) {
            score += 45.0;
        } else if word_start(&title) || word_start(&vendor) {
            score += 20.0;
        }
        // Prefer short names: "openssh" over "openssh_key_parser".
        score -= (product.len() as f32) * 0.3;
        hits.push((score, p));
    }
    hits.sort_by(|a, b| b.0.total_cmp(&a.0));
    hits.truncate(limit);
    hits.into_iter().map(|h| h.1).collect()
}

/// Exact lookup.
pub fn find(vendor: &str, product: &str) -> Option<Product> {
    let needle = format!("\t{vendor}\t{product}\t");
    catalog().text.lines().find(|l| l.contains(&needle)).and_then(parse)
}

/// Number of products a vendor has in the catalog.
pub fn vendor_size(vendor: &str) -> usize {
    let needle = format!("\t{vendor}\t");
    catalog().text.lines().filter(|l| l[1..].starts_with(&needle)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_well_known_products() {
        let top = |q: &str| search(q, 5).into_iter().map(|p| format!("{}:{}", p.vendor, p.product)).collect::<Vec<_>>();
        assert_eq!(top("openssh")[0], "openbsd:openssh");
        assert_eq!(top("linux kernel")[0], "linux:linux_kernel");
        assert!(top("chrome").contains(&"google:chrome".to_string()));
        assert_eq!(top("openbsd openssh")[0], "openbsd:openssh");
        assert!(search("zzzzqqqq-not-a-product", 5).is_empty());
        assert_eq!(find("openbsd", "openssh").unwrap().title, "OpenBSD OpenSSH");
        assert!(vendor_size("openbsd") >= 2);
    }
}
