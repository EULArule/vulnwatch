//! FIRST EPSS: probability that a CVE will be exploited in the next 30 days.

use std::collections::HashMap;

use anyhow::Result;

use crate::net::Net;

const URL: &str = "https://api.first.org/data/v1/epss";

/// CVE id -> (probability, percentile). Unknown ids are simply absent.
pub fn lookup(net: &Net, ids: &[String]) -> Result<HashMap<String, (f32, f32)>> {
    let mut out = HashMap::new();
    for chunk in ids.chunks(100) {
        let v = net.get_json(URL, &[("cve", &chunk.join(",")), ("limit", "100")], &[])?;
        for row in v["data"].as_array().into_iter().flatten() {
            let num = |k: &str| row[k].as_str().and_then(|s| s.parse::<f32>().ok());
            if let (Some(id), Some(p), Some(pct)) = (row["cve"].as_str(), num("epss"), num("percentile")) {
                out.insert(id.to_string(), (p, pct));
            }
        }
    }
    Ok(out)
}
