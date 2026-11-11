#!/usr/bin/env python3
"""Build the bundled product catalog from the NVD CPE dictionary feed.

    curl -O https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz
    tools/build-catalog.py nvdcpe-2.0.tar.gz crates/core/data/catalog.tsv.gz

Output: gzip TSV, one product per line, most-versioned (roughly: best known) first:
    part <TAB> vendor <TAB> product <TAB> title <TAB> version_count
"""
import gzip, json, re, sys, tarfile

def split_cpe(name):
    # cpe:2.3:part:vendor:product:version:...  with "\:" escapes inside components
    return re.split(r"(?<!\\):", name)

def unescape(s):
    return re.sub(r"\\(.)", r"\1", s)

def pretty(s):
    return " ".join(w if any(c.isupper() for c in w) else w.capitalize() for w in unescape(s).replace("_", " ").split())

def main(src, dst):
    products = {}  # (vendor, product) -> [part, count, best_title, best_rank]
    with tarfile.open(src) as tar:
        for member in tar:
            if not member.name.endswith(".json"):
                continue
            for item in json.load(tar.extractfile(member))["products"]:
                cpe = item["cpe"]
                if cpe.get("deprecated"):
                    continue
                parts = split_cpe(cpe["cpeName"])
                if len(parts) < 6:
                    continue
                part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
                entry = products.setdefault((vendor, product), [part, 0, None, 99])
                entry[1] += 1
                title = next((t["title"] for t in cpe.get("titles", []) if t.get("lang") == "en"), None)
                if not title:
                    continue
                if version in ("-", "*"):
                    rank = 0
                else:
                    # Strip the version (and whatever follows) from a versioned title.
                    v = unescape(version)
                    i = title.find(" " + v)
                    title = title[:i] if i > 0 else title
                    rank = 1 if i > 0 else 2
                title = title.strip()
                if title and (rank < entry[3] or (rank == entry[3] and len(title) < len(entry[2]))):
                    entry[2], entry[3] = title, rank
    rows = sorted(products.items(), key=lambda kv: (-kv[1][1], kv[0]))
    with gzip.open(dst, "wt", encoding="utf-8", compresslevel=9) as out:
        for (vendor, product), (part, count, title, _) in rows:
            title = (title or f"{pretty(vendor)} {pretty(product)}").replace("\t", " ")
            out.write(f"{part}\t{unescape(vendor)}\t{unescape(product)}\t{title}\t{count}\n")
    print(f"{len(rows)} products -> {dst}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
