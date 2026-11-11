//! The web UI is embedded into the binary. Make sure the directory exists so a plain
//! `cargo build` works before the UI has been built (the result then serves a hint page).
use std::{fs, path::Path};

fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/dist");
    if !dist.join("index.html").exists() {
        fs::create_dir_all(&dist).unwrap();
        fs::write(
            dist.join("index.html"),
            "<!doctype html><meta charset=utf-8><title>vulnwatch</title>\
             <body style=\"font-family:sans-serif;margin:3rem\"><h1>vulnwatch</h1>\
             <p>The web UI has not been built. Run <code>./build.sh</code> and rebuild the server.</p>",
        )
        .unwrap();
    }
    println!("cargo:rerun-if-changed=../../ui/dist");
}
