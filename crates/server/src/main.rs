//! vulnwatch daemon: checks for new vulnerabilities on a timer and serves the web UI + API.

use std::{
    io::Read,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use include_dir::{include_dir, Dir};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use vulnwatch_core::{Core, VERSION};

/// The largest request taken. Nearly all are tiny; an import with years of alerts is not.
const MAX_BODY: u64 = 64 << 20;

static UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../ui/dist");

const HELP: &str = "\
vulnwatch - watch products for new vulnerabilities

USAGE: vulnwatch [OPTIONS]

  --listen ADDR    Address to serve on (default 127.0.0.1:8088; use 0.0.0.0:8088 for your network)
  --data DIR       Where to keep the database (default ~/.local/share/vulnwatch)
  --token TOKEN    Access token (or set VULNWATCH_TOKEN). Generated and remembered if omitted
  --no-auth        Do not require a token (only for trusted networks / behind your own auth)
  --once           Run one check, print the result and exit
  -h, --help       Show this help
  -V, --version    Show the version
";

struct Options {
    listen: String,
    data: PathBuf,
    token: Option<String>,
    no_auth: bool,
    once: bool,
}

fn options() -> Result<Options> {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share"));
    let mut o = Options {
        listen: std::env::var("VULNWATCH_LISTEN").unwrap_or_else(|_| "127.0.0.1:8088".into()),
        data: std::env::var_os("VULNWATCH_DATA").map(PathBuf::from).unwrap_or_else(|| data.join("vulnwatch")),
        token: std::env::var("VULNWATCH_TOKEN").ok().filter(|t| !t.is_empty()),
        no_auth: false,
        once: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |name: &str| args.next().with_context(|| format!("{name} needs a value"));
        match a.as_str() {
            "--listen" => o.listen = value("--listen")?,
            "--data" => o.data = value("--data")?.into(),
            "--token" => o.token = Some(value("--token")?),
            "--no-auth" => o.no_auth = true,
            "--once" => o.once = true,
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("vulnwatch {VERSION}");
                std::process::exit(0);
            }
            other => bail!("unknown option `{other}` (try --help)"),
        }
    }
    Ok(o)
}

struct Logger;
impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            eprintln!("{:5} {}", r.level(), r.args());
        }
    }
    fn flush(&self) {}
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 24];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).context("no secure random source")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("vulnwatch: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let opts = options()?;
    log::set_logger(&Logger).ok();
    log::set_max_level(log::LevelFilter::Info);
    std::fs::create_dir_all(&opts.data).with_context(|| format!("cannot create {}", opts.data.display()))?;
    let core = Arc::new(Core::open(&opts.data, false)?);

    if opts.once {
        let report = core.poll();
        for a in &report.alerts {
            println!("{}\t{}\t{}", a.sub_name, a.vuln_id, a.vuln["summary"].as_str().unwrap_or_default());
        }
        eprintln!("checked {} advisories, {} new alert(s)", report.checked, report.alerts.len());
        for e in &report.errors {
            eprintln!("error: {e}");
        }
        std::process::exit(if report.errors.is_empty() { 0 } else { 2 });
    }

    let token = if opts.no_auth {
        None
    } else {
        Some(match opts.token.or_else(|| core.kv_get("token")) {
            Some(t) => t,
            None => {
                let t = random_token()?;
                core.kv_set("token", &t)?;
                t
            }
        })
    };

    let server = Arc::new(Server::http(&opts.listen).map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", opts.listen))?);
    let shown = opts.listen.replace("0.0.0.0", "localhost");
    match &token {
        Some(t) => {
            log::info!("vulnwatch {VERSION} serving on http://{shown}");
            // Deliberately on stdout and nowhere else: this line is the credential.
            println!("Open  http://{shown}/#token={t}");
            println!("Token {t}   (enter this in the Android app to pair it)");
        }
        None => log::warn!("vulnwatch {VERSION} serving on http://{shown} WITHOUT authentication"),
    }

    {
        let core = core.clone();
        thread::Builder::new().name("poll".into()).spawn(move || poll_loop(&core))?;
    }
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let (server, core, token) = (server.clone(), core.clone(), token.clone());
            thread::spawn(move || {
                while let Ok(req) = server.recv() {
                    handle(req, &core, token.as_deref());
                }
            })
        })
        .collect();
    for w in workers {
        w.join().ok();
    }
    Ok(())
}

fn poll_loop(core: &Core) {
    // Let the listener come up first; then check immediately so a restart catches up.
    thread::sleep(Duration::from_secs(2));
    loop {
        // Automatic checking can be turned off in settings. Keep looking, so that turning it
        // back on takes effect without a restart.
        if core.settings().check_every().is_none() {
            thread::sleep(Duration::from_secs(15));
            continue;
        }
        let started = Instant::now();
        let report = core.poll();
        if !report.alerts.is_empty() {
            log::info!("{} new alert(s) from {} advisories", report.alerts.len(), report.checked);
        }
        for e in &report.errors {
            log::warn!("check: {e}");
        }
        // Re-read the interval each round so a settings change applies without a restart.
        let wait = core.settings().check_every().unwrap_or_default();
        thread::sleep(wait.saturating_sub(started.elapsed()).max(Duration::from_secs(30)));
    }
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn json_response(status: u16, body: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(body.to_string())
        .with_status_code(StatusCode(status))
        .with_header(header("Content-Type", "application/json"))
        .with_header(header("Cache-Control", "no-store"))
}

/// Compare without leaking how many leading characters matched.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorized(req: &Request, token: Option<&str>) -> bool {
    let Some(token) = token else { return true };
    req.headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
        .is_some_and(|given| same(given.trim(), token))
}

fn handle(mut req: Request, core: &Core, token: Option<&str>) {
    let path = req.url().split(['?', '#']).next().unwrap_or("/").to_string();
    let result = match (req.method(), path.as_str()) {
        (Method::Get, "/api/health") => {
            req.respond(json_response(200, &json!({ "ok": true, "version": VERSION, "auth": token.is_some() })))
        }
        (Method::Post, "/api/rpc") => {
            let response = if !authorized(&req, token) {
                // Slow down guessing a little.
                thread::sleep(Duration::from_millis(300));
                json_response(401, &json!({ "error": "unauthorized" }))
            } else {
                let mut body = String::new();
                match req.as_reader().take(MAX_BODY).read_to_string(&mut body).ok().and_then(|_| serde_json::from_str::<Value>(&body).ok()) {
                    None => json_response(400, &json!({ "error": "invalid request" })),
                    Some(call) => {
                        let method = call["method"].as_str().unwrap_or_default();
                        match core.call(method, call["params"].clone()) {
                            Ok(result) => json_response(200, &json!({ "result": result })),
                            Err(e) => {
                                log::info!("{method}: {e:#}");
                                json_response(200, &json!({ "error": format!("{e:#}") }))
                            }
                        }
                    }
                }
            };
            req.respond(response)
        }
        (Method::Get | Method::Head, _) if !path.starts_with("/api/") => {
            let rel = path.trim_start_matches('/');
            let (file, cache) = match UI.get_file(rel) {
                // Vite fingerprints everything under assets/, so those never change.
                Some(f) if rel.starts_with("assets/") => (Some(f), "public, max-age=31536000, immutable"),
                Some(f) => (Some(f), "no-cache"),
                // Unknown paths get the app shell (it routes client-side).
                None if !rel.contains('.') => (UI.get_file("index.html"), "no-cache"),
                None => (None, "no-cache"),
            };
            match file {
                Some(f) => {
                    let mime = match f.path().extension().and_then(|e| e.to_str()).unwrap_or_default() {
                        "html" => "text/html; charset=utf-8",
                        "js" => "text/javascript; charset=utf-8",
                        "css" => "text/css; charset=utf-8",
                        "svg" => "image/svg+xml",
                        "png" => "image/png",
                        "ico" => "image/x-icon",
                        "json" | "webmanifest" => "application/json",
                        "woff2" => "font/woff2",
                        _ => "application/octet-stream",
                    };
                    req.respond(
                        Response::from_data(f.contents())
                            .with_header(header("Content-Type", mime))
                            .with_header(header("Cache-Control", cache))
                            .with_header(header("X-Content-Type-Options", "nosniff"))
                            .with_header(header("Referrer-Policy", "no-referrer"))
                            .with_header(header("X-Frame-Options", "DENY")),
                    )
                }
                None => req.respond(Response::from_string("not found").with_status_code(StatusCode(404))),
            }
        }
        _ => req.respond(json_response(404, &json!({ "error": "not found" }))),
    };
    if let Err(e) = result {
        log::debug!("response failed: {e}");
    }
}
