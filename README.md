# vulnwatch

Look up any product, see every known vulnerability for it, and get alerted when a new one
appears — in a browser or as an Android app.

- **Search** 150,000 products instantly (bundled catalog), or packages from npm, PyPI, crates.io,
  Go, Maven, Debian and more, or plain keywords.
- **Browse** a product's vulnerabilities: severity, CVSS, exploit likelihood (EPSS), whether it is
  being exploited in the wild (CISA KEV), fixed versions, references.
- **Subscribe** with one tap, and give each subscription its own filter: minimum severity,
  exploited only, attack vector, exploit likelihood, words that must or must not appear.
  A live preview shows what the filter would have let through.
- **Get notified**: Android notifications from the app (no Google Play services involved),
  browser notifications, [ntfy](https://ntfy.sh), or a webhook (Slack, Mattermost, Discord, …).

One Rust core does all of it. It runs as a small server with the web UI built in, and the same
core is compiled into the Android app.

## Run the server

```sh
./build.sh              # builds in containers (podman or docker); nothing else to install
./dist/vulnwatch
```

It prints a link such as `http://127.0.0.1:8088/#token=…`. Open it and you are signed in.

| Option | Environment | Default | |
|---|---|---|---|
| `--listen ADDR` | `VULNWATCH_LISTEN` | `127.0.0.1:8088` | Use `0.0.0.0:8088` to reach it from other devices |
| `--data DIR` | `VULNWATCH_DATA` | `~/.local/share/vulnwatch` | One SQLite file lives here |
| `--token TOKEN` | `VULNWATCH_TOKEN` | generated once and stored | The password for the UI and API |
| `--no-auth` | | | No password (only behind something that already protects it) |
| `--once` | | | Run one check, print the result, exit |

vulnwatch speaks plain HTTP. To use it over the internet, put it behind a reverse proxy with
HTTPS (Caddy, nginx, Tailscale serve, …); the token would otherwise travel unencrypted.

## Android app

```sh
./build.sh android      # -> dist/vulnwatch.apk (arm64 + arm32)
```

Copy the APK to the phone and open it. The first build downloads the Android SDK and NDK into a
container image and takes a while. The APK is signed with a key created at
`ui/src-tauri/android/release.jks`; keep that file, Android only accepts updates signed by the same key.

The app works on its own: it checks the feeds from the phone and keeps everything on the phone.
Under **Settings → Background alerts** you choose how:

| Mode | How it works | Typical delay |
|---|---|---|
| **Battery friendly** (default) | A WorkManager job, as often as every 15 minutes. Android may delay it while the phone is idle. | 15–60 min |
| **Always on** | A foreground service with a permanent notification, checking as often as every minute. | minutes |
| **Off** | Checks only while the app is open. | |

Neither mode uses Firebase or Google Play services, so it behaves the same on GrapheneOS,
LineageOS and the like. For reliable delivery allow notifications and exempt the app from battery
optimisation; the settings page offers both when needed.

**Pairing with a server** (Settings → Use my vulnwatch server): the app becomes a client of your
server, sharing its subscriptions and alerts, and only asks it "anything new?" in the background.

## Where the data comes from

| Source | Used for |
|---|---|
| [NVD](https://nvd.nist.gov/developers/vulnerabilities) | Product listings, new and changed CVEs, CVSS scores |
| [cve.org](https://www.cve.org) | CVE records as published by the vendor (often earlier and with fixed versions); optional fast delta feed |
| [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) | CVEs on product pages that NVD has not analysed yet (it runs weeks behind) |
| [ENISA EUVD](https://euvd.enisa.europa.eu) | The same, whenever CIRCL is not answering |
| [CVEdetails](https://www.cvedetails.com) | Optional addition to product pages; needs an API token from a cvedetails account (Settings → Sources) |
| [OSV](https://osv.dev) | Package advisories (GitHub advisories, PyPA, RustSec, Go, distributions, …) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | "Exploited in the wild" |
| [FIRST EPSS](https://www.first.org/epss/) | Probability of exploitation |

Records for the same vulnerability are merged. A subscription alerts once per vulnerability, and
once more if it later shows up as exploited. A new subscription also alerts for what was
published in the week before it was created (Settings → Sources changes how far back), and
opening or refreshing a watched product's page adds anything recent on it that the checks have
not reported yet. Alerts you delete do not come back. No account is needed anywhere; a free
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (Settings → Sources) raises
NVD's rate limit.

## Layout

```
crates/core     the engine: catalog, sources, filters, subscriptions, alerts, the JSON API
crates/server   the `vulnwatch` binary: HTTP + embedded web UI + check loop
ui              the web UI (Svelte)
ui/src-tauri    the app shell (Tauri 2) and the Android background code (android/kotlin)
tools           catalog builder, Android build image
```

The UI talks to the core through one call, `rpc(method, params)`: over `POST /api/rpc` (with
`Authorization: Bearer TOKEN`) on the server, directly in the app. That makes the API scriptable:

```sh
curl -s localhost:8088/api/rpc -H "Authorization: Bearer $TOKEN" \
  -d '{"method":"search","params":{"q":"openssh"}}'
```

Development: `./build.sh test` runs the tests. With Rust and Node installed, run
`cargo run -p vulnwatch` and, in `ui/`, `npm run dev` for a hot-reloading UI on port 5173.
`tools/build-catalog.py` rebuilds the product catalog from the NVD CPE dictionary.

## Changes from 0.1

0.1 was a command-line watcher configured with a TOML file. Subscriptions and settings now live
in the UI; the TOML configuration, the `command` and `stdout` notifiers and the RSS and
GitHub-repository sources are gone. Webhook and ntfy remain.

## License

[MIT](LICENSE). The vulnerability data the app fetches stays under its sources' own terms.
