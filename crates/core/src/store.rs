//! SQLite persistence: settings, subscriptions, alerts, cursors, response cache.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::matcher::Subscription;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id INTEGER NOT NULL,
    sub_name TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    exploited INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    read INTEGER NOT NULL DEFAULT 0,
    vuln TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    UNIQUE (sub_id, vuln_id, kind)
);
CREATE INDEX IF NOT EXISTS alerts_created ON alerts (created_at);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL, body TEXT NOT NULL);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// A new vulnerability that passed the subscription's filter.
    New,
    /// A vulnerability that has just become known-exploited.
    Exploited,
}

impl AlertKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Exploited => "exploited",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    pub sub_id: i64,
    pub sub_name: String,
    pub vuln_id: String,
    pub kind: AlertKind,
    pub created_at: DateTime<Utc>,
    pub read: bool,
    /// `Advisory::view(true)` snapshot taken when the alert fired.
    pub vuln: Value,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.execute_batch(SCHEMA)?;
        // Databases from before alerts could be deleted individually.
        let has_deleted = conn.prepare("SELECT 1 FROM pragma_table_info('alerts') WHERE name = 'deleted'")?.exists([])?;
        if !has_deleted {
            conn.execute_batch("ALTER TABLE alerts ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0")?;
        }
        Ok(Self { conn })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    // ── key/value ───────────────────────────────────────────────────────────

    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let raw: Option<String> =
            self.conn.query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0)).optional()?;
        Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
    }

    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, serde_json::to_string(value)?],
        )?;
        Ok(())
    }

    pub fn delete(&self, key: &str) -> Result<()> {
        self.conn.execute("DELETE FROM kv WHERE key = ?1", [key])?;
        Ok(())
    }

    // ── subscriptions ───────────────────────────────────────────────────────

    pub fn subscriptions(&self) -> Result<Vec<Subscription>> {
        let mut stmt = self.conn.prepare("SELECT id, body, created_at FROM subscriptions ORDER BY name COLLATE NOCASE")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
        let mut out = vec![];
        for row in rows {
            let (id, body, created) = row?;
            if let Ok(mut sub) = serde_json::from_str::<Subscription>(&body) {
                sub.id = id;
                sub.created_at = created.parse().ok();
                out.push(sub);
            }
        }
        Ok(out)
    }

    /// Insert (id 0) or update. Returns the id.
    pub fn save_subscription(&self, sub: &Subscription) -> Result<i64> {
        let body = serde_json::to_string(sub)?;
        if sub.id == 0 {
            self.conn.execute(
                "INSERT INTO subscriptions (name, body, created_at) VALUES (?1, ?2, ?3)",
                params![sub.name, body, Utc::now().to_rfc3339()],
            )?;
            Ok(self.conn.last_insert_rowid())
        } else {
            let n = self.conn.execute(
                "UPDATE subscriptions SET name = ?1, body = ?2 WHERE id = ?3",
                params![sub.name, body, sub.id],
            )?;
            anyhow::ensure!(n == 1, "subscription {} not found", sub.id);
            self.conn.execute("UPDATE alerts SET sub_name = ?1 WHERE sub_id = ?2", params![sub.name, sub.id])?;
            Ok(sub.id)
        }
    }

    pub fn delete_subscription(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM subscriptions WHERE id = ?1", [id])?;
        self.conn.execute("DELETE FROM alerts WHERE sub_id = ?1", [id])?;
        self.delete(&format!("osv_cursor:{id}"))?;
        self.delete(&format!("caught_up:{id}"))?;
        Ok(())
    }

    // ── alerts ──────────────────────────────────────────────────────────────

    /// Was an alert already recorded for this subscription and vulnerability (deleted ones
    /// included, so they do not come back)? Returns whether any recorded alert already said
    /// "exploited".
    pub fn prior_alert(&self, sub_id: i64, ids: &[&str]) -> Result<Option<bool>> {
        let mut found = None;
        for id in ids {
            let mut stmt = self.conn.prepare_cached("SELECT exploited FROM alerts WHERE sub_id = ?1 AND vuln_id = ?2")?;
            for row in stmt.query_map(params![sub_id, id], |r| r.get::<_, bool>(0))? {
                found = Some(found.unwrap_or(false) | row?);
            }
        }
        Ok(found)
    }

    pub fn insert_alert(
        &self,
        sub_id: i64,
        sub_name: &str,
        vuln_id: &str,
        kind: AlertKind,
        exploited: bool,
        vuln: &Value,
    ) -> Result<Option<Alert>> {
        let now = Utc::now();
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO alerts (sub_id, sub_name, vuln_id, kind, exploited, created_at, vuln)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![sub_id, sub_name, vuln_id, kind.as_str(), exploited, now.to_rfc3339(), vuln.to_string()],
        )?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(Alert {
            id: self.conn.last_insert_rowid(),
            sub_id,
            sub_name: sub_name.to_string(),
            vuln_id: vuln_id.to_string(),
            kind,
            created_at: now,
            read: false,
            vuln: vuln.clone(),
        }))
    }

    /// Newest first. `before_id` pages backwards; `after_id` returns only newer alerts (oldest first).
    pub fn alerts(
        &self,
        sub_id: Option<i64>,
        unread_only: bool,
        before_id: Option<i64>,
        after_id: Option<i64>,
        limit: u32,
    ) -> Result<Vec<Alert>> {
        let mut sql = String::from(
            "SELECT id, sub_id, sub_name, vuln_id, kind, created_at, read, vuln FROM alerts WHERE deleted = 0",
        );
        if let Some(s) = sub_id {
            sql.push_str(&format!(" AND sub_id = {s}"));
        }
        if unread_only {
            sql.push_str(" AND read = 0");
        }
        if let Some(b) = before_id {
            sql.push_str(&format!(" AND id < {b}"));
        }
        if let Some(a) = after_id {
            sql.push_str(&format!(" AND id > {a} ORDER BY id ASC"));
        } else {
            sql.push_str(" ORDER BY id DESC");
        }
        sql.push_str(&format!(" LIMIT {limit}"));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok(Alert {
                id: r.get(0)?,
                sub_id: r.get(1)?,
                sub_name: r.get(2)?,
                vuln_id: r.get(3)?,
                kind: if r.get::<_, String>(4)? == "exploited" { AlertKind::Exploited } else { AlertKind::New },
                created_at: r.get::<_, String>(5)?.parse().unwrap_or_default(),
                read: r.get(6)?,
                vuln: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or(Value::Null),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn max_alert_id(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COALESCE(MAX(id), 0) FROM alerts", [], |r| r.get(0))?)
    }

    pub fn unread_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM alerts WHERE read = 0 AND deleted = 0", [], |r| r.get(0))?)
    }

    /// Per-subscription `(total, unread)` alert counts.
    pub fn alert_counts(&self) -> Result<std::collections::HashMap<i64, (i64, i64)>> {
        let mut stmt = self.conn.prepare("SELECT sub_id, COUNT(*), SUM(read = 0) FROM alerts WHERE deleted = 0 GROUP BY sub_id")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Mark alerts read/unread. `ids = None` means all (optionally limited to one subscription).
    pub fn mark_read(&self, ids: Option<&[i64]>, sub_id: Option<i64>, read: bool) -> Result<()> {
        match ids {
            Some(ids) => {
                for id in ids {
                    self.conn.execute("UPDATE alerts SET read = ?1 WHERE id = ?2", params![read, id])?;
                }
            }
            None => {
                match sub_id {
                    Some(s) => {
                        self.conn.execute("UPDATE alerts SET read = ?1 WHERE sub_id = ?2", params![read, s])?
                    }
                    None => self.conn.execute("UPDATE alerts SET read = ?1", params![read])?,
                };
            }
        }
        Ok(())
    }

    /// Remove alerts from the feed. `ids = None` means all (optionally limited to one
    /// subscription). The rows stay behind, emptied, as a record of what the user has already
    /// been told; without it the next check would raise the same alerts again.
    pub fn delete_alerts(&self, ids: Option<&[i64]>, sub_id: Option<i64>) -> Result<()> {
        const GONE: &str = "UPDATE alerts SET deleted = 1, read = 1, vuln = 'null' WHERE deleted = 0";
        match (ids, sub_id) {
            (Some(ids), _) => {
                for id in ids {
                    self.conn.execute(&format!("{GONE} AND id = ?1"), [id])?;
                }
            }
            (None, Some(s)) => {
                self.conn.execute(&format!("{GONE} AND sub_id = ?1"), [s])?;
            }
            (None, None) => {
                self.conn.execute(GONE, [])?;
            }
        }
        // Nothing that old can alert again (`max_age_days` is at most a year).
        let cutoff = (Utc::now() - chrono::Duration::days(400)).to_rfc3339();
        self.conn.execute("DELETE FROM alerts WHERE deleted = 1 AND created_at < ?1", [cutoff])?;
        Ok(())
    }

    // ── response cache ──────────────────────────────────────────────────────

    pub fn cache_get(&self, key: &str, max_age_secs: i64) -> Result<Option<Value>> {
        Ok(self.cache_entry(key, max_age_secs)?.map(|(_, body)| body))
    }

    /// Like `cache_get`, with the time (Unix seconds) the entry was stored.
    pub fn cache_entry(&self, key: &str, max_age_secs: i64) -> Result<Option<(i64, Value)>> {
        let row: Option<(i64, String)> = self
            .conn
            .query_row("SELECT fetched_at, body FROM cache WHERE key = ?1", [key], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        Ok(row
            .filter(|(at, _)| Utc::now().timestamp() - at <= max_age_secs)
            .and_then(|(at, body)| Some((at, serde_json::from_str(&body).ok()?))))
    }

    pub fn cache_put(&self, key: &str, body: &Value) -> Result<()> {
        let now = Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO cache (key, fetched_at, body) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET fetched_at = excluded.fetched_at, body = excluded.body",
            params![key, now, body.to_string()],
        )?;
        // Keep the cache small: drop anything older than a week.
        self.conn.execute("DELETE FROM cache WHERE fetched_at < ?1", [now - 7 * 86400])?;
        Ok(())
    }

    pub fn cache_clear(&self) -> Result<()> {
        self.conn.execute("DELETE FROM cache", [])?;
        Ok(())
    }
}
