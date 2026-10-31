//! SQLite-backed state: one table per kind of record, each holding a JSON value and an optional expiry.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::clock::Clock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// Authentication requests waiting for the login form.
    Pending,
    /// Browser sessions and the service providers that used them.
    Sessions,
    /// Single logout in progress: which service providers still have to be logged out.
    Logouts,
    /// Service providers registered through the dev API (declared ones are copied in at startup).
    ServiceProviders,
    /// Responses waiting to be resolved by artifact (HTTP-Artifact binding).
    Artifacts,
}

impl Table {
    const ALL: [Table; 5] =
        [Table::Pending, Table::Sessions, Table::Logouts, Table::ServiceProviders, Table::Artifacts];

    fn name(self) -> &'static str {
        match self {
            Table::Pending => "pending_authn_requests",
            Table::Sessions => "sessions",
            Table::Logouts => "logouts",
            Table::ServiceProviders => "service_providers",
            Table::Artifacts => "artifacts",
        }
    }
}

pub struct Store {
    conn: Mutex<Connection>,
    /// Expiry is judged by the server's (possibly shifted) clock.
    clock: Clock,
}

fn log<T>(result: rusqlite::Result<T>, op: &str, table: Table) -> Option<T> {
    result.map_err(|e| tracing::error!("sqlite {op} on {}: {e}", table.name())).ok()
}

impl Store {
    /// Open (creating if needed) the database at `path`, or an in-memory database when `None`.
    pub fn open(path: Option<&Path>, clock: Clock) -> anyhow::Result<Self> {
        let conn = match path {
            Some(p) => {
                if let Some(dir) = p.parent() {
                    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
                }
                let conn = Connection::open(p).with_context(|| format!("opening {}", p.display()))?;
                // WAL lets readers and the writer work concurrently.
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn
            }
            None => Connection::open_in_memory()?,
        };
        conn.busy_timeout(Duration::from_secs(5))?;
        for table in Table::ALL {
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {0} (
                    key        TEXT PRIMARY KEY,
                    value      TEXT NOT NULL,
                    expires_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS {0}_expires_at ON {0} (expires_at);",
                table.name()
            ))?;
        }
        Ok(Self { conn: Mutex::new(conn), clock })
    }

    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    pub fn put<T: Serialize>(&self, table: Table, key: &str, value: &T, expires_at: Option<i64>) {
        let Ok(json) = serde_json::to_string(value) else { return };
        let conn = self.conn.lock().unwrap();
        log(
            conn.execute(
                &format!("INSERT OR REPLACE INTO {} (key, value, expires_at) VALUES (?1, ?2, ?3)", table.name()),
                params![key, json, expires_at],
            ),
            "insert",
            table,
        );
    }

    /// Fetch an unexpired record.
    pub fn get<T: DeserializeOwned>(&self, table: Table, key: &str) -> Option<T> {
        let conn = self.conn.lock().unwrap();
        let json: Option<String> = log(
            conn.query_row(
                &format!(
                    "SELECT value FROM {} WHERE key = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
                    table.name()
                ),
                params![key, self.clock.now()],
                |r| r.get(0),
            )
            .optional(),
            "select",
            table,
        )
        .flatten();
        json.and_then(|j| serde_json::from_str(&j).ok())
    }

    pub fn contains(&self, table: Table, key: &str) -> bool {
        self.get::<serde_json::Value>(table, key).is_some()
    }

    /// Atomically delete and return an unexpired record (pending requests).
    pub fn take<T: DeserializeOwned>(&self, table: Table, key: &str) -> Option<T> {
        let conn = self.conn.lock().unwrap();
        let json: Option<String> = log(
            conn.query_row(
                &format!(
                    "DELETE FROM {} WHERE key = ?1 AND (expires_at IS NULL OR expires_at > ?2) RETURNING value",
                    table.name()
                ),
                params![key, self.clock.now()],
                |r| r.get(0),
            )
            .optional(),
            "delete",
            table,
        )
        .flatten();
        json.and_then(|j| serde_json::from_str(&j).ok())
    }

    pub fn remove(&self, table: Table, key: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        log(conn.execute(&format!("DELETE FROM {} WHERE key = ?1", table.name()), params![key]), "delete", table)
            .is_some_and(|n| n > 0)
    }

    /// All unexpired records.
    pub fn list<T: DeserializeOwned>(&self, table: Table) -> Vec<T> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .prepare(&format!("SELECT value FROM {} WHERE expires_at IS NULL OR expires_at > ?1", table.name()))
            .and_then(|mut stmt| {
                stmt.query_map(params![self.clock.now()], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()
            });
        log(rows, "select", table).unwrap_or_default().iter().filter_map(|j| serde_json::from_str(j).ok()).collect()
    }

    /// All unexpired records with their keys and expiry.
    pub fn entries<T: DeserializeOwned>(&self, table: Table) -> Vec<(String, T, Option<i64>)> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .prepare(&format!(
                "SELECT key, value, expires_at FROM {} WHERE expires_at IS NULL OR expires_at > ?1",
                table.name()
            ))
            .and_then(|mut stmt| {
                stmt.query_map(params![self.clock.now()], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?))
                })?
                .collect::<Result<Vec<_>, _>>()
            });
        log(rows, "select", table)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v, exp)| Some((k, serde_json::from_str(&v).ok()?, exp)))
            .collect()
    }

    /// Read-modify-write a record (expired or not) in one transaction. Returns `None` if missing.
    pub fn update<T, R>(&self, table: Table, key: &str, f: impl FnOnce(&mut T) -> R) -> Option<R>
    where
        T: Serialize + DeserializeOwned,
    {
        let mut conn = self.conn.lock().unwrap();
        let tx = log(conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate), "begin", table)?;
        let json: String = log(
            tx.query_row(&format!("SELECT value FROM {} WHERE key = ?1", table.name()), params![key], |r| r.get(0))
                .optional(),
            "select",
            table,
        )??;
        let mut value: T = serde_json::from_str(&json).ok()?;
        let result = f(&mut value);
        let json = serde_json::to_string(&value).ok()?;
        log(
            tx.execute(&format!("UPDATE {} SET value = ?2 WHERE key = ?1", table.name()), params![key, json]),
            "update",
            table,
        )?;
        log(tx.commit(), "commit", table)?;
        Some(result)
    }

    /// Delete every record in a table.
    pub fn clear(&self, table: Table) {
        let conn = self.conn.lock().unwrap();
        log(conn.execute(&format!("DELETE FROM {}", table.name()), []), "delete", table);
    }

    /// Delete every expired record.
    pub fn purge_expired(&self) {
        let conn = self.conn.lock().unwrap();
        let t = self.clock.now();
        for table in Table::ALL {
            log(
                conn.execute(
                    &format!("DELETE FROM {} WHERE expires_at IS NOT NULL AND expires_at <= ?1", table.name()),
                    params![t],
                ),
                "purge",
                table,
            );
        }
    }
}
