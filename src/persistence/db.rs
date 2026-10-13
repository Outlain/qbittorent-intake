//! A short-lived connection per operation avoids sharing SQLite connections
//! between asynchronous tasks. One private, idle connection keeps SQLite from
//! recreating its WAL files between operations. Multi-step claims should use
//! one worker connection and an IMMEDIATE transaction.
use super::{schema, state};
use anyhow::{bail, Context, Result};
use rusqlite::{
    params_from_iter,
    types::{Value as SqlValue, ValueRef},
    Connection, OptionalExtension,
};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    fmt::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Database {
    pub path: PathBuf,
    // Never queried or lent to callers: this connection holds no transaction.
    // Arc keeps it alive until the last Database clone is dropped. Mutex makes
    // the handle safe to share across threads; normal operations do not lock it.
    _idle_connection: Arc<Mutex<Connection>>,
}
impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path == Path::new(":memory:") {
            bail!("Use a file-backed SQLite database so worker connections share state");
        }
        state::reject_symlink(&path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = open_connection(&path)?;
        let transaction = connection.transaction()?;
        for (table, columns) in [
            ("jobs", schema::JOBS),
            ("scan_runs", schema::SCAN_RUNS),
            ("scan_files", schema::SCAN_FILES),
            ("scanner_control", schema::SCANNER_CONTROL),
        ] {
            let definition = columns
                .iter()
                .map(|(name, kind)| format!("\"{name}\" {kind}"))
                .collect::<Vec<_>>()
                .join(", ");
            transaction.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {table} ({definition})"
            ))?;
            let present = column_names(&transaction, table)?;
            for (name, kind) in columns {
                if !present.contains(*name) {
                    // Historical upgrades were additive. Existing rows and scan
                    // checkpoints are never rewritten or deleted by migration.
                    if kind.contains("PRIMARY KEY") || kind.contains("UNIQUE") {
                        bail!("Incompatible {table} table: missing identity column {name}");
                    }
                    transaction
                        .execute_batch(&format!("ALTER TABLE {table} ADD COLUMN \"{name}\" {kind}"))
                        .with_context(|| format!("Could not add {table}.{name}"))?;
                }
            }
        }
        transaction.execute_batch("CREATE INDEX IF NOT EXISTS ix_jobs_qbt_hash ON jobs(qbt_hash);
            CREATE INDEX IF NOT EXISTS ix_jobs_hook_due ON jobs(hook_status,hook_due_at);
            CREATE INDEX IF NOT EXISTS ix_scan_runs_lease ON scan_runs(lease_expires_at);
            CREATE INDEX IF NOT EXISTS ix_scan_runs_queue ON scan_runs(queued_at,priority);
            CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_files_job_path ON scan_files(job_id,relative_path);
            CREATE INDEX IF NOT EXISTS ix_scan_files_job_id ON scan_files(job_id);
            CREATE INDEX IF NOT EXISTS ix_scan_files_job_status ON scan_files(job_id,status);
            CREATE INDEX IF NOT EXISTS ix_scan_files_job_status_scanned ON scan_files(job_id,status,scanned_at);")?;
        transaction.commit()?;
        // A migration may touch many pages. Drop its connection and page cache
        // before opening the small idle connection retained for this lifetime.
        drop(connection);
        let idle = open_connection(&path)?;
        debug_assert!(idle.is_autocommit());
        Ok(Self {
            path,
            _idle_connection: Arc::new(Mutex::new(idle)),
        })
    }
    pub fn connect(&self) -> Result<Connection> {
        open_connection(&self.path)
    }
    pub fn get_job(&self, id: &str) -> Result<Option<Value>> {
        let c = self.connect()?;
        query_one(
            &c,
            &format!("SELECT {} FROM jobs WHERE id=?", job_columns()),
            [id],
        )
    }
    pub fn list_jobs(&self) -> Result<Vec<Value>> {
        let c = self.connect()?;
        query_values(
            &c,
            &format!(
                "SELECT {} FROM jobs ORDER BY created_at DESC,id",
                job_columns()
            ),
            [],
        )
    }
    pub fn insert_job(&self, value: &Value) -> Result<()> {
        self.insert("jobs", value)
    }
    pub fn update_job(&self, id: &str, value: &Value) -> Result<()> {
        self.update("jobs", "id", &Value::from(id), value)
    }
    pub fn get_scan_run(&self, id: &str) -> Result<Option<Value>> {
        let c = self.connect()?;
        query_one(&c, "SELECT * FROM scan_runs WHERE job_id=?", [id])
    }
    pub fn save_scan_run(&self, id: &str, value: &Value) -> Result<()> {
        let mut row = value
            .as_object()
            .context("Scan run must be an object")?
            .clone();
        row.insert("job_id".into(), id.into());
        self.upsert("scan_runs", &["job_id"], &Value::Object(row))
    }
    pub fn list_scan_files(&self, id: &str) -> Result<Vec<Value>> {
        let c = self.connect()?;
        query_values(
            &c,
            "SELECT * FROM scan_files WHERE job_id=? ORDER BY relative_path",
            [id],
        )
    }
    pub fn save_scan_file(&self, id: &str, value: &Value) -> Result<()> {
        let mut row = value
            .as_object()
            .context("Scan file must be an object")?
            .clone();
        row.insert("job_id".into(), id.into());
        self.upsert(
            "scan_files",
            &["job_id", "relative_path"],
            &Value::Object(row),
        )
    }
    pub fn torrent_data(&self, id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .connect()?
            .query_row("SELECT torrent_file_data FROM jobs WHERE id=?", [id], |r| {
                r.get::<_, Option<Vec<u8>>>(0)
            })
            .optional()?
            .flatten())
    }
    pub fn set_torrent_data(&self, id: &str, data: &[u8]) -> Result<()> {
        self.connect()?.execute(
            "UPDATE jobs SET torrent_file_data=? WHERE id=?",
            rusqlite::params![data, id],
        )?;
        Ok(())
    }
    pub fn insert(&self, table: &str, value: &Value) -> Result<()> {
        self.write(table, value, None)
    }
    pub fn upsert(&self, table: &str, keys: &[&str], value: &Value) -> Result<()> {
        self.write(table, value, Some(keys))
    }
    fn write(&self, table: &str, value: &Value, keys: Option<&[&str]>) -> Result<()> {
        let mut c = self.connect()?;
        // IMMEDIATE reserves the writer before checking whether a row exists.
        // This makes a partial upsert atomic and works with legacy Python
        // schemas whose NOT NULL columns have no SQLite DEFAULT expression.
        let transaction = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let allowed = column_names(&transaction, table)?;
        let supplied = validated_columns(&allowed, table, value)?;
        if let Some(keys) = keys {
            if !keys
                .iter()
                .all(|k| allowed.contains(*k) && value.get(*k).is_some())
            {
                bail!("Missing or invalid conflict columns");
            }
            let predicate = keys
                .iter()
                .map(|k| format!("\"{k}\"=?"))
                .collect::<Vec<_>>()
                .join(" AND ");
            let key_values = keys
                .iter()
                .map(|k| sql_value(&value[*k]))
                .collect::<Result<Vec<_>>>()?;
            let exists: bool = transaction.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
                params_from_iter(&key_values),
                |r| r.get(0),
            )?;
            if exists {
                let updates = supplied
                    .iter()
                    .filter(|(n, _)| !keys.contains(n))
                    .collect::<Vec<_>>();
                if !updates.is_empty() {
                    let assignments = updates
                        .iter()
                        .enumerate()
                        .map(|(i, (n, _))| format!("\"{n}\"=?{}", i + 1))
                        .collect::<Vec<_>>()
                        .join(",");
                    let mut args = updates
                        .iter()
                        .map(|(_, v)| sql_value(v))
                        .collect::<Result<Vec<_>>>()?;
                    args.extend(key_values);
                    let changed = updates
                        .iter()
                        .enumerate()
                        .map(|(i, (n, _))| format!("\"{n}\" IS NOT ?{}", i + 1))
                        .collect::<Vec<_>>()
                        .join(" OR ");
                    transaction.execute(
                        &format!(
                            "UPDATE {table} SET {assignments} WHERE {predicate} AND ({changed})"
                        ),
                        params_from_iter(args),
                    )?;
                }
                transaction.commit()?;
                return Ok(());
            }
        }
        let mut complete = insert_defaults(table);
        for (name, value) in supplied {
            complete.insert(name.into(), value.clone());
        }
        let names = complete
            .keys()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>();
        let placeholders = vec!["?"; complete.len()].join(",");
        let sql = format!(
            "INSERT INTO {table} ({}) VALUES ({placeholders})",
            names.join(",")
        );
        transaction.execute(
            &sql,
            params_from_iter(
                complete
                    .values()
                    .map(sql_value)
                    .collect::<Result<Vec<_>>>()?,
            ),
        )?;
        transaction.commit()?;
        Ok(())
    }
    pub fn update(&self, table: &str, key: &str, id: &Value, value: &Value) -> Result<()> {
        let c = self.connect()?;
        let allowed = column_names(&c, table)?;
        let columns = validated_columns(&allowed, table, value)?;
        if !allowed.contains(key) {
            bail!("Invalid row key");
        }
        if columns.is_empty() {
            return Ok(());
        }
        let assignments = columns
            .iter()
            .enumerate()
            .map(|(i, (n, _))| format!("\"{n}\"=?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        // NULL-safe comparisons suppress only an identical patch. A real
        // state, timestamp, fingerprint, or lease change still commits with
        // the same SQLite durability settings and transaction boundaries.
        let changed = columns
            .iter()
            .enumerate()
            .map(|(i, (n, _))| format!("\"{n}\" IS NOT ?{}", i + 1))
            .collect::<Vec<_>>()
            .join(" OR ");
        let mut args = columns
            .into_iter()
            .map(|(_, v)| sql_value(v))
            .collect::<Result<Vec<_>>>()?;
        args.push(sql_value(id)?);
        c.execute(
            &format!("UPDATE {table} SET {assignments} WHERE \"{key}\"=? AND ({changed})"),
            params_from_iter(args),
        )?;
        Ok(())
    }
}
fn open_connection(path: &Path) -> Result<Connection> {
    for suffix in ["", "-wal", "-shm"] {
        state::reject_symlink(&PathBuf::from(format!("{}{suffix}", path.display())))?;
    }
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(30))?;
    connection.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;",
    )?;
    for suffix in ["", "-wal", "-shm"] {
        let file = PathBuf::from(format!("{}{suffix}", path.display()));
        if file.exists() {
            state::make_private(&file)?;
        }
    }
    Ok(connection)
}
pub(crate) fn job_columns() -> String {
    // Excluding the BLOB at the SQL level avoids reading tens of MiB of private
    // torrent metadata for every ordinary UI refresh or scheduler pass.
    let capacity = schema::JOBS.iter().map(|(name, _)| name.len() + 3).sum();
    let mut columns = String::with_capacity(capacity);
    for (name, _) in schema::JOBS {
        if *name == "torrent_file_data" {
            continue;
        }
        if !columns.is_empty() {
            columns.push(',');
        }
        write!(columns, "\"{name}\"").expect("writing into a String cannot fail");
    }
    columns
}
fn insert_defaults(table: &str) -> Map<String, Value> {
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string();
    let value = match table {
        "jobs" => {
            serde_json::json!({
                "created_at": now,
                "updated_at": now,
                "staging_overridden": false,
                "custom_tags_json": "[]",
                "state": "submitted",
                "is_terminal": false,
                "hook_attempts": 0
            })
        }
        "scan_runs" => {
            serde_json::json!({
                "priority": 0,
                "pause_requested": false,
                "attempts": 0,
                "failure_count": 0,
                "total_files": 0,
                "completed_files": 0,
                "total_bytes": 0,
                "completed_bytes": 0,
                "updated_at": now
            })
        }
        "scan_files" => serde_json::json!({"status":"pending","attempts":0}),
        "scanner_control" => {
            serde_json::json!({"boost_until_queue_empty":false,"maintenance_mode":false,"updated_at":now})
        }
        _ => serde_json::json!({}),
    };
    value.as_object().unwrap().clone()
}
fn known_table(table: &str) -> Result<()> {
    if !["jobs", "scan_runs", "scan_files", "scanner_control"].contains(&table) {
        bail!("Unknown database table");
    }
    Ok(())
}
pub fn column_names(c: &Connection, table: &str) -> Result<HashSet<String>> {
    known_table(table)?;
    let mut s = c.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = s
        .query_map([], |r| r.get(1))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    Ok(columns)
}
fn validated_columns<'a>(
    allowed: &HashSet<String>,
    table: &str,
    value: &'a Value,
) -> Result<Vec<(&'a str, &'a Value)>> {
    let object = value
        .as_object()
        .context("Database row must be an object")?;
    for key in object.keys() {
        if !allowed.contains(key) {
            bail!("Unknown {table} column: {key}");
        }
    }
    Ok(object.iter().map(|(k, v)| (k.as_str(), v)).collect())
}
fn sql_value(value: &Value) -> Result<SqlValue> {
    Ok(match value {
        Value::Null => SqlValue::Null,
        Value::Bool(v) => SqlValue::Integer(i64::from(*v)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqlValue::Integer(i)
            } else if n.is_f64() {
                SqlValue::Real(n.as_f64().unwrap())
            } else {
                bail!("Integer exceeds SQLite signed 64-bit range")
            }
        }
        Value::String(s) => SqlValue::Text(s.clone()),
        _ => bail!("Serialize nested database values explicitly"),
    })
}
fn row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let mut object = Map::new();
    for i in 0..row.as_ref().column_count() {
        let name = row.as_ref().column_name(i)?;
        if name == "torrent_file_data" {
            continue;
        }
        let value = match row.get_ref(i)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(v) => {
                if [
                    "is_terminal",
                    "staging_overridden",
                    "pause_requested",
                    "boost_until_queue_empty",
                    "maintenance_mode",
                ]
                .contains(&name)
                {
                    Value::Bool(v != 0)
                } else {
                    v.into()
                }
            }
            ValueRef::Real(v) => serde_json::Number::from_f64(v)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            ValueRef::Text(v) => String::from_utf8_lossy(v).into_owned().into(),
            ValueRef::Blob(_) => Value::Null,
        };
        object.insert(name.to_owned(), value);
    }
    Ok(Value::Object(object))
}
pub fn query_values<P: rusqlite::Params>(
    c: &Connection,
    sql: &str,
    params: P,
) -> Result<Vec<Value>> {
    let mut s = c.prepare(sql)?;
    let rows = s
        .query_map(params, row_value)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}
pub fn query_one<P: rusqlite::Params>(
    c: &Connection,
    sql: &str,
    params: P,
) -> Result<Option<Value>> {
    Ok(c.query_row(sql, params, row_value).optional()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    pub fn job() -> Value {
        json!({"id":"job-1","magnet_uri":"magnet:?xt=urn:btih:123","final_parent":"/media","staging_preference":"local","staging_root_initial":"/staging","managed_tag":"intake","unique_tag":"ti_job_1"})
    }
    #[test]
    fn idle_connection_follows_database_clones_and_closes_with_the_last_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("database.sqlite");
        let database = Database::open(&path).unwrap();
        database.insert_job(&job()).unwrap();
        let wal = directory.path().join("database.sqlite-wal");
        let shared_memory = directory.path().join("database.sqlite-shm");
        assert!(std::fs::metadata(&wal).unwrap().len() > 0);
        let clone = database.clone();
        drop(database);
        assert!(wal.exists());
        assert!(shared_memory.exists());
        assert_eq!(
            clone.get_job("job-1").unwrap().unwrap()["state"],
            "submitted"
        );
        clone
            .update_job("job-1", &json!({"state":"downloading"}))
            .unwrap();
        drop(clone);
        assert!(
            !wal.exists(),
            "the final connection must perform normal SQLite cleanup"
        );
        assert!(!shared_memory.exists());
        let reopened = Database::open(&path).unwrap();
        assert_eq!(
            reopened.get_job("job-1").unwrap().unwrap()["state"],
            "downloading"
        );
    }
    #[test]
    fn idle_connection_keeps_full_durability_and_does_not_pin_checkpoints() {
        // SQLite's WAL-reset race is fixed in 3.51.3. Keep the bundled release
        // new enough for concurrent short-lived writers and checkpoints.
        assert!(rusqlite::version_number() >= 3_051_003);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("database.sqlite");
        let database = Database::open(&path).unwrap();
        database.insert_job(&job()).unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "wal_autocheckpoint", |row| row.get::<_, i64>(0))
                .unwrap(),
            1000
        );
        assert!(database._idle_connection.lock().unwrap().is_autocommit());
        let checkpoint = |connection: &Connection| {
            connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
        };
        assert_eq!(checkpoint(&connection), (0, 0, 0));
        drop(connection);
        // A write larger than the normal 1000-page threshold should advance
        // the main database automatically even though the idle handle lives.
        let metadata = vec![b'x'; 5 * 1024 * 1024];
        database.set_torrent_data("job-1", &metadata).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > metadata.len() as u64);
        let connection = database.connect().unwrap();
        assert_eq!(checkpoint(&connection), (0, 0, 0));
        assert_eq!(
            std::fs::metadata(directory.path().join("database.sqlite-wal"))
                .unwrap()
                .len(),
            0
        );
        assert!(database._idle_connection.lock().unwrap().is_autocommit());
        assert_eq!(database.torrent_data("job-1").unwrap().unwrap(), metadata);
        assert_eq!(
            connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }
    #[test]
    fn partial_checkpoints_preserve_existing_facts() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db")).unwrap();
        db.insert_job(&job()).unwrap();
        db.save_scan_run(
            "job-1",
            &json!({"root_path":"/staging/test","total_files":5}),
        )
        .unwrap();
        db.save_scan_run("job-1", &json!({"pause_requested":true}))
            .unwrap();
        let run = db.get_scan_run("job-1").unwrap().unwrap();
        assert_eq!(run["total_files"], 5);
        assert_eq!(run["pause_requested"], true);
        db.save_scan_file(
            "job-1",
            &json!({"relative_path":"a.txt","size_bytes":10,"mtime_ns":20}),
        )
        .unwrap();
        db.save_scan_file("job-1", &json!({"relative_path":"a.txt","status":"clean"}))
            .unwrap();
        let rows = db.list_scan_files("job-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["size_bytes"], 10);
        assert_eq!(rows[0]["mtime_ns"], 20);
        assert_eq!(rows[0]["status"], "clean");
        db.set_torrent_data("job-1", b"secret metadata").unwrap();
        assert_eq!(
            db.torrent_data("job-1").unwrap().unwrap(),
            b"secret metadata"
        );
        assert!(db
            .get_job("job-1")
            .unwrap()
            .unwrap()
            .get("torrent_file_data")
            .is_none());
        assert!(db
            .update_job("job-1", &json!({"bad_column;DROP TABLE jobs":1}))
            .is_err());
    }
    #[test]
    fn identical_patches_skip_updates_but_null_and_real_changes_commit() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(directory.path().join("state.db")).unwrap();
        database.insert_job(&job()).unwrap();
        database
            .save_scan_file(
                "job-1",
                &json!({"relative_path":"file","size_bytes":42,"mtime_ns":123}),
            )
            .unwrap();
        database
            .save_scan_run("job-1", &json!({"root_path":"/staging"}))
            .unwrap();
        let observer = database.connect().unwrap();
        // A test-only trigger counts attempted row mutations independently of
        // whether SQLite optimizes an unchanged physical page write.
        observer.execute_batch("CREATE TABLE observed_updates (table_name TEXT);
            CREATE TRIGGER observe_job AFTER UPDATE ON jobs BEGIN INSERT INTO observed_updates VALUES ('jobs'); END;
            CREATE TRIGGER observe_file AFTER UPDATE ON scan_files BEGIN INSERT INTO observed_updates VALUES ('scan_files'); END;
            CREATE TRIGGER observe_run AFTER UPDATE ON scan_runs BEGIN INSERT INTO observed_updates VALUES ('scan_runs'); END;
            PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        for _ in 0..3 {
            database
                .update_job(
                    "job-1",
                    &json!({"is_terminal":false,"last_error":null,"state":"submitted"}),
                )
                .unwrap();
            database
                .save_scan_file(
                    "job-1",
                    &json!({"relative_path":"file","status":"pending","threat_name":null}),
                )
                .unwrap();
            database
                .save_scan_run(
                    "job-1",
                    &json!({"pause_requested":false,"root_path":"/staging"}),
                )
                .unwrap();
        }
        let count = || {
            observer
                .query_row("SELECT count(*) FROM observed_updates", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert_eq!(count(), 0);
        assert_eq!(
            std::fs::metadata(directory.path().join("state.db-wal"))
                .unwrap()
                .len(),
            0
        );
        database
            .update_job("job-1", &json!({"is_terminal":true,"last_error":"failure"}))
            .unwrap();
        database
            .update_job("job-1", &json!({"last_error":null}))
            .unwrap();
        database
            .save_scan_file(
                "job-1",
                &json!({"relative_path":"file","status":"clean","scan_duration_seconds":1.25}),
            )
            .unwrap();
        database
            .save_scan_run("job-1", &json!({"pause_requested":true}))
            .unwrap();
        assert_eq!(count(), 4);
        assert!(
            std::fs::metadata(directory.path().join("state.db-wal"))
                .unwrap()
                .len()
                > 0
        );
        let row = database.get_job("job-1").unwrap().unwrap();
        assert_eq!(row["is_terminal"], true);
        assert!(row["last_error"].is_null());
        assert_eq!(
            database.list_scan_files("job-1").unwrap()[0]["scan_duration_seconds"],
            1.25
        );
        // Existing legacy/custom columns still use the actual schema check.
        assert!(database.update_job("job-1", &json!({"unknown":1})).is_err());
    }
    #[test]
    fn python_schema_without_server_defaults_is_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        let c = Connection::open(&path).unwrap();
        for (table, columns) in [
            ("jobs", schema::JOBS),
            ("scan_runs", schema::SCAN_RUNS),
            ("scan_files", schema::SCAN_FILES),
            ("scanner_control", schema::SCANNER_CONTROL),
        ] {
            let definition = columns
                .iter()
                .filter(|(n, _)| {
                    ![
                        "custom_tags_json",
                        "ctime_ns",
                        "device",
                        "inode",
                        "maintenance_mode",
                        "maintenance_reason",
                        "maintenance_started_at",
                    ]
                    .contains(n)
                })
                .map(|(n, t)| format!("\"{n}\" {}", t.split(" DEFAULT ").next().unwrap()))
                .collect::<Vec<_>>()
                .join(",");
            c.execute_batch(&format!("CREATE TABLE {table} ({definition})"))
                .unwrap();
        }
        drop(c);
        let db = Database::open(&path).unwrap();
        db.insert_job(&job()).unwrap();
        db.save_scan_run("job-1", &json!({"root_path":"/staging"}))
            .unwrap();
        db.save_scan_file(
            "job-1",
            &json!({"relative_path":"a","size_bytes":1,"mtime_ns":2}),
        )
        .unwrap();
        db.save_scan_file("job-1", &json!({"relative_path":"a","status":"clean"}))
            .unwrap();
        assert_eq!(
            db.get_job("job-1").unwrap().unwrap()["custom_tags_json"],
            "[]"
        );
        assert_eq!(db.get_scan_run("job-1").unwrap().unwrap()["attempts"], 0);
    }
}
