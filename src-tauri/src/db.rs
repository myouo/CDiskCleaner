use rusqlite::{Connection, OptionalExtension};
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA_SQL: &str = include_str!("../../data/schema.sql");
const SEED_SQL: &str = include_str!("../../data/seed.sql");

pub struct DbPaths {
    pub db_path: PathBuf,
}

pub fn init_db(data_dir: &Path) -> rusqlite::Result<DbPaths> {
    fs::create_dir_all(data_dir).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let db_path = data_dir.join("rules.db");
    let mut conn = Connection::open(&db_path)?;
    conn.execute_batch(SCHEMA_SQL)?;

    let seed_version: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'seed_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    if seed_version.is_none() {
        conn.execute_batch(SEED_SQL)?;
    }

    Ok(DbPaths { db_path })
}

pub fn open_db(db_path: &Path) -> rusqlite::Result<Connection> {
    Connection::open(db_path)
}
