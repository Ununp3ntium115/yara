//! Database Integration for Scan Results
//!
//! Store and retrieve scan results, rules, and statistics in SQLite.
//!
//! # Example
//!
//! ```no_run
//! use r_yara_scanner::database::{Database, ScanRecord};
//!
//! // Open or create database
//! let db = Database::open("/path/to/scans.db")?;
//!
//! // Store scan result
//! let record = ScanRecord {
//!     file_hash: "abc123...",
//!     file_path: Some("/path/to/file.exe"),
//!     matches: vec!["MalwareRule"],
//!     ..Default::default()
//! };
//! db.store_scan(&record)?;
//!
//! // Query results
//! let results = db.find_by_hash("abc123...")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{ScanError, ScanResult};
use std::path::Path;

/// Database connection for scan results
///
/// Uses SQLite for persistent storage of scan results, rules, and statistics.
#[derive(Debug)]
pub struct Database {
    /// Connection pool
    conn: rusqlite::Connection,
}

impl Database {
    /// Open or create a database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> ScanResult<Self> {
        let conn = rusqlite::Connection::open(path.as_ref())
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let db = Self { conn };
        db.init_schema()?;

        Ok(db)
    }

    /// Open an in-memory database (for testing)
    pub fn open_memory() -> ScanResult<Self> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let db = Self { conn };
        db.init_schema()?;

        Ok(db)
    }

    /// Initialize database schema
    fn init_schema(&self) -> ScanResult<()> {
        self.conn.execute_batch(r#"
            -- Scan results table
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                file_path TEXT,
                file_size INTEGER,
                file_type TEXT,
                scan_time TEXT NOT NULL DEFAULT (datetime('now')),
                scan_duration_ms INTEGER,
                rule_count INTEGER DEFAULT 0,
                match_count INTEGER DEFAULT 0
            );

            -- Index for hash lookups
            CREATE INDEX IF NOT EXISTS idx_scans_hash ON scans(file_hash);

            -- Index for time-based queries
            CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scan_time);

            -- Matched rules table
            CREATE TABLE IF NOT EXISTS scan_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                tags TEXT,
                metadata TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            -- Index for rule queries
            CREATE INDEX IF NOT EXISTS idx_matches_rule ON scan_matches(rule_name);

            -- String matches table
            CREATE TABLE IF NOT EXISTS string_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_id INTEGER NOT NULL,
                identifier TEXT NOT NULL,
                offsets TEXT NOT NULL,
                FOREIGN KEY(match_id) REFERENCES scan_matches(id) ON DELETE CASCADE
            );

            -- Rules table (loaded rule sets)
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL,
                rule_count INTEGER DEFAULT 0,
                pattern_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Statistics table
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_scans INTEGER DEFAULT 0,
                total_matches INTEGER DEFAULT 0,
                total_files_scanned INTEGER DEFAULT 0,
                total_bytes_scanned INTEGER DEFAULT 0,
                last_scan_time TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Initialize statistics row if not exists
            INSERT OR IGNORE INTO statistics (id) VALUES (1);
        "#).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        Ok(())
    }

    /// Store a scan result
    pub fn store_scan(&self, record: &ScanRecord) -> ScanResult<i64> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        // Insert scan record
        tx.execute(
            r#"INSERT INTO scans (file_hash, file_path, file_size, file_type, scan_duration_ms, rule_count, match_count)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            rusqlite::params![
                record.file_hash,
                record.file_path,
                record.file_size,
                record.file_type,
                record.scan_duration_ms,
                record.rule_count,
                record.matches.len() as i64
            ],
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let scan_id = tx.last_insert_rowid();

        // Insert matches
        for match_info in &record.matches {
            tx.execute(
                r#"INSERT INTO scan_matches (scan_id, rule_name, tags, metadata)
                   VALUES (?1, ?2, ?3, ?4)"#,
                rusqlite::params![
                    scan_id,
                    match_info.rule_name,
                    match_info.tags.join(","),
                    serde_json::to_string(&match_info.metadata).unwrap_or_default(),
                ],
            ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

            let match_id = tx.last_insert_rowid();

            // Insert string matches
            for string_match in &match_info.strings {
                tx.execute(
                    r#"INSERT INTO string_matches (match_id, identifier, offsets)
                       VALUES (?1, ?2, ?3)"#,
                    rusqlite::params![
                        match_id,
                        string_match.identifier,
                        serde_json::to_string(&string_match.offsets).unwrap_or_default(),
                    ],
                ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;
            }
        }

        // Update statistics
        tx.execute(
            r#"UPDATE statistics SET
               total_scans = total_scans + 1,
               total_matches = total_matches + ?1,
               total_files_scanned = total_files_scanned + 1,
               total_bytes_scanned = total_bytes_scanned + ?2,
               last_scan_time = datetime('now'),
               updated_at = datetime('now')
               WHERE id = 1"#,
            rusqlite::params![
                record.matches.len() as i64,
                record.file_size.unwrap_or(0),
            ],
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        tx.commit()
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        Ok(scan_id)
    }

    /// Find scans by file hash
    pub fn find_by_hash(&self, hash: &str) -> ScanResult<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, file_hash, file_path, file_size, file_type, scan_time,
                      scan_duration_ms, rule_count, match_count
               FROM scans WHERE file_hash = ?1
               ORDER BY scan_time DESC"#
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let records = stmt.query_map([hash], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                file_hash: row.get(1)?,
                file_path: row.get(2)?,
                file_size: row.get(3)?,
                file_type: row.get(4)?,
                scan_time: row.get(5)?,
                scan_duration_ms: row.get(6)?,
                rule_count: row.get(7)?,
                matches: Vec::new(), // Load separately if needed
            })
        }).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        records.collect::<Result<Vec<_>, _>>()
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))
    }

    /// Find scans by rule name
    pub fn find_by_rule(&self, rule_name: &str) -> ScanResult<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT DISTINCT s.id, s.file_hash, s.file_path, s.file_size, s.file_type,
                      s.scan_time, s.scan_duration_ms, s.rule_count, s.match_count
               FROM scans s
               JOIN scan_matches m ON s.id = m.scan_id
               WHERE m.rule_name = ?1
               ORDER BY s.scan_time DESC"#
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let records = stmt.query_map([rule_name], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                file_hash: row.get(1)?,
                file_path: row.get(2)?,
                file_size: row.get(3)?,
                file_type: row.get(4)?,
                scan_time: row.get(5)?,
                scan_duration_ms: row.get(6)?,
                rule_count: row.get(7)?,
                matches: Vec::new(),
            })
        }).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        records.collect::<Result<Vec<_>, _>>()
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))
    }

    /// Get recent scans
    pub fn get_recent_scans(&self, limit: u32) -> ScanResult<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, file_hash, file_path, file_size, file_type, scan_time,
                      scan_duration_ms, rule_count, match_count
               FROM scans
               ORDER BY scan_time DESC
               LIMIT ?1"#
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let records = stmt.query_map([limit], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                file_hash: row.get(1)?,
                file_path: row.get(2)?,
                file_size: row.get(3)?,
                file_type: row.get(4)?,
                scan_time: row.get(5)?,
                scan_duration_ms: row.get(6)?,
                rule_count: row.get(7)?,
                matches: Vec::new(),
            })
        }).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        records.collect::<Result<Vec<_>, _>>()
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))
    }

    /// Get statistics
    pub fn get_statistics(&self) -> ScanResult<Statistics> {
        let mut stmt = self.conn.prepare(
            r#"SELECT total_scans, total_matches, total_files_scanned,
                      total_bytes_scanned, last_scan_time, created_at, updated_at
               FROM statistics WHERE id = 1"#
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        stmt.query_row([], |row| {
            Ok(Statistics {
                total_scans: row.get(0)?,
                total_matches: row.get(1)?,
                total_files_scanned: row.get(2)?,
                total_bytes_scanned: row.get(3)?,
                last_scan_time: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        }).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))
    }

    /// Store a rule set
    pub fn store_rules(&self, name: &str, source: &str, rule_count: u32, pattern_count: u32) -> ScanResult<i64> {
        self.conn.execute(
            r#"INSERT OR REPLACE INTO rules (name, source, rule_count, pattern_count, updated_at)
               VALUES (?1, ?2, ?3, ?4, datetime('now'))"#,
            rusqlite::params![name, source, rule_count, pattern_count],
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Get a stored rule set
    pub fn get_rules(&self, name: &str) -> ScanResult<Option<StoredRules>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, name, source, rule_count, pattern_count, created_at, updated_at
               FROM rules WHERE name = ?1"#
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let result = stmt.query_row([name], |row| {
            Ok(StoredRules {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                rule_count: row.get(3)?,
                pattern_count: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        });

        match result {
            Ok(rules) => Ok(Some(rules)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ScanError::IoError(std::io::Error::other(e.to_string()))),
        }
    }

    /// List all stored rule sets
    pub fn list_rules(&self) -> ScanResult<Vec<StoredRules>> {
        let mut stmt = self.conn.prepare(
            r#"SELECT id, name, source, rule_count, pattern_count, created_at, updated_at
               FROM rules ORDER BY name"#
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        let rules = stmt.query_map([], |row| {
            Ok(StoredRules {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                rule_count: row.get(3)?,
                pattern_count: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        }).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        rules.collect::<Result<Vec<_>, _>>()
            .map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))
    }

    /// Delete a rule set
    pub fn delete_rules(&self, name: &str) -> ScanResult<bool> {
        let rows = self.conn.execute(
            "DELETE FROM rules WHERE name = ?1",
            [name],
        ).map_err(|e| ScanError::IoError(std::io::Error::other(e.to_string())))?;

        Ok(rows > 0)
    }
}

/// A scan result record
#[derive(Debug, Clone, Default)]
pub struct ScanRecord {
    /// Database ID
    pub id: Option<i64>,
    /// File hash (SHA256)
    pub file_hash: String,
    /// Original file path
    pub file_path: Option<String>,
    /// File size in bytes
    pub file_size: Option<i64>,
    /// Detected file type
    pub file_type: Option<String>,
    /// Scan timestamp
    pub scan_time: Option<String>,
    /// Scan duration in milliseconds
    pub scan_duration_ms: Option<i64>,
    /// Number of rules used
    pub rule_count: Option<i64>,
    /// Matched rules
    pub matches: Vec<MatchInfo>,
}

/// Information about a matched rule
#[derive(Debug, Clone, Default)]
pub struct MatchInfo {
    /// Rule name
    pub rule_name: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Matched strings
    pub strings: Vec<StringMatchInfo>,
}

/// Information about a matched string
#[derive(Debug, Clone, Default)]
pub struct StringMatchInfo {
    /// String identifier
    pub identifier: String,
    /// Match offsets
    pub offsets: Vec<u64>,
}

/// Database statistics
#[derive(Debug, Clone, Default)]
pub struct Statistics {
    /// Total number of scans performed
    pub total_scans: i64,
    /// Total number of rule matches
    pub total_matches: i64,
    /// Total files scanned
    pub total_files_scanned: i64,
    /// Total bytes scanned
    pub total_bytes_scanned: i64,
    /// Last scan timestamp
    pub last_scan_time: Option<String>,
    /// Database creation time
    pub created_at: Option<String>,
    /// Last update time
    pub updated_at: Option<String>,
}

/// A stored rule set
#[derive(Debug, Clone)]
pub struct StoredRules {
    /// Database ID
    pub id: i64,
    /// Rule set name
    pub name: String,
    /// Rule source code
    pub source: String,
    /// Number of rules
    pub rule_count: i64,
    /// Number of patterns
    pub pattern_count: i64,
    /// Creation timestamp
    pub created_at: String,
    /// Last update timestamp
    pub updated_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = Database::open_memory().unwrap();
        let stats = db.get_statistics().unwrap();
        assert_eq!(stats.total_scans, 0);
    }

    #[test]
    fn test_store_and_retrieve_scan() {
        let db = Database::open_memory().unwrap();

        let record = ScanRecord {
            file_hash: "abc123def456".to_string(),
            file_path: Some("/test/file.exe".to_string()),
            file_size: Some(1024),
            file_type: Some("PE".to_string()),
            rule_count: Some(10),
            matches: vec![
                MatchInfo {
                    rule_name: "TestMalware".to_string(),
                    tags: vec!["malware".to_string()],
                    strings: vec![
                        StringMatchInfo {
                            identifier: "$a".to_string(),
                            offsets: vec![0, 100, 200],
                        }
                    ],
                    ..Default::default()
                }
            ],
            ..Default::default()
        };

        let scan_id = db.store_scan(&record).unwrap();
        assert!(scan_id > 0);

        let found = db.find_by_hash("abc123def456").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file_path, Some("/test/file.exe".to_string()));
    }

    #[test]
    fn test_find_by_rule() {
        let db = Database::open_memory().unwrap();

        let record = ScanRecord {
            file_hash: "hash1".to_string(),
            matches: vec![
                MatchInfo {
                    rule_name: "MalwareRule".to_string(),
                    ..Default::default()
                }
            ],
            ..Default::default()
        };

        db.store_scan(&record).unwrap();

        let found = db.find_by_rule("MalwareRule").unwrap();
        assert_eq!(found.len(), 1);

        let not_found = db.find_by_rule("NonExistentRule").unwrap();
        assert!(not_found.is_empty());
    }

    #[test]
    fn test_statistics_update() {
        let db = Database::open_memory().unwrap();

        // Store multiple scans
        for i in 0..5 {
            let record = ScanRecord {
                file_hash: format!("hash{}", i),
                file_size: Some(1000),
                matches: vec![MatchInfo::default()],
                ..Default::default()
            };
            db.store_scan(&record).unwrap();
        }

        let stats = db.get_statistics().unwrap();
        assert_eq!(stats.total_scans, 5);
        assert_eq!(stats.total_files_scanned, 5);
        assert_eq!(stats.total_bytes_scanned, 5000);
        assert_eq!(stats.total_matches, 5);
    }

    #[test]
    fn test_rules_storage() {
        let db = Database::open_memory().unwrap();

        let source = "rule Test { condition: true }";
        db.store_rules("test_rules", source, 1, 0).unwrap();

        let rules = db.get_rules("test_rules").unwrap();
        assert!(rules.is_some());
        let rules = rules.unwrap();
        assert_eq!(rules.name, "test_rules");
        assert_eq!(rules.rule_count, 1);
    }

    #[test]
    fn test_recent_scans() {
        let db = Database::open_memory().unwrap();

        for i in 0..10 {
            let record = ScanRecord {
                file_hash: format!("hash{}", i),
                ..Default::default()
            };
            db.store_scan(&record).unwrap();
        }

        let recent = db.get_recent_scans(5).unwrap();
        assert_eq!(recent.len(), 5);
    }
}
