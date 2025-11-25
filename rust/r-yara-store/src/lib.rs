/// YARA Cryptex Dictionary Store with redb
/// Provides persistent storage for Cryptex dictionary entries

use redb::{CommitError, Database, DatabaseError, ReadableTable, StorageError, TableDefinition, TableError, TransactionError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// Table definitions for redb
/// Store entries as JSON strings for flexibility
const SYMBOL_TO_CODENAME: TableDefinition<&str, &str> = TableDefinition::new("symbol_to_codename");
const CODENAME_TO_ENTRY: TableDefinition<&str, &str> = TableDefinition::new("codename_to_entry");
const ENTRIES_BY_KIND: TableDefinition<(&str, &str), &str> = TableDefinition::new("entries_by_kind");

/// Cryptex dictionary entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptexEntry {
    pub symbol: String,
    pub pyro_name: String,
    pub kind: String,
    pub location: String,
    pub signature: String,
    pub summary: String,
    pub pseudocode: String,
    pub line_references: Vec<LineReference>,
    pub dependencies: Vec<String>,
    pub owner: String,
    pub risk: String,
    pub notes: Vec<String>,
}

/// Line reference for source code locations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineReference {
    pub file: String,
    pub start: u32,
    pub end: u32,
}

/// Errors for Cryptex store operations
#[derive(Error, Debug)]
pub enum CryptexStoreError {
    #[error("Database error: {0}")]
    Database(#[from] redb::Error),
    #[error("Database creation/opening error: {0}")]
    DatabaseError(#[from] DatabaseError),
    #[error("Table error: {0}")]
    Table(#[from] TableError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Commit error: {0}")]
    Commit(#[from] CommitError),
    #[error("Transaction error: {0}")]
    Transaction(#[from] TransactionError),
    #[error("Entry not found: {0}")]
    NotFound(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Cryptex dictionary store backed by redb
pub struct CryptexStore {
    db: Arc<Database>,
}

impl CryptexStore {
    /// Create a new Cryptex store
    pub fn new(db_path: &str) -> Result<Self, CryptexStoreError> {
        let db = Database::create(db_path)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Open an existing Cryptex store
    pub fn open(db_path: &str) -> Result<Self, CryptexStoreError> {
        let db = Database::open(db_path)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Initialize the database schema
    pub fn initialize(&self) -> Result<(), CryptexStoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let _symbol_table = write_txn.open_table(SYMBOL_TO_CODENAME)?;
            let _entry_table = write_txn.open_table(CODENAME_TO_ENTRY)?;
            let _kind_table = write_txn.open_table(ENTRIES_BY_KIND)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Add or update a Cryptex entry
    pub fn upsert_entry(&self, entry: CryptexEntry) -> Result<(), CryptexStoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut symbol_table = write_txn.open_table(SYMBOL_TO_CODENAME)?;
            let mut entry_table = write_txn.open_table(CODENAME_TO_ENTRY)?;
            let mut kind_table = write_txn.open_table(ENTRIES_BY_KIND)?;

            // Store symbol -> codename mapping
            symbol_table.insert(entry.symbol.as_str(), entry.pyro_name.as_str())?;

            // Store codename -> entry mapping (as JSON string)
            let entry_json = serde_json::to_string(&entry)?;
            entry_table.insert(entry.pyro_name.as_str(), entry_json.as_str())?;

            // Index by kind
            kind_table.insert((entry.kind.as_str(), entry.symbol.as_str()), entry.pyro_name.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Lookup entry by symbol
    pub fn lookup_by_symbol(&self, symbol: &str) -> Result<Option<CryptexEntry>, CryptexStoreError> {
        let read_txn = self.db.begin_read()?;
        let symbol_table = read_txn.open_table(SYMBOL_TO_CODENAME)?;
        let entry_table = read_txn.open_table(CODENAME_TO_ENTRY)?;

        if let Some(codename) = symbol_table.get(symbol)? {
            let codename_str = codename.value();
            if let Some(entry_json) = entry_table.get(codename_str)? {
                let entry: CryptexEntry = serde_json::from_str(entry_json.value())?;
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    /// Lookup entry by codename
    pub fn lookup_by_codename(&self, codename: &str) -> Result<Option<CryptexEntry>, CryptexStoreError> {
        let read_txn = self.db.begin_read()?;
        let entry_table = read_txn.open_table(CODENAME_TO_ENTRY)?;

        if let Some(entry_json) = entry_table.get(codename)? {
            let entry: CryptexEntry = serde_json::from_str(entry_json.value())?;
            return Ok(Some(entry));
        }
        Ok(None)
    }

    /// Get all entries
    pub fn get_all_entries(&self) -> Result<Vec<CryptexEntry>, CryptexStoreError> {
        let read_txn = self.db.begin_read()?;
        let entry_table = read_txn.open_table(CODENAME_TO_ENTRY)?;

        let mut entries = Vec::new();
        for item in entry_table.iter()? {
            let (_codename, entry_json) = item?;
            let entry: CryptexEntry = serde_json::from_str(entry_json.value())?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Get entries by kind
    pub fn get_entries_by_kind(&self, kind: &str) -> Result<Vec<CryptexEntry>, CryptexStoreError> {
        let read_txn = self.db.begin_read()?;
        let kind_table = read_txn.open_table(ENTRIES_BY_KIND)?;
        let entry_table = read_txn.open_table(CODENAME_TO_ENTRY)?;

        let mut entries = Vec::new();
        let range = (kind, "")..=(kind, "\u{10FFFF}");
        for item in kind_table.range(range)? {
            let (key, codename) = item?;
            let (_kind, _symbol) = key.value();
            if let Some(entry_json) = entry_table.get(codename.value())? {
                let entry: CryptexEntry = serde_json::from_str(entry_json.value())?;
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Search entries
    pub fn search_entries(&self, query: &str) -> Result<Vec<CryptexEntry>, CryptexStoreError> {
        let all_entries = self.get_all_entries()?;
        let query_lower = query.to_lowercase();
        
        let results: Vec<CryptexEntry> = all_entries
            .into_iter()
            .filter(|entry| {
                entry.symbol.to_lowercase().contains(&query_lower) ||
                entry.pyro_name.to_lowercase().contains(&query_lower) ||
                entry.summary.to_lowercase().contains(&query_lower) ||
                entry.signature.to_lowercase().contains(&query_lower)
            })
            .collect();
        
        Ok(results)
    }

    /// Get statistics
    pub fn get_statistics(&self) -> Result<CryptexStatistics, CryptexStoreError> {
        let entries = self.get_all_entries()?;
        let total = entries.len();
        let functions = entries.iter().filter(|e| e.kind == "function").count();
        let cli_tools = entries.iter().filter(|e| e.kind == "cli").count();
        let modules = entries.iter().filter(|e| e.kind == "module").count();

        Ok(CryptexStatistics {
            total_entries: total,
            functions,
            cli_tools,
            modules,
        })
    }

    /// Batch import entries from JSON
    pub fn import_from_json(&self, json_data: &str) -> Result<usize, CryptexStoreError> {
        let data: serde_json::Value = serde_json::from_str(json_data)?;
        let entries: Vec<CryptexEntry> = serde_json::from_value(data["entries"].clone())?;
        
        let mut count = 0;
        for entry in entries {
            self.upsert_entry(entry)?;
            count += 1;
        }
        Ok(count)
    }
}

/// Statistics about the Cryptex dictionary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptexStatistics {
    pub total_entries: usize,
    pub functions: usize,
    pub cli_tools: usize,
    pub modules: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_store_operations() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        
        let store = CryptexStore::new(db_path.to_str().unwrap()).unwrap();
        store.initialize().unwrap();

        let entry = CryptexEntry {
            symbol: "yr_initialize".to_string(),
            pyro_name: "BlackFlag-Bootstrap-Initialize".to_string(),
            kind: "function".to_string(),
            location: "libyara/libyara.c".to_string(),
            signature: "YR_API int yr_initialize(void);".to_string(),
            summary: "Initializes libyara".to_string(),
            pseudocode: "function yr_initialize():\n    init_arenas()\n    return success".to_string(),
            line_references: vec![],
            dependencies: vec![],
            owner: "libyara/core".to_string(),
            risk: "critical".to_string(),
            notes: vec![],
        };

        store.upsert_entry(entry.clone()).unwrap();
        
        let found = store.lookup_by_symbol("yr_initialize").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().pyro_name, "BlackFlag-Bootstrap-Initialize");

        let found_by_codename = store.lookup_by_codename("BlackFlag-Bootstrap-Initialize").unwrap();
        assert!(found_by_codename.is_some());
    }
}

