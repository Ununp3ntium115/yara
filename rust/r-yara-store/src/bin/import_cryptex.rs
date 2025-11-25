/// Binary to import R-YARA dictionary into redb

use r_yara_store::{CryptexStore, CryptexStoreError};
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "r-yara-import", about = "Import R-YARA dictionary into redb")]
struct Opt {
    /// Path to JSON dictionary file
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// Path to redb database file
    #[structopt(short, long, parse(from_os_str), default_value = "cryptex.db")]
    database: PathBuf,
}

fn main() -> Result<(), CryptexStoreError> {
    let opt = Opt::from_args();

    println!("Importing R-YARA dictionary...");
    println!("Input: {:?}", opt.input);
    println!("Database: {:?}", opt.database);

    // Read JSON file
    let json_data = fs::read_to_string(&opt.input)
        .map_err(|e| CryptexStoreError::Database(redb::Error::Io(e)))?;

    // Create or open store
    let store = if opt.database.exists() {
        println!("Opening existing database...");
        CryptexStore::open(opt.database.to_str().unwrap())?
    } else {
        println!("Creating new database...");
        let store = CryptexStore::new(opt.database.to_str().unwrap())?;
        store.initialize()?;
        store
    };

    // Import entries
    println!("Importing entries...");
    let count = store.import_from_json(&json_data)?;
    
    println!("Successfully imported {} entries", count);

    // Show statistics
    let stats = store.get_statistics()?;
    println!("\nStatistics:");
    println!("  Total entries: {}", stats.total_entries);
    println!("  Functions: {}", stats.functions);
    println!("  CLI tools: {}", stats.cli_tools);
    println!("  Modules: {}", stats.modules);

    Ok(())
}

