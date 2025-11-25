/// Binary to export R-YARA dictionary from redb to JSON

use r_yara_store::CryptexStore;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "r-yara-export", about = "Export R-YARA dictionary from redb to JSON")]
struct Opt {
    /// Path to redb database file
    #[structopt(short, long, parse(from_os_str), default_value = "cryptex.db")]
    database: PathBuf,

    /// Output JSON file path
    #[structopt(short, long, parse(from_os_str), default_value = "cryptex_export.json")]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();

    println!("Exporting R-YARA dictionary...");
    println!("Database: {:?}", opt.database);
    println!("Output: {:?}", opt.output);

    // Open store
    let store = CryptexStore::open(opt.database.to_str().unwrap())?;

    // Get all entries
    println!("Reading entries from database...");
    let entries = store.get_all_entries()?;
    
    println!("Found {} entries", entries.len());

    // Create export structure
    let export_data = serde_json::json!({
        "metadata": {
            "export_date": chrono::Utc::now().to_rfc3339(),
            "total_entries": entries.len(),
            "source": "redb database"
        },
        "entries": entries
    });

    // Write to file
    let json = serde_json::to_string_pretty(&export_data)?;
    fs::write(&opt.output, json)?;
    
    println!("Successfully exported {} entries to {:?}", entries.len(), opt.output);

    // Show statistics
    let stats = store.get_statistics()?;
    println!("\nStatistics:");
    println!("  Total entries: {}", stats.total_entries);
    println!("  Functions: {}", stats.functions);
    println!("  CLI tools: {}", stats.cli_tools);
    println!("  Modules: {}", stats.modules);

    Ok(())
}

