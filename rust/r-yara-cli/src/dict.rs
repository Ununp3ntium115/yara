use anyhow::Result;
use r_yara_store::CryptexStore;
use std::path::PathBuf;

pub fn handle_dict_command(cmd: crate::DictCommands, database: PathBuf) -> Result<()> {
    let store = if database.exists() {
        CryptexStore::open(database.to_str().unwrap())?
    } else {
        let s = CryptexStore::new(database.to_str().unwrap())?;
        s.initialize()?;
        s
    };

    match cmd {
        crate::DictCommands::Import { input } => {
            println!("Importing dictionary from {:?}...", input);
            let json = std::fs::read_to_string(&input)?;
            let count = store.import_from_json(&json)?;
            println!("Imported {} entries", count);
        }
        crate::DictCommands::Export { output } => {
            println!("Exporting dictionary to {:?}...", output);
            let entries = store.get_all_entries()?;
            let json = serde_json::to_string_pretty(&serde_json::json!({
                "entries": entries
            }))?;
            std::fs::write(&output, json)?;
            println!("Exported {} entries", entries.len());
        }
        crate::DictCommands::Lookup { query } => {
            if let Some(entry) = store.lookup_by_symbol(&query).ok().flatten() {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else if let Some(entry) = store.lookup_by_codename(&query).ok().flatten() {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else {
                println!("Entry not found: {}", query);
            }
        }
        crate::DictCommands::Search { query } => {
            let results = store.search_entries(&query)?;
            println!("Found {} entries:", results.len());
            for entry in results {
                println!("  {} -> {}", entry.symbol, entry.pyro_name);
            }
        }
        crate::DictCommands::Stats => {
            let stats = store.get_statistics()?;
            println!("R-YARA Dictionary Statistics:");
            println!("  Total entries: {}", stats.total_entries);
            println!("  Functions: {}", stats.functions);
            println!("  CLI tools: {}", stats.cli_tools);
            println!("  Modules: {}", stats.modules);
        }
    }

    Ok(())
}
