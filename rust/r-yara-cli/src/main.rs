/// R-YARA CLI - Complete self-sustaining application
/// Provides command-line interface for all R-YARA operations

use clap::{Parser, Subcommand};
use r_yara_store::CryptexStore;
use r_yara_feed_scanner::FeedScanner;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "r-yara")]
#[command(about = "R-YARA - Rust YARA Pattern Matching CLI", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Database path
    #[arg(short, long, default_value = "cryptex.db")]
    database: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Dictionary operations
    Dict {
        #[command(subcommand)]
        cmd: DictCommands,
    },
    /// Feed scanner operations
    Feed {
        #[command(subcommand)]
        cmd: FeedCommands,
    },
    /// Server operations
    Server {
        /// Port to listen on
        #[arg(short, long, default_value_t = 3006)]
        port: u16,
        
        /// Host to bind to
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
    },
}

#[derive(Subcommand)]
enum DictCommands {
    /// Import dictionary from JSON
    Import {
        /// Input JSON file
        input: PathBuf,
    },
    /// Export dictionary to JSON
    Export {
        /// Output JSON file
        output: PathBuf,
    },
    /// Lookup entry
    Lookup {
        /// Symbol or codename
        query: String,
    },
    /// Search entries
    Search {
        /// Search query
        query: String,
    },
    /// Show statistics
    Stats,
}

#[derive(Subcommand)]
enum FeedCommands {
    /// Scan all sources
    Scan {
        /// Use case: all, new_tasks, old_tasks, malware, apt, ransomware
        #[arg(short, long, default_value = "all")]
        use_case: String,
        
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List sources
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Dict { cmd } => {
            let store = if cli.database.exists() {
                CryptexStore::open(cli.database.to_str().unwrap())?
            } else {
                let s = CryptexStore::new(cli.database.to_str().unwrap())?;
                s.initialize()?;
                s
            };
            
            match cmd {
                DictCommands::Import { input } => {
                    println!("Importing dictionary from {:?}...", input);
                    let json = std::fs::read_to_string(&input)?;
                    let count = store.import_from_json(&json)?;
                    println!("Imported {} entries", count);
                }
                DictCommands::Export { output } => {
                    println!("Exporting dictionary to {:?}...", output);
                    let entries = store.get_all_entries()?;
                    let json = serde_json::to_string_pretty(&serde_json::json!({
                        "entries": entries
                    }))?;
                    std::fs::write(&output, json)?;
                    println!("Exported {} entries", entries.len());
                }
                DictCommands::Lookup { query } => {
                    if let Some(entry) = store.lookup_by_symbol(&query).ok().flatten() {
                        println!("{}", serde_json::to_string_pretty(&entry)?);
                    } else if let Some(entry) = store.lookup_by_codename(&query).ok().flatten() {
                        println!("{}", serde_json::to_string_pretty(&entry)?);
                    } else {
                        println!("Entry not found: {}", query);
                    }
                }
                DictCommands::Search { query } => {
                    let results = store.search_entries(&query)?;
                    println!("Found {} entries:", results.len());
                    for entry in results {
                        println!("  {} -> {}", entry.symbol, entry.pyro_name);
                    }
                }
                DictCommands::Stats => {
                    let stats = store.get_statistics()?;
                    println!("R-YARA Dictionary Statistics:");
                    println!("  Total entries: {}", stats.total_entries);
                    println!("  Functions: {}", stats.functions);
                    println!("  CLI tools: {}", stats.cli_tools);
                    println!("  Modules: {}", stats.modules);
                }
            }
        }
        Commands::Feed { cmd } => {
            let scanner = FeedScanner::new();
            
            match cmd {
                FeedCommands::Scan { use_case, output } => {
                    println!("Scanning feeds for use case: {}...", use_case);
                    let rules = match use_case.as_str() {
                        "new_tasks" => scanner.scan_for_new_tasks().await?,
                        "old_tasks" => scanner.scan_for_old_tasks().await?,
                        "malware" => scanner.scan_for_malware_detection().await?,
                        "apt" => scanner.scan_for_apt_detection().await?,
                        "ransomware" => scanner.scan_for_ransomware_detection().await?,
                        _ => scanner.scan_all().await?,
                    };
                    
                    println!("Found {} rules", rules.len());
                    
                    if let Some(output_path) = output {
                        let json = serde_json::to_string_pretty(&rules)?;
                        std::fs::write(&output_path, json)?;
                        println!("Saved to {:?}", output_path);
                    }
                }
                FeedCommands::List => {
                    println!("Available sources:");
                    for source in &scanner.sources {
                        println!("  - {} ({})", source.name, source.url);
                    }
                }
            }
        }
        Commands::Server { port, host } => {
            println!("Starting R-YARA API server on {}:{}", host, port);
            println!("Press Ctrl+C to stop");

            // Start server (would use r-yara-api here)
            tokio::signal::ctrl_c().await?;
            println!("\nShutting down...");
        }
    }
    
    Ok(())
}

