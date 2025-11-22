/// Enhanced CLI for YARA Feed Scanner with better output formatting

use anyhow::Result;
use clap::{Parser, Subcommand};
use yara_feed_scanner::{DiscoveredRule, FeedScanner};
use std::fs;
use std::io::Write;

#[derive(Parser)]
#[command(name = "yara-feed-scanner")]
#[command(about = "Scan web feeds for latest YARA rules", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan all sources
    Scan {
        /// Output file for discovered rules
        #[arg(short, long)]
        output: Option<String>,
        
        /// Limit number of rules
        #[arg(short, long)]
        limit: Option<usize>,
    },
    /// Scan for new tasks
    NewTasks {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Scan for old tasks
    OldTasks {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Scan for malware detection
    Malware {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Scan for APT detection
    Apt {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Scan for ransomware detection
    Ransomware {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// List available sources
    ListSources {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },
    /// Test connection to sources
    Test {
        /// Test specific source by name
        #[arg(short, long)]
        source: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let scanner = FeedScanner::new();

    match cli.command {
        Commands::Scan { output, limit } => {
            println!("🔍 Scanning all sources for YARA rules...");
            let mut rules = scanner.scan_all().await?;
            
            if let Some(limit) = limit {
                rules.truncate(limit);
            }
            
            handle_rules(rules, output, cli.verbose).await?;
        }
        Commands::NewTasks { output } => {
            println!("🆕 Scanning for new task rules...");
            let rules = scanner.scan_for_new_tasks().await?;
            handle_rules(rules, output, cli.verbose).await?;
        }
        Commands::OldTasks { output } => {
            println!("📜 Scanning for old task rules...");
            let rules = scanner.scan_for_old_tasks().await?;
            handle_rules(rules, output, cli.verbose).await?;
        }
        Commands::Malware { output } => {
            println!("🦠 Scanning for malware detection rules...");
            let rules = scanner.scan_for_malware_detection().await?;
            handle_rules(rules, output, cli.verbose).await?;
        }
        Commands::Apt { output } => {
            println!("🎯 Scanning for APT detection rules...");
            let rules = scanner.scan_for_apt_detection().await?;
            handle_rules(rules, output, cli.verbose).await?;
        }
        Commands::Ransomware { output } => {
            println!("🔒 Scanning for ransomware detection rules...");
            let rules = scanner.scan_for_ransomware_detection().await?;
            handle_rules(rules, output, cli.verbose).await?;
        }
        Commands::ListSources { detailed } => {
            println!("📋 Available YARA rule sources:\n");
            for (i, source) in scanner.sources.iter().enumerate() {
                println!("{}. {}", i + 1, source.name);
                if detailed {
                    println!("   URL: {}", source.url);
                    println!("   Type: {:?}", source.feed_type);
                    println!("   Enabled: {}", source.enabled);
                    println!("   Description: {}", source.description);
                    if let Some(last_checked) = source.last_checked {
                        println!("   Last checked: {}", last_checked);
                    }
                    println!();
                }
            }
        }
        Commands::Test { source } => {
            if let Some(source_name) = source {
                println!("🧪 Testing source: {}", source_name);
                if let Some(src) = scanner.sources.iter().find(|s| s.name == source_name) {
                    match scanner.scan_source(src).await {
                        Ok(rules) => {
                            println!("✅ Success! Found {} rules", rules.len());
                            for rule in rules.iter().take(5) {
                                println!("   - {}", rule.name);
                            }
                        }
                        Err(e) => {
                            println!("❌ Error: {}", e);
                        }
                    }
                } else {
                    println!("❌ Source not found: {}", source_name);
                }
            } else {
                println!("🧪 Testing all sources...");
                for src in &scanner.sources {
                    if src.enabled {
                        print!("Testing {}... ", src.name);
                        std::io::stdout().flush()?;
                        match scanner.scan_source(src).await {
                            Ok(rules) => {
                                println!("✅ {} rules", rules.len());
                            }
                            Err(e) => {
                                println!("❌ {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_rules(rules: Vec<DiscoveredRule>, output: Option<String>, verbose: bool) -> Result<()> {
    println!("\n📊 Discovered {} YARA rules\n", rules.len());

    if verbose {
        for (i, rule) in rules.iter().enumerate() {
            println!("{}. {}", i + 1, rule.name);
            println!("   Source: {}", rule.source);
            println!("   URL: {}", rule.url);
            println!("   Discovered: {}", rule.discovered_at);
            if !rule.metadata.tags.is_empty() {
                println!("   Tags: {}", rule.metadata.tags.join(", "));
            }
            println!();
        }
    } else {
        for rule in &rules {
            println!("  ✓ {} from {}", rule.name, rule.source);
        }
    }

    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&rules)?;
        fs::write(&output_path, json)?;
        println!("\n💾 Saved {} rules to {}", rules.len(), output_path);
    }

    Ok(())
}

