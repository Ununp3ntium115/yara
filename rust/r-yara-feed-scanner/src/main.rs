/// YARA Feed Scanner CLI
/// Scans web feeds for latest YARA rules

use anyhow::Result;
use clap::{Parser, Subcommand};
use yara_feed_scanner::{DiscoveredRule, FeedScanner, YaraRuleSource};
use std::fs;

#[derive(Parser)]
#[command(name = "yara-feed-scanner")]
#[command(about = "Scan web feeds for latest YARA rules")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan all sources
    Scan {
        /// Output file for discovered rules
        #[arg(short, long)]
        output: Option<String>,
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
    ListSources,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let scanner = FeedScanner::new();

    match cli.command {
        Commands::Scan { output } => {
            println!("Scanning all sources for YARA rules...");
            let rules = scanner.scan_all().await?;
            handle_rules(rules, output).await?;
        }
        Commands::NewTasks { output } => {
            println!("Scanning for new task rules...");
            let rules = scanner.scan_for_new_tasks().await?;
            handle_rules(rules, output).await?;
        }
        Commands::OldTasks { output } => {
            println!("Scanning for old task rules...");
            let rules = scanner.scan_for_old_tasks().await?;
            handle_rules(rules, output).await?;
        }
        Commands::Malware { output } => {
            println!("Scanning for malware detection rules...");
            let rules = scanner.scan_for_malware_detection().await?;
            handle_rules(rules, output).await?;
        }
        Commands::Apt { output } => {
            println!("Scanning for APT detection rules...");
            let rules = scanner.scan_for_apt_detection().await?;
            handle_rules(rules, output).await?;
        }
        Commands::Ransomware { output } => {
            println!("Scanning for ransomware detection rules...");
            let rules = scanner.scan_for_ransomware_detection().await?;
            handle_rules(rules, output).await?;
        }
        Commands::ListSources => {
            println!("Available YARA rule sources:");
            for source in scanner.sources.iter() {
                println!("  - {} ({})", source.name, source.url);
            }
        }
    }

    Ok(())
}

async fn handle_rules(rules: Vec<DiscoveredRule>, output: Option<String>) -> Result<()> {
    println!("Discovered {} YARA rules", rules.len());

    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&rules)?;
        fs::write(&output_path, json)?;
        println!("Saved to {}", output_path);
    } else {
        for rule in &rules {
            println!("  - {} from {}", rule.name, rule.source);
        }
    }

    Ok(())
}

