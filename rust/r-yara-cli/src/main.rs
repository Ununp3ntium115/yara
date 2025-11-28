/// R-YARA CLI - Complete self-sustaining application
/// Provides command-line interface for all R-YARA operations

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod scan;
mod compile;
mod check;
mod info;
mod dict;
mod feed;
mod server;
mod output;

use anyhow::Result;

#[derive(Parser)]
#[command(name = "r-yara")]
#[command(about = "R-YARA - Rust YARA Pattern Matching CLI", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories with YARA rules
    Scan {
        /// YARA rules file or directory
        rules: PathBuf,

        /// Target file or directory to scan
        target: PathBuf,

        /// Scan directories recursively
        #[arg(short, long)]
        recursive: bool,

        /// Number of threads to use
        #[arg(short, long, default_value_t = num_cpus::get())]
        threads: usize,

        /// Output format: text, json, csv
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Maximum matches per rule (0 = unlimited)
        #[arg(short, long, default_value_t = 0)]
        max_matches: usize,

        /// Scan timeout in seconds (0 = no timeout)
        #[arg(long, default_value_t = 0)]
        timeout: u64,

        /// Only print matching files
        #[arg(short = 'n', long)]
        negate: bool,

        /// Print matching strings
        #[arg(short = 's', long)]
        print_strings: bool,

        /// Print string length
        #[arg(short = 'l', long)]
        print_string_length: bool,

        /// Print tags
        #[arg(short = 'g', long)]
        print_tags: bool,

        /// Print metadata
        #[arg(short = 'e', long)]
        print_meta: bool,

        /// Fast matching mode (scan only)
        #[arg(short, long)]
        fast_scan: bool,
    },

    /// Compile YARA rules to binary format
    Compile {
        /// YARA rules file or directory
        rules: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Check and validate YARA rules
    Check {
        /// YARA rules file or directory
        rules: PathBuf,

        /// Show warnings
        #[arg(short, long)]
        warnings: bool,

        /// Detailed output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show file information (hashes, entropy, file type)
    Info {
        /// File to analyze
        file: PathBuf,

        /// Show detailed PE information
        #[arg(long)]
        pe: bool,

        /// Show detailed ELF information
        #[arg(long)]
        elf: bool,

        /// Show detailed Mach-O information
        #[arg(long)]
        macho: bool,

        /// Show detailed DEX information
        #[arg(long)]
        dex: bool,

        /// Calculate all hashes
        #[arg(long)]
        hashes: bool,
    },

    /// Dictionary operations
    Dict {
        #[command(subcommand)]
        cmd: DictCommands,

        /// Database path
        #[arg(short, long, default_value = "cryptex.db")]
        database: PathBuf,
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
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            rules,
            target,
            recursive,
            threads,
            output,
            max_matches,
            timeout,
            negate,
            print_strings,
            print_string_length,
            print_tags,
            print_meta,
            fast_scan,
        } => {
            scan::scan(scan::ScanOptions {
                rules_path: rules,
                target_path: target,
                recursive,
                threads,
                output_format: output,
                max_matches,
                timeout,
                negate,
                print_strings,
                print_string_length,
                print_tags,
                print_meta,
                fast_scan,
            })?;
        }

        Commands::Compile { rules, output } => {
            compile::compile(rules, output)?;
        }

        Commands::Check { rules, warnings, verbose } => {
            check::check(rules, warnings, verbose)?;
        }

        Commands::Info {
            file,
            pe,
            elf,
            macho,
            dex,
            hashes,
        } => {
            info::show_info(info::InfoOptions {
                file_path: file,
                show_pe: pe,
                show_elf: elf,
                show_macho: macho,
                show_dex: dex,
                show_hashes: hashes,
            })?;
        }

        Commands::Dict { cmd, database } => {
            dict::handle_dict_command(cmd, database)?;
        }

        Commands::Feed { cmd } => {
            feed::handle_feed_command(cmd).await?;
        }

        Commands::Server { port, host } => {
            server::run_server(host, port).await?;
        }
    }

    Ok(())
}
