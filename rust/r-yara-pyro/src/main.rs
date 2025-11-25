//! R-YARA PYRO Platform Integration
//!
//! Main binary for running R-YARA API server, workers, and gateway.

use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use r_yara_pyro::{
    api::ApiServer,
    config::RYaraConfig,
    gateway::Gateway,
    workers::{ScannerWorker, TranscoderWorker},
};

#[derive(Parser)]
#[command(name = "r-yara-pyro")]
#[command(about = "R-YARA PYRO Platform Integration", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<String>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the API server
    Server {
        /// Host address to bind
        #[arg(short = 'H', long, default_value = "0.0.0.0")]
        host: String,

        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },

    /// Run a worker
    Worker {
        /// Worker type (scanner, transcoder)
        #[arg(short, long, default_value = "scanner")]
        worker_type: String,

        /// Worker ID (auto-generated if not specified)
        #[arg(short, long)]
        id: Option<String>,

        /// Connect to PYRO Platform
        #[arg(long)]
        connect: bool,
    },

    /// Start the gateway
    Gateway {
        /// Host address to bind
        #[arg(short = 'H', long, default_value = "0.0.0.0")]
        host: String,

        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },

    /// Show configuration
    Config {
        /// Generate default configuration
        #[arg(short, long)]
        generate: bool,

        /// Output file for generated config
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show version and info
    Info,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Load configuration
    let config = if let Some(config_path) = &cli.config {
        RYaraConfig::from_file(config_path)?
    } else {
        RYaraConfig::from_env()
    };

    match cli.command {
        Commands::Server { host, port } => {
            run_server(config, host, port).await?;
        }
        Commands::Worker {
            worker_type,
            id,
            connect,
        } => {
            run_worker(config, worker_type, id, connect).await?;
        }
        Commands::Gateway { host, port } => {
            run_gateway(config, host, port).await?;
        }
        Commands::Config { generate, output } => {
            if generate {
                let config = RYaraConfig::default();
                if let Some(output_path) = output {
                    config.to_file(&output_path)?;
                    println!("Configuration written to {}", output_path);
                } else {
                    println!("{}", serde_json::to_string_pretty(&config)?);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&config)?);
            }
        }
        Commands::Info => {
            print_info();
        }
    }

    Ok(())
}

async fn run_server(
    mut config: RYaraConfig,
    host: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    config.api.host = host;
    config.api.port = port;

    info!("Starting R-YARA API server on {}:{}", config.api.host, config.api.port);

    let server = ApiServer::new(config);

    // Setup graceful shutdown
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
        info!("Received shutdown signal");
    };

    server.run_with_shutdown(shutdown).await?;

    Ok(())
}

async fn run_worker(
    config: RYaraConfig,
    worker_type: String,
    id: Option<String>,
    connect: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting R-YARA {} worker", worker_type);

    match worker_type.as_str() {
        "scanner" => {
            let worker = ScannerWorker::new();
            info!("Scanner worker {} started", worker.worker_id());

            if connect {
                info!("Connecting to PYRO Platform...");
                // TODO: Implement PYRO Platform connection
            }

            // Keep running
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Shutting down scanner worker");
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {}
                }
            }
        }
        "transcoder" => {
            let worker = TranscoderWorker::new();
            info!("Transcoder worker {} started", worker.worker_id());

            if connect {
                info!("Connecting to PYRO Platform...");
                // TODO: Implement PYRO Platform connection
            }

            // Keep running
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Shutting down transcoder worker");
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {}
                }
            }
        }
        _ => {
            return Err(format!("Unknown worker type: {}", worker_type).into());
        }
    }

    Ok(())
}

async fn run_gateway(
    mut config: RYaraConfig,
    host: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    config.api.host = host;
    config.api.port = port;

    info!("Starting R-YARA Gateway on {}:{}", config.api.host, config.api.port);

    let gateway = Gateway::new(config.clone());
    gateway.start().await;

    // Also start the API server for the gateway
    let server = ApiServer::new(config);

    let shutdown = async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
        info!("Received shutdown signal");
        gateway.stop().await;
    };

    server.run_with_shutdown(shutdown).await?;

    Ok(())
}

fn print_info() {
    println!("R-YARA PYRO Platform Integration");
    println!("================================");
    println!("Version: {}", r_yara_pyro::VERSION);
    println!("Component: {}", r_yara_pyro::PYRO_COMPONENT);
    println!();
    println!("Features:");
    println!("  - YARA rule scanning (file and data)");
    println!("  - Rule validation and compilation");
    println!("  - Codename transcoding (encode/decode)");
    println!("  - Dictionary lookup and search");
    println!("  - Feed scanning integration");
    println!("  - Worker task distribution");
    println!("  - API gateway with load balancing");
    println!();
    println!("API Endpoints:");
    println!("  /api/v2/r-yara/health           - Health check");
    println!("  /api/v2/r-yara/scan/file        - Scan file");
    println!("  /api/v2/r-yara/scan/data        - Scan data");
    println!("  /api/v2/r-yara/rules/validate   - Validate rule");
    println!("  /api/v2/r-yara/transcode/encode - Encode rule");
    println!("  /api/v2/r-yara/transcode/decode - Decode rule");
    println!("  /api/v2/r-yara/dictionary/*     - Dictionary ops");
    println!("  /api/v2/r-yara/stats            - Statistics");
    println!();
    println!("Usage:");
    println!("  r-yara-pyro server              - Start API server");
    println!("  r-yara-pyro worker -t scanner   - Run scanner worker");
    println!("  r-yara-pyro gateway             - Start gateway");
    println!("  r-yara-pyro config --generate   - Generate config");
}
