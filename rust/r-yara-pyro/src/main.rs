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
    FmtSubscriber::builder()
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
            let worker_id = id.unwrap_or_else(|| worker.worker_id().to_string());
            info!("Scanner worker {} started", worker_id);

            if connect {
                info!("Connecting to PYRO Platform...");
                let capabilities = worker.capabilities();
                let (pyro_conn, mut task_rx) = r_yara_pyro::pyro_connection::PyroConnectionBuilder::new()
                    .config(config.clone())
                    .worker_id(worker_id.clone())
                    .worker_type("scanner".to_string())
                    .capabilities(capabilities)
                    .build()?;

                // Attempt connection
                if let Err(e) = pyro_conn.connect().await {
                    tracing::warn!("Failed to connect to PYRO Platform: {} - running standalone", e);
                } else {
                    // Spawn connection loop
                    tokio::spawn(async move {
                        pyro_conn.run().await;
                    });

                    // Process incoming tasks
                    tokio::spawn(async move {
                        while let Some(task) = task_rx.recv().await {
                            let result = worker.process_task(task).await;
                            tracing::debug!("Task completed: {:?}", result.success);
                        }
                    });
                }
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
            let worker_id = id.unwrap_or_else(|| worker.worker_id().to_string());
            info!("Transcoder worker {} started", worker_id);

            if connect {
                info!("Connecting to PYRO Platform...");
                let capabilities = worker.capabilities();
                let (pyro_conn, mut task_rx) = r_yara_pyro::pyro_connection::PyroConnectionBuilder::new()
                    .config(config.clone())
                    .worker_id(worker_id.clone())
                    .worker_type("transcoder".to_string())
                    .capabilities(capabilities)
                    .build()?;

                // Attempt connection
                if let Err(e) = pyro_conn.connect().await {
                    tracing::warn!("Failed to connect to PYRO Platform: {} - running standalone", e);
                } else {
                    // Spawn connection loop
                    tokio::spawn(async move {
                        pyro_conn.run().await;
                    });

                    // Process incoming tasks
                    tokio::spawn(async move {
                        while let Some(task) = task_rx.recv().await {
                            let result = worker.process_task(task).await;
                            tracing::debug!("Task completed: {:?}", result.success);
                        }
                    });
                }
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
    println!("PYRO Fire Hydrant API");
    println!("=====================");
    println!("Version: {}", r_yara_pyro::VERSION);
    println!("Component: {}", r_yara_pyro::PYRO_COMPONENT);
    println!();
    println!("The Fire Hydrant - High-pressure YARA scanning powered by R-YARA");
    println!();
    println!("Features:");
    println!("  - Unified YARA scanning with r-yara-scanner");
    println!("  - File and data scanning");
    println!("  - Batch scanning and directory scanning");
    println!("  - Rule management and compilation");
    println!("  - Module introspection (PE, ELF, Hash, Math, etc.)");
    println!("  - Codename transcoding (encode/decode)");
    println!("  - Dictionary lookup and search");
    println!("  - Feed scanning integration");
    println!("  - Worker task distribution");
    println!("  - API gateway with load balancing");
    println!();
    println!("API Endpoints:");
    println!("  /api/v2/r-yara/health                - Health check");
    println!("  /api/v2/r-yara/scan/file             - Scan single file");
    println!("  /api/v2/r-yara/scan/data             - Scan raw data");
    println!("  /api/v2/r-yara/scan/batch            - Scan multiple files");
    println!("  /api/v2/r-yara/scan/directory        - Scan directory");
    println!("  /api/v2/r-yara/modules               - List available modules");
    println!("  /api/v2/r-yara/rules                 - List loaded rules");
    println!("  /api/v2/r-yara/rules/load            - Load rules");
    println!("  /api/v2/r-yara/rules/validate        - Validate rule");
    println!("  /api/v2/r-yara/rules/compile         - Compile rules");
    println!("  /api/v2/r-yara/transcode/encode      - Encode rule");
    println!("  /api/v2/r-yara/transcode/decode      - Decode rule");
    println!("  /api/v2/r-yara/dictionary/*          - Dictionary ops");
    println!("  /api/v2/r-yara/stats                 - Statistics");
    println!();
    println!("Usage:");
    println!("  r-yara-pyro server              - Start Fire Hydrant API server");
    println!("  r-yara-pyro worker -t scanner   - Run scanner worker");
    println!("  r-yara-pyro gateway             - Start gateway");
    println!("  r-yara-pyro config --generate   - Generate config");
}
