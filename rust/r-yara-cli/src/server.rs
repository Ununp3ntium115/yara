use anyhow::Result;

pub async fn run_server(host: String, port: u16) -> Result<()> {
    println!("Starting R-YARA API server on {}:{}", host, port);
    println!("Press Ctrl+C to stop");

    // TODO: Integrate r-yara-api server here when available
    // For now, just wait for ctrl-c
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");

    Ok(())
}
