use anyhow::Result;
use r_yara_feed_scanner::FeedScanner;

pub async fn handle_feed_command(cmd: crate::FeedCommands) -> Result<()> {
    let scanner = FeedScanner::new();

    match cmd {
        crate::FeedCommands::Scan { use_case, output } => {
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
        crate::FeedCommands::List => {
            println!("Available sources:");
            for source in &scanner.sources {
                println!("  - {} ({})", source.name, source.url);
            }
        }
    }

    Ok(())
}
