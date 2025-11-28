/// Output formatting utilities for R-YARA CLI
///
/// This module provides common formatting functions for different output formats
/// (text, JSON, CSV) used across various CLI commands.

use serde::Serialize;

/// Format value as human-readable size
pub fn format_size(bytes: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Format duration in human-readable format
pub fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.2}s", secs)
    } else if secs < 3600.0 {
        format!("{:.0}m {:.0}s", secs / 60.0, secs % 60.0)
    } else {
        format!(
            "{:.0}h {:.0}m",
            secs / 3600.0,
            (secs % 3600.0) / 60.0
        )
    }
}

/// Print a table header
pub fn print_table_header(columns: &[&str]) {
    println!("{}", columns.join(" | "));
    println!(
        "{}",
        columns
            .iter()
            .map(|c| "-".repeat(c.len()))
            .collect::<Vec<_>>()
            .join("-+-")
    );
}

/// Serialize to pretty JSON
pub fn to_pretty_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(100), "100 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0.5), "500ms");
        assert_eq!(format_duration(1.5), "1.50s");
        assert_eq!(format_duration(65.0), "1m 5s");
    }
}
