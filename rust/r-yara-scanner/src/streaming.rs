//! Streaming Scan API
//!
//! Real-time streaming of scan results via channels and async iterators.
//!
//! # Architecture
//!
//! The streaming API provides:
//! - Async scan operations that yield results as they're found
//! - Progress callbacks during scanning
//! - Cancellation support via tokens
//! - Batch streaming for large directory scans
//!
//! # Example
//!
//! ```no_run
//! use r_yara_scanner::streaming::{StreamingScanner, ScanEvent};
//! use tokio::sync::mpsc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let (tx, mut rx) = mpsc::channel(100);
//!     let scanner = StreamingScanner::new(rules);
//!
//!     // Start streaming scan
//!     scanner.scan_directory_stream("/path/to/files", tx).await;
//!
//!     // Process events as they arrive
//!     while let Some(event) = rx.recv().await {
//!         match event {
//!             ScanEvent::FileStart { path } => println!("Scanning: {}", path),
//!             ScanEvent::Match { path, rule } => println!("Match: {} in {}", rule, path),
//!             ScanEvent::FileComplete { path, matches } => println!("Done: {} ({} matches)", path, matches),
//!             ScanEvent::Error { path, error } => eprintln!("Error: {}: {}", path, error),
//!             ScanEvent::Complete { total, matched } => println!("Finished: {} files, {} with matches", total, matched),
//!         }
//!     }
//! }
//! ```

use crate::error::{ScanError, ScanResult};
use crate::{RuleMatch, Scanner};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

/// Events emitted during streaming scans
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Scan started
    Started {
        /// Total files to scan (if known)
        total_files: Option<usize>,
    },

    /// Started scanning a file
    FileStart {
        /// File path
        path: PathBuf,
        /// File size
        size: Option<u64>,
    },

    /// A rule matched
    Match {
        /// File path
        path: PathBuf,
        /// Rule name
        rule: String,
        /// Rule tags
        tags: Vec<String>,
    },

    /// Finished scanning a file
    FileComplete {
        /// File path
        path: PathBuf,
        /// Number of matches
        matches: usize,
        /// Scan duration in milliseconds
        duration_ms: u64,
    },

    /// Error scanning a file
    Error {
        /// File path
        path: PathBuf,
        /// Error message
        error: String,
    },

    /// Progress update
    Progress {
        /// Files scanned so far
        scanned: usize,
        /// Total files
        total: usize,
        /// Files with matches
        matched: usize,
    },

    /// Scan completed
    Complete {
        /// Total files scanned
        total: usize,
        /// Files with matches
        matched: usize,
        /// Total duration in milliseconds
        duration_ms: u64,
    },
}

/// Cancellation token for stopping scans
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a new cancellation token
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cancel the operation
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress tracking for streaming scans
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Files scanned
    pub scanned: AtomicUsize,
    /// Files with matches
    pub matched: AtomicUsize,
    /// Total files (if known)
    pub total: Option<usize>,
}

impl ScanProgress {
    /// Create new progress tracker
    pub fn new(total: Option<usize>) -> Self {
        Self {
            scanned: AtomicUsize::new(0),
            matched: AtomicUsize::new(0),
            total,
        }
    }

    /// Increment scanned count
    pub fn increment_scanned(&self) {
        self.scanned.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment matched count
    pub fn increment_matched(&self) {
        self.matched.fetch_add(1, Ordering::SeqCst);
    }

    /// Get current scanned count
    pub fn get_scanned(&self) -> usize {
        self.scanned.load(Ordering::SeqCst)
    }

    /// Get current matched count
    pub fn get_matched(&self) -> usize {
        self.matched.load(Ordering::SeqCst)
    }

    /// Get progress percentage (0-100)
    pub fn percentage(&self) -> Option<f64> {
        self.total.map(|t| {
            if t == 0 {
                100.0
            } else {
                (self.get_scanned() as f64 / t as f64) * 100.0
            }
        })
    }
}

/// Streaming scanner that emits events during scanning
pub struct StreamingScanner {
    /// Inner scanner
    scanner: Scanner,
    /// Progress update interval (files between updates)
    progress_interval: usize,
}

impl StreamingScanner {
    /// Create a new streaming scanner from rules
    pub fn new(rules: &str) -> ScanResult<Self> {
        let scanner = Scanner::new(rules)?;
        Ok(Self {
            scanner,
            progress_interval: 10,
        })
    }

    /// Create from existing scanner
    pub fn from_scanner(scanner: Scanner) -> Self {
        Self {
            scanner,
            progress_interval: 10,
        }
    }

    /// Set progress update interval
    pub fn with_progress_interval(mut self, interval: usize) -> Self {
        self.progress_interval = interval;
        self
    }

    /// Scan a directory with streaming events
    ///
    /// Events are sent to the provided callback as they occur.
    pub fn scan_directory_with_callback<F>(
        &self,
        path: impl AsRef<Path>,
        recursive: bool,
        token: Option<&CancellationToken>,
        mut callback: F,
    ) -> ScanResult<ScanSummary>
    where
        F: FnMut(ScanEvent),
    {
        let start = std::time::Instant::now();

        // Collect files first to get total count
        let files: Vec<PathBuf> = WalkDir::new(path.as_ref())
            .follow_links(false)
            .max_depth(if recursive { usize::MAX } else { 1 })
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        let total = files.len();
        let progress = ScanProgress::new(Some(total));

        callback(ScanEvent::Started {
            total_files: Some(total),
        });

        let mut all_matches: Vec<(PathBuf, Vec<RuleMatch>)> = Vec::new();

        for file_path in files {
            // Check cancellation
            if let Some(token) = token {
                if token.is_cancelled() {
                    break;
                }
            }

            let file_size = std::fs::metadata(&file_path)
                .ok()
                .map(|m| m.len());

            callback(ScanEvent::FileStart {
                path: file_path.clone(),
                size: file_size,
            });

            let file_start = std::time::Instant::now();

            match self.scanner.scan_file(&file_path) {
                Ok(matches) => {
                    // Emit individual match events
                    for m in &matches {
                        callback(ScanEvent::Match {
                            path: file_path.clone(),
                            rule: m.rule_name.to_string(),
                            tags: m.tags.iter().map(|t| t.to_string()).collect(),
                        });
                    }

                    let match_count = matches.len();

                    if match_count > 0 {
                        progress.increment_matched();
                        all_matches.push((file_path.clone(), matches));
                    }

                    callback(ScanEvent::FileComplete {
                        path: file_path,
                        matches: match_count,
                        duration_ms: file_start.elapsed().as_millis() as u64,
                    });
                }
                Err(e) => {
                    callback(ScanEvent::Error {
                        path: file_path,
                        error: e.to_string(),
                    });
                }
            }

            progress.increment_scanned();

            // Emit progress at intervals
            let scanned = progress.get_scanned();
            if scanned % self.progress_interval == 0 {
                callback(ScanEvent::Progress {
                    scanned,
                    total,
                    matched: progress.get_matched(),
                });
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        callback(ScanEvent::Complete {
            total: progress.get_scanned(),
            matched: progress.get_matched(),
            duration_ms,
        });

        Ok(ScanSummary {
            total_files: progress.get_scanned(),
            files_matched: progress.get_matched(),
            total_matches: all_matches.iter().map(|(_, m)| m.len()).sum(),
            duration_ms,
            matches: all_matches,
        })
    }

    /// Scan bytes with events
    pub fn scan_bytes_with_callback<F>(
        &self,
        data: &[u8],
        identifier: &str,
        mut callback: F,
    ) -> ScanResult<Vec<RuleMatch>>
    where
        F: FnMut(ScanEvent),
    {
        let start = std::time::Instant::now();
        let path = PathBuf::from(identifier);

        callback(ScanEvent::FileStart {
            path: path.clone(),
            size: Some(data.len() as u64),
        });

        let result = self.scanner.scan_bytes(data);

        match &result {
            Ok(matches) => {
                for m in matches {
                    callback(ScanEvent::Match {
                        path: path.clone(),
                        rule: m.rule_name.to_string(),
                        tags: m.tags.iter().map(|t| t.to_string()).collect(),
                    });
                }

                callback(ScanEvent::FileComplete {
                    path,
                    matches: matches.len(),
                    duration_ms: start.elapsed().as_millis() as u64,
                });
            }
            Err(e) => {
                callback(ScanEvent::Error {
                    path,
                    error: e.to_string(),
                });
            }
        }

        result
    }
}

/// Summary of a streaming scan
#[derive(Debug, Clone)]
pub struct ScanSummary {
    /// Total files scanned
    pub total_files: usize,
    /// Files with at least one match
    pub files_matched: usize,
    /// Total number of rule matches
    pub total_matches: usize,
    /// Total duration in milliseconds
    pub duration_ms: u64,
    /// All matches with their file paths
    pub matches: Vec<(PathBuf, Vec<RuleMatch>)>,
}

/// Event collector for testing
#[derive(Debug, Default)]
pub struct EventCollector {
    events: Vec<ScanEvent>,
}

impl EventCollector {
    /// Create a new collector
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Collect an event
    pub fn collect(&mut self, event: ScanEvent) {
        self.events.push(event);
    }

    /// Get collected events
    pub fn events(&self) -> &[ScanEvent] {
        &self.events
    }

    /// Get number of events
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Count events of a specific type
    pub fn count_matches(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Match { .. }))
            .count()
    }

    /// Count errors
    pub fn count_errors(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Error { .. }))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_scanner() -> StreamingScanner {
        let rules = r#"
            rule TestRule {
                strings:
                    $a = "malware"
                condition:
                    $a
            }
        "#;
        StreamingScanner::new(rules).unwrap()
    }

    #[test]
    fn test_scan_bytes_streaming() {
        let scanner = create_test_scanner();
        let mut collector = EventCollector::new();

        let matches = scanner
            .scan_bytes_with_callback(b"this contains malware", "test.bin", |e| {
                collector.collect(e)
            })
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert!(collector.len() >= 2); // At least FileStart and FileComplete
        assert_eq!(collector.count_matches(), 1);
    }

    #[test]
    fn test_scan_directory_streaming() {
        let temp_dir = TempDir::new().unwrap();

        // Create test files
        fs::write(temp_dir.path().join("clean.txt"), "clean file").unwrap();
        fs::write(temp_dir.path().join("infected.txt"), "contains malware").unwrap();

        let scanner = create_test_scanner();
        let mut collector = EventCollector::new();

        let summary = scanner
            .scan_directory_with_callback(temp_dir.path(), false, None, |e| {
                collector.collect(e)
            })
            .unwrap();

        assert_eq!(summary.total_files, 2);
        assert_eq!(summary.files_matched, 1);
        assert_eq!(collector.count_matches(), 1);
    }

    #[test]
    fn test_cancellation() {
        let temp_dir = TempDir::new().unwrap();

        // Create many files
        for i in 0..100 {
            fs::write(temp_dir.path().join(format!("file{}.txt", i)), "test").unwrap();
        }

        let scanner = create_test_scanner();
        let token = CancellationToken::new();
        let mut scanned = 0;

        // Cancel after 5 files
        let summary = scanner
            .scan_directory_with_callback(temp_dir.path(), false, Some(&token), |e| {
                if let ScanEvent::FileComplete { .. } = e {
                    scanned += 1;
                    if scanned >= 5 {
                        token.cancel();
                    }
                }
            })
            .unwrap();

        assert!(summary.total_files < 100);
    }

    #[test]
    fn test_progress_tracking() {
        let progress = ScanProgress::new(Some(100));

        assert_eq!(progress.get_scanned(), 0);
        assert_eq!(progress.percentage(), Some(0.0));

        progress.increment_scanned();
        progress.increment_scanned();
        assert_eq!(progress.get_scanned(), 2);
        assert_eq!(progress.percentage(), Some(2.0));

        progress.increment_matched();
        assert_eq!(progress.get_matched(), 1);
    }
}
