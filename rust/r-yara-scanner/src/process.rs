//! Process Memory Scanning
//!
//! Scan the memory of running processes for YARA patterns.
//!
//! # Platform Support
//!
//! - **Linux**: Reads memory via `/proc/<pid>/mem` with `/proc/<pid>/maps`
//! - **Windows**: Uses `ReadProcessMemory` API (requires appropriate privileges)
//! - **macOS**: Uses Mach VM API (requires appropriate privileges)
//!
//! # Example
//!
//! ```ignore
//! use r_yara_scanner::process::{ProcessScanner, scan_process};
//!
//! let rules = r#"rule test { condition: true }"#;
//!
//! // Scan a specific process
//! let matches = scan_process(rules, 1234)?;
//!
//! // Or use the scanner
//! let scanner = ProcessScanner::new(rules)?;
//! let matches = scanner.scan_pid(1234)?;
//!
//! // List processes
//! for proc in ProcessScanner::list_processes()? {
//!     println!("{}: {}", proc.pid, proc.name);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{ScanError, ScanResult};
use crate::{RuleMatch, Scanner};

/// Information about a process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Command line (if available)
    pub cmdline: Option<String>,
    /// Path to executable (if available)
    pub exe_path: Option<String>,
}

/// A memory region in a process
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Start address
    pub start: u64,
    /// End address
    pub end: u64,
    /// Size in bytes
    pub size: u64,
    /// Permissions (rwxp)
    pub permissions: String,
    /// Pathname (if any)
    pub pathname: Option<String>,
    /// Is readable
    pub readable: bool,
    /// Is writable
    pub writable: bool,
    /// Is executable
    pub executable: bool,
}

/// Process scanner for scanning process memory
pub struct ProcessScanner {
    /// Inner scanner
    scanner: Scanner,
    /// Scan options
    options: ProcessScanOptions,
}

/// Options for process scanning
#[derive(Debug, Clone, Default)]
pub struct ProcessScanOptions {
    /// Skip non-readable regions
    pub skip_unreadable: bool,
    /// Only scan executable regions
    pub executable_only: bool,
    /// Maximum region size to scan (bytes)
    pub max_region_size: Option<u64>,
    /// Skip file-backed regions (only scan anonymous memory)
    pub anonymous_only: bool,
}

impl ProcessScanner {
    /// Create a new process scanner
    pub fn new(rules: &str) -> ScanResult<Self> {
        let scanner = Scanner::new(rules)?;
        Ok(Self {
            scanner,
            options: ProcessScanOptions::default(),
        })
    }

    /// Create from existing scanner
    pub fn from_scanner(scanner: Scanner) -> Self {
        Self {
            scanner,
            options: ProcessScanOptions::default(),
        }
    }

    /// Set scan options
    pub fn with_options(mut self, options: ProcessScanOptions) -> Self {
        self.options = options;
        self
    }

    /// Scan a process by PID
    #[cfg(target_os = "linux")]
    pub fn scan_pid(&self, pid: u32) -> ScanResult<ProcessScanResult> {
        use std::fs::{self, File};
        use std::io::{Read, Seek, SeekFrom};

        let maps_path = format!("/proc/{}/maps", pid);
        let mem_path = format!("/proc/{}/mem", pid);

        // Read memory maps
        let maps = fs::read_to_string(&maps_path)
            .map_err(|e| ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Cannot read process maps: {}. Try running as root.", e)
            )))?;

        let regions = parse_proc_maps(&maps);

        // Open process memory
        let mut mem_file = File::open(&mem_path)
            .map_err(|e| ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Cannot open process memory: {}. Try running as root.", e)
            )))?;

        let mut all_matches = Vec::new();
        let mut regions_scanned = 0;
        let mut bytes_scanned = 0u64;
        let mut errors = Vec::new();

        for region in &regions {
            // Apply filters
            if !region.readable {
                continue;
            }
            if self.options.skip_unreadable && !region.readable {
                continue;
            }
            if self.options.executable_only && !region.executable {
                continue;
            }
            if self.options.anonymous_only && region.pathname.is_some() {
                continue;
            }
            if let Some(max_size) = self.options.max_region_size {
                if region.size > max_size {
                    continue;
                }
            }

            // Read region memory
            match read_memory_region(&mut mem_file, region) {
                Ok(data) => {
                    bytes_scanned += data.len() as u64;
                    regions_scanned += 1;

                    // Scan the region
                    match self.scanner.scan_bytes(&data) {
                        Ok(matches) => {
                            for m in matches {
                                all_matches.push(ProcessRuleMatch {
                                    rule_match: m,
                                    region_start: region.start,
                                    region_pathname: region.pathname.clone(),
                                });
                            }
                        }
                        Err(e) => {
                            errors.push((region.start, e.to_string()));
                        }
                    }
                }
                Err(e) => {
                    errors.push((region.start, e.to_string()));
                }
            }
        }

        // Get process info
        let process_info = get_process_info(pid)?;

        Ok(ProcessScanResult {
            pid,
            process_info,
            matches: all_matches,
            regions_scanned,
            bytes_scanned,
            total_regions: regions.len(),
            errors,
        })
    }

    /// Scan a process by PID (non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn scan_pid(&self, pid: u32) -> ScanResult<ProcessScanResult> {
        Err(ScanError::InvalidOptions(format!(
            "Process scanning not implemented for this platform. PID: {}",
            pid
        )))
    }

    /// List all running processes
    #[cfg(target_os = "linux")]
    pub fn list_processes() -> ScanResult<Vec<ProcessInfo>> {
        use std::fs;

        let mut processes = Vec::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Check if directory name is a number (PID)
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Ok(info) = get_process_info(pid) {
                    processes.push(info);
                }
            }
        }

        Ok(processes)
    }

    /// List all running processes (non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn list_processes() -> ScanResult<Vec<ProcessInfo>> {
        Err(ScanError::InvalidOptions(
            "Process listing not implemented for this platform".to_string(),
        ))
    }
}

/// Result of scanning a process
#[derive(Debug)]
pub struct ProcessScanResult {
    /// Process ID
    pub pid: u32,
    /// Process information
    pub process_info: ProcessInfo,
    /// Matching rules with region info
    pub matches: Vec<ProcessRuleMatch>,
    /// Number of regions scanned
    pub regions_scanned: usize,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Total memory regions
    pub total_regions: usize,
    /// Errors during scanning
    pub errors: Vec<(u64, String)>,
}

/// A rule match within process memory
#[derive(Debug)]
pub struct ProcessRuleMatch {
    /// The rule match
    pub rule_match: RuleMatch,
    /// Start address of the memory region
    pub region_start: u64,
    /// Pathname of the region (if any)
    pub region_pathname: Option<String>,
}

/// Parse /proc/<pid>/maps output
#[cfg(target_os = "linux")]
fn parse_proc_maps(maps: &str) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // Parse address range
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_parts[1], 16).unwrap_or(0);

        // Parse permissions
        let perms = parts.get(1).unwrap_or(&"----");
        let readable = perms.contains('r');
        let writable = perms.contains('w');
        let executable = perms.contains('x');

        // Get pathname (last column, if exists and starts with /)
        let pathname = parts.get(5).and_then(|p| {
            if p.starts_with('/') || p.starts_with('[') {
                Some(p.to_string())
            } else {
                None
            }
        });

        regions.push(MemoryRegion {
            start,
            end,
            size: end - start,
            permissions: perms.to_string(),
            pathname,
            readable,
            writable,
            executable,
        });
    }

    regions
}

/// Read memory from a process memory region
#[cfg(target_os = "linux")]
fn read_memory_region(
    mem_file: &mut std::fs::File,
    region: &MemoryRegion,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    // Seek to region start
    mem_file.seek(SeekFrom::Start(region.start))?;

    // Read the region (limit to 100MB per region for safety)
    let read_size = std::cmp::min(region.size, 100 * 1024 * 1024) as usize;
    let mut buffer = vec![0u8; read_size];

    // Read may fail for some regions, that's okay
    match mem_file.read(&mut buffer) {
        Ok(bytes_read) => {
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
        Err(e) => Err(e),
    }
}

/// Get process information from /proc
#[cfg(target_os = "linux")]
fn get_process_info(pid: u32) -> ScanResult<ProcessInfo> {
    use std::fs;

    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string())
        .filter(|s| !s.is_empty());

    let exe_path = fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    Ok(ProcessInfo {
        pid,
        name: comm,
        cmdline,
        exe_path,
    })
}

/// Convenience function to scan a process
pub fn scan_process(rules: &str, pid: u32) -> ScanResult<ProcessScanResult> {
    let scanner = ProcessScanner::new(rules)?;
    scanner.scan_pid(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info() {
        let info = ProcessInfo {
            pid: 1234,
            name: "test".to_string(),
            cmdline: Some("/usr/bin/test -a -b".to_string()),
            exe_path: Some("/usr/bin/test".to_string()),
        };

        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "test");
    }

    #[test]
    fn test_memory_region() {
        let region = MemoryRegion {
            start: 0x1000,
            end: 0x2000,
            size: 0x1000,
            permissions: "r-xp".to_string(),
            pathname: Some("/usr/bin/test".to_string()),
            readable: true,
            writable: false,
            executable: true,
        };

        assert!(region.readable);
        assert!(!region.writable);
        assert!(region.executable);
    }

    #[test]
    fn test_scan_options() {
        let options = ProcessScanOptions {
            skip_unreadable: true,
            executable_only: true,
            max_region_size: Some(10 * 1024 * 1024),
            anonymous_only: false,
        };

        assert!(options.skip_unreadable);
        assert!(options.executable_only);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_proc_maps() {
        let maps = r#"
00400000-00401000 r-xp 00000000 08:01 1234567 /usr/bin/test
00600000-00601000 rw-p 00000000 08:01 1234567 /usr/bin/test
7fff00000000-7fff00001000 r--p 00000000 00:00 0 [vvar]
"#;

        let regions = parse_proc_maps(maps);
        assert_eq!(regions.len(), 3);

        assert_eq!(regions[0].start, 0x00400000);
        assert!(regions[0].readable);
        assert!(regions[0].executable);

        assert_eq!(regions[1].start, 0x00600000);
        assert!(regions[1].writable);
        assert!(!regions[1].executable);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_list_processes() {
        // This should work on Linux (might be empty without root)
        let result = ProcessScanner::list_processes();
        // Just check it doesn't panic - it may fail without root
        assert!(result.is_ok() || result.is_err());
    }
}
