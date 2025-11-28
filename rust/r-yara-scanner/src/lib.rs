//! R-YARA Scanner
//!
//! A unified YARA scanning engine that ties together all R-YARA components:
//! - **r-yara-parser**: Parse YARA rules
//! - **r-yara-compiler**: Compile rules to bytecode
//! - **r-yara-matcher**: Aho-Corasick pattern matching
//! - **r-yara-vm**: Execute bytecode conditions
//! - **r-yara-modules**: File format modules (PE, ELF, etc.)
//!
//! # Architecture
//!
//! The scanner follows this pipeline:
//!
//! 1. **Parse**: YARA rules are parsed into an AST
//! 2. **Compile**: AST is compiled to executable bytecode with pattern extraction
//! 3. **Match**: Aho-Corasick finds literal string patterns in data
//! 4. **Execute**: VM evaluates rule conditions using match results
//! 5. **Report**: Matching rules with metadata and string offsets
//!
//! # Example
//!
//! ```
//! use r_yara_scanner::{Scanner, scan_bytes};
//!
//! let rules = r#"
//!     rule detect_malware {
//!         strings:
//!             $mz = "MZ"
//!             $pe = "PE"
//!         condition:
//!             $mz at 0 and $pe
//!     }
//! "#;
//!
//! let data = b"MZ\x90\x00...PE\x00\x00"; // PE file header
//! let matches = scan_bytes(rules, data)?;
//!
//! for m in matches {
//!     println!("Matched: {}", m.rule_name);
//!     for s in m.strings {
//!         println!("  {} at offsets: {:?}", s.identifier, s.offsets);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Scanner API
//!
//! The `Scanner` struct provides a reusable scanner instance:
//!
//! ```ignore
//! use r_yara_scanner::Scanner;
//!
//! // Create scanner from rules
//! let scanner = Scanner::new(rules_source)?;
//!
//! // Scan different targets
//! let matches1 = scanner.scan_file("malware.exe")?;
//! let matches2 = scanner.scan_bytes(data)?;
//! let matches3 = scanner.scan_directory("/suspicious/files", true)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod context;
pub mod database;
pub mod error;
pub mod process;
pub mod remote;
pub mod rules;
pub mod streaming;

// Re-export key types
pub use context::{FileType, ModuleData, ScanContext};
pub use database::{Database, MatchInfo, ScanRecord, Statistics, StoredRules, StringMatchInfo};
pub use error::{ScanError, ScanResult};
pub use process::{
    MemoryRegion, ProcessInfo, ProcessRuleMatch, ProcessScanOptions, ProcessScanResult,
    ProcessScanner, scan_process,
};
pub use remote::{LoadedRules, RuleLoader, RuleLoaderConfig, RuleSource};
pub use rules::{compile_rules, load_rules_from_file, load_rules_from_files, load_rules_from_string};
pub use streaming::{CancellationToken, EventCollector, ScanEvent, ScanProgress, ScanSummary, StreamingScanner};

use r_yara_compiler::CompiledRules;
use r_yara_matcher::PatternMatcher;
use r_yara_vm::{RuleMatch as VMRuleMatch, ScanContext as VMScanContext, VM};
use smol_str::SmolStr;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A YARA scanner instance
///
/// Holds compiled rules and pattern matcher, ready to scan multiple targets.
pub struct Scanner {
    /// Compiled rules
    compiled: CompiledRules,
    /// Pattern matcher
    matcher: PatternMatcher,
}

impl Scanner {
    /// Create a new scanner from YARA rules source
    ///
    /// # Arguments
    ///
    /// * `source` - YARA rules source code
    ///
    /// # Example
    ///
    /// ```
    /// use r_yara_scanner::Scanner;
    ///
    /// let source = r#"
    ///     rule example {
    ///         strings:
    ///             $a = "test"
    ///         condition:
    ///             $a
    ///     }
    /// "#;
    ///
    /// let scanner = Scanner::new(source)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(source: &str) -> ScanResult<Self> {
        let compiled = compile_rules(source)?;
        let matcher = PatternMatcher::new(compiled.patterns.clone())?;

        Ok(Self { compiled, matcher })
    }

    /// Create a scanner from a rules file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to YARA rules file
    pub fn from_file<P: AsRef<Path>>(path: P) -> ScanResult<Self> {
        let compiled = load_rules_from_file(path)?;
        let matcher = PatternMatcher::new(compiled.patterns.clone())?;

        Ok(Self { compiled, matcher })
    }

    /// Create a scanner from multiple rules files
    ///
    /// # Arguments
    ///
    /// * `paths` - Iterator of paths to YARA rule files
    pub fn from_files<'a, I, P>(paths: I) -> ScanResult<Self>
    where
        I: IntoIterator<Item = &'a P>,
        P: AsRef<Path> + 'a,
    {
        let compiled = load_rules_from_files(paths)?;
        let matcher = PatternMatcher::new(compiled.patterns.clone())?;

        Ok(Self { compiled, matcher })
    }

    /// Create a scanner from pre-compiled rules
    ///
    /// # Arguments
    ///
    /// * `compiled` - Pre-compiled YARA rules
    pub fn from_compiled(compiled: CompiledRules) -> ScanResult<Self> {
        let matcher = PatternMatcher::new(compiled.patterns.clone())?;

        Ok(Self { compiled, matcher })
    }

    /// Scan a byte slice
    ///
    /// # Arguments
    ///
    /// * `data` - Data to scan
    ///
    /// # Returns
    ///
    /// Vector of matching rules with their metadata and string matches
    pub fn scan_bytes(&self, data: &[u8]) -> ScanResult<Vec<RuleMatch>> {
        // Create scan context with file type detection and module data
        let ctx = ScanContext::new(data);

        // Run pattern matching
        let pattern_matches = self.matcher.scan(data);

        // Create VM scan context
        let vm_ctx = VMScanContext::new(data)
            .with_entrypoint(ctx.entry_point)
            .with_matches(pattern_matches);

        // Create VM and execute rules
        let vm = VM::new(&self.compiled, &self.matcher);
        let vm_matches = vm.scan(&vm_ctx)?;

        // Convert VM matches to scanner matches
        let matches = vm_matches
            .into_iter()
            .map(|vm_match| RuleMatch::from_vm_match(vm_match, &ctx))
            .collect();

        Ok(matches)
    }

    /// Scan a file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to file to scan
    ///
    /// # Example
    ///
    /// ```ignore
    /// use r_yara_scanner::Scanner;
    ///
    /// let scanner = Scanner::new(rules)?;
    /// let matches = scanner.scan_file("suspicious.exe")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> ScanResult<Vec<RuleMatch>> {
        let data = fs::read(path.as_ref())?;
        self.scan_bytes(&data)
    }

    /// Scan all files in a directory
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path
    /// * `recursive` - Whether to scan subdirectories
    ///
    /// # Returns
    ///
    /// Vector of scan results, one per file
    ///
    /// # Example
    ///
    /// ```ignore
    /// use r_yara_scanner::Scanner;
    ///
    /// let scanner = Scanner::new(rules)?;
    /// let results = scanner.scan_directory("/suspicious", true)?;
    ///
    /// for result in results {
    ///     if !result.matches.is_empty() {
    ///         println!("{}: {} matches", result.path.display(), result.matches.len());
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn scan_directory<P: AsRef<Path>>(
        &self,
        path: P,
        recursive: bool,
    ) -> ScanResult<Vec<DirectoryScanResult>> {
        let mut results = Vec::new();
        let walker = if recursive {
            WalkDir::new(path).follow_links(false)
        } else {
            WalkDir::new(path).max_depth(1).follow_links(false)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path().to_path_buf();

            match self.scan_file(&path) {
                Ok(matches) => {
                    results.push(DirectoryScanResult {
                        path,
                        matches,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(DirectoryScanResult {
                        path,
                        matches: Vec::new(),
                        error: Some(e),
                    });
                }
            }
        }

        Ok(results)
    }

    /// Get the number of compiled rules
    pub fn rule_count(&self) -> usize {
        self.compiled.rules.len()
    }

    /// Get the number of patterns
    pub fn pattern_count(&self) -> usize {
        self.compiled.patterns.len()
    }
}

/// A matched rule with metadata and string matches
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule name
    pub rule_name: SmolStr,
    /// Rule tags
    pub tags: Vec<SmolStr>,
    /// Matched strings with their offsets
    pub strings: Vec<StringMatch>,
    /// Rule metadata
    pub meta: Vec<(SmolStr, MetaValue)>,
    /// File type that was scanned
    pub file_type: FileType,
}

impl RuleMatch {
    /// Convert from VM rule match
    fn from_vm_match(vm_match: VMRuleMatch, ctx: &ScanContext) -> Self {
        let meta = vm_match
            .meta
            .into_iter()
            .map(|(k, v)| (k, MetaValue::from_vm_value(v)))
            .collect();

        let strings = vm_match
            .strings
            .into_iter()
            .map(StringMatch::from_vm_match)
            .collect();

        Self {
            rule_name: vm_match.name,
            tags: vm_match.tags,
            strings,
            meta,
            file_type: ctx.file_type,
        }
    }
}

/// A matched string pattern
#[derive(Debug, Clone)]
pub struct StringMatch {
    /// String identifier (e.g., "$a")
    pub identifier: SmolStr,
    /// Offsets where this string matched
    pub offsets: Vec<u64>,
}

impl StringMatch {
    fn from_vm_match(vm_match: r_yara_vm::StringMatch) -> Self {
        Self {
            identifier: vm_match.identifier,
            offsets: vm_match.offsets,
        }
    }
}

/// Metadata value
#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    String(SmolStr),
    Integer(i64),
    Boolean(bool),
    Float(f64),
}

impl MetaValue {
    fn from_vm_value(value: r_yara_vm::Value) -> Self {
        match value {
            r_yara_vm::Value::Bool(b) => MetaValue::Boolean(b),
            r_yara_vm::Value::Int(i) => MetaValue::Integer(i),
            r_yara_vm::Value::Float(f) => MetaValue::Float(f),
            r_yara_vm::Value::String(s) => MetaValue::String(s),
            r_yara_vm::Value::Undefined => MetaValue::Boolean(false),
        }
    }
}

/// Result of scanning a file in a directory
#[derive(Debug)]
pub struct DirectoryScanResult {
    /// Path to the scanned file
    pub path: PathBuf,
    /// Matches found
    pub matches: Vec<RuleMatch>,
    /// Error if scan failed
    pub error: Option<ScanError>,
}

/// Scan bytes with inline rules (convenience function)
///
/// # Arguments
///
/// * `rules` - YARA rules source code
/// * `data` - Data to scan
///
/// # Example
///
/// ```
/// use r_yara_scanner::scan_bytes;
///
/// let rules = r#"
///     rule test {
///         strings:
///             $a = "malware"
///         condition:
///             $a
///     }
/// "#;
///
/// let data = b"This contains malware string";
/// let matches = scan_bytes(rules, data)?;
/// assert_eq!(matches.len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn scan_bytes(rules: &str, data: &[u8]) -> ScanResult<Vec<RuleMatch>> {
    let scanner = Scanner::new(rules)?;
    scanner.scan_bytes(data)
}

/// Scan a file with inline rules (convenience function)
///
/// # Arguments
///
/// * `rules` - YARA rules source code
/// * `path` - Path to file to scan
pub fn scan_file<P: AsRef<Path>>(rules: &str, path: P) -> ScanResult<Vec<RuleMatch>> {
    let scanner = Scanner::new(rules)?;
    scanner.scan_file(path)
}

/// Scan a directory with inline rules (convenience function)
///
/// # Arguments
///
/// * `rules` - YARA rules source code
/// * `path` - Directory path
/// * `recursive` - Whether to scan subdirectories
pub fn scan_directory<P: AsRef<Path>>(
    rules: &str,
    path: P,
    recursive: bool,
) -> ScanResult<Vec<DirectoryScanResult>> {
    let scanner = Scanner::new(rules)?;
    scanner.scan_directory(path, recursive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let source = r#"
            rule test {
                condition: true
            }
        "#;

        let scanner = Scanner::new(source);
        assert!(scanner.is_ok());

        let scanner = scanner.unwrap();
        assert_eq!(scanner.rule_count(), 1);
    }

    #[test]
    fn test_scan_bytes_simple() {
        let source = r#"
            rule test {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let scanner = Scanner::new(source).unwrap();
        let matches = scanner.scan_bytes(b"this is a test string").unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name.as_str(), "test");
    }

    #[test]
    fn test_scan_bytes_no_match() {
        let source = r#"
            rule test {
                strings:
                    $a = "missing"
                condition:
                    $a
            }
        "#;

        let scanner = Scanner::new(source).unwrap();
        let matches = scanner.scan_bytes(b"this is a test string").unwrap();

        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_bytes_multiple_rules() {
        let source = r#"
            rule rule1 {
                strings:
                    $a = "test"
                condition:
                    $a
            }

            rule rule2 {
                strings:
                    $b = "string"
                condition:
                    $b
            }
        "#;

        let scanner = Scanner::new(source).unwrap();
        let matches = scanner.scan_bytes(b"this is a test string").unwrap();

        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_scan_bytes_with_metadata() {
        let source = r#"
            rule test {
                meta:
                    author = "test"
                    version = 1
                    enabled = true
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let scanner = Scanner::new(source).unwrap();
        let matches = scanner.scan_bytes(b"test data").unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].meta.len(), 3);
    }

    #[test]
    fn test_scan_bytes_with_tags() {
        let source = r#"
            rule test : malware suspicious {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let scanner = Scanner::new(source).unwrap();
        let matches = scanner.scan_bytes(b"test data").unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].tags.len(), 2);
    }

    #[test]
    fn test_convenience_scan_bytes() {
        let rules = r#"
            rule test {
                strings:
                    $a = "malware"
                condition:
                    $a
            }
        "#;

        let matches = scan_bytes(rules, b"this contains malware").unwrap();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_with_filesize() {
        let source = r#"
            rule test {
                condition:
                    filesize > 10
            }
        "#;

        let scanner = Scanner::new(source).unwrap();

        let matches_pass = scanner.scan_bytes(b"this is longer than 10 bytes").unwrap();
        assert_eq!(matches_pass.len(), 1);

        let matches_fail = scanner.scan_bytes(b"short").unwrap();
        assert!(matches_fail.is_empty());
    }

    #[test]
    fn test_scan_with_quantifiers() {
        let source = r#"
            rule test {
                strings:
                    $a = "test"
                    $b = "data"
                condition:
                    all of them
            }
        "#;

        let scanner = Scanner::new(source).unwrap();

        let matches_pass = scanner.scan_bytes(b"test and data").unwrap();
        assert_eq!(matches_pass.len(), 1);

        let matches_fail = scanner.scan_bytes(b"only test").unwrap();
        assert!(matches_fail.is_empty());
    }

    #[test]
    fn test_string_match_offsets() {
        let source = r#"
            rule test {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let scanner = Scanner::new(source).unwrap();
        let matches = scanner.scan_bytes(b"test at start and test again").unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].strings.len(), 1);
        assert_eq!(matches[0].strings[0].offsets.len(), 2);
        assert_eq!(matches[0].strings[0].offsets[0], 0);
        assert_eq!(matches[0].strings[0].offsets[1], 18);
    }
}
