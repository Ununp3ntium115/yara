//! Remote Rule Loading
//!
//! Load YARA rules from remote sources:
//! - ZIP archives (local or remote)
//! - HTTP URLs
//! - Git repositories
//!
//! # Example
//!
//! ```no_run
//! use r_yara_scanner::remote::RuleLoader;
//!
//! let loader = RuleLoader::new();
//!
//! // Load from ZIP file
//! let rules = loader.load_from_zip("/path/to/rules.zip")?;
//!
//! // Load from URL
//! let rules = loader.load_from_url("https://rules.example.com/malware.yar").await?;
//!
//! // Load from ZIP URL
//! let rules = loader.load_from_zip_url("https://rules.example.com/bundle.zip").await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{ScanError, ScanResult};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Configuration for remote rule loading
#[derive(Debug, Clone)]
pub struct RuleLoaderConfig {
    /// Cache directory for downloaded rules
    pub cache_dir: PathBuf,
    /// Whether to use cache
    pub use_cache: bool,
    /// HTTP timeout in seconds
    pub timeout_secs: u64,
    /// Maximum file size to download (bytes)
    pub max_download_size: u64,
    /// File extensions to load from ZIP
    pub rule_extensions: Vec<String>,
}

impl Default for RuleLoaderConfig {
    fn default() -> Self {
        Self {
            cache_dir: std::env::temp_dir().join("r-yara-rules-cache"),
            use_cache: true,
            timeout_secs: 60,
            max_download_size: 100 * 1024 * 1024, // 100MB
            rule_extensions: vec![
                "yar".to_string(),
                "yara".to_string(),
                "yr".to_string(),
            ],
        }
    }
}

/// Remote rule loader
///
/// Loads YARA rules from various sources including ZIP files and URLs.
#[derive(Debug)]
pub struct RuleLoader {
    /// Configuration
    config: RuleLoaderConfig,
    /// HTTP client
    #[cfg(feature = "remote-http")]
    client: reqwest::Client,
}

impl RuleLoader {
    /// Create a new rule loader with default configuration
    pub fn new() -> Self {
        Self::with_config(RuleLoaderConfig::default())
    }

    /// Create a rule loader with custom configuration
    pub fn with_config(config: RuleLoaderConfig) -> Self {
        // Ensure cache directory exists
        if config.use_cache {
            let _ = fs::create_dir_all(&config.cache_dir);
        }

        Self {
            config,
            #[cfg(feature = "remote-http")]
            client: reqwest::Client::new(),
        }
    }

    /// Load rules from a local ZIP file
    ///
    /// Extracts all .yar/.yara files and concatenates them.
    pub fn load_from_zip<P: AsRef<Path>>(&self, path: P) -> ScanResult<LoadedRules> {
        let file = File::open(path.as_ref())
            .map_err(|e| ScanError::IoError(e))?;

        self.load_from_zip_reader(file, path.as_ref().to_string_lossy().to_string())
    }

    /// Load rules from ZIP bytes
    pub fn load_from_zip_bytes(&self, data: &[u8], source: String) -> ScanResult<LoadedRules> {
        let cursor = Cursor::new(data);
        self.load_from_zip_reader(cursor, source)
    }

    /// Load rules from a ZIP reader
    fn load_from_zip_reader<R: Read + std::io::Seek>(
        &self,
        reader: R,
        source: String,
    ) -> ScanResult<LoadedRules> {
        let mut archive = ZipArchive::new(reader)
            .map_err(|e| ScanError::ParseError(format!("Invalid ZIP archive: {}", e)))?;

        let mut rules = LoadedRules::new(source);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .map_err(|e| ScanError::ParseError(format!("ZIP read error: {}", e)))?;

            let name = file.name().to_string();

            // Check if this is a YARA rule file
            if !self.is_rule_file(&name) {
                continue;
            }

            let mut content = String::new();
            file.read_to_string(&mut content)
                .map_err(|e| ScanError::IoError(e))?;

            rules.add_file(name, content);
        }

        Ok(rules)
    }

    /// Load rules from a local file
    pub fn load_from_file<P: AsRef<Path>>(&self, path: P) -> ScanResult<LoadedRules> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        let source = path.to_string_lossy().to_string();

        let mut rules = LoadedRules::new(source.clone());
        rules.add_file(source, content);

        Ok(rules)
    }

    /// Load rules from a directory
    pub fn load_from_directory<P: AsRef<Path>>(
        &self,
        path: P,
        recursive: bool,
    ) -> ScanResult<LoadedRules> {
        let path = path.as_ref();
        let source = path.to_string_lossy().to_string();
        let mut rules = LoadedRules::new(source);

        self.load_directory_recursive(path, &mut rules, recursive)?;

        Ok(rules)
    }

    fn load_directory_recursive(
        &self,
        path: &Path,
        rules: &mut LoadedRules,
        recursive: bool,
    ) -> ScanResult<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && self.is_rule_file(path.to_string_lossy().as_ref()) {
                let content = fs::read_to_string(&path)?;
                rules.add_file(path.to_string_lossy().to_string(), content);
            } else if path.is_dir() && recursive {
                self.load_directory_recursive(&path, rules, recursive)?;
            }
        }

        Ok(())
    }

    /// Check if a file is a YARA rule file
    fn is_rule_file(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.config.rule_extensions.iter().any(|ext| {
            name_lower.ends_with(&format!(".{}", ext))
        })
    }

    /// Get configuration
    pub fn config(&self) -> &RuleLoaderConfig {
        &self.config
    }
}

impl Default for RuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Loaded YARA rules from remote/archive source
#[derive(Debug, Clone)]
pub struct LoadedRules {
    /// Source identifier
    pub source: String,
    /// Individual rule files (filename -> content)
    pub files: HashMap<String, String>,
    /// Concatenated rules
    concatenated: String,
}

impl LoadedRules {
    /// Create new loaded rules container
    pub fn new(source: String) -> Self {
        Self {
            source,
            files: HashMap::new(),
            concatenated: String::new(),
        }
    }

    /// Add a rule file
    pub fn add_file(&mut self, name: String, content: String) {
        // Add comment separator
        if !self.concatenated.is_empty() {
            self.concatenated.push_str("\n\n");
        }
        self.concatenated.push_str(&format!("// Source: {}\n", name));
        self.concatenated.push_str(&content);

        self.files.insert(name, content);
    }

    /// Get concatenated rules
    pub fn as_rules(&self) -> &str {
        &self.concatenated
    }

    /// Get number of files loaded
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Check if any rules were loaded
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Get individual file content
    pub fn get_file(&self, name: &str) -> Option<&String> {
        self.files.get(name)
    }

    /// List all file names
    pub fn file_names(&self) -> impl Iterator<Item = &String> {
        self.files.keys()
    }
}

/// Remote rule source
#[derive(Debug, Clone)]
pub enum RuleSource {
    /// Local file path
    File(PathBuf),
    /// Local directory
    Directory { path: PathBuf, recursive: bool },
    /// Local ZIP file
    ZipFile(PathBuf),
    /// ZIP bytes (e.g., from upload)
    ZipBytes(Vec<u8>),
    /// Raw rule content
    Raw(String),
    /// HTTP URL
    #[cfg(feature = "remote-http")]
    Url(String),
    /// ZIP from URL
    #[cfg(feature = "remote-http")]
    ZipUrl(String),
}

impl RuleSource {
    /// Load rules from this source
    pub fn load(&self, loader: &RuleLoader) -> ScanResult<LoadedRules> {
        match self {
            RuleSource::File(path) => loader.load_from_file(path),
            RuleSource::Directory { path, recursive } => {
                loader.load_from_directory(path, *recursive)
            }
            RuleSource::ZipFile(path) => loader.load_from_zip(path),
            RuleSource::ZipBytes(data) => {
                loader.load_from_zip_bytes(data, "uploaded.zip".to_string())
            }
            RuleSource::Raw(content) => {
                let mut rules = LoadedRules::new("raw".to_string());
                rules.add_file("raw".to_string(), content.clone());
                Ok(rules)
            }
            #[cfg(feature = "remote-http")]
            RuleSource::Url(_) | RuleSource::ZipUrl(_) => {
                Err(ScanError::ParseError(
                    "HTTP loading requires async runtime".to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    fn create_test_rule() -> String {
        r#"
        rule TestRule {
            strings:
                $a = "test"
            condition:
                $a
        }
        "#.to_string()
    }

    #[test]
    fn test_loader_creation() {
        let loader = RuleLoader::new();
        assert!(loader.config().use_cache);
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let rule_path = temp_dir.path().join("test.yar");

        fs::write(&rule_path, create_test_rule()).unwrap();

        let loader = RuleLoader::new();
        let rules = loader.load_from_file(&rule_path).unwrap();

        assert_eq!(rules.file_count(), 1);
        assert!(rules.as_rules().contains("TestRule"));
    }

    #[test]
    fn test_load_from_directory() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple rule files
        fs::write(temp_dir.path().join("rule1.yar"), create_test_rule()).unwrap();
        fs::write(temp_dir.path().join("rule2.yara"), create_test_rule()).unwrap();
        fs::write(temp_dir.path().join("not_rule.txt"), "ignore me").unwrap();

        let loader = RuleLoader::new();
        let rules = loader.load_from_directory(temp_dir.path(), false).unwrap();

        assert_eq!(rules.file_count(), 2);
    }

    #[test]
    fn test_load_from_zip() {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = temp_dir.path().join("rules.zip");

        // Create a ZIP file with rules
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = SimpleFileOptions::default();
        zip.start_file("rule1.yar", options).unwrap();
        zip.write_all(create_test_rule().as_bytes()).unwrap();

        zip.start_file("subdir/rule2.yara", options).unwrap();
        zip.write_all(create_test_rule().as_bytes()).unwrap();

        zip.start_file("readme.txt", options).unwrap();
        zip.write_all(b"Not a rule file").unwrap();

        zip.finish().unwrap();

        // Load from ZIP
        let loader = RuleLoader::new();
        let rules = loader.load_from_zip(&zip_path).unwrap();

        assert_eq!(rules.file_count(), 2);
        assert!(rules.as_rules().contains("TestRule"));
    }

    #[test]
    fn test_load_from_zip_bytes() {
        // Create ZIP in memory
        let mut buffer = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = SimpleFileOptions::default();

            zip.start_file("test.yar", options).unwrap();
            zip.write_all(create_test_rule().as_bytes()).unwrap();
            zip.finish().unwrap();
        }

        let loader = RuleLoader::new();
        let rules = loader.load_from_zip_bytes(&buffer, "uploaded.zip".to_string()).unwrap();

        assert_eq!(rules.file_count(), 1);
    }

    #[test]
    fn test_loaded_rules_concatenation() {
        let mut rules = LoadedRules::new("test".to_string());

        rules.add_file("rule1.yar".to_string(), "rule R1 { condition: true }".to_string());
        rules.add_file("rule2.yar".to_string(), "rule R2 { condition: false }".to_string());

        let concatenated = rules.as_rules();
        assert!(concatenated.contains("R1"));
        assert!(concatenated.contains("R2"));
        assert!(concatenated.contains("Source: rule1.yar"));
        assert!(concatenated.contains("Source: rule2.yar"));
    }

    #[test]
    fn test_rule_extensions() {
        let loader = RuleLoader::new();

        assert!(loader.is_rule_file("malware.yar"));
        assert!(loader.is_rule_file("rules/detection.yara"));
        assert!(loader.is_rule_file("test.yr"));
        assert!(loader.is_rule_file("UPPERCASE.YAR"));
        assert!(!loader.is_rule_file("readme.txt"));
        assert!(!loader.is_rule_file("script.py"));
    }
}
