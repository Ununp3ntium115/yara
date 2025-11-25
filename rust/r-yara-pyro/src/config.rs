//! Configuration for R-YARA PYRO integration
//!
//! Provides configuration management for API server, workers, streaming,
//! storage, and PYRO platform integration settings.

use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use thiserror::Error;

/// Configuration error
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Environment variable not found: {0}")]
    EnvNotFound(String),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] serde_json::Error),
}

/// API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Host address to bind to
    #[serde(default = "default_host")]
    pub host: String,
    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,
    /// API path prefix
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Enable CORS
    #[serde(default = "default_true")]
    pub cors_enabled: bool,
    /// Maximum request body size in bytes
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_prefix() -> String {
    "/api/v2/r-yara".to_string()
}

fn default_true() -> bool {
    true
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            prefix: default_prefix(),
            cors_enabled: default_true(),
            max_body_size: default_max_body_size(),
        }
    }
}

/// Worker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Maximum concurrent tasks per worker
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_tasks: u32,
    /// Heartbeat interval in milliseconds
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_ms: u64,
    /// Default task timeout in milliseconds
    #[serde(default = "default_task_timeout")]
    pub task_timeout_ms: u64,
    /// Worker reconnect delay in milliseconds
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay_ms: u64,
}

fn default_max_concurrent() -> u32 {
    4
}

fn default_heartbeat() -> u64 {
    30000
}

fn default_task_timeout() -> u64 {
    60000
}

fn default_reconnect_delay() -> u64 {
    5000
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: default_max_concurrent(),
            heartbeat_interval_ms: default_heartbeat(),
            task_timeout_ms: default_task_timeout(),
            reconnect_delay_ms: default_reconnect_delay(),
        }
    }
}

/// Streaming configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Chunk size for streaming
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
    /// Maximum WebSocket connections
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// WebSocket ping interval in seconds
    #[serde(default = "default_ping_interval")]
    pub ping_interval_secs: u64,
    /// Buffer size for stream channels
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_chunk_size() -> usize {
    4096
}

fn default_max_connections() -> u32 {
    100
}

fn default_ping_interval() -> u64 {
    30
}

fn default_buffer_size() -> usize {
    1024
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            chunk_size: default_chunk_size(),
            max_connections: default_max_connections(),
            ping_interval_secs: default_ping_interval(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to dictionary database
    #[serde(default = "default_dictionary_path")]
    pub dictionary_path: PathBuf,
    /// Path to rules directory
    #[serde(default = "default_rules_path")]
    pub rules_path: PathBuf,
    /// Path to cache directory
    #[serde(default = "default_cache_path")]
    pub cache_path: PathBuf,
}

fn default_dictionary_path() -> PathBuf {
    PathBuf::from("data/dictionary.redb")
}

fn default_rules_path() -> PathBuf {
    PathBuf::from("data/rules")
}

fn default_cache_path() -> PathBuf {
    PathBuf::from("data/cache")
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            dictionary_path: default_dictionary_path(),
            rules_path: default_rules_path(),
            cache_path: default_cache_path(),
        }
    }
}

/// PYRO Platform integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyroConfig {
    /// PYRO Platform WebSocket URL
    #[serde(default)]
    pub ws_url: Option<String>,
    /// Authentication token
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Enable PYRO integration
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// PYRO Platform root directory
    #[serde(default)]
    pub pyro_root: Option<PathBuf>,
}

impl Default for PyroConfig {
    fn default() -> Self {
        Self {
            ws_url: None,
            auth_token: None,
            enabled: true,
            pyro_root: None,
        }
    }
}

/// Complete R-YARA configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RYaraConfig {
    /// API server configuration
    #[serde(default)]
    pub api: ApiConfig,
    /// Worker configuration
    #[serde(default)]
    pub worker: WorkerConfig,
    /// Streaming configuration
    #[serde(default)]
    pub stream: StreamConfig,
    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,
    /// PYRO integration configuration
    #[serde(default)]
    pub pyro: PyroConfig,
}

impl RYaraConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // API config
        if let Ok(host) = env::var("RYARA_API_HOST") {
            config.api.host = host;
        }
        if let Ok(port) = env::var("RYARA_API_PORT") {
            if let Ok(p) = port.parse() {
                config.api.port = p;
            }
        }
        if let Ok(prefix) = env::var("RYARA_API_PREFIX") {
            config.api.prefix = prefix;
        }

        // Worker config
        if let Ok(max) = env::var("RYARA_WORKER_MAX_CONCURRENT") {
            if let Ok(m) = max.parse() {
                config.worker.max_concurrent_tasks = m;
            }
        }
        if let Ok(hb) = env::var("RYARA_WORKER_HEARTBEAT_MS") {
            if let Ok(h) = hb.parse() {
                config.worker.heartbeat_interval_ms = h;
            }
        }

        // Storage config
        if let Ok(dict) = env::var("RYARA_DICTIONARY_PATH") {
            config.storage.dictionary_path = PathBuf::from(dict);
        }
        if let Ok(rules) = env::var("RYARA_RULES_PATH") {
            config.storage.rules_path = PathBuf::from(rules);
        }

        // PYRO config
        if let Ok(ws_url) = env::var("PYRO_WS_URL") {
            config.pyro.ws_url = Some(ws_url);
        }
        if let Ok(token) = env::var("PYRO_AUTH_TOKEN") {
            config.pyro.auth_token = Some(token);
        }
        if let Ok(root) = env::var("PYRO_ROOT") {
            config.pyro.pyro_root = Some(PathBuf::from(root));
        }
        if let Ok(enabled) = env::var("PYRO_ENABLED") {
            config.pyro.enabled = enabled.to_lowercase() != "false" && enabled != "0";
        }

        config
    }

    /// Load configuration from a JSON file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to a JSON file
    pub fn to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get the full API address
    pub fn api_address(&self) -> String {
        format!("{}:{}", self.api.host, self.api.port)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.api.port == 0 {
            return Err(ConfigError::Invalid("API port cannot be 0".to_string()));
        }
        if self.worker.max_concurrent_tasks == 0 {
            return Err(ConfigError::Invalid(
                "Worker max concurrent tasks cannot be 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RYaraConfig::default();
        assert_eq!(config.api.port, 8080);
        assert_eq!(config.worker.max_concurrent_tasks, 4);
    }

    #[test]
    fn test_config_validation() {
        let config = RYaraConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_api_address() {
        let config = RYaraConfig::default();
        assert_eq!(config.api_address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_serialization() {
        let config = RYaraConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: RYaraConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.api.port, config.api.port);
    }
}
