//! API Client for R-YARA

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// API client error
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API error: {0}")]
    Api(String),
}

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub success: bool,
    pub matches: Vec<serde_json::Value>,
    pub match_count: usize,
    pub error: Option<String>,
    pub execution_time_ms: Option<u64>,
}

/// Transcode result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscodeResult {
    pub success: bool,
    pub transcoded: String,
    pub mappings: HashMap<String, String>,
    pub direction: String,
    pub error: Option<String>,
}

/// Dictionary entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryEntry {
    pub symbol: String,
    pub codename: String,
    pub category: Option<String>,
    pub description: Option<String>,
}

/// R-YARA API Client
pub struct ApiClient {
    client: Client,
    base_url: String,
    api_prefix: String,
    auth_token: Option<String>,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_prefix: "/api/v2/r-yara".to_string(),
            auth_token: None,
        }
    }

    /// Set API prefix
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.api_prefix = prefix.into();
        self
    }

    /// Set authentication token
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Build full URL
    fn url(&self, endpoint: &str) -> String {
        format!("{}{}{}", self.base_url, self.api_prefix, endpoint)
    }

    /// Add auth header if set
    fn auth_header(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.auth_token {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    /// Health check
    pub async fn health(&self) -> Result<serde_json::Value, ClientError> {
        let response = self
            .auth_header(self.client.get(self.url("/health")))
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Dictionary lookup
    pub async fn lookup(&self, query: &str) -> Result<Option<DictionaryEntry>, ClientError> {
        let url = format!("{}?query={}", self.url("/dictionary/lookup"), query);
        let response: serde_json::Value =
            self.auth_header(self.client.get(&url)).send().await?.json().await?;

        if response.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(Some(DictionaryEntry {
                symbol: response["symbol"].as_str().unwrap_or("").to_string(),
                codename: response["codename"].as_str().unwrap_or("").to_string(),
                category: response.get("category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                description: response.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
            }))
        } else {
            Ok(None)
        }
    }

    /// Dictionary search
    pub async fn search(&self, query: &str, limit: Option<u32>) -> Result<Vec<DictionaryEntry>, ClientError> {
        let limit = limit.unwrap_or(50);
        let url = format!("{}?q={}&limit={}", self.url("/dictionary/search"), query, limit);
        let response: serde_json::Value =
            self.auth_header(self.client.get(&url)).send().await?.json().await?;

        let entries = response
            .get("results")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        Some(DictionaryEntry {
                            symbol: e.get("symbol")?.as_str()?.to_string(),
                            codename: e.get("codename")?.as_str()?.to_string(),
                            category: e.get("category").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            description: e.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(entries)
    }

    /// Dictionary stats
    pub async fn dictionary_stats(&self) -> Result<serde_json::Value, ClientError> {
        let response = self
            .auth_header(self.client.get(self.url("/dictionary/stats")))
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Scan file
    pub async fn scan_file(
        &self,
        file_path: &str,
        rules: Option<&str>,
        rules_file: Option<&str>,
    ) -> Result<ScanResult, ClientError> {
        let mut payload = serde_json::json!({ "file_path": file_path });
        if let Some(r) = rules {
            payload["rules"] = serde_json::Value::String(r.to_string());
        }
        if let Some(rf) = rules_file {
            payload["rules_file"] = serde_json::Value::String(rf.to_string());
        }

        let response: serde_json::Value = self
            .auth_header(self.client.post(self.url("/scan/file")))
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        let data = response.get("data").cloned().unwrap_or_default();
        Ok(ScanResult {
            success: response.get("success").and_then(|v| v.as_bool()).unwrap_or(false),
            matches: data.get("matches").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
            match_count: data.get("match_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            error: response.get("error").and_then(|v| v.as_str()).map(|s| s.to_string()),
            execution_time_ms: response.get("execution_time_ms").and_then(|v| v.as_u64()),
        })
    }

    /// Scan data
    pub async fn scan_data(
        &self,
        data: &[u8],
        rules: Option<&str>,
        rules_file: Option<&str>,
    ) -> Result<ScanResult, ClientError> {
        let data_str = String::from_utf8_lossy(data);
        let mut payload = serde_json::json!({ "data": data_str });
        if let Some(r) = rules {
            payload["rules"] = serde_json::Value::String(r.to_string());
        }
        if let Some(rf) = rules_file {
            payload["rules_file"] = serde_json::Value::String(rf.to_string());
        }

        let response: serde_json::Value = self
            .auth_header(self.client.post(self.url("/scan/data")))
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        let resp_data = response.get("data").cloned().unwrap_or_default();
        Ok(ScanResult {
            success: response.get("success").and_then(|v| v.as_bool()).unwrap_or(false),
            matches: resp_data.get("matches").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
            match_count: resp_data.get("match_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            error: response.get("error").and_then(|v| v.as_str()).map(|s| s.to_string()),
            execution_time_ms: response.get("execution_time_ms").and_then(|v| v.as_u64()),
        })
    }

    /// Validate rule
    pub async fn validate_rule(&self, rule: &str) -> Result<serde_json::Value, ClientError> {
        let payload = serde_json::json!({ "rule": rule });
        let response = self
            .auth_header(self.client.post(self.url("/rules/validate")))
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Encode rule
    pub async fn encode(&self, rule: &str) -> Result<TranscodeResult, ClientError> {
        let payload = serde_json::json!({ "rule": rule });
        let response: serde_json::Value = self
            .auth_header(self.client.post(self.url("/transcode/encode")))
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        let data = response.get("data").cloned().unwrap_or_default();
        Ok(TranscodeResult {
            success: response.get("success").and_then(|v| v.as_bool()).unwrap_or(false),
            transcoded: data.get("transcoded").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            mappings: data
                .get("mappings")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            direction: "encode".to_string(),
            error: response.get("error").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    }

    /// Decode rule
    pub async fn decode(&self, rule: &str) -> Result<TranscodeResult, ClientError> {
        let payload = serde_json::json!({ "rule": rule });
        let response: serde_json::Value = self
            .auth_header(self.client.post(self.url("/transcode/decode")))
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        let data = response.get("data").cloned().unwrap_or_default();
        Ok(TranscodeResult {
            success: response.get("success").and_then(|v| v.as_bool()).unwrap_or(false),
            transcoded: data.get("transcoded").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            mappings: data
                .get("mappings")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            direction: "decode".to_string(),
            error: response.get("error").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    }

    /// Scan feeds
    pub async fn scan_feeds(&self, use_case: &str) -> Result<serde_json::Value, ClientError> {
        let url = format!("{}/{}", self.url("/feed/scan"), use_case);
        let response = self
            .auth_header(self.client.post(&url))
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    /// Get stats
    pub async fn stats(&self) -> Result<serde_json::Value, ClientError> {
        let response = self
            .auth_header(self.client.get(self.url("/stats")))
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }
}

impl Default for ApiClient {
    fn default() -> Self {
        Self::new("http://localhost:8080")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ApiClient::new("http://localhost:8080");
        assert_eq!(client.url("/health"), "http://localhost:8080/api/v2/r-yara/health");
    }

    #[test]
    fn test_client_with_prefix() {
        let client = ApiClient::new("http://localhost:8080").with_prefix("/api/v1/yara");
        assert_eq!(client.url("/health"), "http://localhost:8080/api/v1/yara/health");
    }
}
