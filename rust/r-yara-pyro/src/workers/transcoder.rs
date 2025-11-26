//! Transcoder worker implementation
//!
//! Handles YARA rule transcoding (codename encoding/decoding) and dictionary operations.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use regex::Regex;

use crate::protocol::{TaskResult, TaskType, WorkerTask};

use super::base::{BaseWorker, WorkerState, WorkerStats};

/// Transcoder worker for codename operations
pub struct TranscoderWorker {
    base: BaseWorker,
    /// Symbol to codename mapping
    dictionary: Arc<RwLock<HashMap<String, String>>>,
    /// Codename to symbol reverse mapping
    reverse_dictionary: Arc<RwLock<HashMap<String, String>>>,
}

impl TranscoderWorker {
    /// Create a new transcoder worker
    pub fn new() -> Self {
        let base = BaseWorker::new(
            "r-yara-transcoder",
            vec![TaskType::Transcode, TaskType::DictionaryLookup],
        );

        Self {
            base,
            dictionary: Arc::new(RwLock::new(HashMap::new())),
            reverse_dictionary: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get worker ID
    pub fn worker_id(&self) -> &str {
        &self.base.worker_id
    }

    /// Get worker type
    pub fn worker_type(&self) -> &str {
        &self.base.worker_type
    }

    /// Get capabilities
    pub fn capabilities(&self) -> Vec<TaskType> {
        self.base.capabilities.clone()
    }

    /// Get current state
    pub async fn state(&self) -> WorkerState {
        self.base.get_state().await
    }

    /// Get statistics
    pub async fn stats(&self) -> WorkerStats {
        self.base.get_stats().await
    }

    /// Process a task
    pub async fn process_task(&self, task: WorkerTask) -> TaskResult {
        let start = Instant::now();
        self.base.task_started(&task).await;

        let result = match task.task_type {
            TaskType::Transcode => self.transcode(&task).await,
            TaskType::DictionaryLookup => self.dictionary_lookup(&task).await,
            _ => TaskResult::failure(&task.task_id, "Unsupported task type"),
        };

        let elapsed = start.elapsed().as_millis() as u64;
        self.base
            .task_completed(&task.task_id, result.success, elapsed)
            .await;

        result.with_execution_time(elapsed)
    }

    /// Transcode a YARA rule
    async fn transcode(&self, task: &WorkerTask) -> TaskResult {
        let rule = match task.payload.get("rule") {
            Some(serde_json::Value::String(r)) => r.clone(),
            _ => return TaskResult::failure(&task.task_id, "Missing rule in payload"),
        };

        let direction = task
            .payload
            .get("direction")
            .and_then(|d| d.as_str())
            .unwrap_or("encode");

        let (transcoded, mappings) = if direction == "encode" {
            self.encode_rule(&rule).await
        } else {
            self.decode_rule(&rule).await
        };

        TaskResult::success(
            &task.task_id,
            serde_json::json!({
                "original": rule,
                "transcoded": transcoded,
                "mappings": mappings,
                "direction": direction
            }),
        )
    }

    /// Encode a rule with codenames
    async fn encode_rule(&self, rule: &str) -> (String, HashMap<String, String>) {
        let mut transcoded = rule.to_string();
        let mut mappings = HashMap::new();

        // Find rule names
        let rule_pattern = Regex::new(r"rule\s+(\w+)").unwrap();
        for cap in rule_pattern.captures_iter(rule) {
            let original = cap.get(1).unwrap().as_str();
            if !mappings.contains_key(original) {
                let codename = self.generate_codename(original).await;
                mappings.insert(original.to_string(), codename.clone());
            }
        }

        // Find string identifiers
        let string_pattern = Regex::new(r"\$(\w+)\s*=").unwrap();
        for cap in string_pattern.captures_iter(rule) {
            let original = format!("${}", cap.get(1).unwrap().as_str());
            if !mappings.contains_key(&original) {
                let codename = self.generate_codename(&original).await;
                mappings.insert(original.clone(), codename.clone());
            }
        }

        // Apply mappings
        for (original, codename) in &mappings {
            transcoded = transcoded.replace(original, codename);
        }

        (transcoded, mappings)
    }

    /// Decode a rule from codenames
    async fn decode_rule(&self, rule: &str) -> (String, HashMap<String, String>) {
        let mut transcoded = rule.to_string();
        let mut mappings = HashMap::new();

        // Find potential codenames (R_XXXXXX format)
        let codename_pattern = Regex::new(r"R_[A-F0-9]{6}").unwrap();
        let reverse_dict = self.reverse_dictionary.read().await;

        for mat in codename_pattern.find_iter(rule) {
            let codename = mat.as_str();
            if let Some(original) = reverse_dict.get(codename) {
                mappings.insert(codename.to_string(), original.clone());
                transcoded = transcoded.replace(codename, original);
            }
        }

        (transcoded, mappings)
    }

    /// Generate a codename for an identifier
    async fn generate_codename(&self, identifier: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        identifier.hash(&mut hasher);
        let hash = hasher.finish();
        let codename = format!("R_{:06X}", hash as u32 & 0xFFFFFF);

        // Cache the mapping
        let mut dict = self.dictionary.write().await;
        dict.insert(identifier.to_string(), codename.clone());
        drop(dict);

        let mut reverse = self.reverse_dictionary.write().await;
        reverse.insert(codename.clone(), identifier.to_string());

        codename
    }

    /// Dictionary lookup
    async fn dictionary_lookup(&self, task: &WorkerTask) -> TaskResult {
        let query = match task.payload.get("query") {
            Some(serde_json::Value::String(q)) => q,
            _ => return TaskResult::failure(&task.task_id, "Missing query in payload"),
        };

        let lookup_type = task
            .payload
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("codename");

        let result = if lookup_type == "codename" {
            // Look up codename -> symbol
            let reverse = self.reverse_dictionary.read().await;
            if let Some(symbol) = reverse.get(query) {
                serde_json::json!({
                    "found": true,
                    "codename": query,
                    "symbol": symbol
                })
            } else {
                serde_json::json!({
                    "found": false,
                    "query": query
                })
            }
        } else {
            // Look up symbol -> codename
            let dict = self.dictionary.read().await;
            if let Some(codename) = dict.get(query) {
                serde_json::json!({
                    "found": true,
                    "symbol": query,
                    "codename": codename
                })
            } else {
                serde_json::json!({
                    "found": false,
                    "query": query
                })
            }
        };

        TaskResult::success(&task.task_id, result)
    }

    /// Load dictionary from JSON
    pub async fn load_dictionary(&self, data: &str) -> Result<usize, String> {
        let entries: Vec<serde_json::Value> =
            serde_json::from_str(data).map_err(|e| e.to_string())?;

        let mut dict = self.dictionary.write().await;
        let mut reverse = self.reverse_dictionary.write().await;
        let mut count = 0;

        for entry in entries {
            if let (Some(symbol), Some(codename)) = (
                entry.get("symbol").and_then(|s| s.as_str()),
                entry.get("codename").and_then(|c| c.as_str()),
            ) {
                dict.insert(symbol.to_string(), codename.to_string());
                reverse.insert(codename.to_string(), symbol.to_string());
                count += 1;
            }
        }

        Ok(count)
    }

    /// Get dictionary statistics
    pub async fn dictionary_stats(&self) -> serde_json::Value {
        let dict = self.dictionary.read().await;
        serde_json::json!({
            "total_entries": dict.len(),
            "status": if dict.is_empty() { "empty" } else { "loaded" }
        })
    }
}

impl Default for TranscoderWorker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transcoder_worker_creation() {
        let worker = TranscoderWorker::new();
        assert_eq!(worker.worker_type(), "r-yara-transcoder");
    }

    #[tokio::test]
    async fn test_encode_rule() {
        let worker = TranscoderWorker::new();
        let rule = r#"rule test_rule { strings: $a = "test" condition: $a }"#;
        let (transcoded, mappings) = worker.encode_rule(rule).await;

        assert!(!mappings.is_empty());
        assert!(!transcoded.contains("test_rule"));
    }

    #[tokio::test]
    async fn test_codename_generation() {
        let worker = TranscoderWorker::new();
        let codename = worker.generate_codename("test").await;
        assert!(codename.starts_with("R_"));
        assert_eq!(codename.len(), 8); // R_ + 6 hex chars
    }

    #[tokio::test]
    async fn test_dictionary_roundtrip() {
        let worker = TranscoderWorker::new();

        // Generate codename
        let codename = worker.generate_codename("my_symbol").await;

        // Look up by codename
        let reverse = worker.reverse_dictionary.read().await;
        assert_eq!(reverse.get(&codename), Some(&"my_symbol".to_string()));
    }
}
