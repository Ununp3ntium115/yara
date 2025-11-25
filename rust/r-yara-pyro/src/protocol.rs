//! Protocol definitions for R-YARA PYRO Platform integration
//!
//! Defines message types, task structures, and streaming protocols
//! for communication between R-YARA components and PYRO Platform.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Message types for streaming protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    /// Start of a rule stream
    RuleStart,
    /// Chunk of rule data
    RuleChunk,
    /// End of a rule stream
    RuleEnd,
    /// Match result
    Match,
    /// Error message
    Error,
    /// Heartbeat ping
    Heartbeat,
    /// Worker registration
    WorkerRegister,
    /// Worker deregistration
    WorkerUnregister,
    /// Task assignment
    TaskAssign,
    /// Task result
    TaskResult,
    /// Acknowledgment
    Ack,
}

/// Task types for worker processing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    /// Scan a file with YARA rules
    ScanFile,
    /// Scan raw data with YARA rules
    ScanData,
    /// Validate YARA rule syntax
    ValidateRule,
    /// Compile YARA rules
    CompileRules,
    /// Transcode rules (encode/decode)
    Transcode,
    /// Dictionary lookup
    DictionaryLookup,
    /// Stream rules to workers
    StreamRules,
    /// Feed scanning
    ScanFeeds,
}

/// Stream message for real-time communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMessage {
    /// Message type
    pub message_type: MessageType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Optional rule ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Optional rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    /// Chunk index for multi-part messages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_index: Option<u32>,
    /// Total chunks for multi-part messages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_chunks: Option<u32>,
    /// Data payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl StreamMessage {
    /// Create a new stream message
    pub fn new(message_type: MessageType) -> Self {
        Self {
            message_type,
            timestamp: Utc::now(),
            rule_id: None,
            rule_name: None,
            chunk_index: None,
            total_chunks: None,
            data: None,
            error: None,
            metadata: None,
        }
    }

    /// Create a heartbeat message
    pub fn heartbeat() -> Self {
        Self::new(MessageType::Heartbeat)
    }

    /// Create an error message
    pub fn error(message: impl Into<String>) -> Self {
        let mut msg = Self::new(MessageType::Error);
        msg.error = Some(message.into());
        msg
    }

    /// Create a rule start message
    pub fn rule_start(rule_id: impl Into<String>, rule_name: impl Into<String>) -> Self {
        let mut msg = Self::new(MessageType::RuleStart);
        msg.rule_id = Some(rule_id.into());
        msg.rule_name = Some(rule_name.into());
        msg
    }

    /// Create a rule chunk message
    pub fn rule_chunk(
        rule_id: impl Into<String>,
        chunk_index: u32,
        total_chunks: u32,
        data: serde_json::Value,
    ) -> Self {
        let mut msg = Self::new(MessageType::RuleChunk);
        msg.rule_id = Some(rule_id.into());
        msg.chunk_index = Some(chunk_index);
        msg.total_chunks = Some(total_chunks);
        msg.data = Some(data);
        msg
    }

    /// Create a rule end message
    pub fn rule_end(rule_id: impl Into<String>) -> Self {
        let mut msg = Self::new(MessageType::RuleEnd);
        msg.rule_id = Some(rule_id.into());
        msg
    }

    /// Set data payload
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Worker task definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerTask {
    /// Unique task ID
    pub task_id: String,
    /// Task type
    pub task_type: TaskType,
    /// Task priority (0-10, higher is more important)
    #[serde(default = "default_priority")]
    pub priority: u8,
    /// Timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Task payload
    pub payload: HashMap<String, serde_json::Value>,
    /// Assigned worker ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_worker: Option<String>,
    /// Task creation time
    pub created_at: DateTime<Utc>,
}

fn default_priority() -> u8 {
    5
}

fn default_timeout() -> u64 {
    60000
}

impl WorkerTask {
    /// Create a new worker task
    pub fn new(task_type: TaskType, payload: HashMap<String, serde_json::Value>) -> Self {
        Self {
            task_id: Uuid::new_v4().to_string(),
            task_type,
            priority: default_priority(),
            timeout_ms: default_timeout(),
            payload,
            assigned_worker: None,
            created_at: Utc::now(),
        }
    }

    /// Create a scan file task
    pub fn scan_file(file_path: impl Into<String>, rules: Option<String>) -> Self {
        let mut payload = HashMap::new();
        payload.insert(
            "file_path".to_string(),
            serde_json::Value::String(file_path.into()),
        );
        if let Some(r) = rules {
            payload.insert("rules".to_string(), serde_json::Value::String(r));
        }
        Self::new(TaskType::ScanFile, payload)
    }

    /// Create a validate rule task
    pub fn validate_rule(rule: impl Into<String>) -> Self {
        let mut payload = HashMap::new();
        payload.insert(
            "rule".to_string(),
            serde_json::Value::String(rule.into()),
        );
        Self::new(TaskType::ValidateRule, payload)
    }

    /// Create a transcode task
    pub fn transcode(rule: impl Into<String>, direction: impl Into<String>) -> Self {
        let mut payload = HashMap::new();
        payload.insert(
            "rule".to_string(),
            serde_json::Value::String(rule.into()),
        );
        payload.insert(
            "direction".to_string(),
            serde_json::Value::String(direction.into()),
        );
        Self::new(TaskType::Transcode, payload)
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority.min(10);
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    /// Task ID this result is for
    pub task_id: String,
    /// Whether the task succeeded
    pub success: bool,
    /// Result data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Execution time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_time_ms: Option<u64>,
    /// Result timestamp
    pub timestamp: DateTime<Utc>,
}

impl TaskResult {
    /// Create a successful result
    pub fn success(task_id: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            task_id: task_id.into(),
            success: true,
            data: Some(data),
            error: None,
            execution_time_ms: None,
            timestamp: Utc::now(),
        }
    }

    /// Create a failed result
    pub fn failure(task_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            task_id: task_id.into(),
            success: false,
            data: None,
            error: Some(error.into()),
            execution_time_ms: None,
            timestamp: Utc::now(),
        }
    }

    /// Set execution time
    pub fn with_execution_time(mut self, ms: u64) -> Self {
        self.execution_time_ms = Some(ms);
        self
    }
}

/// Worker registration message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegistration {
    /// Worker ID
    pub worker_id: String,
    /// Worker type
    pub worker_type: String,
    /// Worker capabilities (task types it can handle)
    pub capabilities: Vec<TaskType>,
    /// Maximum concurrent tasks
    pub max_concurrent_tasks: u32,
    /// Worker version
    pub version: String,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl WorkerRegistration {
    /// Create a new worker registration
    pub fn new(
        worker_id: impl Into<String>,
        worker_type: impl Into<String>,
        capabilities: Vec<TaskType>,
    ) -> Self {
        Self {
            worker_id: worker_id.into(),
            worker_type: worker_type.into(),
            capabilities,
            max_concurrent_tasks: 4,
            version: crate::VERSION.to_string(),
            metadata: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_message_creation() {
        let msg = StreamMessage::new(MessageType::Heartbeat);
        assert_eq!(msg.message_type, MessageType::Heartbeat);
        assert!(msg.error.is_none());
    }

    #[test]
    fn test_worker_task_creation() {
        let task = WorkerTask::scan_file("/path/to/file", None);
        assert_eq!(task.task_type, TaskType::ScanFile);
        assert_eq!(task.priority, 5);
    }

    #[test]
    fn test_task_result_success() {
        let result = TaskResult::success("task-1", serde_json::json!({"matches": []}));
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[test]
    fn test_serialization() {
        let msg = StreamMessage::heartbeat();
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("heartbeat"));
    }
}
