//! Base worker trait and common functionality

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::RYaraConfig;
use crate::protocol::{TaskType, WorkerTask};

/// Worker state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    /// Worker is initializing
    Initializing,
    /// Worker is idle and ready for tasks
    Idle,
    /// Worker is processing tasks
    Processing,
    /// Worker is shutting down
    ShuttingDown,
    /// Worker has stopped
    Stopped,
    /// Worker encountered an error
    Error,
}

/// Worker statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerStats {
    /// Total tasks processed
    pub tasks_processed: u64,
    /// Successful tasks
    pub tasks_succeeded: u64,
    /// Failed tasks
    pub tasks_failed: u64,
    /// Total execution time in milliseconds
    pub total_execution_time_ms: u64,
    /// Average execution time in milliseconds
    pub avg_execution_time_ms: f64,
    /// Current active tasks
    pub active_tasks: u32,
}

impl WorkerStats {
    /// Record a task completion
    pub fn record_task(&mut self, success: bool, execution_time_ms: u64) {
        self.tasks_processed += 1;
        if success {
            self.tasks_succeeded += 1;
        } else {
            self.tasks_failed += 1;
        }
        self.total_execution_time_ms += execution_time_ms;
        self.avg_execution_time_ms =
            self.total_execution_time_ms as f64 / self.tasks_processed as f64;
    }
}

/// Base worker implementation with common functionality
pub struct BaseWorker {
    pub worker_id: String,
    pub worker_type: String,
    pub capabilities: Vec<TaskType>,
    pub config: Arc<RYaraConfig>,
    pub state: Arc<RwLock<WorkerState>>,
    pub stats: Arc<RwLock<WorkerStats>>,
    pub current_tasks: Arc<RwLock<HashMap<String, WorkerTask>>>,
    pub started_at: DateTime<Utc>,
}

impl BaseWorker {
    /// Create a new base worker
    pub fn new(worker_type: impl Into<String>, capabilities: Vec<TaskType>) -> Self {
        Self {
            worker_id: format!("r-yara-{}", Uuid::new_v4().to_string()[..8].to_string()),
            worker_type: worker_type.into(),
            capabilities,
            config: Arc::new(RYaraConfig::from_env()),
            state: Arc::new(RwLock::new(WorkerState::Initializing)),
            stats: Arc::new(RwLock::new(WorkerStats::default())),
            current_tasks: Arc::new(RwLock::new(HashMap::new())),
            started_at: Utc::now(),
        }
    }

    /// Set configuration
    pub fn with_config(mut self, config: RYaraConfig) -> Self {
        self.config = Arc::new(config);
        self
    }

    /// Set worker ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.worker_id = id.into();
        self
    }

    /// Get current state
    pub async fn get_state(&self) -> WorkerState {
        self.state.read().await.clone()
    }

    /// Set state
    pub async fn set_state(&self, state: WorkerState) {
        *self.state.write().await = state;
    }

    /// Get statistics
    pub async fn get_stats(&self) -> WorkerStats {
        self.stats.read().await.clone()
    }

    /// Record task start
    pub async fn task_started(&self, task: &WorkerTask) {
        let mut tasks = self.current_tasks.write().await;
        tasks.insert(task.task_id.clone(), task.clone());
        self.stats.write().await.active_tasks = tasks.len() as u32;
    }

    /// Record task completion
    pub async fn task_completed(&self, task_id: &str, success: bool, execution_time_ms: u64) {
        let mut tasks = self.current_tasks.write().await;
        tasks.remove(task_id);
        let mut stats = self.stats.write().await;
        stats.active_tasks = tasks.len() as u32;
        stats.record_task(success, execution_time_ms);
    }

    /// Check if can accept more tasks
    pub async fn can_accept_task(&self) -> bool {
        let tasks = self.current_tasks.read().await;
        tasks.len() < self.config.worker.max_concurrent_tasks as usize
    }
}

// Need to add async_trait to Cargo.toml
// For now, we'll use a simpler approach

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_base_worker_creation() {
        let worker = BaseWorker::new("test", vec![TaskType::ScanFile]);
        assert_eq!(worker.worker_type, "test");
        assert!(worker.worker_id.starts_with("r-yara-"));
    }

    #[tokio::test]
    async fn test_worker_state() {
        let worker = BaseWorker::new("test", vec![]);
        assert_eq!(worker.get_state().await, WorkerState::Initializing);

        worker.set_state(WorkerState::Idle).await;
        assert_eq!(worker.get_state().await, WorkerState::Idle);
    }

    #[tokio::test]
    async fn test_worker_stats() {
        let worker = BaseWorker::new("test", vec![]);
        let mut stats = worker.stats.write().await;
        stats.record_task(true, 100);
        stats.record_task(false, 200);
        drop(stats);

        let stats = worker.get_stats().await;
        assert_eq!(stats.tasks_processed, 2);
        assert_eq!(stats.tasks_succeeded, 1);
        assert_eq!(stats.tasks_failed, 1);
    }
}
