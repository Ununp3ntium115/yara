//! Async task queue for distributed processing

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::protocol::{TaskType, WorkerTask, TaskResult};

/// Task status in the queue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Task entry in the queue
#[derive(Debug, Clone, Serialize)]
pub struct TaskEntry {
    pub task_id: String,
    pub task_type: TaskType,
    pub status: TaskStatus,
    pub priority: u8,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: Option<TaskResult>,
    pub error: Option<String>,
}

impl TaskEntry {
    pub fn new(task_id: String, task_type: TaskType, priority: u8) -> Self {
        Self {
            task_id,
            task_type,
            status: TaskStatus::Queued,
            priority,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            result: None,
            error: None,
        }
    }
}

/// Task queue for async task processing
pub struct TaskQueue {
    /// Pending tasks by ID
    tasks: Arc<RwLock<HashMap<String, TaskEntry>>>,
    /// Channel for queued tasks
    sender: mpsc::Sender<(String, WorkerTask)>,
    /// Receiver for task processor
    receiver: Arc<RwLock<mpsc::Receiver<(String, WorkerTask)>>>,
    /// Maximum queue size
    max_size: usize,
}

impl TaskQueue {
    /// Create a new task queue
    pub fn new(max_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(max_size);
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            sender,
            receiver: Arc::new(RwLock::new(receiver)),
            max_size,
        }
    }

    /// Submit a task to the queue
    pub async fn submit(&self, task: WorkerTask, priority: u8) -> Result<String, String> {
        let task_id = task.task_id.clone();

        // Check queue size
        let tasks = self.tasks.read().await;
        if tasks.len() >= self.max_size {
            return Err("Queue is full".to_string());
        }
        drop(tasks);

        // Create task entry
        let entry = TaskEntry::new(task_id.clone(), task.task_type.clone(), priority);

        // Store task entry
        let mut tasks = self.tasks.write().await;
        tasks.insert(task_id.clone(), entry);
        drop(tasks);

        // Queue task for processing
        self.sender
            .send((task_id.clone(), task))
            .await
            .map_err(|e| format!("Failed to queue task: {}", e))?;

        Ok(task_id)
    }

    /// Get task status
    pub async fn get_status(&self, task_id: &str) -> Option<TaskEntry> {
        let tasks = self.tasks.read().await;
        tasks.get(task_id).cloned()
    }

    /// Update task status
    pub async fn update_status(&self, task_id: &str, status: TaskStatus) {
        let mut tasks = self.tasks.write().await;
        if let Some(entry) = tasks.get_mut(task_id) {
            entry.status = status.clone();
            match status {
                TaskStatus::Running => entry.started_at = Some(Utc::now()),
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled => {
                    entry.completed_at = Some(Utc::now());
                }
                _ => {}
            }
        }
    }

    /// Set task result
    pub async fn set_result(&self, task_id: &str, result: TaskResult) {
        let mut tasks = self.tasks.write().await;
        if let Some(entry) = tasks.get_mut(task_id) {
            if result.success {
                entry.status = TaskStatus::Completed;
            } else {
                entry.status = TaskStatus::Failed;
                entry.error = result.error.clone();
            }
            entry.completed_at = Some(Utc::now());
            entry.result = Some(result);
        }
    }

    /// Get next task to process
    pub async fn next_task(&self) -> Option<(String, WorkerTask)> {
        let mut receiver = self.receiver.write().await;
        receiver.recv().await
    }

    /// Get queue statistics
    pub async fn stats(&self) -> serde_json::Value {
        let tasks = self.tasks.read().await;

        let mut queued = 0;
        let mut running = 0;
        let mut completed = 0;
        let mut failed = 0;

        for entry in tasks.values() {
            match entry.status {
                TaskStatus::Queued => queued += 1,
                TaskStatus::Running => running += 1,
                TaskStatus::Completed => completed += 1,
                TaskStatus::Failed => failed += 1,
                TaskStatus::Cancelled => {}
            }
        }

        serde_json::json!({
            "total": tasks.len(),
            "queued": queued,
            "running": running,
            "completed": completed,
            "failed": failed,
            "max_size": self.max_size
        })
    }

    /// Clean up completed tasks older than specified duration
    pub async fn cleanup(&self, max_age_secs: i64) {
        let now = Utc::now();
        let mut tasks = self.tasks.write().await;

        tasks.retain(|_, entry| {
            if let Some(completed_at) = entry.completed_at {
                (now - completed_at).num_seconds() < max_age_secs
            } else {
                true
            }
        });
    }

    /// List recent tasks
    pub async fn list_recent(&self, limit: usize) -> Vec<TaskEntry> {
        let tasks = self.tasks.read().await;
        let mut entries: Vec<_> = tasks.values().cloned().collect();
        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        entries.truncate(limit);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_task_queue_submit() {
        let queue = TaskQueue::new(100);

        let task = WorkerTask::new(
            TaskType::ScanFile,
            HashMap::new(),
        );

        let result = queue.submit(task, 1).await;
        assert!(result.is_ok());

        let task_id = result.unwrap();
        let status = queue.get_status(&task_id).await;
        assert!(status.is_some());
        assert_eq!(status.unwrap().status, TaskStatus::Queued);
    }

    #[tokio::test]
    async fn test_task_queue_stats() {
        let queue = TaskQueue::new(100);

        let task = WorkerTask::new(
            TaskType::ValidateRule,
            HashMap::new(),
        );

        let _ = queue.submit(task, 1).await;

        let stats = queue.stats().await;
        assert_eq!(stats["total"], 1);
        assert_eq!(stats["queued"], 1);
    }
}
