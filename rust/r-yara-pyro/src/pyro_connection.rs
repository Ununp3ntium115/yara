//! PYRO Platform connection module
//!
//! Provides connectivity to the PYRO Platform for worker registration
//! and task distribution.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

use crate::protocol::{WorkerTask, TaskResult, TaskType};
use crate::config::RYaraConfig;

/// PYRO Platform connection status
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

/// Worker registration message
#[derive(Debug, Serialize)]
pub struct WorkerRegistration {
    pub worker_id: String,
    pub worker_type: String,
    pub capabilities: Vec<TaskType>,
    pub version: String,
    pub hostname: String,
}

/// Message from PYRO Platform
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PyroMessage {
    /// Task assignment
    TaskAssignment {
        task_id: String,
        task_type: TaskType,
        payload: serde_json::Value,
        priority: u8,
    },
    /// Acknowledgment
    Ack { message_id: String },
    /// Error
    Error { code: String, message: String },
    /// Ping
    Ping,
    /// Registration confirmed
    Registered { worker_id: String },
}

/// Message to PYRO Platform
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMessage {
    /// Worker registration
    Register(WorkerRegistration),
    /// Task result
    TaskResult {
        task_id: String,
        result: TaskResult,
    },
    /// Heartbeat
    Heartbeat { worker_id: String },
    /// Pong response
    Pong,
}

/// PYRO Platform connection
#[allow(dead_code)]
pub struct PyroConnection {
    /// Configuration
    config: RYaraConfig,
    /// Connection status
    status: Arc<RwLock<ConnectionStatus>>,
    /// Worker ID
    worker_id: String,
    /// Worker type
    worker_type: String,
    /// Capabilities
    capabilities: Vec<TaskType>,
    /// Incoming task channel
    task_sender: mpsc::Sender<WorkerTask>,
    /// Result receiver for sending back to PYRO
    result_receiver: Arc<RwLock<mpsc::Receiver<(String, TaskResult)>>>,
    /// Result sender (given to workers)
    result_sender: mpsc::Sender<(String, TaskResult)>,
}

impl PyroConnection {
    /// Create a new PYRO connection
    pub fn new(
        config: RYaraConfig,
        worker_id: String,
        worker_type: String,
        capabilities: Vec<TaskType>,
    ) -> (Self, mpsc::Receiver<WorkerTask>) {
        let (task_sender, task_receiver) = mpsc::channel(100);
        let (result_sender, result_receiver) = mpsc::channel(100);

        let conn = Self {
            config,
            status: Arc::new(RwLock::new(ConnectionStatus::Disconnected)),
            worker_id,
            worker_type,
            capabilities,
            task_sender,
            result_receiver: Arc::new(RwLock::new(result_receiver)),
            result_sender,
        };

        (conn, task_receiver)
    }

    /// Get result sender for workers to send results back
    pub fn result_sender(&self) -> mpsc::Sender<(String, TaskResult)> {
        self.result_sender.clone()
    }

    /// Get current connection status
    pub async fn status(&self) -> ConnectionStatus {
        self.status.read().await.clone()
    }

    /// Connect to PYRO Platform
    pub async fn connect(&self) -> Result<(), String> {
        let pyro_url = match &self.config.pyro.ws_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => {
                warn!("No PYRO Platform URL configured, running in standalone mode");
                return Ok(());
            }
        };

        info!("Connecting to PYRO Platform at {}", pyro_url);
        *self.status.write().await = ConnectionStatus::Connecting;

        // Build WebSocket URL
        let ws_url = format!(
            "{}/ws/workers/{}",
            pyro_url.replace("http://", "ws://").replace("https://", "wss://"),
            self.worker_id
        );

        // Attempt connection with retry logic
        let max_retries = 3;
        let mut retry_count = 0;

        while retry_count < max_retries {
            match self.attempt_connection(&ws_url).await {
                Ok(()) => {
                    *self.status.write().await = ConnectionStatus::Connected;
                    info!("Connected to PYRO Platform");
                    return Ok(());
                }
                Err(e) => {
                    retry_count += 1;
                    warn!(
                        "Connection attempt {} failed: {}. Retrying...",
                        retry_count, e
                    );
                    tokio::time::sleep(Duration::from_secs(2_u64.pow(retry_count))).await;
                }
            }
        }

        *self.status.write().await = ConnectionStatus::Error;
        Err(format!(
            "Failed to connect to PYRO Platform after {} retries",
            max_retries
        ))
    }

    /// Attempt WebSocket connection
    async fn attempt_connection(&self, ws_url: &str) -> Result<(), String> {
        // For now, we use HTTP polling as a fallback
        // Full WebSocket implementation would use tokio-tungstenite

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        // Try to reach the PYRO Platform health endpoint
        let health_url = format!(
            "{}/api/health",
            ws_url
                .replace("ws://", "http://")
                .replace("wss://", "https://")
                .split("/ws/")
                .next()
                .unwrap_or("")
        );

        let response = client
            .get(&health_url)
            .header("X-Worker-ID", &self.worker_id)
            .header("X-Worker-Type", &self.worker_type)
            .send()
            .await
            .map_err(|e| format!("Health check failed: {}", e))?;

        if response.status().is_success() {
            info!("PYRO Platform health check passed");
            Ok(())
        } else {
            Err(format!(
                "PYRO Platform returned status: {}",
                response.status()
            ))
        }
    }

    /// Run the connection loop (processes tasks and results)
    pub async fn run(&self) {
        let status = self.status.read().await.clone();
        if status != ConnectionStatus::Connected {
            debug!("Not connected to PYRO Platform, skipping run loop");
            return;
        }

        info!("Starting PYRO connection loop");

        // Heartbeat interval
        let mut heartbeat_interval = interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = heartbeat_interval.tick() => {
                    self.send_heartbeat().await;
                }
                result = async {
                    let mut receiver = self.result_receiver.write().await;
                    receiver.recv().await
                } => {
                    if let Some((task_id, result)) = result {
                        self.send_result(&task_id, result).await;
                    }
                }
            }
        }
    }

    /// Send heartbeat to PYRO Platform
    async fn send_heartbeat(&self) {
        debug!("Sending heartbeat to PYRO Platform");
        // In a full implementation, this would send via WebSocket
    }

    /// Send task result to PYRO Platform
    async fn send_result(&self, task_id: &str, result: TaskResult) {
        debug!("Sending result for task {} to PYRO Platform", task_id);

        let pyro_url = match &self.config.pyro.ws_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => return,
        };

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create HTTP client: {}", e);
                return;
            }
        };

        let result_url = format!("{}/api/v2/tasks/{}/result", pyro_url, task_id);

        match client
            .post(&result_url)
            .header("X-Worker-ID", &self.worker_id)
            .json(&result)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("Result sent successfully for task {}", task_id);
                } else {
                    warn!(
                        "Failed to send result for task {}: {}",
                        task_id,
                        response.status()
                    );
                }
            }
            Err(e) => {
                error!("Failed to send result for task {}: {}", task_id, e);
            }
        }
    }

    /// Disconnect from PYRO Platform
    pub async fn disconnect(&self) {
        info!("Disconnecting from PYRO Platform");
        *self.status.write().await = ConnectionStatus::Disconnected;
    }
}

/// Builder for PYRO connections
pub struct PyroConnectionBuilder {
    config: Option<RYaraConfig>,
    worker_id: Option<String>,
    worker_type: String,
    capabilities: Vec<TaskType>,
}

impl Default for PyroConnectionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PyroConnectionBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            worker_id: None,
            worker_type: "scanner".to_string(),
            capabilities: vec![TaskType::ScanFile, TaskType::ScanData],
        }
    }

    pub fn config(mut self, config: RYaraConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn worker_id(mut self, id: String) -> Self {
        self.worker_id = Some(id);
        self
    }

    pub fn worker_type(mut self, wtype: String) -> Self {
        self.worker_type = wtype;
        self
    }

    pub fn capabilities(mut self, caps: Vec<TaskType>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn build(self) -> Result<(PyroConnection, mpsc::Receiver<WorkerTask>), String> {
        let config = self.config.ok_or("Configuration required")?;
        let worker_id = self
            .worker_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Ok(PyroConnection::new(
            config,
            worker_id,
            self.worker_type,
            self.capabilities,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_builder() {
        let config = RYaraConfig::default();
        let result = PyroConnectionBuilder::new()
            .config(config)
            .worker_type("scanner".to_string())
            .capabilities(vec![TaskType::ScanFile])
            .build();

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connection_status() {
        let config = RYaraConfig::default();
        let (conn, _rx) = PyroConnectionBuilder::new()
            .config(config)
            .build()
            .unwrap();

        assert_eq!(conn.status().await, ConnectionStatus::Disconnected);
    }
}
