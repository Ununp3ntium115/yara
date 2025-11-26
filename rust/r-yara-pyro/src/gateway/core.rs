//! Gateway core implementation

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::RYaraConfig;
use crate::workers::{ScannerWorker, TranscoderWorker};

/// Service endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub name: String,
    pub url: String,
    pub health_path: String,
    pub healthy: bool,
    pub last_check: Option<DateTime<Utc>>,
}

impl ServiceEndpoint {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            health_path: "/health".to_string(),
            healthy: false,
            last_check: None,
        }
    }

    pub fn with_health_path(mut self, path: impl Into<String>) -> Self {
        self.health_path = path.into();
        self
    }
}

/// Gateway statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayStats {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub active_connections: u32,
    pub start_time: Option<DateTime<Utc>>,
}

impl GatewayStats {
    pub fn new() -> Self {
        Self {
            start_time: Some(Utc::now()),
            ..Default::default()
        }
    }

    pub fn uptime_seconds(&self) -> f64 {
        self.start_time
            .map(|s| (Utc::now() - s).num_seconds() as f64)
            .unwrap_or(0.0)
    }

    pub fn success_rate(&self) -> f64 {
        if self.requests_total > 0 {
            self.requests_success as f64 / self.requests_total as f64
        } else {
            1.0
        }
    }
}

/// R-YARA API Gateway
pub struct Gateway {
    #[allow(dead_code)]
    config: Arc<RYaraConfig>,
    services: Arc<RwLock<HashMap<String, ServiceEndpoint>>>,
    stats: Arc<RwLock<GatewayStats>>,
    scanner: Arc<ScannerWorker>,
    transcoder: Arc<TranscoderWorker>,
    running: Arc<RwLock<bool>>,
}

impl Gateway {
    /// Create a new gateway
    pub fn new(config: RYaraConfig) -> Self {
        Self {
            config: Arc::new(config),
            services: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(GatewayStats::new())),
            scanner: Arc::new(ScannerWorker::new()),
            transcoder: Arc::new(TranscoderWorker::new()),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Register an external service
    pub async fn register_service(&self, endpoint: ServiceEndpoint) {
        let name = endpoint.name.clone();
        let mut services = self.services.write().await;
        services.insert(name.clone(), endpoint);
        info!("Registered service: {}", name);
    }

    /// Unregister a service
    pub async fn unregister_service(&self, name: &str) {
        let mut services = self.services.write().await;
        if services.remove(name).is_some() {
            info!("Unregistered service: {}", name);
        }
    }

    /// Start the gateway
    pub async fn start(&self) {
        *self.running.write().await = true;
        info!("R-YARA Gateway started");

        // Start health checking background task
        let services = self.services.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            while *running.read().await {
                Self::check_services_health(&services).await;
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        });
    }

    /// Stop the gateway
    pub async fn stop(&self) {
        *self.running.write().await = false;
        info!("R-YARA Gateway stopped");
    }

    /// Check health of all services
    async fn check_services_health(services: &Arc<RwLock<HashMap<String, ServiceEndpoint>>>) {
        let mut services = services.write().await;
        for (name, endpoint) in services.iter_mut() {
            let healthy = Self::check_endpoint_health(endpoint).await;
            endpoint.healthy = healthy;
            endpoint.last_check = Some(Utc::now());

            if !healthy {
                warn!("Service {} is unhealthy", name);
            }
        }
    }

    /// Check health of a single endpoint
    async fn check_endpoint_health(endpoint: &ServiceEndpoint) -> bool {
        let url = format!("{}{}", endpoint.url, endpoint.health_path);

        match reqwest::Client::new()
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Route a request to appropriate service
    pub async fn route_request(
        &self,
        service: &str,
        method: &str,
        path: &str,
        data: Option<serde_json::Value>,
    ) -> serde_json::Value {
        self.stats.write().await.requests_total += 1;

        // Handle local services
        let result = match service {
            "scanner" => self.handle_scanner_request(path, data).await,
            "transcoder" => self.handle_transcoder_request(path, data).await,
            _ => {
                // Try external service
                match self.proxy_to_service(service, method, path, data).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        self.stats.write().await.requests_failed += 1;
                        serde_json::json!({
                            "error": e,
                            "success": false
                        })
                    }
                }
            }
        };

        if result.get("success").and_then(|v| v.as_bool()).unwrap_or(true) {
            self.stats.write().await.requests_success += 1;
        } else {
            self.stats.write().await.requests_failed += 1;
        }

        result
    }

    /// Handle scanner requests locally
    async fn handle_scanner_request(
        &self,
        path: &str,
        data: Option<serde_json::Value>,
    ) -> serde_json::Value {
        use crate::protocol::{TaskType, WorkerTask};
        use std::collections::HashMap;

        let payload: HashMap<String, serde_json::Value> = data
            .and_then(|d| serde_json::from_value(d).ok())
            .unwrap_or_default();

        let task_type = if path.contains("/scan/file") {
            TaskType::ScanFile
        } else if path.contains("/scan/data") {
            TaskType::ScanData
        } else if path.contains("/validate") {
            TaskType::ValidateRule
        } else if path.contains("/compile") {
            TaskType::CompileRules
        } else {
            return serde_json::json!({
                "error": format!("Unknown scanner path: {}", path),
                "success": false
            });
        };

        let task = WorkerTask::new(task_type, payload);
        let result = self.scanner.process_task(task).await;

        serde_json::json!({
            "success": result.success,
            "data": result.data,
            "error": result.error
        })
    }

    /// Handle transcoder requests locally
    async fn handle_transcoder_request(
        &self,
        path: &str,
        data: Option<serde_json::Value>,
    ) -> serde_json::Value {
        use crate::protocol::{TaskType, WorkerTask};
        use std::collections::HashMap;

        let mut payload: HashMap<String, serde_json::Value> = data
            .and_then(|d| serde_json::from_value(d).ok())
            .unwrap_or_default();

        let task_type = if path.contains("/encode") {
            payload.insert(
                "direction".to_string(),
                serde_json::Value::String("encode".to_string()),
            );
            TaskType::Transcode
        } else if path.contains("/decode") {
            payload.insert(
                "direction".to_string(),
                serde_json::Value::String("decode".to_string()),
            );
            TaskType::Transcode
        } else if path.contains("/lookup") {
            TaskType::DictionaryLookup
        } else {
            return serde_json::json!({
                "error": format!("Unknown transcoder path: {}", path),
                "success": false
            });
        };

        let task = WorkerTask::new(task_type, payload);
        let result = self.transcoder.process_task(task).await;

        serde_json::json!({
            "success": result.success,
            "data": result.data,
            "error": result.error
        })
    }

    /// Proxy request to external service
    async fn proxy_to_service(
        &self,
        service: &str,
        method: &str,
        path: &str,
        data: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let services = self.services.read().await;
        let endpoint = services
            .get(service)
            .ok_or_else(|| format!("Service {} not found", service))?;

        if !endpoint.healthy {
            return Err(format!("Service {} is unhealthy", service));
        }

        let url = format!("{}{}", endpoint.url, path);
        let client = reqwest::Client::new();

        let response = match method.to_uppercase().as_str() {
            "GET" => client.get(&url).send().await,
            "POST" => client.post(&url).json(&data).send().await,
            "PUT" => client.put(&url).json(&data).send().await,
            "DELETE" => client.delete(&url).send().await,
            _ => return Err(format!("Unsupported method: {}", method)),
        };

        match response {
            Ok(resp) => resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e)),
            Err(e) => Err(format!("Request failed: {}", e)),
        }
    }

    /// Get gateway statistics
    pub async fn get_stats(&self) -> serde_json::Value {
        let stats = self.stats.read().await;
        let services = self.services.read().await;

        serde_json::json!({
            "gateway": {
                "requests_total": stats.requests_total,
                "requests_success": stats.requests_success,
                "requests_failed": stats.requests_failed,
                "active_connections": stats.active_connections,
                "uptime_seconds": stats.uptime_seconds(),
                "success_rate": stats.success_rate()
            },
            "services": services.iter().map(|(name, svc)| {
                (name.clone(), serde_json::json!({
                    "url": svc.url,
                    "healthy": svc.healthy,
                    "last_check": svc.last_check
                }))
            }).collect::<HashMap<_, _>>()
        })
    }

    /// Get gateway health
    pub async fn get_health(&self) -> serde_json::Value {
        let services = self.services.read().await;
        let healthy_count = services.values().filter(|s| s.healthy).count();
        let total_count = services.len();

        let status = if total_count == 0 || healthy_count == total_count {
            "healthy"
        } else if healthy_count > 0 {
            "degraded"
        } else {
            "unhealthy"
        };

        let stats = self.stats.read().await;

        serde_json::json!({
            "status": status,
            "services_healthy": healthy_count,
            "services_total": total_count,
            "uptime_seconds": stats.uptime_seconds()
        })
    }

    // Convenience methods

    /// Scan a file
    pub async fn scan_file(&self, file_path: &str, rules: Option<&str>) -> serde_json::Value {
        let mut data = serde_json::json!({ "file_path": file_path });
        if let Some(r) = rules {
            data["rules"] = serde_json::Value::String(r.to_string());
        }
        self.route_request("scanner", "POST", "/scan/file", Some(data))
            .await
    }

    /// Validate a rule
    pub async fn validate_rule(&self, rule: &str) -> serde_json::Value {
        let data = serde_json::json!({ "rule": rule });
        self.route_request("scanner", "POST", "/rules/validate", Some(data))
            .await
    }

    /// Encode a rule
    pub async fn encode_rule(&self, rule: &str) -> serde_json::Value {
        let data = serde_json::json!({ "rule": rule });
        self.route_request("transcoder", "POST", "/transcode/encode", Some(data))
            .await
    }

    /// Decode a rule
    pub async fn decode_rule(&self, rule: &str) -> serde_json::Value {
        let data = serde_json::json!({ "rule": rule });
        self.route_request("transcoder", "POST", "/transcode/decode", Some(data))
            .await
    }

    /// Lookup in dictionary
    pub async fn lookup(&self, query: &str) -> serde_json::Value {
        let data = serde_json::json!({ "query": query });
        self.route_request("transcoder", "POST", "/dictionary/lookup", Some(data))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gateway_creation() {
        let config = RYaraConfig::default();
        let gateway = Gateway::new(config);
        let health = gateway.get_health().await;
        assert_eq!(health["status"], "healthy");
    }

    #[tokio::test]
    async fn test_service_registration() {
        let config = RYaraConfig::default();
        let gateway = Gateway::new(config);

        let endpoint = ServiceEndpoint::new("test", "http://localhost:9999");
        gateway.register_service(endpoint).await;

        let stats = gateway.get_stats().await;
        assert!(stats["services"].get("test").is_some());
    }
}
