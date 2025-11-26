//! Request routing and load balancing

#![allow(dead_code)]

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Load balancing strategy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    RoundRobin,
    Random,
    LeastConnections,
    Weighted,
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        Self::RoundRobin
    }
}

/// Route definition
#[derive(Debug, Clone)]
pub struct Route {
    pub pattern: String,
    pub service: String,
    pub methods: Vec<String>,
    pub priority: i32,
    regex: Regex,
}

impl Route {
    /// Create a new route
    pub fn new(pattern: impl Into<String>, service: impl Into<String>) -> Self {
        let pattern = pattern.into();
        // Convert path parameters {param} to regex capture groups
        let regex_pattern = pattern
            .replace("{", "(?P<")
            .replace("}", ">[^/]+)");
        let regex = Regex::new(&format!("^{}$", regex_pattern))
            .unwrap_or_else(|_| Regex::new("^$").unwrap());

        Self {
            pattern,
            service: service.into(),
            methods: vec!["GET".to_string(), "POST".to_string()],
            priority: 0,
            regex,
        }
    }

    /// Set allowed methods
    pub fn with_methods(mut self, methods: Vec<&str>) -> Self {
        self.methods = methods.into_iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Check if route matches path and method
    pub fn matches(&self, path: &str, method: &str) -> Option<HashMap<String, String>> {
        if !self.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return None;
        }

        self.regex.captures(path).map(|caps| {
            self.regex
                .capture_names()
                .flatten()
                .filter_map(|name| {
                    caps.name(name)
                        .map(|m| (name.to_string(), m.as_str().to_string()))
                })
                .collect()
        })
    }
}

/// Service instance for load balancing
#[derive(Debug)]
pub struct ServiceInstance {
    pub url: String,
    pub weight: u32,
    pub connections: AtomicUsize,
    pub healthy: bool,
}

impl Clone for ServiceInstance {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            weight: self.weight,
            connections: AtomicUsize::new(self.connections.load(Ordering::SeqCst)),
            healthy: self.healthy,
        }
    }
}

impl ServiceInstance {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            weight: 1,
            connections: AtomicUsize::new(0),
            healthy: true,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn increment_connections(&self) {
        self.connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_connections(&self) {
        self.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Request router
pub struct Router {
    routes: Vec<Route>,
    services: HashMap<String, Vec<ServiceInstance>>,
    strategy: LoadBalanceStrategy,
    round_robin_indices: HashMap<String, AtomicUsize>,
}

impl Router {
    /// Create a new router
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            services: HashMap::new(),
            strategy: LoadBalanceStrategy::default(),
            round_robin_indices: HashMap::new(),
        }
    }

    /// Set load balancing strategy
    pub fn with_strategy(mut self, strategy: LoadBalanceStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Add a route
    pub fn add_route(&mut self, route: Route) {
        self.routes.push(route);
        // Sort by priority (higher first)
        self.routes.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Add a service instance
    pub fn add_service_instance(&mut self, service: impl Into<String>, instance: ServiceInstance) {
        let service = service.into();
        self.services
            .entry(service.clone())
            .or_insert_with(Vec::new)
            .push(instance);
        self.round_robin_indices
            .entry(service)
            .or_insert_with(|| AtomicUsize::new(0));
    }

    /// Match a path to a route
    pub fn match_route(&self, path: &str, method: &str) -> Option<(&Route, HashMap<String, String>)> {
        for route in &self.routes {
            if let Some(params) = route.matches(path, method) {
                return Some((route, params));
            }
        }
        None
    }

    /// Get service URL using load balancing
    pub fn get_service_url(&self, service: &str) -> Option<String> {
        let instances: Vec<_> = self
            .services
            .get(service)?
            .iter()
            .filter(|i| i.healthy)
            .collect();

        if instances.is_empty() {
            return None;
        }

        let selected = match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let index = self
                    .round_robin_indices
                    .get(service)
                    .map(|i| i.fetch_add(1, Ordering::SeqCst))
                    .unwrap_or(0);
                &instances[index % instances.len()]
            }
            LoadBalanceStrategy::Random => {
                use rand::Rng;
                let index = rand::thread_rng().gen_range(0..instances.len());
                &instances[index]
            }
            LoadBalanceStrategy::LeastConnections => {
                instances
                    .iter()
                    .min_by_key(|i| i.connection_count())
                    .unwrap()
            }
            LoadBalanceStrategy::Weighted => {
                use rand::Rng;
                let total_weight: u32 = instances.iter().map(|i| i.weight).sum();
                let mut r = rand::thread_rng().gen_range(0..total_weight);
                let mut selected = &instances[0];
                for instance in &instances {
                    if r < instance.weight {
                        selected = instance;
                        break;
                    }
                    r -= instance.weight;
                }
                selected
            }
        };

        Some(selected.url.clone())
    }

    /// Get all routes
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Create default R-YARA router
pub fn create_default_router() -> Router {
    let mut router = Router::new();

    // Dictionary routes
    router.add_route(Route::new("/api/v2/r-yara/dictionary/lookup", "dictionary"));
    router.add_route(Route::new("/api/v2/r-yara/dictionary/search", "dictionary"));
    router.add_route(Route::new("/api/v2/r-yara/dictionary/stats", "dictionary"));

    // Scanner routes
    router.add_route(Route::new("/api/v2/r-yara/scan/file", "scanner").with_methods(vec!["POST"]));
    router.add_route(Route::new("/api/v2/r-yara/scan/data", "scanner").with_methods(vec!["POST"]));
    router.add_route(
        Route::new("/api/v2/r-yara/rules/validate", "scanner").with_methods(vec!["POST"]),
    );
    router.add_route(
        Route::new("/api/v2/r-yara/rules/compile", "scanner").with_methods(vec!["POST"]),
    );

    // Transcoder routes
    router.add_route(
        Route::new("/api/v2/r-yara/transcode/encode", "transcoder").with_methods(vec!["POST"]),
    );
    router.add_route(
        Route::new("/api/v2/r-yara/transcode/decode", "transcoder").with_methods(vec!["POST"]),
    );

    // Feed scanner routes
    router.add_route(
        Route::new("/api/v2/r-yara/feed/scan/{use_case}", "feed-scanner")
            .with_methods(vec!["POST"]),
    );

    // Worker routes
    router.add_route(
        Route::new("/api/v2/r-yara/worker/task", "worker").with_methods(vec!["POST"]),
    );
    router.add_route(Route::new("/api/v2/r-yara/worker/task/{task_id}", "worker"));

    router
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_matching() {
        let route = Route::new("/api/v2/r-yara/scan/file", "scanner").with_methods(vec!["POST"]);

        assert!(route.matches("/api/v2/r-yara/scan/file", "POST").is_some());
        assert!(route.matches("/api/v2/r-yara/scan/file", "GET").is_none());
        assert!(route.matches("/api/v2/r-yara/scan/data", "POST").is_none());
    }

    #[test]
    fn test_route_with_params() {
        let route = Route::new("/api/v2/r-yara/worker/task/{task_id}", "worker");

        let params = route
            .matches("/api/v2/r-yara/worker/task/abc123", "GET")
            .unwrap();
        assert_eq!(params.get("task_id"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_router_matching() {
        let router = create_default_router();

        let (route, _) = router
            .match_route("/api/v2/r-yara/scan/file", "POST")
            .unwrap();
        assert_eq!(route.service, "scanner");
    }

    #[test]
    fn test_load_balancing() {
        let mut router = Router::new();
        router.add_service_instance("test", ServiceInstance::new("http://localhost:8001"));
        router.add_service_instance("test", ServiceInstance::new("http://localhost:8002"));

        // Round robin should cycle through instances
        let url1 = router.get_service_url("test").unwrap();
        let url2 = router.get_service_url("test").unwrap();

        assert_ne!(url1, url2);
    }
}
