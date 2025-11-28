//! Request routing and load balancing

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tokio::time::Instant;

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

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is closed - requests flow through normally
    Closed,
    /// Circuit is open - requests are rejected immediately
    Open,
    /// Circuit is half-open - limited requests allowed to test recovery
    HalfOpen,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self::Closed
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Time in seconds before attempting recovery
    pub reset_timeout_secs: u64,
    /// Number of successes required to close circuit from half-open
    pub success_threshold: u32,
    /// Time window for counting failures
    pub window_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout_secs: 30,
            success_threshold: 3,
            window_secs: 60,
        }
    }
}

/// Circuit breaker for preventing cascading failures
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    failures: AtomicU64,
    successes: AtomicU64,
    last_failure: RwLock<Option<Instant>>,
    last_state_change: RwLock<Instant>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(CircuitState::Closed),
            failures: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            last_failure: RwLock::new(None),
            last_state_change: RwLock::new(Instant::now()),
        }
    }

    /// Check if request should be allowed
    pub fn should_allow(&self) -> bool {
        let state = *self.state.read().unwrap();
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                let last_change = *self.last_state_change.read().unwrap();
                if last_change.elapsed() >= Duration::from_secs(self.config.reset_timeout_secs) {
                    self.transition_to(CircuitState::HalfOpen);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let state = *self.state.read().unwrap();
        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failures.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let successes = self.successes.fetch_add(1, Ordering::SeqCst) + 1;
                if successes >= self.config.success_threshold as u64 {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        *self.last_failure.write().unwrap() = Some(Instant::now());
        let state = *self.state.read().unwrap();

        match state {
            CircuitState::Closed => {
                let failures = self.failures.fetch_add(1, Ordering::SeqCst) + 1;
                if failures >= self.config.failure_threshold as u64 {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Single failure in half-open state opens the circuit
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {}
        }
    }

    /// Transition to a new state
    fn transition_to(&self, new_state: CircuitState) {
        let mut state = self.state.write().unwrap();
        if *state != new_state {
            *state = new_state;
            *self.last_state_change.write().unwrap() = Instant::now();
            self.failures.store(0, Ordering::SeqCst);
            self.successes.store(0, Ordering::SeqCst);
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read().unwrap()
    }

    /// Get failure count
    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::SeqCst)
    }

    /// Reset the circuit breaker
    pub fn reset(&self) {
        self.transition_to(CircuitState::Closed);
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

/// Service instance with circuit breaker
pub struct ServiceInstanceWithBreaker {
    pub instance: ServiceInstance,
    pub circuit_breaker: CircuitBreaker,
    pub response_times: RwLock<Vec<Duration>>,
    pub last_health_check: RwLock<Option<DateTime<Utc>>>,
}

impl ServiceInstanceWithBreaker {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            instance: ServiceInstance::new(url),
            circuit_breaker: CircuitBreaker::default(),
            response_times: RwLock::new(Vec::with_capacity(100)),
            last_health_check: RwLock::new(None),
        }
    }

    pub fn with_circuit_breaker_config(mut self, config: CircuitBreakerConfig) -> Self {
        self.circuit_breaker = CircuitBreaker::new(config);
        self
    }

    pub fn record_response_time(&self, duration: Duration) {
        let mut times = self.response_times.write().unwrap();
        if times.len() >= 100 {
            times.remove(0);
        }
        times.push(duration);
    }

    pub fn average_response_time(&self) -> Option<Duration> {
        let times = self.response_times.read().unwrap();
        if times.is_empty() {
            None
        } else {
            let total: Duration = times.iter().sum();
            Some(total / times.len() as u32)
        }
    }

    pub fn is_available(&self) -> bool {
        self.instance.healthy && self.circuit_breaker.should_allow()
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base delay between retries in milliseconds
    pub base_delay_ms: u64,
    /// Maximum delay between retries in milliseconds
    pub max_delay_ms: u64,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate delay for a given retry attempt (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_ms = (self.base_delay_ms as f64 * self.backoff_multiplier.powi(attempt as i32)) as u64;
        Duration::from_millis(delay_ms.min(self.max_delay_ms))
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

    #[test]
    fn test_circuit_breaker_closed_state() {
        let breaker = CircuitBreaker::default();

        // Should start closed
        assert_eq!(breaker.state(), CircuitState::Closed);
        assert!(breaker.should_allow());

        // Record some successes
        breaker.record_success();
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new(config);

        // Record failures up to threshold
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Closed);
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Closed);
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Open);

        // Should not allow requests when open
        assert!(!breaker.should_allow());
    }

    #[test]
    fn test_circuit_breaker_success_resets_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new(config);

        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.failure_count(), 2);

        // Success resets failure count
        breaker.record_success();
        assert_eq!(breaker.failure_count(), 0);
    }

    #[test]
    fn test_retry_config_exponential_backoff() {
        let config = RetryConfig {
            base_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        // First attempt: 100ms
        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        // Second attempt: 200ms
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        // Third attempt: 400ms
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
        // Fourth attempt: 800ms
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(800));
    }

    #[test]
    fn test_retry_config_max_delay_cap() {
        let config = RetryConfig {
            base_delay_ms: 100,
            max_delay_ms: 500,
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        // Large attempt should be capped at max
        assert_eq!(config.delay_for_attempt(10), Duration::from_millis(500));
    }

    #[test]
    fn test_service_instance_with_breaker() {
        let instance = ServiceInstanceWithBreaker::new("http://localhost:8000");

        assert!(instance.is_available());
        assert!(instance.average_response_time().is_none());

        // Record some response times
        instance.record_response_time(Duration::from_millis(100));
        instance.record_response_time(Duration::from_millis(200));

        // Average should be 150ms
        let avg = instance.average_response_time().unwrap();
        assert_eq!(avg, Duration::from_millis(150));
    }

    #[test]
    fn test_service_instance_connection_tracking() {
        let instance = ServiceInstance::new("http://localhost:8000");

        assert_eq!(instance.connection_count(), 0);

        instance.increment_connections();
        instance.increment_connections();
        assert_eq!(instance.connection_count(), 2);

        instance.decrement_connections();
        assert_eq!(instance.connection_count(), 1);
    }

    #[test]
    fn test_least_connections_load_balancing() {
        let mut router = Router::new().with_strategy(LoadBalanceStrategy::LeastConnections);

        let instance1 = ServiceInstance::new("http://localhost:8001");
        instance1.increment_connections();
        instance1.increment_connections();

        let instance2 = ServiceInstance::new("http://localhost:8002");
        // instance2 has 0 connections

        router.add_service_instance("test", instance1);
        router.add_service_instance("test", instance2);

        // Should select instance with least connections
        let url = router.get_service_url("test").unwrap();
        assert_eq!(url, "http://localhost:8002");
    }
}
