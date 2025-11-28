//! API Gateway for R-YARA PYRO Platform
//!
//! Provides unified access to all R-YARA services with load balancing,
//! health monitoring, and request routing.

mod core;
mod routing;

pub use core::{Gateway, GatewayStats, ServiceEndpoint};
pub use routing::{
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    LoadBalanceStrategy, RetryConfig, Route, Router,
    ServiceInstance, ServiceInstanceWithBreaker,
    create_default_router,
};
