//! API Gateway for R-YARA PYRO Platform
//!
//! Provides unified access to all R-YARA services with load balancing,
//! health monitoring, and request routing.

mod core;
mod routing;

pub use core::Gateway;
pub use routing::{Router, Route, LoadBalanceStrategy};
