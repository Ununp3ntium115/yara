//! R-YARA PYRO Platform Integration
//!
//! This crate provides R-YARA capabilities as an installable component
//! for PYRO Platform workers, APIs, and endpoints.
//!
//! # Components
//!
//! - `protocol` - Streaming and worker communication protocols
//! - `config` - Configuration management
//! - `workers` - Worker implementations for distributed processing
//! - `api` - API server and client components
//! - `gateway` - API gateway for unified access
//! - `task_queue` - Async task queue for distributed processing
//! - `pyro_connection` - PYRO Platform connectivity
//! - `hashing` - Comprehensive cryptographic hashing (PYRO signatures)

pub mod protocol;
pub mod config;
pub mod workers;
pub mod api;
pub mod gateway;
pub mod task_queue;
pub mod pyro_connection;
pub mod hashing;

pub use protocol::{StreamMessage, MessageType, WorkerTask, TaskType, TaskResult};
pub use config::RYaraConfig;
pub use workers::{Worker, ScannerWorker, TranscoderWorker};
pub use api::{ApiServer, ApiClient};
pub use gateway::Gateway;
pub use task_queue::TaskQueue;
pub use pyro_connection::PyroConnection;
pub use hashing::{PyroSignature, HashAlgorithm};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// PYRO component identifier - Pyro Fire Hydrant API
pub const PYRO_COMPONENT: &str = "pyro-fire-hydrant";
