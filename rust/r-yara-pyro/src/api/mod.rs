//! API server and client for R-YARA PYRO Platform
//!
//! Provides HTTP REST API and WebSocket endpoints for R-YARA operations.

mod server;
mod client;
mod handlers;
mod routes;

pub use server::ApiServer;
pub use client::ApiClient;
pub use handlers::*;
pub use routes::create_router;
