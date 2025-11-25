//! API Server implementation

use axum::{
    routing::{get, post},
    Router,
    Extension,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::config::RYaraConfig;
use crate::workers::{ScannerWorker, TranscoderWorker};

use super::handlers;
use super::routes;

/// Shared application state
pub struct AppState {
    pub config: RYaraConfig,
    pub scanner: ScannerWorker,
    pub transcoder: TranscoderWorker,
}

impl AppState {
    pub fn new(config: RYaraConfig) -> Self {
        Self {
            config,
            scanner: ScannerWorker::new(),
            transcoder: TranscoderWorker::new(),
        }
    }
}

/// R-YARA API Server
pub struct ApiServer {
    config: RYaraConfig,
    state: Arc<RwLock<AppState>>,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(config: RYaraConfig) -> Self {
        let state = Arc::new(RwLock::new(AppState::new(config.clone())));
        Self { config, state }
    }

    /// Create the router with all routes
    pub fn create_router(&self) -> Router {
        let state = self.state.clone();
        let prefix = &self.config.api.prefix;

        // CORS configuration
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        // Build routes
        let api_routes = Router::new()
            // Health
            .route("/health", get(handlers::health))
            // Dictionary
            .route("/dictionary/lookup", get(handlers::dictionary_lookup))
            .route("/dictionary/search", get(handlers::dictionary_search))
            .route("/dictionary/stats", get(handlers::dictionary_stats))
            // Scanning
            .route("/scan/file", post(handlers::scan_file))
            .route("/scan/data", post(handlers::scan_data))
            // Rules
            .route("/rules/validate", post(handlers::validate_rule))
            .route("/rules/compile", post(handlers::compile_rules))
            // Transcoding
            .route("/transcode/encode", post(handlers::transcode_encode))
            .route("/transcode/decode", post(handlers::transcode_decode))
            // Feed scanning
            .route("/feed/scan/:use_case", post(handlers::scan_feeds))
            // Worker
            .route("/worker/task", post(handlers::submit_task))
            .route("/worker/task/:task_id", get(handlers::get_task_status))
            // Stats
            .route("/stats", get(handlers::get_stats));

        Router::new()
            .nest(prefix, api_routes)
            .layer(Extension(state))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
    }

    /// Run the server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = self.config.api_address().parse()?;
        let router = self.create_router();

        info!("R-YARA API server starting on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;

        Ok(())
    }

    /// Run the server with graceful shutdown
    pub async fn run_with_shutdown(
        self,
        shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let addr: SocketAddr = self.config.api_address().parse()?;
        let router = self.create_router();

        info!("R-YARA API server starting on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal)
            .await;

        info!("R-YARA API server stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        let config = RYaraConfig::default();
        let state = AppState::new(config);
        assert_eq!(state.scanner.worker_type(), "r-yara-scanner");
    }

    #[test]
    fn test_server_creation() {
        let config = RYaraConfig::default();
        let server = ApiServer::new(config);
        let _ = server.create_router();
    }
}
