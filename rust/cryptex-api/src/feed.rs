/// YARA Feed Scanner API endpoints

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use yara_feed_scanner::{DiscoveredRule, FeedScanner};

#[derive(Deserialize)]
struct ScanRequest {
    output: Option<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    success: bool,
    rules: Vec<DiscoveredRule>,
    rule_count: usize,
    use_case: String,
}

use crate::AppState;

/// Scan all sources
pub async fn scan_all(
    State(state): State<AppState>,
    Json(_request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scanner = state.scanner.read().await;
    let rules = scanner.scan_all().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ScanResponse {
        success: true,
        rule_count: rules.len(),
        rules,
        use_case: "all".to_string(),
    }))
}

/// Scan for new tasks
pub async fn scan_new_tasks(
    State(state): State<AppState>,
    Json(_request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scanner = state.scanner.read().await;
    let rules = scanner.scan_for_new_tasks().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ScanResponse {
        success: true,
        rule_count: rules.len(),
        rules,
        use_case: "new_tasks".to_string(),
    }))
}

/// Scan for old tasks
pub async fn scan_old_tasks(
    State(state): State<AppState>,
    Json(_request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scanner = state.scanner.read().await;
    let rules = scanner.scan_for_old_tasks().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ScanResponse {
        success: true,
        rule_count: rules.len(),
        rules,
        use_case: "old_tasks".to_string(),
    }))
}

/// Scan for malware detection
pub async fn scan_malware(
    State(state): State<AppState>,
    Json(_request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scanner = state.scanner.read().await;
    let rules = scanner.scan_for_malware_detection().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ScanResponse {
        success: true,
        rule_count: rules.len(),
        rules,
        use_case: "malware".to_string(),
    }))
}

/// Scan for APT detection
pub async fn scan_apt(
    State(state): State<AppState>,
    Json(_request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scanner = state.scanner.read().await;
    let rules = scanner.scan_for_apt_detection().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ScanResponse {
        success: true,
        rule_count: rules.len(),
        rules,
        use_case: "apt".to_string(),
    }))
}

/// Scan for ransomware detection
pub async fn scan_ransomware(
    State(state): State<AppState>,
    Json(_request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    let scanner = state.scanner.read().await;
    let rules = scanner.scan_for_ransomware_detection().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ScanResponse {
        success: true,
        rule_count: rules.len(),
        rules,
        use_case: "ransomware".to_string(),
    }))
}

/// Create feed scanner router
pub fn create_router(_scanner: Arc<RwLock<FeedScanner>>) -> Router<AppState> {
    Router::new()
        .route("/api/v2/yara/feed/scan/all", post(scan_all))
        .route("/api/v2/yara/feed/scan/new-tasks", post(scan_new_tasks))
        .route("/api/v2/yara/feed/scan/old-tasks", post(scan_old_tasks))
        .route("/api/v2/yara/feed/scan/malware", post(scan_malware))
        .route("/api/v2/yara/feed/scan/apt", post(scan_apt))
        .route("/api/v2/yara/feed/scan/ransomware", post(scan_ransomware))
}

