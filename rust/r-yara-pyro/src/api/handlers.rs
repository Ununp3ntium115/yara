//! API request handlers

use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::protocol::{TaskType, WorkerTask};

use super::server::AppState;

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

/// Health check endpoint
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "r-yara".to_string(),
        version: crate::VERSION.to_string(),
    })
}

/// Dictionary lookup query params
#[derive(Deserialize)]
pub struct LookupQuery {
    pub query: String,
    #[serde(rename = "type")]
    pub lookup_type: Option<String>,
}

/// Dictionary lookup endpoint
pub async fn dictionary_lookup(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Query(params): Query<LookupQuery>,
) -> Json<serde_json::Value> {
    let state = state.read().await;
    let payload: HashMap<String, serde_json::Value> = [
        ("query".to_string(), serde_json::Value::String(params.query)),
        (
            "type".to_string(),
            serde_json::Value::String(params.lookup_type.unwrap_or_else(|| "codename".to_string())),
        ),
    ]
    .into_iter()
    .collect();

    let task = WorkerTask::new(TaskType::DictionaryLookup, payload);
    let result = state.transcoder.process_task(task).await;

    Json(result.data.unwrap_or(serde_json::json!({"found": false})))
}

/// Dictionary search query params
#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<u32>,
}

/// Dictionary search endpoint
pub async fn dictionary_search(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
    Query(params): Query<SearchQuery>,
) -> Json<serde_json::Value> {
    // TODO: Implement full search
    Json(serde_json::json!({
        "results": [],
        "query": params.q,
        "limit": params.limit.unwrap_or(50),
        "count": 0
    }))
}

/// Dictionary stats endpoint
pub async fn dictionary_stats(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
) -> Json<serde_json::Value> {
    let state = state.read().await;
    Json(state.transcoder.dictionary_stats().await)
}

/// Scan file request
#[derive(Deserialize)]
pub struct ScanFileRequest {
    pub file_path: String,
    pub rules: Option<String>,
    pub rules_file: Option<String>,
}

/// Scan file endpoint
pub async fn scan_file(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<ScanFileRequest>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    let mut payload: HashMap<String, serde_json::Value> = HashMap::new();
    payload.insert(
        "file_path".to_string(),
        serde_json::Value::String(request.file_path),
    );
    if let Some(rules) = request.rules {
        payload.insert("rules".to_string(), serde_json::Value::String(rules));
    }
    if let Some(rules_file) = request.rules_file {
        payload.insert(
            "rules_file".to_string(),
            serde_json::Value::String(rules_file),
        );
    }

    let task = WorkerTask::new(TaskType::ScanFile, payload);
    let result = state.scanner.process_task(task).await;

    Json(serde_json::json!({
        "success": result.success,
        "data": result.data,
        "error": result.error,
        "execution_time_ms": result.execution_time_ms
    }))
}

/// Scan data request
#[derive(Deserialize)]
pub struct ScanDataRequest {
    pub data: String,
    pub rules: Option<String>,
    pub rules_file: Option<String>,
}

/// Scan data endpoint
pub async fn scan_data(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<ScanDataRequest>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    let mut payload: HashMap<String, serde_json::Value> = HashMap::new();
    payload.insert("data".to_string(), serde_json::Value::String(request.data));
    if let Some(rules) = request.rules {
        payload.insert("rules".to_string(), serde_json::Value::String(rules));
    }
    if let Some(rules_file) = request.rules_file {
        payload.insert(
            "rules_file".to_string(),
            serde_json::Value::String(rules_file),
        );
    }

    let task = WorkerTask::new(TaskType::ScanData, payload);
    let result = state.scanner.process_task(task).await;

    Json(serde_json::json!({
        "success": result.success,
        "data": result.data,
        "error": result.error,
        "execution_time_ms": result.execution_time_ms
    }))
}

/// Validate rule request
#[derive(Deserialize)]
pub struct ValidateRuleRequest {
    pub rule: String,
}

/// Validate rule endpoint
pub async fn validate_rule(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<ValidateRuleRequest>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    let payload: HashMap<String, serde_json::Value> =
        [("rule".to_string(), serde_json::Value::String(request.rule))]
            .into_iter()
            .collect();

    let task = WorkerTask::new(TaskType::ValidateRule, payload);
    let result = state.scanner.process_task(task).await;

    Json(serde_json::json!({
        "success": result.success,
        "data": result.data,
        "error": result.error
    }))
}

/// Compile rules request
#[derive(Deserialize)]
pub struct CompileRulesRequest {
    pub rules: String,
    pub output_path: Option<String>,
    pub return_data: Option<bool>,
}

/// Compile rules endpoint
pub async fn compile_rules(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<CompileRulesRequest>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    let mut payload: HashMap<String, serde_json::Value> = HashMap::new();
    payload.insert("rules".to_string(), serde_json::Value::String(request.rules));
    if let Some(path) = request.output_path {
        payload.insert("output_path".to_string(), serde_json::Value::String(path));
    }
    if let Some(return_data) = request.return_data {
        payload.insert("return_data".to_string(), serde_json::Value::Bool(return_data));
    }

    let task = WorkerTask::new(TaskType::CompileRules, payload);
    let result = state.scanner.process_task(task).await;

    Json(serde_json::json!({
        "success": result.success,
        "data": result.data,
        "error": result.error
    }))
}

/// Transcode request
#[derive(Deserialize)]
pub struct TranscodeRequest {
    pub rule: String,
}

/// Transcode encode endpoint
pub async fn transcode_encode(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<TranscodeRequest>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    let payload: HashMap<String, serde_json::Value> = [
        ("rule".to_string(), serde_json::Value::String(request.rule)),
        (
            "direction".to_string(),
            serde_json::Value::String("encode".to_string()),
        ),
    ]
    .into_iter()
    .collect();

    let task = WorkerTask::new(TaskType::Transcode, payload);
    let result = state.transcoder.process_task(task).await;

    Json(serde_json::json!({
        "success": result.success,
        "data": result.data,
        "error": result.error
    }))
}

/// Transcode decode endpoint
pub async fn transcode_decode(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<TranscodeRequest>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    let payload: HashMap<String, serde_json::Value> = [
        ("rule".to_string(), serde_json::Value::String(request.rule)),
        (
            "direction".to_string(),
            serde_json::Value::String("decode".to_string()),
        ),
    ]
    .into_iter()
    .collect();

    let task = WorkerTask::new(TaskType::Transcode, payload);
    let result = state.transcoder.process_task(task).await;

    Json(serde_json::json!({
        "success": result.success,
        "data": result.data,
        "error": result.error
    }))
}

/// Feed scan endpoint
pub async fn scan_feeds(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
    Path(use_case): Path<String>,
) -> Json<serde_json::Value> {
    // TODO: Integrate with feed scanner
    Json(serde_json::json!({
        "success": true,
        "use_case": use_case,
        "rules": [],
        "rule_count": 0,
        "message": "Feed scanning available via r-yara-feed-scanner"
    }))
}

/// Submit task request
#[derive(Deserialize)]
pub struct SubmitTaskRequest {
    pub task_type: String,
    pub payload: HashMap<String, serde_json::Value>,
    pub priority: Option<u8>,
    pub timeout_ms: Option<u64>,
}

/// Submit task endpoint
pub async fn submit_task(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<SubmitTaskRequest>,
) -> Json<serde_json::Value> {
    let task_id = uuid::Uuid::new_v4().to_string();

    // TODO: Queue task for async processing
    Json(serde_json::json!({
        "success": true,
        "task_id": task_id,
        "status": "queued",
        "message": "Task queued for processing"
    }))
}

/// Get task status endpoint
pub async fn get_task_status(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
    Path(task_id): Path<String>,
) -> Json<serde_json::Value> {
    // TODO: Look up task status
    Json(serde_json::json!({
        "task_id": task_id,
        "status": "unknown",
        "message": "Task tracking not yet implemented"
    }))
}

/// Get stats endpoint
pub async fn get_stats(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    Json(serde_json::json!({
        "scanner": state.scanner.stats().await,
        "transcoder": state.transcoder.stats().await,
        "version": crate::VERSION
    }))
}
