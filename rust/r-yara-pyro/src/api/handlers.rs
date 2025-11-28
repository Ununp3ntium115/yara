//! API request handlers

use axum::{
    extract::{Extension, Path, Query},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::protocol::{TaskType, WorkerTask};
use crate::task_queue::TaskStatus;

use super::server::AppState;

// Import r-yara-scanner
use r_yara_scanner::{Scanner, MetaValue};

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
    pub offset: Option<u32>,
    pub field: Option<String>,
}

/// Dictionary search endpoint - Full implementation
pub async fn dictionary_search(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Query(params): Query<SearchQuery>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    let field = params.field.unwrap_or_else(|| "all".to_string());

    // Create search task for transcoder
    let payload: HashMap<String, serde_json::Value> = [
        ("query".to_string(), serde_json::Value::String(params.q.clone())),
        ("limit".to_string(), serde_json::Value::Number(limit.into())),
        ("offset".to_string(), serde_json::Value::Number(offset.into())),
        ("field".to_string(), serde_json::Value::String(field.clone())),
        ("operation".to_string(), serde_json::Value::String("search".to_string())),
    ]
    .into_iter()
    .collect();

    let task = WorkerTask::new(TaskType::DictionaryLookup, payload);
    let result = state.transcoder.process_task(task).await;

    if result.success {
        Json(result.data.unwrap_or(serde_json::json!({
            "results": [],
            "query": params.q,
            "limit": limit,
            "offset": offset,
            "count": 0
        })))
    } else {
        Json(serde_json::json!({
            "results": [],
            "query": params.q,
            "limit": limit,
            "offset": offset,
            "count": 0,
            "error": result.error
        }))
    }
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

/// Feed scan request body
#[derive(Deserialize)]
pub struct FeedScanRequest {
    pub feeds: Option<Vec<String>>,
    pub max_rules: Option<u32>,
    pub include_raw: Option<bool>,
}

/// Feed scan endpoint - Full implementation with r-yara-feed-scanner integration
pub async fn scan_feeds(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Path(use_case): Path<String>,
    Json(request): Json<Option<FeedScanRequest>>,
) -> Json<serde_json::Value> {
    let state = state.read().await;
    let request = request.unwrap_or(FeedScanRequest {
        feeds: None,
        max_rules: None,
        include_raw: None,
    });

    // Default feeds by use case
    let default_feeds = match use_case.as_str() {
        "malware" => vec![
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/",
        ],
        "apt" => vec![
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_",
        ],
        "ransomware" => vec![
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_",
        ],
        "webshell" => vec![
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells",
        ],
        _ => vec![],
    };

    let feeds: Vec<String> = request.feeds.unwrap_or_else(|| {
        default_feeds.iter().map(|s| s.to_string()).collect()
    });

    let max_rules = request.max_rules.unwrap_or(100);
    let include_raw = request.include_raw.unwrap_or(false);

    // Create feed scan task
    let payload: HashMap<String, serde_json::Value> = [
        ("use_case".to_string(), serde_json::Value::String(use_case.clone())),
        ("feeds".to_string(), serde_json::json!(feeds)),
        ("max_rules".to_string(), serde_json::Value::Number(max_rules.into())),
        ("include_raw".to_string(), serde_json::Value::Bool(include_raw)),
    ]
    .into_iter()
    .collect();

    let task = WorkerTask::new(TaskType::ScanFeeds, payload);
    let result = state.scanner.process_task(task).await;

    if result.success {
        Json(result.data.unwrap_or(serde_json::json!({
            "success": true,
            "use_case": use_case,
            "rules": [],
            "rule_count": 0
        })))
    } else {
        Json(serde_json::json!({
            "success": false,
            "use_case": use_case,
            "rules": [],
            "rule_count": 0,
            "error": result.error
        }))
    }
}

/// Submit task request
#[derive(Deserialize)]
pub struct SubmitTaskRequest {
    pub task_type: String,
    pub payload: HashMap<String, serde_json::Value>,
    pub priority: Option<u8>,
    pub timeout_ms: Option<u64>,
}

/// Submit task endpoint - Full async task queue implementation
pub async fn submit_task(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<SubmitTaskRequest>,
) -> Json<serde_json::Value> {
    // Parse task type
    let task_type = match request.task_type.as_str() {
        "scan_file" => TaskType::ScanFile,
        "scan_data" => TaskType::ScanData,
        "validate_rule" => TaskType::ValidateRule,
        "compile_rules" => TaskType::CompileRules,
        "transcode" => TaskType::Transcode,
        "dictionary_lookup" => TaskType::DictionaryLookup,
        "feed_scan" | "scan_feeds" => TaskType::ScanFeeds,
        _ => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Unknown task type: {}", request.task_type)
            }));
        }
    };

    let priority = request.priority.unwrap_or(5);
    let task = WorkerTask::new(task_type, request.payload);
    let task_id = task.task_id.clone();

    // Queue task for async processing
    let state = state.read().await;
    match state.task_queue.submit(task, priority).await {
        Ok(id) => {
            Json(serde_json::json!({
                "success": true,
                "task_id": id,
                "status": "queued",
                "priority": priority,
                "message": "Task queued for processing"
            }))
        }
        Err(e) => {
            Json(serde_json::json!({
                "success": false,
                "task_id": task_id,
                "error": e
            }))
        }
    }
}

/// Get task status endpoint - Full implementation
pub async fn get_task_status(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Path(task_id): Path<String>,
) -> Json<serde_json::Value> {
    let state = state.read().await;

    match state.task_queue.get_status(&task_id).await {
        Some(entry) => {
            let status_str = match entry.status {
                TaskStatus::Queued => "queued",
                TaskStatus::Running => "running",
                TaskStatus::Completed => "completed",
                TaskStatus::Failed => "failed",
                TaskStatus::Cancelled => "cancelled",
            };

            let mut response = serde_json::json!({
                "task_id": entry.task_id,
                "task_type": format!("{:?}", entry.task_type),
                "status": status_str,
                "priority": entry.priority,
                "created_at": entry.created_at.to_rfc3339(),
            });

            if let Some(started_at) = entry.started_at {
                response["started_at"] = serde_json::Value::String(started_at.to_rfc3339());
            }

            if let Some(completed_at) = entry.completed_at {
                response["completed_at"] = serde_json::Value::String(completed_at.to_rfc3339());
            }

            if let Some(result) = entry.result {
                response["result"] = serde_json::json!({
                    "success": result.success,
                    "data": result.data,
                    "error": result.error,
                    "execution_time_ms": result.execution_time_ms
                });
            }

            if let Some(error) = entry.error {
                response["error"] = serde_json::Value::String(error);
            }

            Json(response)
        }
        None => {
            Json(serde_json::json!({
                "task_id": task_id,
                "status": "not_found",
                "message": "Task not found"
            }))
        }
    }
}

/// List recent tasks endpoint
pub async fn list_tasks(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let state = state.read().await;
    let limit: usize = params
        .get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(20);

    let tasks = state.task_queue.list_recent(limit).await;

    let task_list: Vec<serde_json::Value> = tasks
        .into_iter()
        .map(|entry| {
            let status_str = match entry.status {
                TaskStatus::Queued => "queued",
                TaskStatus::Running => "running",
                TaskStatus::Completed => "completed",
                TaskStatus::Failed => "failed",
                TaskStatus::Cancelled => "cancelled",
            };

            serde_json::json!({
                "task_id": entry.task_id,
                "task_type": format!("{:?}", entry.task_type),
                "status": status_str,
                "priority": entry.priority,
                "created_at": entry.created_at.to_rfc3339(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "tasks": task_list,
        "count": task_list.len(),
        "queue_stats": state.task_queue.stats().await
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

/// Batch scan request
#[derive(Deserialize)]
pub struct BatchScanRequest {
    pub files: Vec<String>,
    pub rules: Option<String>,
    pub rules_file: Option<String>,
}

/// Batch scan endpoint - Scan multiple files with r-yara-scanner
pub async fn batch_scan(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<BatchScanRequest>,
) -> Json<serde_json::Value> {
    // Get rules source
    let rules = match (&request.rules, &request.rules_file) {
        (Some(r), _) => r.clone(),
        (None, Some(rf)) => match tokio::fs::read_to_string(rf).await {
            Ok(content) => content,
            Err(e) => {
                return Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to read rules file: {}", e)
                }));
            }
        },
        _ => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Missing rules or rules_file"
            }));
        }
    };

    // Create scanner
    let scanner = match Scanner::new(&rules) {
        Ok(s) => s,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to compile rules: {}", e)
            }));
        }
    };

    // Scan all files
    let mut results = Vec::new();
    for file_path in &request.files {
        match scanner.scan_file(file_path) {
            Ok(matches) => {
                let matches_json: Vec<serde_json::Value> = matches
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "rule": m.rule_name.as_str(),
                            "tags": m.tags.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                            "strings": m.strings.iter().map(|s| {
                                serde_json::json!({
                                    "identifier": s.identifier.as_str(),
                                    "offsets": s.offsets
                                })
                            }).collect::<Vec<_>>(),
                            "meta": m.meta.iter().map(|(k, v)| {
                                let value = match v {
                                    MetaValue::String(s) => serde_json::Value::String(s.to_string()),
                                    MetaValue::Integer(i) => serde_json::Value::Number((*i).into()),
                                    MetaValue::Boolean(b) => serde_json::Value::Bool(*b),
                                    MetaValue::Float(f) => serde_json::json!(f),
                                };
                                (k.as_str(), value)
                            }).collect::<HashMap<_, _>>()
                        })
                    })
                    .collect();

                results.push(serde_json::json!({
                    "file": file_path,
                    "success": true,
                    "matches": matches_json,
                    "match_count": matches.len()
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "file": file_path,
                    "success": false,
                    "error": e.to_string()
                }));
            }
        }
    }

    Json(serde_json::json!({
        "success": true,
        "results": results,
        "total_files": request.files.len()
    }))
}

/// Scan directory request
#[derive(Deserialize)]
pub struct ScanDirectoryRequest {
    pub directory: String,
    pub recursive: Option<bool>,
    pub rules: Option<String>,
    pub rules_file: Option<String>,
}

/// Scan directory endpoint - Scan all files in a directory with r-yara-scanner
pub async fn scan_directory(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
    Json(request): Json<ScanDirectoryRequest>,
) -> Json<serde_json::Value> {
    // Get rules source
    let rules = match (&request.rules, &request.rules_file) {
        (Some(r), _) => r.clone(),
        (None, Some(rf)) => match tokio::fs::read_to_string(rf).await {
            Ok(content) => content,
            Err(e) => {
                return Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to read rules file: {}", e)
                }));
            }
        },
        _ => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Missing rules or rules_file"
            }));
        }
    };

    // Create scanner
    let scanner = match Scanner::new(&rules) {
        Ok(s) => s,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to compile rules: {}", e)
            }));
        }
    };

    // Scan directory
    let recursive = request.recursive.unwrap_or(false);
    match scanner.scan_directory(&request.directory, recursive) {
        Ok(results) => {
            let results_json: Vec<serde_json::Value> = results
                .iter()
                .map(|result| {
                    if let Some(err) = &result.error {
                        serde_json::json!({
                            "file": result.path.display().to_string(),
                            "success": false,
                            "error": err.to_string()
                        })
                    } else {
                        let matches_json: Vec<serde_json::Value> = result.matches
                            .iter()
                            .map(|m| {
                                serde_json::json!({
                                    "rule": m.rule_name.as_str(),
                                    "tags": m.tags.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                                    "strings": m.strings.iter().map(|s| {
                                        serde_json::json!({
                                            "identifier": s.identifier.as_str(),
                                            "offsets": s.offsets
                                        })
                                    }).collect::<Vec<_>>()
                                })
                            })
                            .collect();

                        serde_json::json!({
                            "file": result.path.display().to_string(),
                            "success": true,
                            "matches": matches_json,
                            "match_count": result.matches.len()
                        })
                    }
                })
                .collect();

            Json(serde_json::json!({
                "success": true,
                "directory": request.directory,
                "recursive": recursive,
                "results": results_json,
                "total_files": results.len()
            }))
        }
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": format!("Directory scan failed: {}", e)
        })),
    }
}

/// List modules endpoint
pub async fn list_modules() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "success": true,
        "modules": [
            {
                "name": "pe",
                "description": "Portable Executable (Windows) file analysis",
                "functions": ["is_pe", "is_dll", "exports", "imports", "sections", "resources"]
            },
            {
                "name": "elf",
                "description": "Executable and Linkable Format (Linux/Unix) file analysis",
                "functions": ["is_elf", "type", "machine", "sections", "segments"]
            },
            {
                "name": "macho",
                "description": "Mach-O (macOS) file analysis",
                "functions": ["is_macho", "file_type", "commands"]
            },
            {
                "name": "dex",
                "description": "Android DEX file analysis",
                "functions": ["is_dex", "classes", "methods"]
            },
            {
                "name": "hash",
                "description": "Cryptographic hash functions",
                "functions": ["md5", "sha1", "sha256", "crc32"]
            },
            {
                "name": "math",
                "description": "Mathematical operations",
                "functions": ["entropy", "mean", "min", "max"]
            }
        ]
    }))
}

/// Load rules request
#[derive(Deserialize)]
pub struct LoadRulesRequest {
    pub rules: Option<String>,
    pub rules_file: Option<String>,
}

/// Load rules endpoint
pub async fn load_rules(
    Json(request): Json<LoadRulesRequest>,
) -> Json<serde_json::Value> {
    // Get rules source
    let rules = match (&request.rules, &request.rules_file) {
        (Some(r), _) => r.clone(),
        (None, Some(rf)) => match tokio::fs::read_to_string(rf).await {
            Ok(content) => content,
            Err(e) => {
                return Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to read rules file: {}", e)
                }));
            }
        },
        _ => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Missing rules or rules_file"
            }));
        }
    };

    // Try to compile rules to validate
    match Scanner::new(&rules) {
        Ok(scanner) => {
            Json(serde_json::json!({
                "success": true,
                "message": "Rules loaded successfully",
                "rule_count": scanner.rule_count(),
                "pattern_count": scanner.pattern_count()
            }))
        }
        Err(e) => {
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to load rules: {}", e)
            }))
        }
    }
}

/// List rules endpoint - returns info about loaded rules
pub async fn list_rules(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
) -> Json<serde_json::Value> {
    // Note: This endpoint returns available rule information
    // In a production system, you would track loaded rules in a shared state
    Json(serde_json::json!({
        "success": true,
        "message": "Use POST /rules/load to load rules, then scan with them",
        "info": "Rules are compiled on-demand for each scan operation"
    }))
}
