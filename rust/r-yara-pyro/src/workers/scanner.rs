//! Scanner worker implementation
//!
//! Handles YARA rule scanning, validation, and compilation tasks.
//! Now powered by r-yara-scanner for unified YARA scanning.

use std::path::PathBuf;
use std::time::Instant;
use tokio::process::Command;

use crate::protocol::{TaskResult, TaskType, WorkerTask};

use super::base::{BaseWorker, WorkerState, WorkerStats};

// Import r-yara-scanner
use r_yara_scanner::{Scanner, MetaValue};

/// Scanner worker for YARA operations
/// Now powered by r-yara-scanner - no external binaries needed!
pub struct ScannerWorker {
    base: BaseWorker,
    // Keep yarac for compile_rules (fallback for binary output)
    yarac_binary: Option<PathBuf>,
}

impl ScannerWorker {
    /// Create a new scanner worker
    pub fn new() -> Self {
        let base = BaseWorker::new(
            "r-yara-scanner",
            vec![
                TaskType::ScanFile,
                TaskType::ScanData,
                TaskType::ValidateRule,
                TaskType::CompileRules,
            ],
        );

        // Only look for yarac for compile_rules (binary output)
        let yarac_binary = Self::find_binary("yarac");

        Self {
            base,
            yarac_binary,
        }
    }

    /// Find a binary in PATH or known locations
    fn find_binary(name: &str) -> Option<PathBuf> {
        // Check if binary is in PATH
        if let Ok(output) = std::process::Command::new("which")
            .arg(name)
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
        }

        // Check known locations
        let locations = vec![
            format!("/usr/bin/{}", name),
            format!("/usr/local/bin/{}", name),
            format!("/opt/yara/bin/{}", name),
        ];

        for loc in locations {
            let path = PathBuf::from(&loc);
            if path.exists() {
                return Some(path);
            }
        }

        None
    }

    /// Get worker ID
    pub fn worker_id(&self) -> &str {
        &self.base.worker_id
    }

    /// Get worker type
    pub fn worker_type(&self) -> &str {
        &self.base.worker_type
    }

    /// Get capabilities
    pub fn capabilities(&self) -> Vec<TaskType> {
        self.base.capabilities.clone()
    }

    /// Get current state
    pub async fn state(&self) -> WorkerState {
        self.base.get_state().await
    }

    /// Get statistics
    pub async fn stats(&self) -> WorkerStats {
        self.base.get_stats().await
    }

    /// Process a task
    pub async fn process_task(&self, task: WorkerTask) -> TaskResult {
        let start = Instant::now();
        self.base.task_started(&task).await;

        let result = match task.task_type {
            TaskType::ScanFile => self.scan_file(&task).await,
            TaskType::ScanData => self.scan_data(&task).await,
            TaskType::ValidateRule => self.validate_rule(&task).await,
            TaskType::CompileRules => self.compile_rules(&task).await,
            _ => TaskResult::failure(&task.task_id, "Unsupported task type"),
        };

        let elapsed = start.elapsed().as_millis() as u64;
        self.base
            .task_completed(&task.task_id, result.success, elapsed)
            .await;

        result.with_execution_time(elapsed)
    }

    /// Scan a file with YARA rules using r-yara-scanner
    async fn scan_file(&self, task: &WorkerTask) -> TaskResult {
        let file_path = match task.payload.get("file_path") {
            Some(serde_json::Value::String(p)) => p,
            _ => return TaskResult::failure(&task.task_id, "Missing file_path in payload"),
        };

        let rules = task.payload.get("rules");
        let rules_file = task.payload.get("rules_file");

        // Get rules source
        let rules_source = match (rules, rules_file) {
            (Some(serde_json::Value::String(r)), _) => r.clone(),
            (_, Some(serde_json::Value::String(rf))) => {
                match tokio::fs::read_to_string(rf).await {
                    Ok(content) => content,
                    Err(e) => {
                        return TaskResult::failure(
                            &task.task_id,
                            format!("Failed to read rules file: {}", e),
                        );
                    }
                }
            }
            _ => return TaskResult::failure(&task.task_id, "Missing rules or rules_file in payload"),
        };

        // Create scanner
        let scanner = match Scanner::new(&rules_source) {
            Ok(s) => s,
            Err(e) => {
                return TaskResult::failure(
                    &task.task_id,
                    format!("Failed to compile rules: {}", e),
                );
            }
        };

        // Scan file
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
                            }).collect::<std::collections::HashMap<_, _>>()
                        })
                    })
                    .collect();

                TaskResult::success(
                    &task.task_id,
                    serde_json::json!({
                        "matches": matches_json,
                        "match_count": matches.len(),
                        "file_path": file_path
                    }),
                )
            }
            Err(e) => TaskResult::failure(&task.task_id, format!("Scan failed: {}", e)),
        }
    }

    /// Scan raw data with YARA rules using r-yara-scanner
    async fn scan_data(&self, task: &WorkerTask) -> TaskResult {
        let data = match task.payload.get("data") {
            Some(serde_json::Value::String(d)) => d,
            _ => return TaskResult::failure(&task.task_id, "Missing data in payload"),
        };

        let rules = task.payload.get("rules");
        let rules_file = task.payload.get("rules_file");

        // Get rules source
        let rules_source = match (rules, rules_file) {
            (Some(serde_json::Value::String(r)), _) => r.clone(),
            (_, Some(serde_json::Value::String(rf))) => {
                match tokio::fs::read_to_string(rf).await {
                    Ok(content) => content,
                    Err(e) => {
                        return TaskResult::failure(
                            &task.task_id,
                            format!("Failed to read rules file: {}", e),
                        );
                    }
                }
            }
            _ => return TaskResult::failure(&task.task_id, "Missing rules or rules_file in payload"),
        };

        // Create scanner
        let scanner = match Scanner::new(&rules_source) {
            Ok(s) => s,
            Err(e) => {
                return TaskResult::failure(
                    &task.task_id,
                    format!("Failed to compile rules: {}", e),
                );
            }
        };

        // Scan data
        match scanner.scan_bytes(data.as_bytes()) {
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
                            }).collect::<std::collections::HashMap<_, _>>()
                        })
                    })
                    .collect();

                TaskResult::success(
                    &task.task_id,
                    serde_json::json!({
                        "matches": matches_json,
                        "match_count": matches.len()
                    }),
                )
            }
            Err(e) => TaskResult::failure(&task.task_id, format!("Scan failed: {}", e)),
        }
    }

    /// Validate YARA rule syntax using r-yara-scanner
    async fn validate_rule(&self, task: &WorkerTask) -> TaskResult {
        let rule = match task.payload.get("rule") {
            Some(serde_json::Value::String(r)) => r,
            _ => return TaskResult::failure(&task.task_id, "Missing rule in payload"),
        };

        // Try to compile the rule
        match Scanner::new(rule) {
            Ok(_) => TaskResult::success(
                &task.task_id,
                serde_json::json!({
                    "valid": true,
                    "message": "Rule is valid"
                }),
            ),
            Err(e) => TaskResult::success(
                &task.task_id,
                serde_json::json!({
                    "valid": false,
                    "errors": vec![e.to_string()]
                }),
            ),
        }
    }

    /// Compile YARA rules
    async fn compile_rules(&self, task: &WorkerTask) -> TaskResult {
        let yarac = match &self.yarac_binary {
            Some(path) => path,
            None => return TaskResult::failure(&task.task_id, "YARAC binary not found"),
        };

        let rules = match task.payload.get("rules") {
            Some(serde_json::Value::String(r)) => r,
            _ => return TaskResult::failure(&task.task_id, "Missing rules in payload"),
        };

        let output_path = task
            .payload
            .get("output_path")
            .and_then(|p| p.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!("yara_compiled_{}.yarc", task.task_id))
            });

        // Create temp file for rules
        let temp_rule_path =
            std::env::temp_dir().join(format!("yara_compile_{}.yar", task.task_id));

        if let Err(e) = tokio::fs::write(&temp_rule_path, rules).await {
            return TaskResult::failure(&task.task_id, format!("Failed to write rules: {}", e));
        }

        // Compile
        let temp_rule_str = temp_rule_path.to_string_lossy().to_string();
        let output_path_str = output_path.to_string_lossy().to_string();
        let output = Command::new(yarac)
            .arg(&temp_rule_str)
            .arg(&output_path_str)
            .output()
            .await;

        // Clean up source
        let _ = tokio::fs::remove_file(&temp_rule_path).await;

        match output {
            Ok(out) => {
                if out.status.success() {
                    // Optionally read compiled data
                    let compiled_data = if task
                        .payload
                        .get("return_data")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        match tokio::fs::read(&output_path).await {
                            Ok(data) => Some(base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &data,
                            )),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };

                    TaskResult::success(
                        &task.task_id,
                        serde_json::json!({
                            "compiled": true,
                            "output_path": output_path.to_string_lossy(),
                            "compiled_data": compiled_data
                        }),
                    )
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    TaskResult::failure(&task.task_id, stderr.to_string())
                }
            }
            Err(e) => TaskResult::failure(&task.task_id, format!("Compilation failed: {}", e)),
        }
    }

}

impl Default for ScannerWorker {
    fn default() -> Self {
        Self::new()
    }
}

// Add base64 to Cargo.toml dependencies

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_worker_creation() {
        let worker = ScannerWorker::new();
        assert_eq!(worker.worker_type(), "r-yara-scanner");
    }
}
