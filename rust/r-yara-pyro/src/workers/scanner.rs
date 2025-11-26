//! Scanner worker implementation
//!
//! Handles YARA rule scanning, validation, and compilation tasks.

use std::path::PathBuf;
use std::time::Instant;
use tokio::process::Command;

use crate::protocol::{TaskResult, TaskType, WorkerTask};

use super::base::{BaseWorker, WorkerState, WorkerStats};

/// Scanner worker for YARA operations
pub struct ScannerWorker {
    base: BaseWorker,
    yara_binary: Option<PathBuf>,
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

        let yara_binary = Self::find_binary("yara");
        let yarac_binary = Self::find_binary("yarac");

        Self {
            base,
            yara_binary,
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

    /// Scan a file with YARA rules
    async fn scan_file(&self, task: &WorkerTask) -> TaskResult {
        let yara = match &self.yara_binary {
            Some(path) => path,
            None => return TaskResult::failure(&task.task_id, "YARA binary not found"),
        };

        let file_path = match task.payload.get("file_path") {
            Some(serde_json::Value::String(p)) => p,
            _ => return TaskResult::failure(&task.task_id, "Missing file_path in payload"),
        };

        let rules = task.payload.get("rules");
        let rules_file = task.payload.get("rules_file");

        if rules.is_none() && rules_file.is_none() {
            return TaskResult::failure(&task.task_id, "Missing rules or rules_file in payload");
        }

        // Create temp file for inline rules if needed
        let temp_rules_path = if let Some(serde_json::Value::String(r)) = rules {
            let temp_path = std::env::temp_dir().join(format!("yara_rules_{}.yar", task.task_id));
            if let Err(e) = tokio::fs::write(&temp_path, r).await {
                return TaskResult::failure(&task.task_id, format!("Failed to write rules: {}", e));
            }
            Some(temp_path)
        } else {
            None
        };

        let rules_path = temp_rules_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| {
                rules_file.and_then(|rf| {
                    if let serde_json::Value::String(s) = rf {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
            })
            .unwrap();

        // Run YARA scan
        let output = Command::new(yara)
            .arg("-s")
            .arg("-m")
            .arg(&rules_path)
            .arg(file_path)
            .output()
            .await;

        // Clean up temp file
        if let Some(temp_path) = temp_rules_path {
            let _ = tokio::fs::remove_file(temp_path).await;
        }

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let matches = Self::parse_yara_output(&stdout);

                TaskResult::success(
                    &task.task_id,
                    serde_json::json!({
                        "matches": matches,
                        "match_count": matches.len(),
                        "file_path": file_path
                    }),
                )
            }
            Err(e) => TaskResult::failure(&task.task_id, format!("YARA scan failed: {}", e)),
        }
    }

    /// Scan raw data with YARA rules
    async fn scan_data(&self, task: &WorkerTask) -> TaskResult {
        let yara = match &self.yara_binary {
            Some(path) => path,
            None => return TaskResult::failure(&task.task_id, "YARA binary not found"),
        };

        let data = match task.payload.get("data") {
            Some(serde_json::Value::String(d)) => d,
            _ => return TaskResult::failure(&task.task_id, "Missing data in payload"),
        };

        let rules = task.payload.get("rules");
        let rules_file = task.payload.get("rules_file");

        if rules.is_none() && rules_file.is_none() {
            return TaskResult::failure(&task.task_id, "Missing rules or rules_file in payload");
        }

        // Create temp file for data
        let temp_data_path = std::env::temp_dir().join(format!("yara_data_{}", task.task_id));
        if let Err(e) = tokio::fs::write(&temp_data_path, data.as_bytes()).await {
            return TaskResult::failure(&task.task_id, format!("Failed to write data: {}", e));
        }

        // Create temp file for rules if needed
        let temp_rules_path = if let Some(serde_json::Value::String(r)) = rules {
            let temp_path = std::env::temp_dir().join(format!("yara_rules_{}.yar", task.task_id));
            if let Err(e) = tokio::fs::write(&temp_path, r).await {
                let _ = tokio::fs::remove_file(&temp_data_path).await;
                return TaskResult::failure(&task.task_id, format!("Failed to write rules: {}", e));
            }
            Some(temp_path)
        } else {
            None
        };

        let rules_path = temp_rules_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| {
                rules_file.and_then(|rf| {
                    if let serde_json::Value::String(s) = rf {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
            })
            .unwrap();

        // Run YARA scan
        let temp_data_str = temp_data_path.to_string_lossy().to_string();
        let output = Command::new(yara)
            .arg("-s")
            .arg("-m")
            .arg(&rules_path)
            .arg(&temp_data_str)
            .output()
            .await;

        // Clean up temp files
        let _ = tokio::fs::remove_file(&temp_data_path).await;
        if let Some(temp_path) = temp_rules_path {
            let _ = tokio::fs::remove_file(temp_path).await;
        }

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let matches = Self::parse_yara_output(&stdout);

                TaskResult::success(
                    &task.task_id,
                    serde_json::json!({
                        "matches": matches,
                        "match_count": matches.len()
                    }),
                )
            }
            Err(e) => TaskResult::failure(&task.task_id, format!("YARA scan failed: {}", e)),
        }
    }

    /// Validate YARA rule syntax
    async fn validate_rule(&self, task: &WorkerTask) -> TaskResult {
        let yarac = match &self.yarac_binary {
            Some(path) => path,
            None => return TaskResult::failure(&task.task_id, "YARAC binary not found"),
        };

        let rule = match task.payload.get("rule") {
            Some(serde_json::Value::String(r)) => r,
            _ => return TaskResult::failure(&task.task_id, "Missing rule in payload"),
        };

        // Create temp files
        let temp_rule_path =
            std::env::temp_dir().join(format!("yara_validate_{}.yar", task.task_id));
        let temp_output_path =
            std::env::temp_dir().join(format!("yara_validate_{}.yarc", task.task_id));

        if let Err(e) = tokio::fs::write(&temp_rule_path, rule).await {
            return TaskResult::failure(&task.task_id, format!("Failed to write rule: {}", e));
        }

        // Try to compile
        let temp_rule_str = temp_rule_path.to_string_lossy().to_string();
        let temp_output_str = temp_output_path.to_string_lossy().to_string();
        let output = Command::new(yarac)
            .arg(&temp_rule_str)
            .arg(&temp_output_str)
            .output()
            .await;

        // Clean up
        let _ = tokio::fs::remove_file(&temp_rule_path).await;
        let _ = tokio::fs::remove_file(&temp_output_path).await;

        match output {
            Ok(out) => {
                if out.status.success() {
                    TaskResult::success(
                        &task.task_id,
                        serde_json::json!({
                            "valid": true,
                            "message": "Rule is valid"
                        }),
                    )
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    TaskResult::success(
                        &task.task_id,
                        serde_json::json!({
                            "valid": false,
                            "errors": stderr.lines().collect::<Vec<_>>()
                        }),
                    )
                }
            }
            Err(e) => TaskResult::failure(&task.task_id, format!("Validation failed: {}", e)),
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

    /// Parse YARA output into structured matches
    fn parse_yara_output(output: &str) -> Vec<serde_json::Value> {
        let mut matches = Vec::new();
        let mut current_match: Option<serde_json::Value> = None;

        for line in output.lines() {
            if line.is_empty() {
                continue;
            }

            if !line.starts_with("0x") {
                // New rule match
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    if let Some(m) = current_match.take() {
                        matches.push(m);
                    }

                    let rule_name = parts[0];
                    let tags: Vec<&str> = if line.contains('[') && line.contains(']') {
                        let start = line.find('[').unwrap() + 1;
                        let end = line.find(']').unwrap();
                        line[start..end].split(',').map(|s| s.trim()).collect()
                    } else {
                        vec![]
                    };

                    current_match = Some(serde_json::json!({
                        "rule": rule_name,
                        "tags": tags,
                        "strings": []
                    }));
                }
            } else if let Some(ref mut m) = current_match {
                // String match
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                if parts.len() >= 2 {
                    if let Some(strings) = m.get_mut("strings") {
                        if let Some(arr) = strings.as_array_mut() {
                            arr.push(serde_json::json!({
                                "offset": parts[0],
                                "identifier": parts[1],
                                "data": parts.get(2).unwrap_or(&"")
                            }));
                        }
                    }
                }
            }
        }

        if let Some(m) = current_match {
            matches.push(m);
        }

        matches
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

    #[test]
    fn test_parse_yara_output() {
        let output = "test_rule [tag1,tag2] /path/to/file\n0x0:$a: test\n";
        let matches = ScannerWorker::parse_yara_output(output);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0]["rule"], "test_rule");
    }
}
