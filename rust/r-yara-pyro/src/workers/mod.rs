//! Worker implementations for R-YARA PYRO Platform
//!
//! Provides worker base traits and implementations for distributed task processing.

mod base;
mod scanner;
mod transcoder;

pub use base::{BaseWorker, WorkerState, WorkerStats};
pub use scanner::ScannerWorker;
pub use transcoder::TranscoderWorker;

use crate::protocol::TaskType;

/// Worker info trait for common operations
pub trait Worker: Send + Sync {
    fn worker_id(&self) -> &str;
    fn worker_type(&self) -> &str;
    fn capabilities(&self) -> Vec<TaskType>;
}

impl Worker for ScannerWorker {
    fn worker_id(&self) -> &str {
        ScannerWorker::worker_id(self)
    }

    fn worker_type(&self) -> &str {
        ScannerWorker::worker_type(self)
    }

    fn capabilities(&self) -> Vec<TaskType> {
        ScannerWorker::capabilities(self)
    }
}

impl Worker for TranscoderWorker {
    fn worker_id(&self) -> &str {
        TranscoderWorker::worker_id(self)
    }

    fn worker_type(&self) -> &str {
        TranscoderWorker::worker_type(self)
    }

    fn capabilities(&self) -> Vec<TaskType> {
        TranscoderWorker::capabilities(self)
    }
}

/// Create a worker based on type
pub fn create_worker(worker_type: &str) -> Option<Box<dyn Worker>> {
    match worker_type {
        "scanner" | "r-yara-scanner" => Some(Box::new(ScannerWorker::new())),
        "transcoder" | "r-yara-transcoder" => Some(Box::new(TranscoderWorker::new())),
        _ => None,
    }
}

/// Get capabilities for a worker type
pub fn get_capabilities(worker_type: &str) -> Vec<TaskType> {
    match worker_type {
        "scanner" | "r-yara-scanner" => vec![
            TaskType::ScanFile,
            TaskType::ScanData,
            TaskType::ValidateRule,
            TaskType::CompileRules,
        ],
        "transcoder" | "r-yara-transcoder" => vec![
            TaskType::Transcode,
            TaskType::DictionaryLookup,
        ],
        _ => vec![],
    }
}
