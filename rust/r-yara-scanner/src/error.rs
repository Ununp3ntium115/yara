//! Error types for the scanner

use thiserror::Error;

/// Scanner errors
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Parse error: {0}")]
    Parse(#[from] r_yara_parser::ParseError),

    #[error("Compile error: {0}")]
    Compile(#[from] r_yara_compiler::CompileError),

    #[error("Matcher error: {0}")]
    Matcher(#[from] r_yara_matcher::MatcherError),

    #[error("VM error: {0}")]
    VM(#[from] r_yara_vm::VMError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid rule file: {0}")]
    InvalidRuleFile(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Module error: {0}")]
    Module(#[from] r_yara_modules::ModuleError),

    #[error("Scan timeout")]
    Timeout,

    #[error("Scan aborted")]
    Aborted,

    #[error("Invalid scan options: {0}")]
    InvalidOptions(String),
}

/// Result type for scanner operations
pub type ScanResult<T> = Result<T, ScanError>;
