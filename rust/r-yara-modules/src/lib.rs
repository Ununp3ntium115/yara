//! R-YARA Modules
//!
//! This crate provides YARA-compatible module implementations for use in R-YARA rules.
//! Each module exposes functions that operate on scan data ranges.
//!
//! # Available Modules
//!
//! - **pe**: PE (Windows executable) file analysis
//! - **elf**: ELF (Linux executable) file analysis
//! - **hash**: Cryptographic hash functions (md5, sha1, sha256, etc.)
//! - **math**: Mathematical and statistical functions (entropy, mean, etc.)
//! - **time**: Time-related functions
//! - **console**: Debug output functions
//!
//! # Example
//!
//! ```
//! use r_yara_modules::{hash, math};
//!
//! let data = b"Hello, YARA!";
//!
//! // Hash the entire data
//! let md5_hash = hash::md5(data, 0, data.len());
//! let sha256_hash = hash::sha256(data, 0, data.len());
//!
//! // Calculate entropy
//! let entropy = math::entropy(data, 0, data.len());
//! println!("Entropy: {:.2}", entropy);
//! ```

pub mod console;
pub mod elf;
pub mod hash;
pub mod math;
pub mod pe;
pub mod time;

/// Module error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum ModuleError {
    #[error("Invalid range: offset {offset} + size {size} exceeds data length {data_len}")]
    InvalidRange {
        offset: usize,
        size: usize,
        data_len: usize,
    },

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

/// Result type for module operations
pub type ModuleResult<T> = Result<T, ModuleError>;

/// Validate a data range
#[inline]
pub fn validate_range(data: &[u8], offset: usize, size: usize) -> ModuleResult<&[u8]> {
    if offset.saturating_add(size) > data.len() {
        return Err(ModuleError::InvalidRange {
            offset,
            size,
            data_len: data.len(),
        });
    }
    Ok(&data[offset..offset + size])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_range_valid() {
        let data = b"Hello, World!";
        let result = validate_range(data, 0, 5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_validate_range_invalid() {
        let data = b"Hello";
        let result = validate_range(data, 3, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_range_overflow() {
        let data = b"Hello";
        let result = validate_range(data, usize::MAX, 1);
        assert!(result.is_err());
    }
}
