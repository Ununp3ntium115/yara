//! Hash Module
//!
//! Provides cryptographic hash functions compatible with YARA's hash module.
//! All functions operate on a specified range of the scanned data.
//!
//! # YARA Compatibility
//!
//! This module is compatible with YARA's built-in hash module:
//!
//! ```yara
//! import "hash"
//!
//! rule HashExample {
//!     condition:
//!         hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" or
//!         hash.sha256(0, 1024) == "abc..."
//! }
//! ```
//!
//! # Example
//!
//! ```
//! use r_yara_modules::hash;
//!
//! let data = b"Hello, World!";
//!
//! // Hash entire data
//! let md5 = hash::md5(data, 0, data.len());
//! let sha1 = hash::sha1(data, 0, data.len());
//! let sha256 = hash::sha256(data, 0, data.len());
//!
//! // Hash a range
//! let partial_md5 = hash::md5(data, 0, 5); // "Hello"
//! ```

use crate::{validate_range, ModuleResult};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

/// Compute MD5 hash of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to hash
///
/// # Returns
///
/// Lowercase hexadecimal string of the MD5 hash
///
/// # Example
///
/// ```
/// use r_yara_modules::hash;
///
/// let data = b"test";
/// let hash = hash::md5(data, 0, data.len());
/// assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
/// ```
pub fn md5(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let digest = md5::compute(slice);
            format!("{:x}", digest)
        }
        Err(_) => String::new(),
    }
}

/// Compute SHA-1 hash of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to hash
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHA-1 hash
pub fn sha1(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut hasher = Sha1::new();
            hasher.update(slice);
            hex::encode(hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

/// Compute SHA-256 hash of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to hash
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHA-256 hash
pub fn sha256(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut hasher = Sha256::new();
            hasher.update(slice);
            hex::encode(hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

/// Compute SHA-512 hash of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to hash
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHA-512 hash
pub fn sha512(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut hasher = Sha512::new();
            hasher.update(slice);
            hex::encode(hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

/// Compute SHA3-256 hash of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to hash
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHA3-256 hash
pub fn sha3_256(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut hasher = Sha3_256::new();
            hasher.update(slice);
            hex::encode(hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

/// Compute SHA3-512 hash of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to hash
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHA3-512 hash
pub fn sha3_512(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut hasher = Sha3_512::new();
            hasher.update(slice);
            hex::encode(hasher.finalize())
        }
        Err(_) => String::new(),
    }
}

/// Compute CRC32 checksum of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to checksum
///
/// # Returns
///
/// The CRC32 checksum as a u32 value
pub fn crc32(data: &[u8], offset: usize, size: usize) -> u32 {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(slice);
            hasher.finalize()
        }
        Err(_) => 0,
    }
}

/// Compute checksum32 of a data range (simple sum of all bytes modulo 2^32).
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to checksum
///
/// # Returns
///
/// The checksum as a u32 value
pub fn checksum32(data: &[u8], offset: usize, size: usize) -> u32 {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut sum: u32 = 0;
            for byte in slice {
                sum = sum.wrapping_add(*byte as u32);
            }
            sum
        }
        Err(_) => 0,
    }
}

/// Compute MD5 hash of a data range and return raw bytes.
pub fn md5_raw(data: &[u8], offset: usize, size: usize) -> ModuleResult<[u8; 16]> {
    let slice = validate_range(data, offset, size)?;
    let digest = md5::compute(slice);
    Ok(digest.0)
}

/// Compute SHA-256 hash of a data range and return raw bytes.
pub fn sha256_raw(data: &[u8], offset: usize, size: usize) -> ModuleResult<[u8; 32]> {
    let slice = validate_range(data, offset, size)?;
    let mut hasher = Sha256::new();
    hasher.update(slice);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        // Empty string
        assert_eq!(md5(b"", 0, 0), "d41d8cd98f00b204e9800998ecf8427e");

        // "test"
        assert_eq!(md5(b"test", 0, 4), "098f6bcd4621d373cade4e832627b4f6");

        // Partial range
        assert_eq!(md5(b"test", 0, 2), md5(b"te", 0, 2));
    }

    #[test]
    fn test_sha1() {
        // Empty string
        assert_eq!(sha1(b"", 0, 0), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        // "test"
        assert_eq!(sha1(b"test", 0, 4), "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
    }

    #[test]
    fn test_sha256() {
        // Empty string
        assert_eq!(
            sha256(b"", 0, 0),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // "test"
        assert_eq!(
            sha256(b"test", 0, 4),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_sha512() {
        // "test"
        let hash = sha512(b"test", 0, 4);
        assert!(hash.starts_with("ee26b0dd"));
        assert_eq!(hash.len(), 128); // 512 bits = 128 hex chars
    }

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256(b"test", 0, 4);
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
    }

    #[test]
    fn test_crc32() {
        // Empty
        assert_eq!(crc32(b"", 0, 0), 0);

        // "test"
        let checksum = crc32(b"test", 0, 4);
        assert_eq!(checksum, 0xd87f7e0c);
    }

    #[test]
    fn test_checksum32() {
        // Empty
        assert_eq!(checksum32(b"", 0, 0), 0);

        // Simple sum
        let data = [1u8, 2, 3, 4, 5];
        assert_eq!(checksum32(&data, 0, 5), 15);
    }

    #[test]
    fn test_invalid_range() {
        let data = b"test";

        // Offset past end
        assert_eq!(md5(data, 10, 1), "");

        // Size past end
        assert_eq!(sha256(data, 0, 100), "");

        // CRC32 returns 0 for invalid range
        assert_eq!(crc32(data, 10, 1), 0);
    }

    #[test]
    fn test_partial_ranges() {
        let data = b"Hello, World!";

        // Hash "Hello"
        let hello_md5 = md5(data, 0, 5);
        assert_eq!(hello_md5, md5(b"Hello", 0, 5));

        // Hash "World"
        let world_md5 = md5(data, 7, 5);
        assert_eq!(world_md5, md5(b"World", 0, 5));
    }

    #[test]
    fn test_raw_functions() {
        let data = b"test";

        let md5_bytes = md5_raw(data, 0, 4).unwrap();
        assert_eq!(md5_bytes.len(), 16);
        assert_eq!(hex::encode(md5_bytes), "098f6bcd4621d373cade4e832627b4f6");

        let sha256_bytes = sha256_raw(data, 0, 4).unwrap();
        assert_eq!(sha256_bytes.len(), 32);
    }
}
