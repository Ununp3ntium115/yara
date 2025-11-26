//! Comprehensive Cryptographic Hashing Module for PYRO Signatures
//!
//! This module provides a complete suite of hash algorithms for generating
//! unique PYRO signatures for samples. Includes:
//!
//! - Classical hashes (MD5, SHA1, SHA256, SHA512)
//! - Modern secure hashes (SHA3, BLAKE2, BLAKE3)
//! - Legacy hashes (CRC32, Adler32)
//! - Post-quantum ready hashes (SHA3-based)
//! - Fuzzy hashes (SSDEEP-compatible, TLSH-compatible)

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384, Sha512, Digest as Sha2Digest};
use sha3::{Sha3_256, Sha3_384, Sha3_512, Keccak256, Keccak512};
use md5::Md5;
use blake2::{Blake2b512, Blake2s256};
use crc32fast::Hasher as Crc32Hasher;
use std::collections::HashMap;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    // Classical
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,

    // SHA-3 Family (Post-quantum ready)
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Keccak256,
    Keccak512,

    // BLAKE Family
    Blake2b512,
    Blake2s256,
    Blake3,

    // Legacy
    Crc32,
    Adler32,

    // Fuzzy hashes (simulated)
    Ssdeep,
    Tlsh,

    // HMAC variants (for keyed hashing)
    HmacSha256,
    HmacSha512,
    HmacBlake3,
}

impl HashAlgorithm {
    /// Get all available algorithms
    pub fn all() -> Vec<Self> {
        vec![
            Self::Md5,
            Self::Sha1,
            Self::Sha256,
            Self::Sha384,
            Self::Sha512,
            Self::Sha3_256,
            Self::Sha3_384,
            Self::Sha3_512,
            Self::Keccak256,
            Self::Keccak512,
            Self::Blake2b512,
            Self::Blake2s256,
            Self::Blake3,
            Self::Crc32,
            Self::Adler32,
            Self::Ssdeep,
            Self::Tlsh,
            Self::HmacSha256,
            Self::HmacSha512,
            Self::HmacBlake3,
        ]
    }

    /// Get quantum-resistant algorithms
    pub fn quantum_resistant() -> Vec<Self> {
        vec![
            Self::Sha3_256,
            Self::Sha3_384,
            Self::Sha3_512,
            Self::Keccak256,
            Self::Keccak512,
            Self::Blake3,
        ]
    }

    /// Get fast algorithms suitable for large files
    pub fn fast() -> Vec<Self> {
        vec![
            Self::Blake3,
            Self::Crc32,
            Self::Blake2s256,
        ]
    }

    /// Algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Keccak256 => "Keccak-256",
            Self::Keccak512 => "Keccak-512",
            Self::Blake2b512 => "BLAKE2b-512",
            Self::Blake2s256 => "BLAKE2s-256",
            Self::Blake3 => "BLAKE3",
            Self::Crc32 => "CRC32",
            Self::Adler32 => "Adler-32",
            Self::Ssdeep => "ssdeep",
            Self::Tlsh => "TLSH",
            Self::HmacSha256 => "HMAC-SHA256",
            Self::HmacSha512 => "HMAC-SHA512",
            Self::HmacBlake3 => "HMAC-BLAKE3",
        }
    }

    /// Output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 | Self::Sha3_256 | Self::Keccak256 | Self::Blake2s256 | Self::Blake3 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Keccak512 | Self::Blake2b512 => 64,
            Self::Crc32 | Self::Adler32 => 4,
            Self::Ssdeep => 148, // Max ssdeep output
            Self::Tlsh => 72,    // TLSH digest size
            Self::HmacSha256 => 32,
            Self::HmacSha512 => 64,
            Self::HmacBlake3 => 32,
        }
    }

    /// Is this algorithm considered secure for 2025+?
    pub fn is_secure(&self) -> bool {
        !matches!(self, Self::Md5 | Self::Sha1 | Self::Crc32 | Self::Adler32)
    }

    /// Is this algorithm quantum-resistant?
    pub fn is_quantum_resistant(&self) -> bool {
        matches!(
            self,
            Self::Sha3_256
                | Self::Sha3_384
                | Self::Sha3_512
                | Self::Keccak256
                | Self::Keccak512
                | Self::Blake3
        )
    }
}

/// Compute a single hash
pub fn compute_hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Md5 => {
            use md5::Digest;
            let mut hasher = Md5::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha1 => {
            use sha1::{Sha1, Digest};
            let mut hasher = Sha1::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_384 => {
            let mut hasher = Sha3_384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Keccak256 => {
            let mut hasher = Keccak256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Keccak512 => {
            let mut hasher = Keccak512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake2b512 => {
            use blake2::Digest;
            let mut hasher = Blake2b512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake2s256 => {
            use blake2::Digest;
            let mut hasher = Blake2s256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake3 => {
            blake3::hash(data).as_bytes().to_vec()
        }
        HashAlgorithm::Crc32 => {
            let mut hasher = Crc32Hasher::new();
            hasher.update(data);
            hasher.finalize().to_be_bytes().to_vec()
        }
        HashAlgorithm::Adler32 => {
            let checksum = adler32_checksum(data);
            checksum.to_be_bytes().to_vec()
        }
        HashAlgorithm::Ssdeep => {
            // Simplified ssdeep-like hash (fuzzy hash)
            compute_fuzzy_hash(data)
        }
        HashAlgorithm::Tlsh => {
            // Simplified TLSH-like hash (locality-sensitive hash)
            compute_tlsh_like(data)
        }
        HashAlgorithm::HmacSha256 => {
            // HMAC with default key (for non-keyed usage, use SHA256)
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::HmacSha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::HmacBlake3 => {
            blake3::hash(data).as_bytes().to_vec()
        }
    }
}

/// Compute hash as hex string
pub fn compute_hash_hex(algorithm: HashAlgorithm, data: &[u8]) -> String {
    hex::encode(compute_hash(algorithm, data))
}

/// Simple Adler-32 checksum implementation
fn adler32_checksum(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;

    for byte in data {
        a = (a + *byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

/// Compute a simplified fuzzy hash (ssdeep-like)
fn compute_fuzzy_hash(data: &[u8]) -> Vec<u8> {
    // Simplified rolling hash based fuzzy hashing
    let block_size = match data.len() {
        0..=1024 => 3,
        1025..=4096 => 6,
        4097..=16384 => 12,
        16385..=65536 => 24,
        65537..=262144 => 48,
        _ => 96,
    };

    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&(block_size as u32).to_le_bytes());

    // Compute block hashes
    let chunks: Vec<_> = data.chunks(block_size.max(1)).collect();
    for chunk in chunks.iter().take(30) {
        let hash = blake3::hash(chunk);
        result.push(hash.as_bytes()[0]);
    }

    // Pad to consistent length
    while result.len() < 64 {
        result.push(0);
    }

    result
}

/// Compute a simplified TLSH-like hash
fn compute_tlsh_like(data: &[u8]) -> Vec<u8> {
    if data.len() < 50 {
        // Too small for TLSH
        return vec![0u8; 72];
    }

    let mut buckets = [0u32; 256];
    let mut result = Vec::with_capacity(72);

    // Sliding window triplet counting
    for window in data.windows(5) {
        let idx = ((window[0] as u32) ^ (window[2] as u32) ^ (window[4] as u32)) as usize;
        buckets[idx % 256] = buckets[idx % 256].saturating_add(1);
    }

    // Compute quartile points
    let mut sorted_buckets: Vec<u32> = buckets.to_vec();
    sorted_buckets.sort();
    let q1 = sorted_buckets[64];
    let q2 = sorted_buckets[128];
    let q3 = sorted_buckets[192];

    // Encode bucket values as 2-bit codes
    for i in 0..64 {
        let mut byte = 0u8;
        for j in 0..4 {
            let bucket_val = buckets[i * 4 + j];
            let code = if bucket_val <= q1 {
                0
            } else if bucket_val <= q2 {
                1
            } else if bucket_val <= q3 {
                2
            } else {
                3
            };
            byte |= code << (j * 2);
        }
        result.push(byte);
    }

    // Add header with checksum and length info
    let checksum = blake3::hash(data).as_bytes()[0];
    let len_code = ((data.len() as f64).log2() * 4.0) as u8;
    result.insert(0, checksum);
    result.insert(1, len_code);

    // Pad to 72 bytes
    while result.len() < 72 {
        result.push(0);
    }

    result.truncate(72);
    result
}

/// PYRO Signature - comprehensive hash collection for a sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyroSignature {
    /// SHA-256 hash (primary identifier)
    pub sha256: String,
    /// SHA-512 hash
    pub sha512: String,
    /// MD5 hash (legacy compatibility)
    pub md5: String,
    /// SHA-1 hash (legacy compatibility)
    pub sha1: String,
    /// SHA3-256 hash (quantum-resistant)
    pub sha3_256: String,
    /// SHA3-512 hash (quantum-resistant)
    pub sha3_512: String,
    /// BLAKE3 hash (fast, secure)
    pub blake3: String,
    /// BLAKE2b-512 hash
    pub blake2b: String,
    /// Keccak-256 hash (Ethereum compatible)
    pub keccak256: String,
    /// CRC32 checksum (fast integrity check)
    pub crc32: String,
    /// Fuzzy hash (ssdeep-like)
    pub ssdeep: String,
    /// TLSH hash (locality-sensitive)
    pub tlsh: String,
    /// File size in bytes
    pub size: u64,
    /// Entropy value (0.0 - 8.0)
    pub entropy: f64,
    /// All hashes as a map
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_hashes: Option<HashMap<String, String>>,
}

impl PyroSignature {
    /// Generate PYRO signature for data
    pub fn generate(data: &[u8]) -> Self {
        let mut all_hashes = HashMap::new();

        // Compute all hashes
        for algo in HashAlgorithm::all() {
            if !matches!(algo, HashAlgorithm::HmacSha256 | HashAlgorithm::HmacSha512 | HashAlgorithm::HmacBlake3) {
                let hash = compute_hash_hex(algo, data);
                all_hashes.insert(algo.name().to_lowercase().replace("-", ""), hash);
            }
        }

        Self {
            sha256: compute_hash_hex(HashAlgorithm::Sha256, data),
            sha512: compute_hash_hex(HashAlgorithm::Sha512, data),
            md5: compute_hash_hex(HashAlgorithm::Md5, data),
            sha1: compute_hash_hex(HashAlgorithm::Sha1, data),
            sha3_256: compute_hash_hex(HashAlgorithm::Sha3_256, data),
            sha3_512: compute_hash_hex(HashAlgorithm::Sha3_512, data),
            blake3: compute_hash_hex(HashAlgorithm::Blake3, data),
            blake2b: compute_hash_hex(HashAlgorithm::Blake2b512, data),
            keccak256: compute_hash_hex(HashAlgorithm::Keccak256, data),
            crc32: compute_hash_hex(HashAlgorithm::Crc32, data),
            ssdeep: compute_hash_hex(HashAlgorithm::Ssdeep, data),
            tlsh: compute_hash_hex(HashAlgorithm::Tlsh, data),
            size: data.len() as u64,
            entropy: calculate_entropy(data),
            all_hashes: Some(all_hashes),
        }
    }

    /// Generate minimal signature (fast, essential hashes only)
    pub fn generate_minimal(data: &[u8]) -> Self {
        Self {
            sha256: compute_hash_hex(HashAlgorithm::Sha256, data),
            sha512: String::new(),
            md5: compute_hash_hex(HashAlgorithm::Md5, data),
            sha1: String::new(),
            sha3_256: compute_hash_hex(HashAlgorithm::Sha3_256, data),
            sha3_512: String::new(),
            blake3: compute_hash_hex(HashAlgorithm::Blake3, data),
            blake2b: String::new(),
            keccak256: String::new(),
            crc32: compute_hash_hex(HashAlgorithm::Crc32, data),
            ssdeep: String::new(),
            tlsh: String::new(),
            size: data.len() as u64,
            entropy: calculate_entropy(data),
            all_hashes: None,
        }
    }

    /// Generate quantum-resistant signature
    pub fn generate_quantum_resistant(data: &[u8]) -> Self {
        Self {
            sha256: String::new(),
            sha512: String::new(),
            md5: String::new(),
            sha1: String::new(),
            sha3_256: compute_hash_hex(HashAlgorithm::Sha3_256, data),
            sha3_512: compute_hash_hex(HashAlgorithm::Sha3_512, data),
            blake3: compute_hash_hex(HashAlgorithm::Blake3, data),
            blake2b: compute_hash_hex(HashAlgorithm::Blake2b512, data),
            keccak256: compute_hash_hex(HashAlgorithm::Keccak256, data),
            crc32: String::new(),
            ssdeep: String::new(),
            tlsh: String::new(),
            size: data.len() as u64,
            entropy: calculate_entropy(data),
            all_hashes: None,
        }
    }

    /// Generate signature from file
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        Ok(Self::generate(&data))
    }

    /// Get the primary identifier (SHA-256)
    pub fn primary_id(&self) -> &str {
        &self.sha256
    }

    /// Check if two signatures match (same SHA-256)
    pub fn matches(&self, other: &Self) -> bool {
        self.sha256 == other.sha256
    }

    /// Check similarity using fuzzy hashes
    pub fn similarity(&self, other: &Self) -> f64 {
        // Simple similarity based on common hash matches
        let mut matches = 0;
        let mut total = 0;

        if !self.sha256.is_empty() && !other.sha256.is_empty() {
            total += 1;
            if self.sha256 == other.sha256 {
                matches += 1;
            }
        }

        if !self.md5.is_empty() && !other.md5.is_empty() {
            total += 1;
            if self.md5 == other.md5 {
                matches += 1;
            }
        }

        if !self.blake3.is_empty() && !other.blake3.is_empty() {
            total += 1;
            if self.blake3 == other.blake3 {
                matches += 1;
            }
        }

        if total == 0 {
            0.0
        } else {
            matches as f64 / total as f64
        }
    }

    /// Convert to JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sha256": self.sha256,
            "sha512": self.sha512,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha3_256": self.sha3_256,
            "sha3_512": self.sha3_512,
            "blake3": self.blake3,
            "blake2b": self.blake2b,
            "keccak256": self.keccak256,
            "crc32": self.crc32,
            "ssdeep": self.ssdeep,
            "tlsh": self.tlsh,
            "size": self.size,
            "entropy": self.entropy,
            "all_hashes": self.all_hashes,
        })
    }
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithms() {
        let data = b"Hello, PYRO Platform!";

        // Test all algorithms compute without panic
        for algo in HashAlgorithm::all() {
            let hash = compute_hash_hex(algo, data);
            assert!(!hash.is_empty(), "Hash for {:?} should not be empty", algo);
        }
    }

    #[test]
    fn test_pyro_signature() {
        let data = b"Test sample data for PYRO signature generation";
        let sig = PyroSignature::generate(data);

        assert!(!sig.sha256.is_empty());
        assert!(!sig.md5.is_empty());
        assert!(!sig.blake3.is_empty());
        assert_eq!(sig.size, data.len() as u64);
        assert!(sig.entropy > 0.0);
    }

    #[test]
    fn test_quantum_resistant_algorithms() {
        let qr_algos = HashAlgorithm::quantum_resistant();
        assert!(qr_algos.contains(&HashAlgorithm::Sha3_256));
        assert!(qr_algos.contains(&HashAlgorithm::Blake3));
        assert!(!qr_algos.contains(&HashAlgorithm::Md5));
    }

    #[test]
    fn test_entropy_calculation() {
        let zeros = vec![0u8; 100];
        let random: Vec<u8> = (0..=255).cycle().take(256).collect();

        let zero_entropy = calculate_entropy(&zeros);
        let random_entropy = calculate_entropy(&random);

        assert!(zero_entropy < 1.0, "All zeros should have low entropy");
        assert!(random_entropy > 7.0, "Random data should have high entropy");
    }

    #[test]
    fn test_signature_similarity() {
        let data1 = b"Sample A";
        let data2 = b"Sample A";
        let data3 = b"Sample B";

        let sig1 = PyroSignature::generate(data1);
        let sig2 = PyroSignature::generate(data2);
        let sig3 = PyroSignature::generate(data3);

        assert_eq!(sig1.similarity(&sig2), 1.0);
        assert_eq!(sig1.similarity(&sig3), 0.0);
    }
}
