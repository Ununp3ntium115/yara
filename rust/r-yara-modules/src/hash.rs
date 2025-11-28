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

// SHA-1
use sha1::Sha1;

// SHA-2 family
use sha2::{Sha256, Sha384, Sha512};

// SHA-3 family and Keccak
use sha3::{Keccak256, Keccak512, Sha3_256, Sha3_384, Sha3_512, Shake256};
use sha3::digest::{ExtendableOutput, Update as XofUpdate, XofReader};

// BLAKE family
use blake2::{Blake2b512, Blake2s256};

// Post-quantum traits
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, DetachedSignature as PqDetachedSig};

/// Helper macro to create hash function with Digest trait
macro_rules! hash_fn {
    ($hasher:ty, $slice:expr) => {{
        use digest::Digest;
        let mut hasher = <$hasher>::new();
        Digest::update(&mut hasher, $slice);
        hex::encode(Digest::finalize(hasher))
    }};
}

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
        Ok(slice) => hash_fn!(Sha1, slice),
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
        Ok(slice) => hash_fn!(Sha256, slice),
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
        Ok(slice) => hash_fn!(Sha512, slice),
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
        Ok(slice) => hash_fn!(Sha3_256, slice),
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
        Ok(slice) => hash_fn!(Sha3_512, slice),
        Err(_) => String::new(),
    }
}

// ============================================================================
// Quantum-Resistant Hash Functions (Post-Quantum Ready)
// ============================================================================

/// Compute SHA-384 hash of a data range.
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHA-384 hash (96 chars)
pub fn sha384(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => hash_fn!(Sha384, slice),
        Err(_) => String::new(),
    }
}

/// Compute SHA3-384 hash of a data range.
///
/// SHA3-384 is quantum-resistant and provides 192-bit security level.
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHA3-384 hash (96 chars)
pub fn sha3_384(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => hash_fn!(Sha3_384, slice),
        Err(_) => String::new(),
    }
}

/// Compute Keccak-256 hash of a data range.
///
/// Keccak-256 is the original Keccak algorithm before NIST standardization.
/// Used by Ethereum for addresses and transaction hashing.
///
/// # Returns
///
/// Lowercase hexadecimal string of the Keccak-256 hash (64 chars)
pub fn keccak256(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => hash_fn!(Keccak256, slice),
        Err(_) => String::new(),
    }
}

/// Compute Keccak-512 hash of a data range.
///
/// Keccak-512 provides 256-bit security level and is quantum-resistant.
///
/// # Returns
///
/// Lowercase hexadecimal string of the Keccak-512 hash (128 chars)
pub fn keccak512(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => hash_fn!(Keccak512, slice),
        Err(_) => String::new(),
    }
}

/// Compute BLAKE2b-512 hash of a data range.
///
/// BLAKE2b is faster than SHA-256 while being equally secure.
/// Optimized for 64-bit platforms.
///
/// # Returns
///
/// Lowercase hexadecimal string of the BLAKE2b-512 hash (128 chars)
pub fn blake2b512(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => hash_fn!(Blake2b512, slice),
        Err(_) => String::new(),
    }
}

/// Compute BLAKE2s-256 hash of a data range.
///
/// BLAKE2s is optimized for 32-bit platforms while maintaining security.
///
/// # Returns
///
/// Lowercase hexadecimal string of the BLAKE2s-256 hash (64 chars)
pub fn blake2s256(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => hash_fn!(Blake2s256, slice),
        Err(_) => String::new(),
    }
}

/// Compute BLAKE3 hash of a data range.
///
/// BLAKE3 is the fastest cryptographic hash function, significantly faster
/// than SHA-256, SHA-3, and BLAKE2. It is quantum-resistant and suitable
/// for large file hashing.
///
/// # Returns
///
/// Lowercase hexadecimal string of the BLAKE3 hash (64 chars)
pub fn blake3(data: &[u8], offset: usize, size: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let hash = blake3::hash(slice);
            hash.to_hex().to_string()
        }
        Err(_) => String::new(),
    }
}

/// Compute Adler-32 checksum of a data range.
///
/// Adler-32 is faster than CRC32 but slightly weaker for error detection.
/// Used in zlib compression.
///
/// # Returns
///
/// The Adler-32 checksum as a u32 value
pub fn adler32(data: &[u8], offset: usize, size: usize) -> u32 {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            const MOD_ADLER: u32 = 65521;
            let mut a: u32 = 1;
            let mut b: u32 = 0;
            for byte in slice {
                a = (a + *byte as u32) % MOD_ADLER;
                b = (b + a) % MOD_ADLER;
            }
            (b << 16) | a
        }
        Err(_) => 0,
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

// ============================================================================
// SHA-3 XOF (Extendable Output Functions)
// ============================================================================

/// Compute SHAKE256 hash of a data range with specified output length.
///
/// SHAKE256 is a SHA-3 based XOF (Extendable Output Function) that can produce
/// arbitrary length output. It's used internally by SPHINCS+ and other
/// post-quantum schemes.
///
/// Default output is 64 bytes (512 bits) for maximum security.
///
/// # Returns
///
/// Lowercase hexadecimal string of the SHAKE256 hash
pub fn shake256(data: &[u8], offset: usize, size: usize) -> String {
    shake256_n(data, offset, size, 64)
}

/// Compute SHAKE256 hash with custom output length.
///
/// # Arguments
///
/// * `output_bytes` - Number of output bytes (will be doubled for hex)
pub fn shake256_n(data: &[u8], offset: usize, size: usize, output_bytes: usize) -> String {
    match validate_range(data, offset, size) {
        Ok(slice) => {
            let mut hasher = Shake256::default();
            XofUpdate::update(&mut hasher, slice);
            let mut reader = hasher.finalize_xof();
            let mut output = vec![0u8; output_bytes];
            reader.read(&mut output);
            hex::encode(output)
        }
        Err(_) => String::new(),
    }
}

// ============================================================================
// NIST SPHINCS+ Post-Quantum Signatures
// ============================================================================

/// SPHINCS+ key pair for post-quantum digital signatures.
///
/// SPHINCS+ is a stateless hash-based signature scheme selected by NIST
/// for post-quantum cryptography standardization.
pub struct SphincsKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generate a new SPHINCS+ key pair.
///
/// Uses SPHINCS+-SHAKE-256f (fast variant, 256-bit security).
pub fn sphincs_generate_keypair() -> SphincsKeyPair {
    use pqcrypto_sphincsplus::sphincsshake256fsimple;
    let (pk, sk) = sphincsshake256fsimple::keypair();
    SphincsKeyPair {
        public_key: PqPublicKey::as_bytes(&pk).to_vec(),
        secret_key: PqSecretKey::as_bytes(&sk).to_vec(),
    }
}

/// Sign data using SPHINCS+ (post-quantum secure).
///
/// # Arguments
///
/// * `data` - Data to sign
/// * `secret_key` - SPHINCS+ secret key bytes
///
/// # Returns
///
/// Signature bytes as hex string, or empty string on error
pub fn sphincs_sign(data: &[u8], secret_key: &[u8]) -> String {
    use pqcrypto_sphincsplus::sphincsshake256fsimple;

    match sphincsshake256fsimple::SecretKey::from_bytes(secret_key) {
        Ok(sk) => {
            let sig = sphincsshake256fsimple::detached_sign(data, &sk);
            hex::encode(PqDetachedSig::as_bytes(&sig))
        }
        Err(_) => String::new(),
    }
}

/// Verify a SPHINCS+ signature.
///
/// # Arguments
///
/// * `data` - Original data
/// * `signature_hex` - Hex-encoded signature
/// * `public_key` - SPHINCS+ public key bytes
///
/// # Returns
///
/// true if signature is valid, false otherwise
pub fn sphincs_verify(data: &[u8], signature_hex: &str, public_key: &[u8]) -> bool {
    use pqcrypto_sphincsplus::sphincsshake256fsimple;

    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let pk = match sphincsshake256fsimple::PublicKey::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let sig = match sphincsshake256fsimple::DetachedSignature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    sphincsshake256fsimple::verify_detached_signature(&sig, data, &pk).is_ok()
}

/// Get SPHINCS+ public key size in bytes.
pub fn sphincs_public_key_size() -> usize {
    use pqcrypto_sphincsplus::sphincsshake256fsimple;
    sphincsshake256fsimple::public_key_bytes()
}

/// Get SPHINCS+ secret key size in bytes.
pub fn sphincs_secret_key_size() -> usize {
    use pqcrypto_sphincsplus::sphincsshake256fsimple;
    sphincsshake256fsimple::secret_key_bytes()
}

/// Get SPHINCS+ signature size in bytes.
pub fn sphincs_signature_size() -> usize {
    use pqcrypto_sphincsplus::sphincsshake256fsimple;
    sphincsshake256fsimple::signature_bytes()
}

/// Compute MD5 hash of a data range and return raw bytes.
pub fn md5_raw(data: &[u8], offset: usize, size: usize) -> ModuleResult<[u8; 16]> {
    let slice = validate_range(data, offset, size)?;
    let digest = md5::compute(slice);
    Ok(digest.0)
}

/// Compute SHA-256 hash of a data range and return raw bytes.
pub fn sha256_raw(data: &[u8], offset: usize, size: usize) -> ModuleResult<[u8; 32]> {
    use digest::Digest;
    let slice = validate_range(data, offset, size)?;
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, slice);
    Ok(Digest::finalize(hasher).into())
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

    // ========================================================================
    // Quantum-Resistant Hash Function Tests
    // ========================================================================

    #[test]
    fn test_sha384() {
        let hash = sha384(b"test", 0, 4);
        assert_eq!(hash.len(), 96); // 384 bits = 96 hex chars
        // Verify known value
        assert!(hash.starts_with("768412320f"));
    }

    #[test]
    fn test_sha3_384() {
        let hash = sha3_384(b"test", 0, 4);
        assert_eq!(hash.len(), 96); // 384 bits = 96 hex chars
    }

    #[test]
    fn test_sha3_512() {
        let hash = sha3_512(b"test", 0, 4);
        assert_eq!(hash.len(), 128); // 512 bits = 128 hex chars
    }

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"test", 0, 4);
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
        // Keccak-256 (pre-NIST) differs from SHA3-256
        assert_ne!(hash, sha3_256(b"test", 0, 4));
    }

    #[test]
    fn test_keccak512() {
        let hash = keccak512(b"test", 0, 4);
        assert_eq!(hash.len(), 128); // 512 bits = 128 hex chars
    }

    #[test]
    fn test_blake2b512() {
        let hash = blake2b512(b"test", 0, 4);
        assert_eq!(hash.len(), 128); // 512 bits = 128 hex chars
        // Verify it's not empty
        assert!(!hash.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_blake2s256() {
        let hash = blake2s256(b"test", 0, 4);
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
    }

    #[test]
    fn test_blake3() {
        let hash = blake3(b"test", 0, 4);
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
        // BLAKE3 is very fast, verify known test vector
        assert!(hash.starts_with("4878ca0425c"));
    }

    #[test]
    fn test_adler32() {
        // Known test vector
        let checksum = adler32(b"Wikipedia", 0, 9);
        assert_eq!(checksum, 0x11E60398);

        // Empty
        assert_eq!(adler32(b"", 0, 0), 1); // Adler32 of empty is 1
    }

    #[test]
    fn test_shake256() {
        let hash = shake256(b"test", 0, 4);
        assert_eq!(hash.len(), 128); // 64 bytes = 128 hex chars (default)
    }

    #[test]
    fn test_shake256_custom_length() {
        // 32-byte output
        let hash32 = shake256_n(b"test", 0, 4, 32);
        assert_eq!(hash32.len(), 64); // 32 bytes = 64 hex chars

        // 128-byte output
        let hash128 = shake256_n(b"test", 0, 4, 128);
        assert_eq!(hash128.len(), 256); // 128 bytes = 256 hex chars

        // The beginning should be the same
        assert!(hash128.starts_with(&hash32));
    }

    // ========================================================================
    // SPHINCS+ Post-Quantum Signature Tests
    // ========================================================================

    #[test]
    fn test_sphincs_key_sizes() {
        // SPHINCS+-SHAKE-256f key sizes
        let pk_size = sphincs_public_key_size();
        let sk_size = sphincs_secret_key_size();
        let sig_size = sphincs_signature_size();

        assert!(pk_size > 0);
        assert!(sk_size > pk_size);
        assert!(sig_size > 0);

        // SPHINCS+ signatures are large (tens of KB)
        println!("SPHINCS+ key sizes - PK: {} bytes, SK: {} bytes, Sig: {} bytes",
                 pk_size, sk_size, sig_size);
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let message = b"Test message for post-quantum signature";

        // Generate key pair
        let keypair = sphincs_generate_keypair();

        // Sign
        let signature = sphincs_sign(message, &keypair.secret_key);
        assert!(!signature.is_empty());

        // Verify
        let valid = sphincs_verify(message, &signature, &keypair.public_key);
        assert!(valid, "SPHINCS+ signature should verify correctly");

        // Verify fails with wrong message
        let wrong_message = b"Wrong message";
        let invalid = sphincs_verify(wrong_message, &signature, &keypair.public_key);
        assert!(!invalid, "SPHINCS+ should reject wrong message");
    }

    #[test]
    fn test_sphincs_verify_invalid_key() {
        let message = b"Test";
        let keypair = sphincs_generate_keypair();
        let signature = sphincs_sign(message, &keypair.secret_key);

        // Wrong key should fail
        let wrong_key = vec![0u8; sphincs_public_key_size()];
        let invalid = sphincs_verify(message, &signature, &wrong_key);
        assert!(!invalid, "SPHINCS+ should reject wrong public key");
    }

    // ========================================================================
    // Algorithm Comparison Tests
    // ========================================================================

    #[test]
    fn test_all_quantum_resistant_hashes() {
        let data = b"Quantum computing test data";

        // All quantum-resistant hashes should produce different outputs
        let sha3_256_h = sha3_256(data, 0, data.len());
        let sha3_384_h = sha3_384(data, 0, data.len());
        let sha3_512_h = sha3_512(data, 0, data.len());
        let keccak256_h = keccak256(data, 0, data.len());
        let keccak512_h = keccak512(data, 0, data.len());
        let blake2b_h = blake2b512(data, 0, data.len());
        let blake2s_h = blake2s256(data, 0, data.len());
        let blake3_h = blake3(data, 0, data.len());
        let shake256_h = shake256(data, 0, data.len());

        // All should be non-empty
        assert!(!sha3_256_h.is_empty());
        assert!(!sha3_384_h.is_empty());
        assert!(!sha3_512_h.is_empty());
        assert!(!keccak256_h.is_empty());
        assert!(!keccak512_h.is_empty());
        assert!(!blake2b_h.is_empty());
        assert!(!blake2s_h.is_empty());
        assert!(!blake3_h.is_empty());
        assert!(!shake256_h.is_empty());

        // SHA3 and Keccak should differ (different padding)
        assert_ne!(sha3_256_h, keccak256_h);
    }

    #[test]
    fn test_empty_data_hashes() {
        // All hashes should handle empty data
        assert!(!sha384(b"", 0, 0).is_empty());
        assert!(!sha3_384(b"", 0, 0).is_empty());
        assert!(!keccak256(b"", 0, 0).is_empty());
        assert!(!keccak512(b"", 0, 0).is_empty());
        assert!(!blake2b512(b"", 0, 0).is_empty());
        assert!(!blake2s256(b"", 0, 0).is_empty());
        assert!(!blake3(b"", 0, 0).is_empty());
        assert!(!shake256(b"", 0, 0).is_empty());
    }
}
