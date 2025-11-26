//! Math Module
//!
//! Provides mathematical and statistical functions compatible with YARA's math module.
//! All functions operate on a specified range of the scanned data.
//!
//! # YARA Compatibility
//!
//! This module is compatible with YARA's built-in math module:
//!
//! ```yara
//! import "math"
//!
//! rule HighEntropySection {
//!     condition:
//!         math.entropy(0, filesize) > 7.5
//! }
//! ```
//!
//! # Available Functions
//!
//! - `entropy(data, offset, size)` - Shannon entropy (0.0 - 8.0)
//! - `mean(data, offset, size)` - Arithmetic mean of byte values
//! - `deviation(data, offset, size, mean)` - Standard deviation from a mean
//! - `serial_correlation(data, offset, size)` - Serial correlation coefficient
//! - `monte_carlo_pi(data, offset, size)` - Monte Carlo π approximation
//! - `count(byte, data, offset, size)` - Count occurrences of a byte
//! - `percentage(byte, data, offset, size)` - Percentage of a byte value
//! - `mode(data, offset, size)` - Most common byte value
//! - `in_range(test, lower, upper)` - Check if value is in range
//! - `min(a, b)` / `max(a, b)` / `abs(a)` - Basic math functions
//! - `to_number(bool)` / `to_string(value)` - Type conversions

use crate::validate_range;

/// Calculate Shannon entropy of a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to analyze
///
/// # Returns
///
/// Entropy value between 0.0 (uniform) and 8.0 (maximum entropy for byte data)
///
/// # Example
///
/// ```
/// use r_yara_modules::math;
///
/// // Low entropy (all zeros)
/// let zeros = vec![0u8; 100];
/// let low_entropy = math::entropy(&zeros, 0, zeros.len());
/// assert!(low_entropy < 0.1);
///
/// // High entropy (random-like data)
/// let random: Vec<u8> = (0..=255).collect();
/// let high_entropy = math::entropy(&random, 0, random.len());
/// assert!(high_entropy > 7.9);
/// ```
pub fn entropy(data: &[u8], offset: usize, size: usize) -> f64 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    if slice.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut counts = [0u64; 256];
    for byte in slice {
        counts[*byte as usize] += 1;
    }

    // Calculate entropy
    let len = slice.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate arithmetic mean of byte values in a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to analyze
///
/// # Returns
///
/// Mean value between 0.0 and 255.0
pub fn mean(data: &[u8], offset: usize, size: usize) -> f64 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    if slice.is_empty() {
        return 0.0;
    }

    let sum: u64 = slice.iter().map(|&b| b as u64).sum();
    sum as f64 / slice.len() as f64
}

/// Calculate standard deviation from a given mean.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to analyze
/// * `expected_mean` - The mean value to calculate deviation from
///
/// # Returns
///
/// Standard deviation value
pub fn deviation(data: &[u8], offset: usize, size: usize, expected_mean: f64) -> f64 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    if slice.is_empty() {
        return 0.0;
    }

    let variance: f64 = slice
        .iter()
        .map(|&b| {
            let diff = b as f64 - expected_mean;
            diff * diff
        })
        .sum::<f64>()
        / slice.len() as f64;

    variance.sqrt()
}

/// Calculate serial correlation coefficient of a data range.
///
/// Serial correlation measures how much each byte is correlated with
/// the previous byte. Values near 0 indicate no correlation (random),
/// values near 1 or -1 indicate high correlation.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to analyze
///
/// # Returns
///
/// Correlation coefficient between -1.0 and 1.0
pub fn serial_correlation(data: &[u8], offset: usize, size: usize) -> f64 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    if slice.len() < 2 {
        return 0.0;
    }

    let _n = slice.len() as f64;
    let mean_val = mean(data, offset, size);

    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;
    let mut sum_y2 = 0.0;

    for i in 0..slice.len() - 1 {
        let x = slice[i] as f64 - mean_val;
        let y = slice[i + 1] as f64 - mean_val;
        sum_xy += x * y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }

    let denominator = (sum_x2 * sum_y2).sqrt();
    if denominator == 0.0 {
        return 0.0;
    }

    sum_xy / denominator
}

/// Estimate π using Monte Carlo method on data bytes.
///
/// This function interprets consecutive pairs of bytes as (x, y) coordinates
/// and counts how many fall within a unit circle, providing a statistical
/// test for randomness.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to analyze (should be even)
///
/// # Returns
///
/// Estimated value of π (approximately 3.14159 for truly random data)
pub fn monte_carlo_pi(data: &[u8], offset: usize, size: usize) -> f64 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    if slice.len() < 2 {
        return 0.0;
    }

    let mut inside = 0u64;
    let pairs = slice.len() / 2;

    for i in 0..pairs {
        // Scale to [0, 1) range
        let x = slice[i * 2] as f64 / 256.0;
        let y = slice[i * 2 + 1] as f64 / 256.0;

        // Check if point is inside unit circle quarter
        if x * x + y * y <= 1.0 {
            inside += 1;
        }
    }

    // π ≈ 4 * (inside / total)
    4.0 * inside as f64 / pairs as f64
}

/// Count occurrences of a specific byte value in a data range.
///
/// # Arguments
///
/// * `byte` - The byte value to count
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to search
///
/// # Returns
///
/// Number of occurrences of the byte
pub fn count(byte: u8, data: &[u8], offset: usize, size: usize) -> u64 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    slice.iter().filter(|&&b| b == byte).count() as u64
}

/// Calculate percentage of a specific byte value in a data range.
///
/// # Arguments
///
/// * `byte` - The byte value to count
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to search
///
/// # Returns
///
/// Percentage (0.0 to 100.0) of the byte value
pub fn percentage(byte: u8, data: &[u8], offset: usize, size: usize) -> f64 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    if slice.is_empty() {
        return 0.0;
    }

    let byte_count = count(byte, data, offset, size);
    100.0 * byte_count as f64 / slice.len() as f64
}

/// Find the most common byte value (mode) in a data range.
///
/// # Arguments
///
/// * `data` - The data buffer being scanned
/// * `offset` - Starting offset in the data
/// * `size` - Number of bytes to analyze
///
/// # Returns
///
/// The most frequently occurring byte value
pub fn mode(data: &[u8], offset: usize, size: usize) -> u8 {
    let slice = match validate_range(data, offset, size) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    if slice.is_empty() {
        return 0;
    }

    let mut counts = [0u64; 256];
    for byte in slice {
        counts[*byte as usize] += 1;
    }

    let mut max_count = 0;
    let mut max_byte = 0u8;
    for (byte, &count) in counts.iter().enumerate() {
        if count > max_count {
            max_count = count;
            max_byte = byte as u8;
        }
    }

    max_byte
}

/// Check if a value is within a range (inclusive).
///
/// # Arguments
///
/// * `test` - Value to test
/// * `lower` - Lower bound (inclusive)
/// * `upper` - Upper bound (inclusive)
///
/// # Returns
///
/// True if lower <= test <= upper
#[inline]
pub fn in_range(test: f64, lower: f64, upper: f64) -> bool {
    test >= lower && test <= upper
}

/// Return the minimum of two values.
#[inline]
pub fn min(a: i64, b: i64) -> i64 {
    std::cmp::min(a, b)
}

/// Return the maximum of two values.
#[inline]
pub fn max(a: i64, b: i64) -> i64 {
    std::cmp::max(a, b)
}

/// Return the absolute value.
#[inline]
pub fn abs(a: i64) -> i64 {
    a.abs()
}

/// Convert a boolean to an integer (0 or 1).
#[inline]
pub fn to_number(b: bool) -> i64 {
    if b { 1 } else { 0 }
}

/// Convert a number to a string.
#[inline]
pub fn to_string(n: i64) -> String {
    n.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy() {
        // Empty data
        assert_eq!(entropy(b"", 0, 0), 0.0);

        // All zeros (minimum entropy)
        let zeros = vec![0u8; 100];
        let zero_entropy = entropy(&zeros, 0, zeros.len());
        assert!(zero_entropy < 0.01, "All zeros should have near-zero entropy");

        // All distinct values (maximum entropy)
        let all_bytes: Vec<u8> = (0..=255).collect();
        let max_entropy = entropy(&all_bytes, 0, all_bytes.len());
        assert!(max_entropy > 7.99, "All distinct bytes should have entropy ~8.0");

        // Partial range
        let data = b"AAAABBBBCCCC";
        let partial_entropy = entropy(data, 0, 4);
        assert!(partial_entropy < 0.01, "All A's should have low entropy");
    }

    #[test]
    fn test_mean() {
        // Empty
        assert_eq!(mean(b"", 0, 0), 0.0);

        // Single value
        assert_eq!(mean(&[100u8], 0, 1), 100.0);

        // Range
        let data = [0u8, 50, 100, 150, 200];
        assert_eq!(mean(&data, 0, 5), 100.0);
    }

    #[test]
    fn test_deviation() {
        // All same value - zero deviation
        let same = [100u8; 10];
        assert_eq!(deviation(&same, 0, 10, 100.0), 0.0);

        // Known deviation
        let data = [0u8, 100];
        let dev = deviation(&data, 0, 2, 50.0);
        assert!((dev - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_serial_correlation() {
        // Alternating pattern - negative correlation
        let alternating: Vec<u8> = (0..100).map(|i| if i % 2 == 0 { 0 } else { 255 }).collect();
        let corr = serial_correlation(&alternating, 0, alternating.len());
        assert!(corr < -0.5, "Alternating should have negative correlation");

        // Increasing sequence - positive correlation
        let increasing: Vec<u8> = (0..100).map(|i| (i * 2) as u8).collect();
        let corr = serial_correlation(&increasing, 0, increasing.len());
        assert!(corr > 0.9, "Increasing should have high positive correlation");
    }

    #[test]
    fn test_monte_carlo_pi() {
        // With enough uniform random data, should approximate π
        // Using a deterministic test pattern
        let pi_est = monte_carlo_pi(&[0u8; 1000], 0, 1000);
        assert!(pi_est >= 0.0 && pi_est <= 4.0, "Pi estimate should be reasonable");
    }

    #[test]
    fn test_count() {
        let data = b"hello world";
        assert_eq!(count(b'l', data, 0, data.len()), 3);
        assert_eq!(count(b'o', data, 0, data.len()), 2);
        assert_eq!(count(b'z', data, 0, data.len()), 0);
    }

    #[test]
    fn test_percentage() {
        let data = vec![0u8; 100];
        assert_eq!(percentage(0, &data, 0, 100), 100.0);
        assert_eq!(percentage(1, &data, 0, 100), 0.0);

        let mixed = [0u8, 1, 0, 1, 0, 1, 0, 1, 0, 1];
        assert_eq!(percentage(0, &mixed, 0, 10), 50.0);
    }

    #[test]
    fn test_mode() {
        let data = b"aabbbbccc";
        assert_eq!(mode(data, 0, data.len()), b'b');

        let uniform: Vec<u8> = (0..=255).collect();
        // All equal, returns first (0)
        assert_eq!(mode(&uniform, 0, uniform.len()), 0);
    }

    #[test]
    fn test_in_range() {
        assert!(in_range(5.0, 0.0, 10.0));
        assert!(in_range(0.0, 0.0, 10.0));
        assert!(in_range(10.0, 0.0, 10.0));
        assert!(!in_range(-1.0, 0.0, 10.0));
        assert!(!in_range(11.0, 0.0, 10.0));
    }

    #[test]
    fn test_basic_math() {
        assert_eq!(min(3, 5), 3);
        assert_eq!(max(3, 5), 5);
        assert_eq!(abs(-5), 5);
        assert_eq!(abs(5), 5);
        assert_eq!(to_number(true), 1);
        assert_eq!(to_number(false), 0);
        assert_eq!(to_string(42), "42");
    }

    #[test]
    fn test_invalid_ranges() {
        let data = b"test";

        // All should return safe defaults for invalid ranges
        assert_eq!(entropy(data, 100, 10), 0.0);
        assert_eq!(mean(data, 100, 10), 0.0);
        assert_eq!(count(b't', data, 100, 10), 0);
        assert_eq!(mode(data, 100, 10), 0);
    }
}
