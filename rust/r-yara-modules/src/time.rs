//! Time Module
//!
//! Provides time-related functions compatible with YARA's time module.
//!
//! # YARA Compatibility
//!
//! This module is compatible with YARA's built-in time module:
//!
//! ```yara
//! import "time"
//!
//! rule RecentFile {
//!     condition:
//!         time.now() - pe.timestamp > 31536000  // older than 1 year
//! }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp.
///
/// # Returns
///
/// Current time as seconds since Unix epoch (January 1, 1970)
///
/// # Example
///
/// ```
/// use r_yara_modules::time;
///
/// let timestamp = time::now();
/// assert!(timestamp > 1700000000); // After Nov 2023
/// ```
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now() {
        let timestamp = now();
        // Should be after 2024
        assert!(timestamp > 1704067200, "Timestamp should be after 2024");
        // Should be reasonable (not in far future)
        assert!(timestamp < 2000000000, "Timestamp should be reasonable");
    }

    #[test]
    fn test_now_consistency() {
        let t1 = now();
        let t2 = now();
        // Second call should be >= first
        assert!(t2 >= t1);
        // Should not differ by more than 1 second
        assert!(t2 - t1 <= 1);
    }
}
