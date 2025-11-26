//! Console Module
//!
//! Provides debug output functions compatible with YARA's console module.
//!
//! # YARA Compatibility
//!
//! This module is compatible with YARA's built-in console module:
//!
//! ```yara
//! import "console"
//!
//! rule DebugRule {
//!     strings:
//!         $a = "test"
//!     condition:
//!         console.log("Checking rule...") and $a
//! }
//! ```
//!
//! Note: In YARA, console.log always returns true to allow chaining in conditions.

/// Log a message to the console.
///
/// # Arguments
///
/// * `message` - The message to log
///
/// # Returns
///
/// Always returns true (for condition chaining)
///
/// # Example
///
/// ```
/// use r_yara_modules::console;
///
/// // Can be used in conditions
/// if console::log("Processing file...") {
///     // This always executes
/// }
/// ```
pub fn log(message: &str) -> bool {
    eprintln!("[YARA] {}", message);
    true
}

/// Log an integer value in hexadecimal format.
///
/// # Arguments
///
/// * `value` - The integer value to log
///
/// # Returns
///
/// Always returns true (for condition chaining)
pub fn hex(value: i64) -> bool {
    eprintln!("[YARA] 0x{:x}", value);
    true
}

/// Log a formatted message with an integer value.
///
/// # Arguments
///
/// * `format` - The format string (use {} for placeholder)
/// * `value` - The integer value
///
/// # Returns
///
/// Always returns true
pub fn log_int(format: &str, value: i64) -> bool {
    let message = format.replace("{}", &value.to_string());
    eprintln!("[YARA] {}", message);
    true
}

/// Log a formatted message with a string value.
///
/// # Arguments
///
/// * `format` - The format string (use {} for placeholder)
/// * `value` - The string value
///
/// # Returns
///
/// Always returns true
pub fn log_str(format: &str, value: &str) -> bool {
    let message = format.replace("{}", value);
    eprintln!("[YARA] {}", message);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_returns_true() {
        assert!(log("test message"));
    }

    #[test]
    fn test_hex_returns_true() {
        assert!(hex(255));
        assert!(hex(0x1234));
    }

    #[test]
    fn test_log_int() {
        assert!(log_int("Value is {}", 42));
    }

    #[test]
    fn test_log_str() {
        assert!(log_str("Hello {}", "World"));
    }
}
