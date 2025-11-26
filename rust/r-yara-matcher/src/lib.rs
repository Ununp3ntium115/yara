//! R-YARA Pattern Matching Engine
//!
//! A high-performance pattern matching engine using Aho-Corasick (via Daachorse)
//! for literal strings and a regex engine for regular expressions.
//!
//! # Architecture
//!
//! The matcher uses a two-phase approach:
//! 1. **AC Phase**: Fast multi-pattern matching using Daachorse (double-array Aho-Corasick)
//! 2. **Regex Phase**: Full regex matching for patterns that require it
//!
//! # Example
//!
//! ```
//! use r_yara_matcher::{PatternMatcher, Pattern, PatternKind};
//!
//! let patterns = vec![
//!     Pattern::new(0, "MZ".as_bytes().to_vec(), PatternKind::Literal),
//!     Pattern::new(1, "PE".as_bytes().to_vec(), PatternKind::Literal),
//! ];
//!
//! let matcher = PatternMatcher::new(patterns).unwrap();
//! let data = b"MZ header followed by PE signature";
//! let matches = matcher.scan(data);
//!
//! assert!(!matches.is_empty());
//! ```

use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder};
use regex::bytes::Regex;
use smol_str::SmolStr;
use std::collections::HashMap;
use thiserror::Error;

/// Pattern matching errors
#[derive(Debug, Error)]
pub enum MatcherError {
    #[error("Failed to build Aho-Corasick automaton: {0}")]
    AcBuildError(String),

    #[error("Invalid regex pattern '{pattern}': {error}")]
    InvalidRegex { pattern: String, error: String },

    #[error("Invalid hex pattern: {0}")]
    InvalidHexPattern(String),
}

/// Pattern identifier
pub type PatternId = usize;

/// Kind of pattern
#[derive(Debug, Clone, PartialEq)]
pub enum PatternKind {
    /// Literal byte pattern (fastest)
    Literal,
    /// Literal with case insensitivity
    LiteralNocase,
    /// Wide string (UTF-16LE)
    Wide,
    /// Wide with case insensitivity
    WideNocase,
    /// Hex pattern with wildcards
    Hex,
    /// Regular expression
    Regex,
}

/// Modifiers that affect matching behavior
#[derive(Debug, Clone, Default)]
pub struct PatternModifiers {
    /// Case insensitive matching
    pub nocase: bool,
    /// Wide string (UTF-16LE)
    pub wide: bool,
    /// ASCII (standard) encoding
    pub ascii: bool,
    /// Fullword matching
    pub fullword: bool,
    /// XOR range for encoded strings
    pub xor: Option<(u8, u8)>,
    /// Base64 encoding variants
    pub base64: bool,
}

/// A pattern to match
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Unique identifier for this pattern
    pub id: PatternId,
    /// The pattern bytes (for literals) or compiled form
    pub bytes: Vec<u8>,
    /// Kind of pattern
    pub kind: PatternKind,
    /// Pattern modifiers
    pub modifiers: PatternModifiers,
    /// Original pattern name (e.g., "$a")
    pub name: Option<SmolStr>,
}

impl Pattern {
    /// Create a new pattern
    pub fn new(id: PatternId, bytes: Vec<u8>, kind: PatternKind) -> Self {
        Self {
            id,
            bytes,
            kind,
            modifiers: PatternModifiers::default(),
            name: None,
        }
    }

    /// Create a pattern with modifiers
    pub fn with_modifiers(
        id: PatternId,
        bytes: Vec<u8>,
        kind: PatternKind,
        modifiers: PatternModifiers,
    ) -> Self {
        Self {
            id,
            bytes,
            kind,
            modifiers,
            name: None,
        }
    }

    /// Set the pattern name
    pub fn with_name(mut self, name: impl Into<SmolStr>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// A match result
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    /// Pattern that matched
    pub pattern_id: PatternId,
    /// Offset where the match starts
    pub offset: usize,
    /// Length of the match
    pub length: usize,
}

impl Match {
    /// Create a new match
    pub fn new(pattern_id: PatternId, offset: usize, length: usize) -> Self {
        Self {
            pattern_id,
            offset,
            length,
        }
    }

    /// Get the end offset of this match
    pub fn end(&self) -> usize {
        self.offset + self.length
    }
}

/// Statistics about a scan
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    /// Number of bytes scanned
    pub bytes_scanned: usize,
    /// Number of AC atoms checked
    pub ac_atoms_checked: usize,
    /// Number of regex evaluations
    pub regex_evaluations: usize,
    /// Number of matches found
    pub matches_found: usize,
}

/// The main pattern matcher
pub struct PatternMatcher {
    /// Aho-Corasick automaton for literal patterns
    ac: Option<DoubleArrayAhoCorasick<PatternId>>,
    /// Map from AC pattern index to our pattern ID
    ac_pattern_map: Vec<PatternId>,
    /// Compiled regex patterns
    regexes: Vec<(PatternId, Regex)>,
    /// Hex patterns with wildcards (need special handling)
    hex_patterns: Vec<(PatternId, HexPattern)>,
    /// All patterns for reference
    patterns: Vec<Pattern>,
}

/// A compiled hex pattern with wildcards
#[derive(Debug, Clone)]
pub struct HexPattern {
    /// Atoms extracted for AC matching
    pub atoms: Vec<Vec<u8>>,
    /// Full pattern tokens for verification
    pub tokens: Vec<HexToken>,
    /// Minimum pattern length
    pub min_length: usize,
    /// Maximum pattern length (None = unbounded)
    pub max_length: Option<usize>,
}

/// Token in a hex pattern
#[derive(Debug, Clone, PartialEq)]
pub enum HexToken {
    /// Exact byte
    Byte(u8),
    /// Wildcard (matches any byte)
    Wildcard,
    /// Nibble wildcard (matches high or low nibble)
    NibbleWildcard { high: Option<u8>, low: Option<u8> },
    /// Jump (variable gap)
    Jump { min: usize, max: Option<usize> },
    /// Alternation between sub-patterns
    Alternation(Vec<Vec<HexToken>>),
}

impl PatternMatcher {
    /// Create a new pattern matcher from a list of patterns
    pub fn new(patterns: Vec<Pattern>) -> Result<Self, MatcherError> {
        let mut ac_patterns: Vec<(Vec<u8>, PatternId)> = Vec::new();
        let mut regexes: Vec<(PatternId, Regex)> = Vec::new();
        let mut hex_patterns: Vec<(PatternId, HexPattern)> = Vec::new();

        for pattern in &patterns {
            match &pattern.kind {
                PatternKind::Literal | PatternKind::Wide => {
                    let bytes = if pattern.kind == PatternKind::Wide {
                        // Convert to UTF-16LE
                        pattern
                            .bytes
                            .iter()
                            .flat_map(|&b| [b, 0])
                            .collect()
                    } else {
                        pattern.bytes.clone()
                    };
                    ac_patterns.push((bytes, pattern.id));
                }
                PatternKind::LiteralNocase | PatternKind::WideNocase => {
                    // For nocase, we add both lowercase and uppercase versions
                    // Or we can use a case-folded approach
                    let bytes = if pattern.kind == PatternKind::WideNocase {
                        pattern
                            .bytes
                            .iter()
                            .flat_map(|&b| [b, 0])
                            .collect()
                    } else {
                        pattern.bytes.clone()
                    };

                    // Add lowercase version
                    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
                    ac_patterns.push((lower, pattern.id));

                    // Add uppercase version (might duplicate but AC handles it)
                    let upper: Vec<u8> = bytes.iter().map(|b| b.to_ascii_uppercase()).collect();
                    if upper != bytes {
                        ac_patterns.push((upper, pattern.id));
                    }
                }
                PatternKind::Hex => {
                    // Parse hex pattern and extract atoms
                    let hex_pattern = parse_hex_pattern(&pattern.bytes)?;
                    // Add atoms to AC if there are fixed sequences
                    for atom in &hex_pattern.atoms {
                        if atom.len() >= 2 {
                            ac_patterns.push((atom.clone(), pattern.id));
                        }
                    }
                    hex_patterns.push((pattern.id, hex_pattern));
                }
                PatternKind::Regex => {
                    let pattern_str = String::from_utf8_lossy(&pattern.bytes);
                    let regex = Regex::new(&pattern_str).map_err(|e| MatcherError::InvalidRegex {
                        pattern: pattern_str.to_string(),
                        error: e.to_string(),
                    })?;
                    regexes.push((pattern.id, regex));
                }
            }
        }

        // Build AC automaton if we have literal patterns
        let (ac, ac_pattern_map) = if !ac_patterns.is_empty() {
            let builder = DoubleArrayAhoCorasickBuilder::new();
            let pattern_map: Vec<PatternId> = ac_patterns.iter().map(|(_, id)| *id).collect();
            let patterns_only: Vec<&[u8]> = ac_patterns.iter().map(|(p, _)| p.as_slice()).collect();

            let ac = builder
                .build(patterns_only)
                .map_err(|e| MatcherError::AcBuildError(format!("{:?}", e)))?;

            (Some(ac), pattern_map)
        } else {
            (None, Vec::new())
        };

        Ok(Self {
            ac,
            ac_pattern_map,
            regexes,
            hex_patterns,
            patterns,
        })
    }

    /// Scan data for all pattern matches
    pub fn scan(&self, data: &[u8]) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut seen = HashMap::new();

        // Phase 1: AC matching for literals
        if let Some(ref ac) = self.ac {
            for m in ac.find_overlapping_iter(data) {
                let pattern_id = self.ac_pattern_map[m.value()];
                let offset = m.start();
                let length = m.end() - m.start();

                // Deduplicate matches at same position
                let key = (pattern_id, offset);
                if !seen.contains_key(&key) {
                    seen.insert(key, true);
                    matches.push(Match::new(pattern_id, offset, length));
                }
            }
        }

        // Phase 2: Hex pattern verification
        for (pattern_id, hex_pattern) in &self.hex_patterns {
            for m in match_hex_pattern(data, hex_pattern) {
                let key = (*pattern_id, m.offset);
                if !seen.contains_key(&key) {
                    seen.insert(key, true);
                    matches.push(Match::new(*pattern_id, m.offset, m.length));
                }
            }
        }

        // Phase 3: Regex matching
        for (pattern_id, regex) in &self.regexes {
            for m in regex.find_iter(data) {
                let key = (*pattern_id, m.start());
                if !seen.contains_key(&key) {
                    seen.insert(key, true);
                    matches.push(Match::new(*pattern_id, m.start(), m.end() - m.start()));
                }
            }
        }

        // Sort by offset
        matches.sort_by_key(|m| (m.offset, m.pattern_id));
        matches
    }

    /// Scan with statistics
    pub fn scan_with_stats(&self, data: &[u8]) -> (Vec<Match>, ScanStats) {
        let mut stats = ScanStats {
            bytes_scanned: data.len(),
            ..Default::default()
        };

        let matches = self.scan(data);
        stats.matches_found = matches.len();

        (matches, stats)
    }

    /// Get pattern by ID
    pub fn get_pattern(&self, id: PatternId) -> Option<&Pattern> {
        self.patterns.iter().find(|p| p.id == id)
    }

    /// Get total number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

/// Parse a hex pattern from bytes into a structured form
fn parse_hex_pattern(bytes: &[u8]) -> Result<HexPattern, MatcherError> {
    // For now, treat the entire pattern as a sequence of bytes/wildcards
    // This is a simplified parser - full implementation would handle all YARA hex syntax
    let mut tokens = Vec::new();
    let mut atoms = Vec::new();
    let mut current_atom = Vec::new();

    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'?' => {
                // Flush current atom
                if !current_atom.is_empty() {
                    atoms.push(current_atom.clone());
                    current_atom.clear();
                }

                if i + 1 < bytes.len() && bytes[i + 1] == b'?' {
                    tokens.push(HexToken::Wildcard);
                    i += 2;
                } else {
                    tokens.push(HexToken::Wildcard);
                    i += 1;
                }
            }
            b'[' => {
                // Jump marker
                if !current_atom.is_empty() {
                    atoms.push(current_atom.clone());
                    current_atom.clear();
                }

                // Find closing bracket
                let end = bytes[i..].iter().position(|&b| b == b']').unwrap_or(0) + i;
                // Parse range (simplified)
                tokens.push(HexToken::Jump {
                    min: 0,
                    max: Some(100),
                });
                i = end + 1;
            }
            b' ' | b'\t' | b'\n' | b'\r' => {
                i += 1;
            }
            c if c.is_ascii_hexdigit() => {
                // Parse hex byte
                if i + 1 < bytes.len() && bytes[i + 1].is_ascii_hexdigit() {
                    let hex_str = std::str::from_utf8(&bytes[i..i + 2]).unwrap_or("00");
                    if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
                        tokens.push(HexToken::Byte(byte));
                        current_atom.push(byte);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    // Flush final atom
    if !current_atom.is_empty() {
        atoms.push(current_atom);
    }

    let min_length = tokens
        .iter()
        .map(|t| match t {
            HexToken::Byte(_) | HexToken::Wildcard | HexToken::NibbleWildcard { .. } => 1,
            HexToken::Jump { min, .. } => *min,
            HexToken::Alternation(alts) => alts
                .iter()
                .map(|a| a.len())
                .min()
                .unwrap_or(0),
        })
        .sum();

    Ok(HexPattern {
        atoms,
        tokens,
        min_length,
        max_length: None, // Could calculate but leave open for now
    })
}

/// Match a hex pattern against data
fn match_hex_pattern(data: &[u8], pattern: &HexPattern) -> Vec<Match> {
    let mut matches = Vec::new();

    if pattern.tokens.is_empty() {
        return matches;
    }

    // Simple brute-force matching for now
    // A production implementation would use atoms for filtering
    'outer: for start in 0..data.len() {
        let mut pos = start;
        let mut token_idx = 0;

        while token_idx < pattern.tokens.len() && pos < data.len() {
            match &pattern.tokens[token_idx] {
                HexToken::Byte(b) => {
                    if data[pos] != *b {
                        continue 'outer;
                    }
                    pos += 1;
                }
                HexToken::Wildcard => {
                    pos += 1;
                }
                HexToken::NibbleWildcard { high, low } => {
                    let byte = data[pos];
                    if let Some(h) = high {
                        if (byte >> 4) != *h {
                            continue 'outer;
                        }
                    }
                    if let Some(l) = low {
                        if (byte & 0x0F) != *l {
                            continue 'outer;
                        }
                    }
                    pos += 1;
                }
                HexToken::Jump { min, max: _ } => {
                    // For jumps, we need to try different skip amounts
                    // Simplified: just skip min bytes and continue
                    pos += min;
                    // TODO: Full implementation needs backtracking for variable-length jumps
                }
                HexToken::Alternation(alts) => {
                    // Try each alternative
                    let mut matched = false;
                    for _alt in alts {
                        // TODO: Recursive matching for alternation groups
                        matched = true;
                        break;
                    }
                    if !matched {
                        continue 'outer;
                    }
                }
            }
            token_idx += 1;
        }

        // Check if we matched all tokens
        if token_idx == pattern.tokens.len() {
            matches.push(Match::new(0, start, pos - start));
        }
    }

    matches
}

// ==================== XOR Matching ====================

/// Generate XOR variants of a pattern
pub fn generate_xor_variants(pattern: &[u8], min: u8, max: u8) -> Vec<Vec<u8>> {
    (min..=max)
        .map(|key| pattern.iter().map(|b| b ^ key).collect())
        .collect()
}

// ==================== Base64 Matching ====================

/// Standard base64 alphabet (for custom alphabet support in future)
#[allow(dead_code)]
const BASE64_STANDARD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Generate base64 encoded variants of a pattern
pub fn generate_base64_variants(pattern: &[u8]) -> Vec<Vec<u8>> {
    use base64::{engine::general_purpose, Engine};

    let mut variants = Vec::new();

    // Standard base64
    let encoded = general_purpose::STANDARD.encode(pattern);
    variants.push(encoded.into_bytes());

    // Also add URL-safe variant
    let url_encoded = general_purpose::URL_SAFE.encode(pattern);
    variants.push(url_encoded.into_bytes());

    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_matching() {
        let patterns = vec![
            Pattern::new(0, b"MZ".to_vec(), PatternKind::Literal),
            Pattern::new(1, b"PE".to_vec(), PatternKind::Literal),
        ];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = b"MZ header... PE\x00\x00 signature";
        let matches = matcher.scan(data);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].pattern_id, 0);
        assert_eq!(matches[0].offset, 0);
        assert_eq!(matches[1].pattern_id, 1);
    }

    #[test]
    fn test_nocase_matching() {
        let patterns = vec![Pattern::new(
            0,
            b"test".to_vec(),
            PatternKind::LiteralNocase,
        )];

        let matcher = PatternMatcher::new(patterns).unwrap();

        // Should match both cases
        let matches1 = matcher.scan(b"This is a TEST string");
        let matches2 = matcher.scan(b"This is a test string");

        assert!(!matches1.is_empty());
        assert!(!matches2.is_empty());
    }

    #[test]
    fn test_wide_matching() {
        let patterns = vec![Pattern::new(0, b"MZ".to_vec(), PatternKind::Wide)];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = b"M\x00Z\x00 header";
        let matches = matcher.scan(data);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0);
        assert_eq!(matches[0].length, 4); // M\x00Z\x00
    }

    #[test]
    fn test_regex_matching() {
        let patterns = vec![Pattern::new(0, b"test[0-9]+".to_vec(), PatternKind::Regex)];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = b"This is test123 and test456";
        let matches = matcher.scan(data);

        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_hex_pattern_matching() {
        let patterns = vec![Pattern::new(
            0,
            b"4D 5A 90 00".to_vec(),
            PatternKind::Hex,
        )];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = &[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];
        let matches = matcher.scan(data);

        assert!(!matches.is_empty());
    }

    #[test]
    fn test_hex_wildcard() {
        let patterns = vec![Pattern::new(0, b"4D ?? 90".to_vec(), PatternKind::Hex)];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = &[0x4D, 0xFF, 0x90]; // ?? matches 0xFF
        let matches = matcher.scan(data);

        assert!(!matches.is_empty());
    }

    #[test]
    fn test_xor_variants() {
        let pattern = b"MZ";
        let variants = generate_xor_variants(pattern, 0x01, 0x03);

        assert_eq!(variants.len(), 3);
        assert_eq!(variants[0], vec![b'M' ^ 1, b'Z' ^ 1]);
        assert_eq!(variants[1], vec![b'M' ^ 2, b'Z' ^ 2]);
        assert_eq!(variants[2], vec![b'M' ^ 3, b'Z' ^ 3]);
    }

    #[test]
    fn test_overlapping_patterns() {
        let patterns = vec![
            Pattern::new(0, b"ab".to_vec(), PatternKind::Literal),
            Pattern::new(1, b"bc".to_vec(), PatternKind::Literal),
        ];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = b"abc";
        let matches = matcher.scan(data);

        // Should find both overlapping matches
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_multiple_matches_same_pattern() {
        let patterns = vec![Pattern::new(0, b"test".to_vec(), PatternKind::Literal)];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = b"test test test";
        let matches = matcher.scan(data);

        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].offset, 0);
        assert_eq!(matches[1].offset, 5);
        assert_eq!(matches[2].offset, 10);
    }

    #[test]
    fn test_empty_data() {
        let patterns = vec![Pattern::new(0, b"test".to_vec(), PatternKind::Literal)];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let matches = matcher.scan(b"");

        assert!(matches.is_empty());
    }

    #[test]
    fn test_no_patterns() {
        let matcher = PatternMatcher::new(vec![]).unwrap();
        let matches = matcher.scan(b"some data");

        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_with_stats() {
        let patterns = vec![Pattern::new(0, b"test".to_vec(), PatternKind::Literal)];

        let matcher = PatternMatcher::new(patterns).unwrap();
        let data = b"test data test";
        let (matches, stats) = matcher.scan_with_stats(data);

        assert_eq!(matches.len(), 2);
        assert_eq!(stats.bytes_scanned, 14);
        assert_eq!(stats.matches_found, 2);
    }
}
