//! R-YARA Parser
//!
//! A high-performance YARA rule parser written in Rust.
//!
//! This crate provides:
//! - **Lexer**: Tokenizes YARA rules using Logos for efficient lexical analysis
//! - **AST**: Abstract Syntax Tree definitions for YARA rules
//! - **Parser**: (Coming soon) Full YARA rule parser using LALRPOP
//!
//! # Example
//!
//! ```
//! use r_yara_parser::lexer::{Lexer, Token};
//!
//! let source = r#"
//!     rule example {
//!         strings:
//!             $a = "test"
//!         condition:
//!             $a
//!     }
//! "#;
//!
//! let lexer = Lexer::new(source);
//! for result in lexer {
//!     match result {
//!         Ok(spanned) => println!("{:?}", spanned.token),
//!         Err(e) => eprintln!("Error: {}", e),
//!     }
//! }
//! ```
//!
//! # Architecture
//!
//! The parser is designed to be modular and extensible:
//!
//! 1. **Lexer** (`lexer.rs`): Uses Logos for zero-copy tokenization
//! 2. **AST** (`ast.rs`): Type-safe representation of YARA rules
//! 3. **Parser** (planned): LALRPOP-based grammar for full parsing
//! 4. **Errors** (planned): Rich error messages with source locations
//!
//! # Performance Goals
//!
//! - Zero-copy string handling with `SmolStr`
//! - Efficient memory layout for AST nodes
//! - Fast lexing with Logos (faster than handwritten lexers)
//! - Parallel parsing support for large rule sets

pub mod ast;
pub mod lexer;

// Re-export commonly used types
pub use ast::{
    BinaryExpr, BinaryOp, Expression, ForExpr, ForIterable, ForIterator, HexString, HexToken,
    Identifier, Import, Include, MetaEntry, MetaValue, OfExpr, Quantifier, QuantifierKind,
    RangeExpr, RegexModifiers, RegexString, Rule, RuleModifiers, SourceFile, StringDeclaration,
    StringModifiers, StringPattern, StringSet, TextString, UnaryExpr, UnaryOp,
};

pub use lexer::{Lexer, LexerError, NumberValue, Span, SpannedToken, Token};

/// Parse a YARA source file into an AST.
///
/// This is the main entry point for parsing YARA rules.
///
/// # Arguments
///
/// * `source` - The YARA source code to parse
///
/// # Returns
///
/// A `Result` containing either the parsed `SourceFile` or a `ParseError`
///
/// # Example
///
/// ```ignore
/// use r_yara_parser::parse;
///
/// let source = r#"rule test { condition: true }"#;
/// let ast = parse(source)?;
/// println!("Parsed {} rules", ast.rules.len());
/// ```
pub fn parse(_source: &str) -> Result<SourceFile, ParseError> {
    // TODO: Implement full parser with LALRPOP
    // For now, return an empty source file as placeholder
    Ok(SourceFile::new())
}

/// Tokenize YARA source code.
///
/// Returns an iterator of tokens with span information.
///
/// # Arguments
///
/// * `source` - The YARA source code to tokenize
///
/// # Example
///
/// ```
/// use r_yara_parser::tokenize;
///
/// let source = "rule test { condition: true }";
/// for result in tokenize(source) {
///     if let Ok(token) = result {
///         println!("{:?}", token.token);
///     }
/// }
/// ```
pub fn tokenize(source: &str) -> Lexer<'_> {
    Lexer::new(source)
}

/// Parser error type
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseError {
    #[error("Lexer error: {0}")]
    Lexer(#[from] LexerError),

    #[error("Unexpected token at {span:?}: expected {expected}, found {found}")]
    UnexpectedToken {
        span: Span,
        expected: String,
        found: String,
    },

    #[error("Unexpected end of file")]
    UnexpectedEof,

    #[error("Invalid rule: {message}")]
    InvalidRule { span: Span, message: String },

    #[error("Invalid expression: {message}")]
    InvalidExpression { span: Span, message: String },

    #[error("Invalid string pattern: {message}")]
    InvalidPattern { span: Span, message: String },

    #[error("Duplicate identifier: {name}")]
    DuplicateIdentifier { span: Span, name: String },

    #[error("Undefined identifier: {name}")]
    UndefinedIdentifier { span: Span, name: String },
}

impl ParseError {
    /// Get the span associated with this error, if any
    pub fn span(&self) -> Option<Span> {
        match self {
            ParseError::Lexer(e) => match e {
                LexerError::InvalidToken { span, .. } => Some(*span),
                LexerError::UnterminatedString { start } => Some(Span::new(*start, *start + 1)),
                LexerError::UnterminatedRegex { start } => Some(Span::new(*start, *start + 1)),
                LexerError::UnterminatedHexString { start } => Some(Span::new(*start, *start + 1)),
            },
            ParseError::UnexpectedToken { span, .. } => Some(*span),
            ParseError::UnexpectedEof => None,
            ParseError::InvalidRule { span, .. } => Some(*span),
            ParseError::InvalidExpression { span, .. } => Some(*span),
            ParseError::InvalidPattern { span, .. } => Some(*span),
            ParseError::DuplicateIdentifier { span, .. } => Some(*span),
            ParseError::UndefinedIdentifier { span, .. } => Some(*span),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize() {
        let source = "rule test { condition: true }";
        let tokens: Vec<_> = tokenize(source)
            .filter_map(|r| r.ok())
            .map(|st| st.token)
            .collect();

        assert!(tokens.contains(&Token::Rule));
        assert!(tokens.contains(&Token::Condition));
        assert!(tokens.contains(&Token::True));
    }

    #[test]
    fn test_parse_placeholder() {
        let source = "rule test { condition: true }";
        let result = parse(source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_complex_rule_tokenization() {
        let source = r#"
            import "pe"

            rule detect_malware : malware {
                meta:
                    author = "R-YARA"
                    description = "Detect malware patterns"
                    severity = 5

                strings:
                    $mz = { 4D 5A }
                    $text = "malicious" nocase wide
                    $regex = /evil[0-9]+/i

                condition:
                    $mz at 0 and
                    any of ($text, $regex) and
                    filesize < 1MB
            }
        "#;

        let tokens: Vec<_> = tokenize(source).collect();
        let ok_tokens: Vec<_> = tokens.iter().filter(|r| r.is_ok()).collect();

        // Verify key tokens are present
        assert!(ok_tokens.len() > 20);
    }

    #[test]
    fn test_string_modifiers_tokenization() {
        let source = r#"$a = "test" nocase wide ascii fullword xor base64"#;
        let tokens: Vec<_> = tokenize(source)
            .filter_map(|r| r.ok())
            .map(|st| st.token)
            .collect();

        assert!(tokens.contains(&Token::Nocase));
        assert!(tokens.contains(&Token::Wide));
        assert!(tokens.contains(&Token::Ascii));
        assert!(tokens.contains(&Token::Fullword));
        assert!(tokens.contains(&Token::Xor));
        assert!(tokens.contains(&Token::Base64));
    }

    #[test]
    fn test_hex_pattern_tokenization() {
        let source = r#"$hex = { 4D 5A ?? [4-8] ( 00 | FF ) }"#;
        let tokens: Vec<_> = tokenize(source)
            .filter_map(|r| r.ok())
            .collect();

        // Should have string identifier, assign, and hex string
        assert!(tokens.iter().any(|t| matches!(t.token, Token::StringIdentifier(_))));
        assert!(tokens.iter().any(|t| matches!(t.token, Token::Assign)));
        assert!(tokens.iter().any(|t| matches!(t.token, Token::HexString(_))));
    }

    #[test]
    fn test_quantifier_expressions() {
        let source = "all of them any of ($a*) 2 of ($a, $b, $c)";
        let tokens: Vec<_> = tokenize(source)
            .filter_map(|r| r.ok())
            .map(|st| st.token)
            .collect();

        assert!(tokens.contains(&Token::All));
        assert!(tokens.contains(&Token::Any));
        assert!(tokens.contains(&Token::Of));
        assert!(tokens.contains(&Token::Them));
    }
}
