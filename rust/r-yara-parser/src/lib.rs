//! R-YARA Parser
//!
//! A high-performance YARA rule parser written in Rust.
//!
//! This crate provides:
//! - **Lexer**: Tokenizes YARA rules using Logos for efficient lexical analysis
//! - **AST**: Abstract Syntax Tree definitions for YARA rules
//! - **Parser**: Hand-written recursive descent parser for full YARA syntax
//!
//! # Example
//!
//! ```
//! use r_yara_parser::parse;
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
//! match parse(source) {
//!     Ok(ast) => {
//!         println!("Parsed {} rules", ast.rules.len());
//!         for rule in &ast.rules {
//!             println!("  - {}", rule.name);
//!         }
//!     }
//!     Err(e) => eprintln!("Parse error: {}", e),
//! }
//! ```
//!
//! # Architecture
//!
//! The parser is designed to be modular and extensible:
//!
//! 1. **Lexer** (`lexer.rs`): Uses Logos for zero-copy tokenization
//! 2. **AST** (`ast.rs`): Type-safe representation of YARA rules
//! 3. **Parser** (`parser.rs`): Hand-written recursive descent parser
//!
//! # Performance Goals
//!
//! - Zero-copy string handling with `SmolStr`
//! - Efficient memory layout for AST nodes
//! - Fast lexing with Logos (faster than handwritten lexers)
//! - Parallel parsing support for large rule sets

pub mod ast;
pub mod lexer;
pub mod parser;

// Re-export commonly used types from AST
pub use ast::{
    AtExpr, Base64Modifier, BinaryExpr, BinaryOp, Expression, FieldAccess, ForExpr, ForIterable,
    ForIterator, FunctionCall, HexString, HexToken, Identifier, Import, Include, IndexExpr, InExpr,
    MatchesExpr, MetaEntry, MetaValue, OfExpr, Quantifier, QuantifierKind, RangeExpr,
    RegexModifiers, RegexString, Rule, RuleModifiers, SourceFile, StringCountExpr,
    StringDeclaration, StringLengthExpr, StringModifiers, StringOffsetExpr, StringPattern,
    StringSet, TextString, UnaryExpr, UnaryOp, XorModifier,
};

// Re-export lexer types
pub use lexer::{Lexer, LexerError, NumberValue, Span, SpannedToken, Token};

// Re-export parser functions
pub use parser::{parse, parse_expression, parse_hex_tokens, parse_regex, Parser};

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
    fn test_parse_simple() {
        let source = "rule test { condition: true }";
        let result = parse(source);
        assert!(result.is_ok());
        let ast = result.unwrap();
        assert_eq!(ast.rules.len(), 1);
        assert_eq!(ast.rules[0].name.as_str(), "test");
    }

    #[test]
    fn test_parse_with_imports() {
        let source = r#"
            import "pe"
            import "hash"

            rule test {
                condition:
                    pe.is_pe
            }
        "#;
        let result = parse(source);
        assert!(result.is_ok());
        let ast = result.unwrap();
        assert_eq!(ast.imports.len(), 2);
        assert_eq!(ast.rules.len(), 1);
    }

    #[test]
    fn test_parse_full_rule() {
        let source = r#"
            import "pe"

            private rule detect_malware : malware suspicious {
                meta:
                    author = "R-YARA"
                    description = "Detect malware patterns"
                    severity = 5
                    malicious = true

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

        let result = parse(source);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());

        let ast = result.unwrap();
        assert_eq!(ast.imports.len(), 1);
        assert_eq!(ast.rules.len(), 1);

        let rule = &ast.rules[0];
        assert_eq!(rule.name.as_str(), "detect_malware");
        assert!(rule.modifiers.is_private);
        assert_eq!(rule.tags.len(), 2);
        assert_eq!(rule.meta.len(), 4);
        assert_eq!(rule.strings.len(), 3);
    }

    #[test]
    fn test_parse_complex_condition() {
        let source = r#"
            rule complex_condition {
                strings:
                    $a = "test"
                    $b = "hello"
                condition:
                    ($a or $b) and
                    #a > 5 and
                    @a[0] < 1000 and
                    filesize < 10KB
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_for_expression() {
        let source = r#"
            rule for_test {
                strings:
                    $a = "test"
                condition:
                    for all i in (0..filesize) : ( @a[i] < 100 )
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_quantifier_expressions() {
        let source = r#"
            rule quantifiers {
                strings:
                    $a = "test"
                    $b = "hello"
                    $c = "world"
                condition:
                    any of them or
                    all of ($a, $b) or
                    2 of ($a, $b, $c)
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());
    }

    #[test]
    fn test_string_modifiers() {
        let source = r#"
            rule modifiers {
                strings:
                    $a = "test" nocase wide ascii fullword
                    $b = "xored" xor(0x01-0xff)
                    $c = "encoded" base64
                condition:
                    any of them
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
        let ast = result.unwrap();
        assert_eq!(ast.rules[0].strings.len(), 3);
    }
}
