//! YARA Rule Lexer
//!
//! Tokenizes YARA rules using the Logos library for efficient lexical analysis.
//! Supports all YARA syntax including strings, hex patterns, and regular expressions.

use logos::Logos;
use std::fmt;

/// Token types for YARA rules
#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\r\n\f]+")]  // Skip whitespace
pub enum Token {
    // Keywords
    #[token("rule")]
    Rule,

    #[token("private")]
    Private,

    #[token("global")]
    Global,

    #[token("meta")]
    Meta,

    #[token("strings")]
    Strings,

    #[token("condition")]
    Condition,

    #[token("import")]
    Import,

    #[token("include")]
    Include,

    #[token("true")]
    True,

    #[token("false")]
    False,

    #[token("not")]
    Not,

    #[token("and")]
    And,

    #[token("or")]
    Or,

    #[token("all")]
    All,

    #[token("any")]
    Any,

    #[token("none")]
    None,

    #[token("of")]
    Of,

    #[token("them")]
    Them,

    #[token("for")]
    For,

    #[token("in")]
    In,

    #[token("at")]
    At,

    #[token("filesize")]
    Filesize,

    #[token("entrypoint")]
    Entrypoint,

    #[token("contains")]
    Contains,

    #[token("icontains")]
    IContains,

    #[token("startswith")]
    StartsWith,

    #[token("istartswith")]
    IStartsWith,

    #[token("endswith")]
    EndsWith,

    #[token("iendswith")]
    IEndsWith,

    #[token("iequals")]
    IEquals,

    #[token("matches")]
    Matches,

    #[token("defined")]
    Defined,

    // String modifiers
    #[token("nocase")]
    Nocase,

    #[token("wide")]
    Wide,

    #[token("ascii")]
    Ascii,

    #[token("fullword")]
    Fullword,

    #[token("xor")]
    Xor,

    #[token("base64")]
    Base64,

    #[token("base64wide")]
    Base64Wide,

    // Operators
    #[token("=")]
    Assign,

    #[token("==")]
    Equal,

    #[token("!=")]
    NotEqual,

    #[token("<")]
    LessThan,

    #[token("<=")]
    LessEqual,

    #[token(">")]
    GreaterThan,

    #[token(">=")]
    GreaterEqual,

    #[token("+")]
    Plus,

    #[token("-")]
    Minus,

    #[token("*")]
    Star,

    #[token("\\")]
    Backslash,

    #[token("%")]
    Percent,

    #[token("&")]
    Ampersand,

    #[token("|")]
    Pipe,

    #[token("^")]
    Caret,

    #[token("~")]
    Tilde,

    #[token("<<")]
    ShiftLeft,

    #[token(">>")]
    ShiftRight,

    #[token("..")]
    DotDot,

    #[token(".")]
    Dot,

    // Delimiters
    #[token("{")]
    LBrace,

    #[token("}")]
    RBrace,

    #[token("(")]
    LParen,

    #[token(")")]
    RParen,

    #[token("[")]
    LBracket,

    #[token("]")]
    RBracket,

    #[token(":")]
    Colon,

    #[token(",")]
    Comma,

    // Identifiers and literals
    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    Identifier(String),

    #[regex(r"\$[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    StringIdentifier(String),

    #[regex(r"#[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    StringCount(String),

    #[regex(r"@[a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    StringOffset(String),

    #[regex(r"![a-zA-Z_][a-zA-Z0-9_]*", |lex| lex.slice().to_string())]
    StringLength(String),

    // Numbers
    #[regex(r"0x[0-9a-fA-F]+", parse_hex_number)]
    #[regex(r"0o[0-7]+", parse_octal_number)]
    #[regex(r"[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?", parse_number)]
    Number(NumberValue),

    // Size suffixes
    #[regex(r"[0-9]+KB", |lex| parse_size(lex.slice(), 1024))]
    #[regex(r"[0-9]+MB", |lex| parse_size(lex.slice(), 1024 * 1024))]
    #[regex(r"[0-9]+GB", |lex| parse_size(lex.slice(), 1024 * 1024 * 1024))]
    SizeValue(i64),

    // String literals
    #[regex(r#""([^"\\]|\\.)*""#, parse_string_literal)]
    StringLiteral(String),

    // Hex strings - must start with whitespace + hex byte/wildcard to distinguish from LBrace
    // Pattern: { followed by whitespace, then hex content (bytes, wildcards, jumps, alternations)
    #[regex(r"\{\s+([0-9a-fA-F]{2}|\?\?|\?[0-9a-fA-F]|[0-9a-fA-F]\?)[\s0-9a-fA-F\[\]\(\)\|\?\-]*\}", |lex| lex.slice().to_string())]
    HexString(String),

    // Regular expressions
    #[regex(r"/([^/\\]|\\.)+/[ismx]*", |lex| lex.slice().to_string())]
    Regex(String),

    // Comments (captured for documentation)
    #[regex(r"//[^\n]*", |lex| lex.slice().to_string())]
    LineComment(String),

    #[regex(r"/\*([^*]|\*[^/])*\*/", |lex| lex.slice().to_string())]
    BlockComment(String),
}

/// Numeric value representation
#[derive(Debug, Clone, PartialEq)]
pub enum NumberValue {
    Integer(i64),
    Float(f64),
}

impl fmt::Display for NumberValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NumberValue::Integer(n) => write!(f, "{}", n),
            NumberValue::Float(n) => write!(f, "{}", n),
        }
    }
}

fn parse_hex_number(lex: &mut logos::Lexer<Token>) -> NumberValue {
    let slice = lex.slice();
    let value = i64::from_str_radix(&slice[2..], 16).unwrap_or(0);
    NumberValue::Integer(value)
}

fn parse_octal_number(lex: &mut logos::Lexer<Token>) -> NumberValue {
    let slice = lex.slice();
    let value = i64::from_str_radix(&slice[2..], 8).unwrap_or(0);
    NumberValue::Integer(value)
}

fn parse_number(lex: &mut logos::Lexer<Token>) -> NumberValue {
    let slice = lex.slice();
    if slice.contains('.') || slice.contains('e') || slice.contains('E') {
        NumberValue::Float(slice.parse().unwrap_or(0.0))
    } else {
        NumberValue::Integer(slice.parse().unwrap_or(0))
    }
}

fn parse_size(slice: &str, multiplier: i64) -> i64 {
    let num_str = &slice[..slice.len() - 2];
    num_str.parse::<i64>().unwrap_or(0) * multiplier
}

fn parse_string_literal(lex: &mut logos::Lexer<Token>) -> String {
    let slice = lex.slice();
    // Remove quotes and unescape
    let inner = &slice[1..slice.len() - 1];
    unescape_string(inner)
}

fn unescape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('x') => {
                    // Hex escape \xNN
                    let mut hex = String::new();
                    if let Some(h1) = chars.next() {
                        hex.push(h1);
                    }
                    if let Some(h2) = chars.next() {
                        hex.push(h2);
                    }
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                    }
                }
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Span information for tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Token with span information
#[derive(Debug, Clone)]
pub struct SpannedToken {
    pub token: Token,
    pub span: Span,
}

impl SpannedToken {
    pub fn new(token: Token, span: Span) -> Self {
        Self { token, span }
    }
}

/// Lexer wrapper that provides span information
pub struct Lexer<'source> {
    inner: logos::Lexer<'source, Token>,
}

impl<'source> Lexer<'source> {
    pub fn new(source: &'source str) -> Self {
        Self {
            inner: Token::lexer(source),
        }
    }

    pub fn source(&self) -> &'source str {
        self.inner.source()
    }
}

impl<'source> Iterator for Lexer<'source> {
    type Item = Result<SpannedToken, LexerError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(token) => {
                let span = self.inner.span();
                Some(Ok(SpannedToken::new(
                    token,
                    Span::new(span.start, span.end),
                )))
            }
            Err(()) => {
                let span = self.inner.span();
                Some(Err(LexerError::InvalidToken {
                    span: Span::new(span.start, span.end),
                    text: self.inner.slice().to_string(),
                }))
            }
        }
    }
}

/// Lexer error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum LexerError {
    #[error("Invalid token at {span:?}: '{text}'")]
    InvalidToken { span: Span, text: String },

    #[error("Unterminated string starting at position {start}")]
    UnterminatedString { start: usize },

    #[error("Unterminated regex starting at position {start}")]
    UnterminatedRegex { start: usize },

    #[error("Unterminated hex string starting at position {start}")]
    UnterminatedHexString { start: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(source: &str) -> Vec<Token> {
        Lexer::new(source)
            .filter_map(|r| r.ok())
            .map(|st| st.token)
            .collect()
    }

    #[test]
    fn test_keywords() {
        let tokens = lex("rule private global meta strings condition");
        assert_eq!(
            tokens,
            vec![
                Token::Rule,
                Token::Private,
                Token::Global,
                Token::Meta,
                Token::Strings,
                Token::Condition
            ]
        );
    }

    #[test]
    fn test_identifiers() {
        let tokens = lex("my_rule $my_string #count @offset !length");
        assert_eq!(
            tokens,
            vec![
                Token::Identifier("my_rule".to_string()),
                Token::StringIdentifier("$my_string".to_string()),
                Token::StringCount("#count".to_string()),
                Token::StringOffset("@offset".to_string()),
                Token::StringLength("!length".to_string()),
            ]
        );
    }

    #[test]
    fn test_numbers() {
        let tokens = lex("42 0x1F 3.14 1e10");
        assert_eq!(
            tokens,
            vec![
                Token::Number(NumberValue::Integer(42)),
                Token::Number(NumberValue::Integer(31)),
                Token::Number(NumberValue::Float(3.14)),
                Token::Number(NumberValue::Float(1e10)),
            ]
        );
    }

    #[test]
    fn test_size_values() {
        let tokens = lex("10KB 5MB 2GB");
        assert_eq!(
            tokens,
            vec![
                Token::SizeValue(10 * 1024),
                Token::SizeValue(5 * 1024 * 1024),
                Token::SizeValue(2 * 1024 * 1024 * 1024),
            ]
        );
    }

    #[test]
    fn test_string_literal() {
        let tokens = lex(r#""hello world" "escaped\n\t""#);
        assert_eq!(
            tokens,
            vec![
                Token::StringLiteral("hello world".to_string()),
                Token::StringLiteral("escaped\n\t".to_string()),
            ]
        );
    }

    #[test]
    fn test_operators() {
        let tokens = lex("== != < <= > >= + - * and or not");
        assert_eq!(
            tokens,
            vec![
                Token::Equal,
                Token::NotEqual,
                Token::LessThan,
                Token::LessEqual,
                Token::GreaterThan,
                Token::GreaterEqual,
                Token::Plus,
                Token::Minus,
                Token::Star,
                Token::And,
                Token::Or,
                Token::Not,
            ]
        );
    }

    #[test]
    fn test_string_modifiers() {
        let tokens = lex("nocase wide ascii fullword xor base64");
        assert_eq!(
            tokens,
            vec![
                Token::Nocase,
                Token::Wide,
                Token::Ascii,
                Token::Fullword,
                Token::Xor,
                Token::Base64,
            ]
        );
    }

    #[test]
    fn test_hex_string() {
        let tokens = lex("{ 4D 5A ?? [4-8] ( 00 | FF ) }");
        assert_eq!(tokens.len(), 1);
        match &tokens[0] {
            Token::HexString(s) => {
                assert!(s.contains("4D"));
                assert!(s.contains("5A"));
            }
            _ => panic!("Expected hex string"),
        }
    }

    #[test]
    fn test_regex() {
        let tokens = lex(r"/hello.*world/i /[a-z]+/");
        assert_eq!(tokens.len(), 2);
        match &tokens[0] {
            Token::Regex(r) => assert!(r.contains("hello")),
            _ => panic!("Expected regex"),
        }
    }

    #[test]
    fn test_comments() {
        let tokens = lex("rule // comment\n test /* block */");
        // Comments are captured as tokens
        assert!(tokens.iter().any(|t| matches!(t, Token::LineComment(_))));
        assert!(tokens.iter().any(|t| matches!(t, Token::BlockComment(_))));
    }

    #[test]
    fn test_simple_rule() {
        let source = r#"
            rule test_rule {
                meta:
                    author = "test"
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let tokens = lex(source);
        assert!(tokens.contains(&Token::Rule));
        assert!(tokens.contains(&Token::Meta));
        assert!(tokens.contains(&Token::Strings));
        assert!(tokens.contains(&Token::Condition));
    }
}
