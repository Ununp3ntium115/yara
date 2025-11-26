//! YARA Rule Parser
//!
//! Integrates the Logos lexer with the LALRPOP-generated parser.

use crate::ast::*;
use crate::lexer::{Lexer, LexerError, NumberValue, Span, SpannedToken, Token};
use crate::ParseError;
use lalrpop_util::lalrpop_mod;
use smol_str::SmolStr;

/// Internal enum for string modifiers during parsing
#[derive(Debug, Clone)]
pub enum StringMod {
    Nocase,
    Wide,
    Ascii,
    Fullword,
    Private,
    Xor(Option<(u8, u8)>),
    Base64(Option<SmolStr>, bool),
}

// Include the generated parser
lalrpop_mod!(pub grammar);

/// Parse a YARA source file into an AST
pub fn parse(source: &str) -> Result<SourceFile, ParseError> {
    let lexer = Lexer::new(source);
    let tokens = TokenStream::new(lexer)?;

    grammar::SourceFileParser::new()
        .parse(tokens)
        .map_err(|e| convert_lalrpop_error(e, source))
}

/// Parse a single expression (useful for testing)
pub fn parse_expression(source: &str) -> Result<Expression, ParseError> {
    let lexer = Lexer::new(source);
    let tokens = TokenStream::new(lexer)?;

    grammar::ExpressionParser::new()
        .parse(tokens)
        .map_err(|e| convert_lalrpop_error(e, source))
}

/// Token stream adapter for LALRPOP
pub struct TokenStream {
    tokens: Vec<(usize, Token, usize)>,
    index: usize,
}

impl TokenStream {
    pub fn new(lexer: Lexer<'_>) -> Result<Self, ParseError> {
        let mut tokens = Vec::new();

        for result in lexer {
            match result {
                Ok(spanned) => {
                    // Skip comments for parsing
                    match &spanned.token {
                        Token::LineComment(_) | Token::BlockComment(_) => continue,
                        _ => {}
                    }
                    tokens.push((spanned.span.start, spanned.token, spanned.span.end));
                }
                Err(e) => return Err(ParseError::Lexer(e)),
            }
        }

        Ok(Self { tokens, index: 0 })
    }
}

impl Iterator for TokenStream {
    type Item = Result<(usize, Token, usize), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.tokens.len() {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            Some(Ok(token))
        } else {
            None
        }
    }
}

/// Convert LALRPOP error to our ParseError type
fn convert_lalrpop_error(
    error: lalrpop_util::ParseError<usize, Token, ParseError>,
    _source: &str,
) -> ParseError {
    match error {
        lalrpop_util::ParseError::InvalidToken { location } => ParseError::UnexpectedToken {
            span: Span::new(location, location + 1),
            expected: "valid token".to_string(),
            found: "invalid token".to_string(),
        },
        lalrpop_util::ParseError::UnrecognizedEof { location, expected } => {
            ParseError::UnexpectedToken {
                span: Span::new(location, location),
                expected: expected.join(", "),
                found: "end of file".to_string(),
            }
        }
        lalrpop_util::ParseError::UnrecognizedToken { token, expected } => {
            ParseError::UnexpectedToken {
                span: Span::new(token.0, token.2),
                expected: expected.join(", "),
                found: format!("{:?}", token.1),
            }
        }
        lalrpop_util::ParseError::ExtraToken { token } => ParseError::UnexpectedToken {
            span: Span::new(token.0, token.2),
            expected: "end of input".to_string(),
            found: format!("{:?}", token.1),
        },
        lalrpop_util::ParseError::User { error } => error,
    }
}

/// Parse hex string tokens from the raw hex string
pub fn parse_hex_tokens(hex_str: &str) -> Vec<HexToken> {
    let mut tokens = Vec::new();
    let content = hex_str
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();

    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => continue,
            '?' => {
                if chars.peek() == Some(&'?') {
                    chars.next();
                    tokens.push(HexToken::Wildcard);
                } else if let Some(&next) = chars.peek() {
                    if next.is_ascii_hexdigit() {
                        chars.next();
                        tokens.push(HexToken::NibbleWildcard {
                            high: None,
                            low: Some(hex_digit(next)),
                        });
                    } else {
                        tokens.push(HexToken::Wildcard);
                    }
                } else {
                    tokens.push(HexToken::Wildcard);
                }
            }
            '[' => {
                // Parse jump: [n] or [n-m]
                let mut num_str = String::new();
                let mut max_str = String::new();
                let mut has_dash = false;

                while let Some(&c) = chars.peek() {
                    if c == ']' {
                        chars.next();
                        break;
                    } else if c == '-' {
                        has_dash = true;
                        chars.next();
                    } else if c.is_ascii_digit() {
                        chars.next();
                        if has_dash {
                            max_str.push(c);
                        } else {
                            num_str.push(c);
                        }
                    } else {
                        chars.next();
                    }
                }

                let min = num_str.parse().unwrap_or(0);
                let max = if has_dash {
                    if max_str.is_empty() {
                        None // Unlimited
                    } else {
                        Some(max_str.parse().unwrap_or(min))
                    }
                } else {
                    Some(min)
                };

                tokens.push(HexToken::Jump { min, max });
            }
            '(' => {
                // Parse alternation
                let mut alternatives: Vec<Vec<HexToken>> = vec![Vec::new()];

                while let Some(&c) = chars.peek() {
                    if c == ')' {
                        chars.next();
                        break;
                    } else if c == '|' {
                        chars.next();
                        alternatives.push(Vec::new());
                    } else if c == '?' {
                        chars.next();
                        if chars.peek() == Some(&'?') {
                            chars.next();
                            alternatives.last_mut().unwrap().push(HexToken::Wildcard);
                        } else {
                            alternatives.last_mut().unwrap().push(HexToken::Wildcard);
                        }
                    } else if c.is_ascii_hexdigit() {
                        chars.next();
                        if let Some(&next) = chars.peek() {
                            if next.is_ascii_hexdigit() {
                                chars.next();
                                let byte = (hex_digit(c) << 4) | hex_digit(next);
                                alternatives.last_mut().unwrap().push(HexToken::Byte(byte));
                            } else if next == '?' {
                                chars.next();
                                alternatives.last_mut().unwrap().push(HexToken::NibbleWildcard {
                                    high: Some(hex_digit(c)),
                                    low: None,
                                });
                            }
                        }
                    } else {
                        chars.next();
                    }
                }

                tokens.push(HexToken::Alternation(alternatives));
            }
            c if c.is_ascii_hexdigit() => {
                if let Some(&next) = chars.peek() {
                    if next.is_ascii_hexdigit() {
                        chars.next();
                        let byte = (hex_digit(c) << 4) | hex_digit(next);
                        tokens.push(HexToken::Byte(byte));
                    } else if next == '?' {
                        chars.next();
                        tokens.push(HexToken::NibbleWildcard {
                            high: Some(hex_digit(c)),
                            low: None,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    tokens
}

fn hex_digit(c: char) -> u8 {
    match c {
        '0'..='9' => c as u8 - b'0',
        'a'..='f' => c as u8 - b'a' + 10,
        'A'..='F' => c as u8 - b'A' + 10,
        _ => 0,
    }
}

/// Parse regex string into pattern and modifiers
pub fn parse_regex(regex_str: &str) -> (String, RegexModifiers) {
    let mut modifiers = RegexModifiers::default();

    // Find the closing /
    let content = regex_str.trim_start_matches('/');
    if let Some(last_slash) = content.rfind('/') {
        let pattern = &content[..last_slash];
        let mod_str = &content[last_slash + 1..];

        for c in mod_str.chars() {
            match c {
                'i' => modifiers.case_insensitive = true,
                's' => modifiers.dot_matches_all = true,
                'm' => modifiers.multiline = true,
                'x' => modifiers.extended = true,
                _ => {}
            }
        }

        (pattern.to_string(), modifiers)
    } else {
        (content.to_string(), modifiers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_tokens() {
        let tokens = parse_hex_tokens("{ 4D 5A }");
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], HexToken::Byte(0x4D)));
        assert!(matches!(tokens[1], HexToken::Byte(0x5A)));
    }

    #[test]
    fn test_parse_hex_with_wildcard() {
        let tokens = parse_hex_tokens("{ 4D ?? 5A }");
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], HexToken::Byte(0x4D)));
        assert!(matches!(tokens[1], HexToken::Wildcard));
        assert!(matches!(tokens[2], HexToken::Byte(0x5A)));
    }

    #[test]
    fn test_parse_hex_with_jump() {
        let tokens = parse_hex_tokens("{ 4D [4-8] 5A }");
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[1], HexToken::Jump { min: 4, max: Some(8) }));
    }

    #[test]
    fn test_parse_hex_with_alternation() {
        let tokens = parse_hex_tokens("{ ( 4D | 5A ) }");
        assert_eq!(tokens.len(), 1);
        if let HexToken::Alternation(alts) = &tokens[0] {
            assert_eq!(alts.len(), 2);
        } else {
            panic!("Expected alternation");
        }
    }

    #[test]
    fn test_parse_regex_modifiers() {
        let (pattern, mods) = parse_regex("/hello.*world/i");
        assert_eq!(pattern, "hello.*world");
        assert!(mods.case_insensitive);
        assert!(!mods.dot_matches_all);
    }

    #[test]
    fn test_parse_regex_multiple_modifiers() {
        let (pattern, mods) = parse_regex("/test/ism");
        assert_eq!(pattern, "test");
        assert!(mods.case_insensitive);
        assert!(mods.dot_matches_all);
        assert!(mods.multiline);
    }
}
