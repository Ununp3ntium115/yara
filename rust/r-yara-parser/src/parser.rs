//! YARA Rule Parser
//!
//! A hand-written recursive descent parser for YARA rules.
//! This approach (used by YARA-X) provides better error messages
//! and faster iteration than grammar-based parsers.

use crate::ast::*;
use crate::lexer::{Lexer, NumberValue, Span, SpannedToken, Token};
use crate::ParseError;
use smol_str::SmolStr;

/// Parser state
pub struct Parser<'source> {
    tokens: Vec<SpannedToken>,
    position: usize,
    source: &'source str,
}

impl<'source> Parser<'source> {
    /// Create a new parser from source code
    pub fn new(source: &'source str) -> Result<Self, ParseError> {
        let lexer = Lexer::new(source);
        let mut tokens = Vec::new();

        for result in lexer {
            match result {
                Ok(spanned) => {
                    // Skip comments
                    match &spanned.token {
                        Token::LineComment(_) | Token::BlockComment(_) => continue,
                        _ => tokens.push(spanned),
                    }
                }
                Err(e) => return Err(ParseError::Lexer(e)),
            }
        }

        Ok(Self {
            tokens,
            position: 0,
            source,
        })
    }

    /// Parse the entire source file
    pub fn parse(&mut self) -> Result<SourceFile, ParseError> {
        let mut imports = Vec::new();
        let mut includes = Vec::new();
        let mut rules = Vec::new();

        while !self.is_at_end() {
            match self.peek() {
                Some(Token::Import) => imports.push(self.parse_import()?),
                Some(Token::Include) => includes.push(self.parse_include()?),
                Some(Token::Rule) | Some(Token::Private) | Some(Token::Global) => {
                    rules.push(self.parse_rule()?);
                }
                Some(other) => {
                    return Err(ParseError::UnexpectedToken {
                        span: self.current_span(),
                        expected: "import, include, or rule".to_string(),
                        found: format!("{:?}", other),
                    });
                }
                None => break,
            }
        }

        Ok(SourceFile {
            imports,
            includes,
            rules,
        })
    }

    // ==================== Import/Include ====================

    fn parse_import(&mut self) -> Result<Import, ParseError> {
        let start = self.current_span().start;
        self.expect(Token::Import)?;

        let name = self.expect_string_literal()?;
        let end = self.previous_span().end;

        Ok(Import {
            module_name: SmolStr::new(&name),
            span: Span::new(start, end),
        })
    }

    fn parse_include(&mut self) -> Result<Include, ParseError> {
        let start = self.current_span().start;
        self.expect(Token::Include)?;

        let path = self.expect_string_literal()?;
        let end = self.previous_span().end;

        Ok(Include {
            path: SmolStr::new(&path),
            span: Span::new(start, end),
        })
    }

    // ==================== Rule ====================

    fn parse_rule(&mut self) -> Result<Rule, ParseError> {
        let start = self.current_span().start;

        // Parse modifiers
        let modifiers = self.parse_rule_modifiers()?;

        // Parse 'rule' keyword
        self.expect(Token::Rule)?;

        // Parse rule name
        let name = self.expect_identifier()?;

        // Parse optional tags
        let tags = if self.check(Token::Colon) {
            self.advance();
            self.parse_tags()?
        } else {
            Vec::new()
        };

        // Parse rule body
        self.expect(Token::LBrace)?;

        let meta = if self.check(Token::Meta) {
            self.parse_meta_section()?
        } else {
            Vec::new()
        };

        let strings = if self.check(Token::Strings) {
            self.parse_strings_section()?
        } else {
            Vec::new()
        };

        self.expect(Token::Condition)?;
        self.expect(Token::Colon)?;

        let condition = self.parse_expression()?;

        self.expect(Token::RBrace)?;

        let end = self.previous_span().end;

        Ok(Rule {
            name: SmolStr::new(&name),
            modifiers,
            tags,
            meta,
            strings,
            condition,
            span: Span::new(start, end),
        })
    }

    fn parse_rule_modifiers(&mut self) -> Result<RuleModifiers, ParseError> {
        let mut modifiers = RuleModifiers::default();

        loop {
            if self.check(Token::Private) {
                self.advance();
                modifiers.is_private = true;
            } else if self.check(Token::Global) {
                self.advance();
                modifiers.is_global = true;
            } else {
                break;
            }
        }

        Ok(modifiers)
    }

    fn parse_tags(&mut self) -> Result<Vec<SmolStr>, ParseError> {
        let mut tags = Vec::new();

        while let Some(Token::Identifier(_)) = self.peek() {
            let tag = self.expect_identifier()?;
            tags.push(SmolStr::new(&tag));
        }

        Ok(tags)
    }

    // ==================== Meta Section ====================

    fn parse_meta_section(&mut self) -> Result<Vec<MetaEntry>, ParseError> {
        self.expect(Token::Meta)?;
        self.expect(Token::Colon)?;

        let mut entries = Vec::new();

        while let Some(Token::Identifier(_)) = self.peek() {
            entries.push(self.parse_meta_entry()?);
        }

        Ok(entries)
    }

    fn parse_meta_entry(&mut self) -> Result<MetaEntry, ParseError> {
        let start = self.current_span().start;
        let key = self.expect_identifier()?;

        self.expect(Token::Assign)?;

        let value = self.parse_meta_value()?;
        let end = self.previous_span().end;

        Ok(MetaEntry {
            key: SmolStr::new(&key),
            value,
            span: Span::new(start, end),
        })
    }

    fn parse_meta_value(&mut self) -> Result<MetaValue, ParseError> {
        match self.peek() {
            Some(Token::StringLiteral(s)) => {
                let s = s.clone();
                self.advance();
                Ok(MetaValue::String(SmolStr::new(&s)))
            }
            Some(Token::Number(n)) => {
                let n = n.clone();
                self.advance();
                match n {
                    NumberValue::Integer(i) => Ok(MetaValue::Integer(i)),
                    NumberValue::Float(_) => Ok(MetaValue::Integer(0)), // Meta doesn't support floats
                }
            }
            Some(Token::True) => {
                self.advance();
                Ok(MetaValue::Boolean(true))
            }
            Some(Token::False) => {
                self.advance();
                Ok(MetaValue::Boolean(false))
            }
            _ => Err(ParseError::UnexpectedToken {
                span: self.current_span(),
                expected: "string, number, or boolean".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    // ==================== Strings Section ====================

    fn parse_strings_section(&mut self) -> Result<Vec<StringDeclaration>, ParseError> {
        self.expect(Token::Strings)?;
        self.expect(Token::Colon)?;

        let mut strings = Vec::new();

        while let Some(Token::StringIdentifier(_)) = self.peek() {
            strings.push(self.parse_string_declaration()?);
        }

        Ok(strings)
    }

    fn parse_string_declaration(&mut self) -> Result<StringDeclaration, ParseError> {
        let start = self.current_span().start;

        let name = match self.advance() {
            Some(SpannedToken {
                token: Token::StringIdentifier(s),
                ..
            }) => s,
            _ => {
                return Err(ParseError::UnexpectedToken {
                    span: self.previous_span(),
                    expected: "string identifier".to_string(),
                    found: "other".to_string(),
                })
            }
        };

        self.expect(Token::Assign)?;

        let pattern = self.parse_string_pattern()?;
        let modifiers = self.parse_string_modifiers()?;

        let end = self.previous_span().end;

        Ok(StringDeclaration {
            name: SmolStr::new(&name),
            pattern,
            modifiers,
            span: Span::new(start, end),
        })
    }

    fn parse_string_pattern(&mut self) -> Result<StringPattern, ParseError> {
        let start = self.current_span().start;

        match self.peek().cloned() {
            Some(Token::StringLiteral(s)) => {
                self.advance();
                let end = self.previous_span().end;
                Ok(StringPattern::Text(TextString {
                    value: SmolStr::new(&s),
                    span: Span::new(start, end),
                }))
            }
            Some(Token::LBrace) => {
                // Parse hex string: { hex_content }
                self.advance();
                let hex_content = self.parse_hex_string_content()?;
                let end = self.previous_span().end;
                Ok(StringPattern::Hex(HexString {
                    tokens: hex_content,
                    span: Span::new(start, end),
                }))
            }
            Some(Token::Regex(r)) => {
                self.advance();
                let end = self.previous_span().end;
                let (pattern, modifiers) = parse_regex(&r);
                Ok(StringPattern::Regex(RegexString {
                    pattern: SmolStr::new(&pattern),
                    modifiers,
                    span: Span::new(start, end),
                }))
            }
            _ => Err(ParseError::UnexpectedToken {
                span: self.current_span(),
                expected: "string, hex pattern, or regex".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn parse_string_modifiers(&mut self) -> Result<StringModifiers, ParseError> {
        let mut modifiers = StringModifiers::default();

        loop {
            match self.peek() {
                Some(Token::Nocase) => {
                    self.advance();
                    modifiers.nocase = true;
                }
                Some(Token::Wide) => {
                    self.advance();
                    modifiers.wide = true;
                }
                Some(Token::Ascii) => {
                    self.advance();
                    modifiers.ascii = true;
                }
                Some(Token::Fullword) => {
                    self.advance();
                    modifiers.fullword = true;
                }
                Some(Token::Private) => {
                    self.advance();
                    modifiers.private = true;
                }
                Some(Token::Xor) => {
                    self.advance();
                    let range = if self.check(Token::LParen) {
                        self.advance();
                        let lo = self.expect_integer()? as u8;
                        let hi = if self.check(Token::Minus) {
                            self.advance();
                            self.expect_integer()? as u8
                        } else {
                            lo
                        };
                        self.expect(Token::RParen)?;
                        Some((lo, hi))
                    } else {
                        None
                    };
                    modifiers.xor = Some(XorModifier { range });
                }
                Some(Token::Base64) => {
                    self.advance();
                    let alphabet = if self.check(Token::LParen) {
                        self.advance();
                        let s = self.expect_string_literal()?;
                        self.expect(Token::RParen)?;
                        Some(SmolStr::new(&s))
                    } else {
                        None
                    };
                    modifiers.base64 = Some(Base64Modifier {
                        alphabet,
                        wide: false,
                    });
                }
                Some(Token::Base64Wide) => {
                    self.advance();
                    let alphabet = if self.check(Token::LParen) {
                        self.advance();
                        let s = self.expect_string_literal()?;
                        self.expect(Token::RParen)?;
                        Some(SmolStr::new(&s))
                    } else {
                        None
                    };
                    modifiers.base64 = Some(Base64Modifier {
                        alphabet,
                        wide: true,
                    });
                }
                _ => break,
            }
        }

        Ok(modifiers)
    }

    /// Parse hex string content between { and }
    /// Collects tokens until RBrace and parses them as hex tokens
    fn parse_hex_string_content(&mut self) -> Result<Vec<HexToken>, ParseError> {
        // Use span-based extraction to get the raw hex content from source
        // This avoids the issue where the lexer splits "4D" into Number(4) + Identifier("D")
        let start_pos = self.current_span().start;
        let mut depth = 1; // We've already consumed the opening {

        while depth > 0 {
            match self.peek() {
                Some(Token::LBrace) => {
                    self.advance();
                    depth += 1;
                }
                Some(Token::RBrace) => {
                    depth -= 1;
                    if depth > 0 {
                        self.advance();
                    }
                }
                Some(Token::LParen) | Some(Token::RParen) |
                Some(Token::LBracket) | Some(Token::RBracket) |
                Some(Token::Pipe) | Some(Token::Minus) |
                Some(Token::Question) | Some(Token::Tilde) => {
                    self.advance();
                }
                Some(Token::Identifier(_)) | Some(Token::Number(_)) => {
                    self.advance();
                }
                None => {
                    return Err(ParseError::UnexpectedEof);
                }
                _ => {
                    self.advance();
                }
            }
        }

        // Get end position before consuming the closing brace
        let end_pos = self.current_span().start;
        self.advance(); // Consume the closing }

        // Extract raw source text and parse it
        let hex_content = &self.source[start_pos..end_pos];
        Ok(parse_hex_tokens(&format!("{{{}}}", hex_content)))
    }

    // ==================== Expressions ====================

    fn parse_expression(&mut self) -> Result<Expression, ParseError> {
        self.parse_or_expression()
    }

    fn parse_or_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_and_expression()?;

        while self.check(Token::Or) {
            self.advance();
            let right = self.parse_and_expression()?;
            let end = self.previous_span().end;
            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op: BinaryOp::Or,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_and_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_not_expression()?;

        while self.check(Token::And) {
            self.advance();
            let right = self.parse_not_expression()?;
            let end = self.previous_span().end;
            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op: BinaryOp::And,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_not_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;

        if self.check(Token::Not) {
            self.advance();
            let expr = self.parse_not_expression()?;
            let end = self.previous_span().end;
            return Ok(Expression::Unary(Box::new(UnaryExpr {
                op: UnaryOp::Not,
                operand: expr,
                span: Span::new(start, end),
            })));
        }

        if self.check(Token::Defined) {
            self.advance();
            let expr = self.parse_not_expression()?;
            return Ok(Expression::Defined(Box::new(expr)));
        }

        self.parse_comparison_expression()
    }

    fn parse_comparison_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_string_op_expression()?;

        loop {
            let op = match self.peek() {
                Some(Token::Equal) => BinaryOp::Equal,
                Some(Token::NotEqual) => BinaryOp::NotEqual,
                Some(Token::LessThan) => BinaryOp::LessThan,
                Some(Token::LessEqual) => BinaryOp::LessEqual,
                Some(Token::GreaterThan) => BinaryOp::GreaterThan,
                Some(Token::GreaterEqual) => BinaryOp::GreaterEqual,
                _ => break,
            };

            self.advance();
            let right = self.parse_string_op_expression()?;
            let end = self.previous_span().end;

            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_string_op_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_bitwise_or_expression()?;

        loop {
            let op = match self.peek() {
                Some(Token::Contains) => BinaryOp::Contains,
                Some(Token::IContains) => BinaryOp::IContains,
                Some(Token::StartsWith) => BinaryOp::StartsWith,
                Some(Token::IStartsWith) => BinaryOp::IStartsWith,
                Some(Token::EndsWith) => BinaryOp::EndsWith,
                Some(Token::IEndsWith) => BinaryOp::IEndsWith,
                Some(Token::IEquals) => BinaryOp::IEquals,
                _ => break,
            };

            self.advance();
            let right = self.parse_bitwise_or_expression()?;
            let end = self.previous_span().end;

            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_bitwise_or_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_bitwise_xor_expression()?;

        while self.check(Token::Pipe) {
            self.advance();
            let right = self.parse_bitwise_xor_expression()?;
            let end = self.previous_span().end;
            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op: BinaryOp::BitOr,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_bitwise_xor_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_bitwise_and_expression()?;

        while self.check(Token::Caret) {
            self.advance();
            let right = self.parse_bitwise_and_expression()?;
            let end = self.previous_span().end;
            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op: BinaryOp::BitXor,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_bitwise_and_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_shift_expression()?;

        while self.check(Token::Ampersand) {
            self.advance();
            let right = self.parse_shift_expression()?;
            let end = self.previous_span().end;
            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op: BinaryOp::BitAnd,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_shift_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_additive_expression()?;

        loop {
            let op = match self.peek() {
                Some(Token::ShiftLeft) => BinaryOp::ShiftLeft,
                Some(Token::ShiftRight) => BinaryOp::ShiftRight,
                _ => break,
            };

            self.advance();
            let right = self.parse_additive_expression()?;
            let end = self.previous_span().end;

            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_additive_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_multiplicative_expression()?;

        loop {
            let op = match self.peek() {
                Some(Token::Plus) => BinaryOp::Add,
                Some(Token::Minus) => BinaryOp::Sub,
                _ => break,
            };

            self.advance();
            let right = self.parse_multiplicative_expression()?;
            let end = self.previous_span().end;

            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_multiplicative_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut left = self.parse_unary_expression()?;

        loop {
            let op = match self.peek() {
                Some(Token::Star) => BinaryOp::Mul,
                Some(Token::Backslash) => BinaryOp::Div,
                Some(Token::Percent) => BinaryOp::Mod,
                _ => break,
            };

            self.advance();
            let right = self.parse_unary_expression()?;
            let end = self.previous_span().end;

            left = Expression::Binary(Box::new(BinaryExpr {
                left,
                op,
                right,
                span: Span::new(start, end),
            }));
        }

        Ok(left)
    }

    fn parse_unary_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;

        if self.check(Token::Minus) {
            self.advance();
            let expr = self.parse_unary_expression()?;
            let end = self.previous_span().end;
            return Ok(Expression::Unary(Box::new(UnaryExpr {
                op: UnaryOp::Neg,
                operand: expr,
                span: Span::new(start, end),
            })));
        }

        if self.check(Token::Tilde) {
            self.advance();
            let expr = self.parse_unary_expression()?;
            let end = self.previous_span().end;
            return Ok(Expression::Unary(Box::new(UnaryExpr {
                op: UnaryOp::BitNot,
                operand: expr,
                span: Span::new(start, end),
            })));
        }

        self.parse_postfix_expression()
    }

    fn parse_postfix_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;
        let mut expr = self.parse_primary_expression()?;

        loop {
            if self.check(Token::LBracket) {
                self.advance();
                let index = self.parse_expression()?;
                self.expect(Token::RBracket)?;
                let end = self.previous_span().end;
                expr = Expression::Index(Box::new(IndexExpr {
                    object: expr,
                    index,
                    span: Span::new(start, end),
                }));
            } else if self.check(Token::Dot) {
                self.advance();
                let field = self.expect_identifier()?;
                let end = self.previous_span().end;
                expr = Expression::FieldAccess(Box::new(FieldAccess {
                    object: expr,
                    field: SmolStr::new(&field),
                    span: Span::new(start, end),
                }));
            } else {
                break;
            }
        }

        Ok(expr)
    }

    fn parse_primary_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;

        // Boolean literals
        if self.check(Token::True) {
            self.advance();
            return Ok(Expression::Boolean(true));
        }
        if self.check(Token::False) {
            self.advance();
            return Ok(Expression::Boolean(false));
        }

        // Number literals
        if let Some(Token::Number(n)) = self.peek().cloned() {
            // Check if this is a numeric quantifier (N of ...)
            if let NumberValue::Integer(_) = n {
                if self.peek_at(1) == Some(&Token::Of) || self.peek_at(1) == Some(&Token::Percent) {
                    return self.parse_quantifier_expression();
                }
            }
            self.advance();
            return Ok(match n {
                NumberValue::Integer(i) => Expression::Integer(i),
                NumberValue::Float(f) => Expression::Float(f),
            });
        }

        // Size values
        if let Some(Token::SizeValue(s)) = self.peek().cloned() {
            self.advance();
            return Ok(Expression::Integer(s));
        }

        // String literal
        if let Some(Token::StringLiteral(s)) = self.peek().cloned() {
            self.advance();
            return Ok(Expression::String(SmolStr::new(&s)));
        }

        // Special keywords
        if self.check(Token::Filesize) {
            self.advance();
            return Ok(Expression::Filesize);
        }
        if self.check(Token::Entrypoint) {
            self.advance();
            return Ok(Expression::Entrypoint);
        }

        // String reference ($a)
        if let Some(Token::StringIdentifier(s)) = self.peek().cloned() {
            self.advance();

            // Check for 'at' expression
            if self.check(Token::At) {
                self.advance();
                let offset = self.parse_expression()?;
                let end = self.previous_span().end;
                return Ok(Expression::At(Box::new(AtExpr {
                    string: SmolStr::new(&s),
                    offset,
                    span: Span::new(start, end),
                })));
            }

            // Check for 'in' expression
            if self.check(Token::In) {
                self.advance();
                self.expect(Token::LParen)?;
                let range_start = self.parse_expression()?;
                self.expect(Token::DotDot)?;
                let range_end = self.parse_expression()?;
                self.expect(Token::RParen)?;
                let end = self.previous_span().end;
                return Ok(Expression::In(Box::new(InExpr {
                    expr: Expression::StringRef(SmolStr::new(&s)),
                    range: RangeExpr {
                        start: range_start,
                        end: range_end,
                        span: Span::new(start, end),
                    },
                    span: Span::new(start, end),
                })));
            }

            return Ok(Expression::StringRef(SmolStr::new(&s)));
        }

        // String count (#a)
        if let Some(Token::StringCount(s)) = self.peek().cloned() {
            self.advance();
            let range = if self.check(Token::In) {
                self.advance();
                self.expect(Token::LParen)?;
                let range_start = self.parse_expression()?;
                self.expect(Token::DotDot)?;
                let range_end = self.parse_expression()?;
                self.expect(Token::RParen)?;
                let end = self.previous_span().end;
                Some(Box::new(RangeExpr {
                    start: range_start,
                    end: range_end,
                    span: Span::new(start, end),
                }))
            } else {
                None
            };
            let end = self.previous_span().end;
            return Ok(Expression::StringCount(StringCountExpr {
                name: SmolStr::new(&s),
                range,
                span: Span::new(start, end),
            }));
        }

        // String offset (@a)
        if let Some(Token::StringOffset(s)) = self.peek().cloned() {
            self.advance();
            let index = if self.check(Token::LBracket) {
                self.advance();
                let idx = self.parse_expression()?;
                self.expect(Token::RBracket)?;
                Some(Box::new(idx))
            } else {
                None
            };
            let end = self.previous_span().end;
            return Ok(Expression::StringOffset(StringOffsetExpr {
                name: SmolStr::new(&s),
                index,
                span: Span::new(start, end),
            }));
        }

        // String length (!a)
        if let Some(Token::StringLength(s)) = self.peek().cloned() {
            self.advance();
            let index = if self.check(Token::LBracket) {
                self.advance();
                let idx = self.parse_expression()?;
                self.expect(Token::RBracket)?;
                Some(Box::new(idx))
            } else {
                None
            };
            let end = self.previous_span().end;
            return Ok(Expression::StringLength(StringLengthExpr {
                name: SmolStr::new(&s),
                index,
                span: Span::new(start, end),
            }));
        }

        // Quantifier expressions (all, any, none, N)
        if self.check(Token::All) || self.check(Token::Any) || self.check(Token::None) {
            return self.parse_quantifier_expression();
        }

        // For expression
        if self.check(Token::For) {
            return self.parse_for_expression();
        }

        // Parenthesized expression
        if self.check(Token::LParen) {
            self.advance();
            let expr = self.parse_expression()?;
            self.expect(Token::RParen)?;
            return Ok(Expression::Paren(Box::new(expr)));
        }

        // Identifier (variable or function call)
        if let Some(Token::Identifier(_)) = self.peek() {
            let ident = self.parse_identifier()?;

            // Check for function call
            if self.check(Token::LParen) {
                self.advance();
                let mut args = Vec::new();
                if !self.check(Token::RParen) {
                    args.push(self.parse_expression()?);
                    while self.check(Token::Comma) {
                        self.advance();
                        args.push(self.parse_expression()?);
                    }
                }
                self.expect(Token::RParen)?;
                let end = self.previous_span().end;
                return Ok(Expression::FunctionCall(Box::new(FunctionCall {
                    function: ident,
                    arguments: args,
                    span: Span::new(start, end),
                })));
            }

            return Ok(Expression::Identifier(ident));
        }

        Err(ParseError::UnexpectedToken {
            span: self.current_span(),
            expected: "expression".to_string(),
            found: format!("{:?}", self.peek()),
        })
    }

    fn parse_quantifier_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;

        let count = if self.check(Token::All) {
            self.advance();
            QuantifierKind::All
        } else if self.check(Token::Any) {
            self.advance();
            QuantifierKind::Any
        } else if self.check(Token::None) {
            self.advance();
            QuantifierKind::None
        } else {
            let n = self.expect_integer()?;
            if self.check(Token::Percent) {
                self.advance();
                QuantifierKind::Percentage(Box::new(Expression::Integer(n)))
            } else {
                QuantifierKind::Count(Box::new(Expression::Integer(n)))
            }
        };

        self.expect(Token::Of)?;

        let strings = self.parse_string_set()?;

        // Check for optional 'at' or 'in'
        let (at, in_range) = if self.check(Token::At) {
            self.advance();
            let offset = self.parse_expression()?;
            (Some(Box::new(offset)), None)
        } else if self.check(Token::In) {
            self.advance();
            self.expect(Token::LParen)?;
            let range_start = self.parse_expression()?;
            self.expect(Token::DotDot)?;
            let range_end = self.parse_expression()?;
            self.expect(Token::RParen)?;
            let end = self.previous_span().end;
            (
                None,
                Some(RangeExpr {
                    start: range_start,
                    end: range_end,
                    span: Span::new(start, end),
                }),
            )
        } else {
            (None, None)
        };

        let end = self.previous_span().end;

        Ok(Expression::Of(Box::new(OfExpr {
            count,
            strings,
            at,
            in_range,
            span: Span::new(start, end),
        })))
    }

    fn parse_string_set(&mut self) -> Result<StringSet, ParseError> {
        if self.check(Token::Them) {
            self.advance();
            return Ok(StringSet::Them);
        }

        self.expect(Token::LParen)?;

        // Check for wildcard pattern
        if let Some(Token::StringIdentifier(s)) = self.peek().cloned() {
            if self.peek_next() == Some(&Token::Star) {
                self.advance(); // consume identifier
                self.advance(); // consume star
                self.expect(Token::RParen)?;
                return Ok(StringSet::Wildcard(SmolStr::new(&s)));
            }
        }

        // Parse explicit list
        let mut strings = Vec::new();
        if let Some(Token::StringIdentifier(s)) = self.peek().cloned() {
            self.advance();
            strings.push(SmolStr::new(&s));
            while self.check(Token::Comma) {
                self.advance();
                if let Some(Token::StringIdentifier(s)) = self.peek().cloned() {
                    self.advance();
                    strings.push(SmolStr::new(&s));
                }
            }
        }

        self.expect(Token::RParen)?;

        Ok(StringSet::Explicit(strings))
    }

    fn parse_for_expression(&mut self) -> Result<Expression, ParseError> {
        let start = self.current_span().start;

        self.expect(Token::For)?;

        // Parse quantifier
        let quantifier = if self.check(Token::All) {
            self.advance();
            QuantifierKind::All
        } else if self.check(Token::Any) {
            self.advance();
            QuantifierKind::Any
        } else if self.check(Token::None) {
            self.advance();
            QuantifierKind::None
        } else {
            let n = self.expect_integer()?;
            if self.check(Token::Percent) {
                self.advance();
                QuantifierKind::Percentage(Box::new(Expression::Integer(n)))
            } else {
                QuantifierKind::Count(Box::new(Expression::Integer(n)))
            }
        };

        // Parse iterator variable(s)
        let variables = if self.check(Token::LParen) {
            self.advance();
            let mut vars = Vec::new();
            let v = self.expect_identifier()?;
            vars.push(SmolStr::new(&v));
            while self.check(Token::Comma) {
                self.advance();
                let v = self.expect_identifier()?;
                vars.push(SmolStr::new(&v));
            }
            self.expect(Token::RParen)?;
            vars
        } else {
            let v = self.expect_identifier()?;
            vec![SmolStr::new(&v)]
        };

        self.expect(Token::In)?;

        // Parse iterable
        let iterable = self.parse_for_iterable()?;

        self.expect(Token::Colon)?;
        self.expect(Token::LParen)?;

        let condition = self.parse_expression()?;

        self.expect(Token::RParen)?;

        let end = self.previous_span().end;

        Ok(Expression::For(Box::new(ForExpr {
            quantifier,
            iterator: ForIterator {
                variables,
                iterable,
            },
            condition,
            span: Span::new(start, end),
        })))
    }

    fn parse_for_iterable(&mut self) -> Result<ForIterable, ParseError> {
        // Range: (start..end)
        if self.check(Token::LParen) {
            self.advance();
            let start_expr = self.parse_expression()?;
            self.expect(Token::DotDot)?;
            let end_expr = self.parse_expression()?;
            self.expect(Token::RParen)?;
            return Ok(ForIterable::Range(RangeExpr {
                start: start_expr,
                end: end_expr,
                span: Span::new(0, 0),
            }));
        }

        // String set
        if self.check(Token::Them)
            || (self.peek() == Some(&Token::LParen)
                && matches!(self.peek_at(1), Some(Token::StringIdentifier(_))))
        {
            return Ok(ForIterable::StringSet(self.parse_string_set()?));
        }

        // Identifier
        let ident = self.parse_identifier()?;
        Ok(ForIterable::Identifier(ident))
    }

    fn parse_identifier(&mut self) -> Result<Identifier, ParseError> {
        let start = self.current_span().start;
        let mut parts = Vec::new();

        let first = self.expect_identifier()?;
        parts.push(SmolStr::new(&first));

        while self.check(Token::Dot) {
            self.advance();
            let next = self.expect_identifier()?;
            parts.push(SmolStr::new(&next));
        }

        let end = self.previous_span().end;

        Ok(Identifier {
            parts,
            span: Span::new(start, end),
        })
    }

    // ==================== Helper Methods ====================

    fn is_at_end(&self) -> bool {
        self.position >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position).map(|t| &t.token)
    }

    fn peek_next(&self) -> Option<&Token> {
        self.tokens.get(self.position + 1).map(|t| &t.token)
    }

    fn peek_at(&self, offset: usize) -> Option<&Token> {
        self.tokens.get(self.position + offset).map(|t| &t.token)
    }

    fn check(&self, token: Token) -> bool {
        self.peek() == Some(&token)
    }

    fn advance(&mut self) -> Option<SpannedToken> {
        if !self.is_at_end() {
            self.position += 1;
            self.tokens.get(self.position - 1).cloned()
        } else {
            None
        }
    }

    fn current_span(&self) -> Span {
        self.tokens
            .get(self.position)
            .map(|t| t.span)
            .unwrap_or(Span::new(self.source.len(), self.source.len()))
    }

    fn previous_span(&self) -> Span {
        self.tokens
            .get(self.position.saturating_sub(1))
            .map(|t| t.span)
            .unwrap_or(Span::new(0, 0))
    }

    fn expect(&mut self, expected: Token) -> Result<(), ParseError> {
        if self.check(expected.clone()) {
            self.advance();
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                span: self.current_span(),
                expected: format!("{:?}", expected),
                found: format!("{:?}", self.peek()),
            })
        }
    }

    fn expect_identifier(&mut self) -> Result<String, ParseError> {
        match self.advance() {
            Some(SpannedToken {
                token: Token::Identifier(s),
                ..
            }) => Ok(s),
            _ => Err(ParseError::UnexpectedToken {
                span: self.previous_span(),
                expected: "identifier".to_string(),
                found: "other".to_string(),
            }),
        }
    }

    fn expect_string_literal(&mut self) -> Result<String, ParseError> {
        match self.advance() {
            Some(SpannedToken {
                token: Token::StringLiteral(s),
                ..
            }) => Ok(s),
            _ => Err(ParseError::UnexpectedToken {
                span: self.previous_span(),
                expected: "string literal".to_string(),
                found: "other".to_string(),
            }),
        }
    }

    fn expect_integer(&mut self) -> Result<i64, ParseError> {
        match self.advance() {
            Some(SpannedToken {
                token: Token::Number(NumberValue::Integer(n)),
                ..
            }) => Ok(n),
            Some(SpannedToken {
                token: Token::SizeValue(n),
                ..
            }) => Ok(n),
            _ => Err(ParseError::UnexpectedToken {
                span: self.previous_span(),
                expected: "integer".to_string(),
                found: "other".to_string(),
            }),
        }
    }
}

// ==================== Helper Functions ====================

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
                                alternatives
                                    .last_mut()
                                    .unwrap()
                                    .push(HexToken::NibbleWildcard {
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

/// Parse a YARA source file into an AST
pub fn parse(source: &str) -> Result<SourceFile, ParseError> {
    let mut parser = Parser::new(source)?;
    parser.parse()
}

/// Parse a single expression (useful for testing)
pub fn parse_expression(source: &str) -> Result<Expression, ParseError> {
    let mut parser = Parser::new(source)?;
    parser.parse_expression()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let source = r#"
            rule test_rule {
                condition:
                    true
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok(), "Parse failed: {:?}", result.err());
        let ast = result.unwrap();
        assert_eq!(ast.rules.len(), 1);
        assert_eq!(ast.rules[0].name.as_str(), "test_rule");
    }

    #[test]
    fn test_parse_rule_with_strings() {
        let source = r#"
            rule test_strings {
                strings:
                    $a = "test"
                    $b = "hello" nocase wide
                condition:
                    $a or $b
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
        let ast = result.unwrap();
        assert_eq!(ast.rules[0].strings.len(), 2);
    }

    #[test]
    fn test_parse_rule_with_meta() {
        let source = r#"
            rule test_meta {
                meta:
                    author = "test"
                    version = 1
                    malicious = true
                condition:
                    true
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
        let ast = result.unwrap();
        assert_eq!(ast.rules[0].meta.len(), 3);
    }

    #[test]
    fn test_parse_import() {
        let source = r#"
            import "pe"
            import "hash"

            rule test {
                condition:
                    true
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
        let ast = result.unwrap();
        assert_eq!(ast.imports.len(), 2);
    }

    #[test]
    fn test_parse_complex_condition() {
        let source = r#"
            rule complex {
                strings:
                    $a = "test"
                condition:
                    $a and filesize < 1MB and #a > 5
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_quantifier() {
        let source = r#"
            rule quantifier {
                strings:
                    $a = "test"
                    $b = "hello"
                condition:
                    any of them
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_for_expression() {
        let source = r#"
            rule for_expr {
                strings:
                    $a = "test"
                condition:
                    for any i in (0..10) : ( @a[i] < 100 )
            }
        "#;

        let result = parse(source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_hex_tokens() {
        let tokens = parse_hex_tokens("{ 4D 5A }");
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], HexToken::Byte(0x4D)));
        assert!(matches!(tokens[1], HexToken::Byte(0x5A)));
    }

    #[test]
    fn test_parse_regex_modifiers() {
        let (pattern, mods) = parse_regex("/hello.*world/i");
        assert_eq!(pattern, "hello.*world");
        assert!(mods.case_insensitive);
    }
}
