//! YARA Abstract Syntax Tree
//!
//! Defines the AST nodes that represent parsed YARA rules.
//! The AST is the output of the parser and input to the compiler.

use crate::lexer::Span;
use smol_str::SmolStr;

/// A complete YARA source file
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Import statements
    pub imports: Vec<Import>,
    /// Include statements
    pub includes: Vec<Include>,
    /// Rule definitions
    pub rules: Vec<Rule>,
}

impl SourceFile {
    pub fn new() -> Self {
        Self {
            imports: Vec::new(),
            includes: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl Default for SourceFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Import statement: `import "pe"`
#[derive(Debug, Clone)]
pub struct Import {
    pub module_name: SmolStr,
    pub span: Span,
}

/// Include statement: `include "rules.yar"`
#[derive(Debug, Clone)]
pub struct Include {
    pub path: SmolStr,
    pub span: Span,
}

/// A YARA rule definition
#[derive(Debug, Clone)]
pub struct Rule {
    /// Rule name
    pub name: SmolStr,
    /// Rule modifiers (private, global)
    pub modifiers: RuleModifiers,
    /// Rule tags
    pub tags: Vec<SmolStr>,
    /// Metadata section
    pub meta: Vec<MetaEntry>,
    /// Strings section
    pub strings: Vec<StringDeclaration>,
    /// Condition expression
    pub condition: Expression,
    /// Full span of the rule
    pub span: Span,
}

/// Rule modifiers
#[derive(Debug, Clone, Default)]
pub struct RuleModifiers {
    pub is_private: bool,
    pub is_global: bool,
}

/// Metadata entry: `key = value`
#[derive(Debug, Clone)]
pub struct MetaEntry {
    pub key: SmolStr,
    pub value: MetaValue,
    pub span: Span,
}

/// Metadata value types
#[derive(Debug, Clone)]
pub enum MetaValue {
    String(SmolStr),
    Integer(i64),
    Boolean(bool),
}

/// String declaration in the strings section
#[derive(Debug, Clone)]
pub struct StringDeclaration {
    /// Variable name (e.g., "$a")
    pub name: SmolStr,
    /// String pattern
    pub pattern: StringPattern,
    /// Modifiers
    pub modifiers: StringModifiers,
    /// Span
    pub span: Span,
}

/// String pattern types
#[derive(Debug, Clone)]
pub enum StringPattern {
    /// Text string: "hello"
    Text(TextString),
    /// Hex string: { 4D 5A }
    Hex(HexString),
    /// Regular expression: /hello.*world/
    Regex(RegexString),
}

/// Text string pattern
#[derive(Debug, Clone)]
pub struct TextString {
    pub value: SmolStr,
    pub span: Span,
}

/// Hex string pattern
#[derive(Debug, Clone)]
pub struct HexString {
    pub tokens: Vec<HexToken>,
    pub span: Span,
}

/// Hex string token
#[derive(Debug, Clone)]
pub enum HexToken {
    /// Literal byte: 4D
    Byte(u8),
    /// Wildcard: ??
    Wildcard,
    /// Nibble wildcard: ?A or A?
    NibbleWildcard { high: Option<u8>, low: Option<u8> },
    /// Jump: [n] or [n-m]
    Jump { min: u32, max: Option<u32> },
    /// Alternation: (AA | BB)
    Alternation(Vec<Vec<HexToken>>),
}

/// Regular expression pattern
#[derive(Debug, Clone)]
pub struct RegexString {
    pub pattern: SmolStr,
    pub modifiers: RegexModifiers,
    pub span: Span,
}

/// Regex modifiers (flags after the closing /)
#[derive(Debug, Clone, Default)]
pub struct RegexModifiers {
    pub case_insensitive: bool,  // i
    pub dot_matches_all: bool,   // s
    pub multiline: bool,         // m
    pub extended: bool,          // x
}

/// String modifiers
#[derive(Debug, Clone, Default)]
pub struct StringModifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
    pub xor: Option<XorModifier>,
    pub base64: Option<Base64Modifier>,
    pub private: bool,
}

/// XOR modifier options
#[derive(Debug, Clone)]
pub struct XorModifier {
    /// Single byte or range
    pub range: Option<(u8, u8)>,
}

/// Base64 modifier options
#[derive(Debug, Clone)]
pub struct Base64Modifier {
    /// Custom alphabet
    pub alphabet: Option<SmolStr>,
    pub wide: bool,
}

/// Expression in the condition section
#[derive(Debug, Clone)]
pub enum Expression {
    /// Boolean literal: true, false
    Boolean(bool),

    /// Integer literal
    Integer(i64),

    /// Float literal
    Float(f64),

    /// String literal
    String(SmolStr),

    /// Identifier reference
    Identifier(Identifier),

    /// String reference: $a
    StringRef(SmolStr),

    /// String count: #a
    StringCount(StringCountExpr),

    /// String offset: @a or @a[n]
    StringOffset(StringOffsetExpr),

    /// String length: !a or !a[n]
    StringLength(StringLengthExpr),

    /// filesize keyword
    Filesize,

    /// entrypoint keyword
    Entrypoint,

    /// Binary operation
    Binary(Box<BinaryExpr>),

    /// Unary operation
    Unary(Box<UnaryExpr>),

    /// Ternary/range expression: (a..b)
    Range(Box<RangeExpr>),

    /// Function call: func(args)
    FunctionCall(Box<FunctionCall>),

    /// Array/dictionary access: obj[index]
    Index(Box<IndexExpr>),

    /// Field access: obj.field
    FieldAccess(Box<FieldAccess>),

    /// Quantifier: any of them, all of ($a*)
    Quantifier(Box<Quantifier>),

    /// For expression: for any i in (0..10): (condition)
    For(Box<ForExpr>),

    /// Parenthesized expression
    Paren(Box<Expression>),

    /// "of" expression: 2 of them
    Of(Box<OfExpr>),

    /// "at" expression: $a at 100
    At(Box<AtExpr>),

    /// "in" expression: $a in (0..100)
    In(Box<InExpr>),

    /// Matches expression: string matches /regex/
    Matches(Box<MatchesExpr>),

    /// Contains expression
    Contains(Box<ContainsExpr>),

    /// Defined check
    Defined(Box<Expression>),
}

/// Identifier (possibly qualified: module.field.subfield)
#[derive(Debug, Clone)]
pub struct Identifier {
    pub parts: Vec<SmolStr>,
    pub span: Span,
}

impl Identifier {
    pub fn simple(name: SmolStr, span: Span) -> Self {
        Self {
            parts: vec![name],
            span,
        }
    }

    pub fn qualified(parts: Vec<SmolStr>, span: Span) -> Self {
        Self { parts, span }
    }

    pub fn name(&self) -> &str {
        self.parts.last().map(|s| s.as_str()).unwrap_or("")
    }
}

/// String count expression: #a or #a in (range)
#[derive(Debug, Clone)]
pub struct StringCountExpr {
    pub name: SmolStr,
    pub range: Option<Box<RangeExpr>>,
    pub span: Span,
}

/// String offset expression: @a or @a[n]
#[derive(Debug, Clone)]
pub struct StringOffsetExpr {
    pub name: SmolStr,
    pub index: Option<Box<Expression>>,
    pub span: Span,
}

/// String length expression: !a or !a[n]
#[derive(Debug, Clone)]
pub struct StringLengthExpr {
    pub name: SmolStr,
    pub index: Option<Box<Expression>>,
    pub span: Span,
}

/// Binary expression
#[derive(Debug, Clone)]
pub struct BinaryExpr {
    pub left: Expression,
    pub op: BinaryOp,
    pub right: Expression,
    pub span: Span,
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    // Logical
    And,
    Or,

    // Comparison
    Equal,
    NotEqual,
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    ShiftRight,

    // String operations
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    IEquals,
    Matches,
}

/// Unary expression
#[derive(Debug, Clone)]
pub struct UnaryExpr {
    pub op: UnaryOp,
    pub operand: Expression,
    pub span: Span,
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
    BitNot,
}

/// Range expression: (start..end)
#[derive(Debug, Clone)]
pub struct RangeExpr {
    pub start: Expression,
    pub end: Expression,
    pub span: Span,
}

/// Function call
#[derive(Debug, Clone)]
pub struct FunctionCall {
    pub function: Identifier,
    pub arguments: Vec<Expression>,
    pub span: Span,
}

/// Index expression: obj[index]
#[derive(Debug, Clone)]
pub struct IndexExpr {
    pub object: Expression,
    pub index: Expression,
    pub span: Span,
}

/// Field access: obj.field
#[derive(Debug, Clone)]
pub struct FieldAccess {
    pub object: Expression,
    pub field: SmolStr,
    pub span: Span,
}

/// Quantifier expression
#[derive(Debug, Clone)]
pub struct Quantifier {
    pub kind: QuantifierKind,
    pub strings: StringSet,
    pub span: Span,
}

/// Quantifier kinds
#[derive(Debug, Clone)]
pub enum QuantifierKind {
    All,
    Any,
    None,
    Count(Box<Expression>),
    Percentage(Box<Expression>),
}

/// String set for quantifiers
#[derive(Debug, Clone)]
pub enum StringSet {
    /// all strings: them
    Them,
    /// explicit set: ($a, $b, $c)
    Explicit(Vec<SmolStr>),
    /// wildcard: ($a*)
    Wildcard(SmolStr),
}

/// For expression
#[derive(Debug, Clone)]
pub struct ForExpr {
    pub quantifier: QuantifierKind,
    pub iterator: ForIterator,
    pub condition: Expression,
    pub span: Span,
}

/// For loop iterator
#[derive(Debug, Clone)]
pub struct ForIterator {
    pub variables: Vec<SmolStr>,
    pub iterable: ForIterable,
}

/// What to iterate over
#[derive(Debug, Clone)]
pub enum ForIterable {
    Range(RangeExpr),
    StringSet(StringSet),
    Identifier(Identifier),
}

/// "of" expression: n of (string_set)
#[derive(Debug, Clone)]
pub struct OfExpr {
    pub count: QuantifierKind,
    pub strings: StringSet,
    pub at: Option<Box<Expression>>,
    pub in_range: Option<RangeExpr>,
    pub span: Span,
}

/// "at" expression
#[derive(Debug, Clone)]
pub struct AtExpr {
    pub string: SmolStr,
    pub offset: Expression,
    pub span: Span,
}

/// "in" expression
#[derive(Debug, Clone)]
pub struct InExpr {
    pub expr: Expression,
    pub range: RangeExpr,
    pub span: Span,
}

/// Matches expression
#[derive(Debug, Clone)]
pub struct MatchesExpr {
    pub expr: Expression,
    pub pattern: RegexString,
    pub span: Span,
}

/// Contains expression
#[derive(Debug, Clone)]
pub struct ContainsExpr {
    pub string: Expression,
    pub substring: Expression,
    pub case_insensitive: bool,
    pub span: Span,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_file_default() {
        let sf = SourceFile::default();
        assert!(sf.imports.is_empty());
        assert!(sf.includes.is_empty());
        assert!(sf.rules.is_empty());
    }

    #[test]
    fn test_identifier_simple() {
        let id = Identifier::simple("test".into(), Span::new(0, 4));
        assert_eq!(id.name(), "test");
    }

    #[test]
    fn test_identifier_qualified() {
        let id = Identifier::qualified(
            vec!["pe".into(), "imports".into(), "hash".into()],
            Span::new(0, 16),
        );
        assert_eq!(id.name(), "hash");
    }
}
