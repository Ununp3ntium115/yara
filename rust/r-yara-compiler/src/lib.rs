//! R-YARA Bytecode Compiler
//!
//! Compiles YARA rules from AST representation to executable bytecode.
//!
//! # Architecture
//!
//! The compiler performs several passes:
//! 1. **Symbol Resolution**: Collect all identifiers and string patterns
//! 2. **Pattern Extraction**: Extract literal atoms for AC matching
//! 3. **Code Generation**: Generate stack-based bytecode
//!
//! # Bytecode Design
//!
//! The bytecode uses a stack-based VM model similar to YARA's original design.
//! Instructions operate on a value stack, with special handling for:
//! - Boolean operations (and, or, not)
//! - Comparisons (eq, ne, lt, gt, le, ge)
//! - String matching (at, in, count)
//! - Quantifiers (all, any, none, N of)
//!
//! # Example
//!
//! ```no_run
//! use r_yara_compiler::Compiler;
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
//! let ast = parse(source).unwrap();
//! let mut compiler = Compiler::new();
//! let compiled = compiler.compile(&ast).unwrap();
//! println!("Compiled {} rules with {} instructions", compiled.rules.len(), compiled.code.len());
//! ```

use indexmap::IndexMap;
use r_yara_matcher::{Pattern, PatternKind, PatternModifiers};
use r_yara_parser::{
    AtExpr, BinaryOp, Expression, ForExpr, FunctionCall, OfExpr, QuantifierKind,
    Rule, SourceFile, StringDeclaration, StringPattern, UnaryOp,
};
use smol_str::SmolStr;
use std::collections::HashMap;
use thiserror::Error;

/// Compilation errors
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("Undefined string identifier: {0}")]
    UndefinedString(String),

    #[error("Undefined identifier: {0}")]
    UndefinedIdentifier(String),

    #[error("Invalid expression: {0}")]
    InvalidExpression(String),

    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),

    #[error("Duplicate rule name: {0}")]
    DuplicateRule(String),

    #[error("Duplicate string identifier: {0}")]
    DuplicateString(String),
}

/// Bytecode opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // Stack operations
    Nop = 0,
    Pop,
    Dup,
    Swap,

    // Push constants
    PushTrue,
    PushFalse,
    PushInt,     // followed by i64
    PushFloat,   // followed by f64
    PushString,  // followed by string index

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,

    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    BitNot,
    ShiftLeft,
    ShiftRight,

    // Comparison
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    Matches,
    IMatches,

    // Logical
    And,
    Or,
    Not,

    // String operations
    StringMatch,      // Check if string matched at all
    StringMatchAt,    // Check if string matched at offset
    StringMatchIn,    // Check if string matched in range
    StringCount,      // Get string match count
    StringCountIn,    // Get string match count in range
    StringOffset,     // Get string offset at index
    StringLength,     // Get string length at index

    // Quantifiers
    OfAll,        // all of (string_set)
    OfAny,        // any of (string_set)
    OfNone,       // none of (string_set)
    OfCount,      // N of (string_set)
    OfPercent,    // N% of (string_set)

    // For loops
    ForIn,        // for expression in iterable
    ForOf,        // for of strings

    // Built-in variables
    Filesize,
    Entrypoint,

    // Control flow
    Jump,
    JumpIfFalse,
    JumpIfTrue,

    // Function calls
    Call,         // followed by function id and arg count

    // End
    Halt,
}

/// A bytecode instruction
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    /// Simple opcode without operands
    Simple(Opcode),
    /// Push integer constant
    PushInt(i64),
    /// Push float constant
    PushFloat(f64),
    /// Push string constant (index into string table)
    PushString(usize),
    /// Jump to offset
    Jump(i32),
    /// Conditional jumps
    JumpIfFalse(i32),
    JumpIfTrue(i32),
    /// String pattern reference
    StringRef(usize),
    /// String pattern with index
    StringRefIndex(usize, Box<Vec<Instruction>>),
    /// Function call
    Call { function_id: usize, arg_count: usize },
    /// String set for quantifier operations
    StringSet(Vec<usize>),
}

impl Instruction {
    /// Get the size of this instruction in bytes (for jump calculations)
    pub fn size(&self) -> usize {
        match self {
            Instruction::Simple(_) => 1,
            Instruction::PushInt(_) => 9,
            Instruction::PushFloat(_) => 9,
            Instruction::PushString(_) => 5,
            Instruction::Jump(_) => 5,
            Instruction::JumpIfFalse(_) => 5,
            Instruction::JumpIfTrue(_) => 5,
            Instruction::StringRef(_) => 5,
            Instruction::StringRefIndex(_, _) => 9,
            Instruction::Call { .. } => 9,
            Instruction::StringSet(set) => 1 + set.len() * 4,
        }
    }
}

/// A compiled YARA rule
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule name
    pub name: SmolStr,
    /// Rule tags
    pub tags: Vec<SmolStr>,
    /// Is private rule
    pub is_private: bool,
    /// Is global rule
    pub is_global: bool,
    /// Metadata
    pub meta: IndexMap<SmolStr, MetaValue>,
    /// String pattern indices
    pub strings: Vec<usize>,
    /// Start index in code array
    pub code_start: usize,
    /// Length of code
    pub code_len: usize,
}

/// Metadata value
#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    String(SmolStr),
    Integer(i64),
    Boolean(bool),
}

/// Compiled rules ready for execution
#[derive(Debug, Clone)]
pub struct CompiledRules {
    /// Bytecode instructions
    pub code: Vec<Instruction>,
    /// Compiled rules
    pub rules: Vec<CompiledRule>,
    /// Pattern definitions for the matcher
    pub patterns: Vec<Pattern>,
    /// String constants table
    pub strings: Vec<String>,
    /// Imported module names
    pub imports: Vec<SmolStr>,
}

impl Default for CompiledRules {
    fn default() -> Self {
        Self {
            code: Vec::new(),
            rules: Vec::new(),
            patterns: Vec::new(),
            strings: Vec::new(),
            imports: Vec::new(),
        }
    }
}

/// Compiler state
pub struct Compiler {
    /// Current rule being compiled
    current_rule: Option<String>,
    /// String pattern name to index mapping
    string_map: HashMap<String, usize>,
    /// String constant to index mapping
    const_strings: HashMap<String, usize>,
    /// Function name to id mapping
    functions: HashMap<String, usize>,
    /// Generated patterns
    patterns: Vec<Pattern>,
    /// Generated code
    code: Vec<Instruction>,
    /// Compiled rules
    rules: Vec<CompiledRule>,
    /// String constants
    string_constants: Vec<String>,
    /// Imports
    imports: Vec<SmolStr>,
    /// Rule name set for duplicate detection
    rule_names: HashMap<String, bool>,
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    /// Create a new compiler
    pub fn new() -> Self {
        let mut functions = HashMap::new();
        // Register built-in functions
        functions.insert("uint8".to_string(), 0);
        functions.insert("uint16".to_string(), 1);
        functions.insert("uint32".to_string(), 2);
        functions.insert("uint16be".to_string(), 3);
        functions.insert("uint32be".to_string(), 4);
        functions.insert("int8".to_string(), 5);
        functions.insert("int16".to_string(), 6);
        functions.insert("int32".to_string(), 7);
        functions.insert("int16be".to_string(), 8);
        functions.insert("int32be".to_string(), 9);

        Self {
            current_rule: None,
            string_map: HashMap::new(),
            const_strings: HashMap::new(),
            functions,
            patterns: Vec::new(),
            code: Vec::new(),
            rules: Vec::new(),
            string_constants: Vec::new(),
            imports: Vec::new(),
            rule_names: HashMap::new(),
        }
    }

    /// Compile a source file
    pub fn compile(&mut self, source: &SourceFile) -> Result<CompiledRules, CompileError> {
        // Process imports
        for import in &source.imports {
            self.imports.push(import.module_name.clone());
        }

        // Compile each rule
        for rule in &source.rules {
            self.compile_rule(rule)?;
        }

        Ok(CompiledRules {
            code: std::mem::take(&mut self.code),
            rules: std::mem::take(&mut self.rules),
            patterns: std::mem::take(&mut self.patterns),
            strings: std::mem::take(&mut self.string_constants),
            imports: std::mem::take(&mut self.imports),
        })
    }

    /// Compile a single rule
    fn compile_rule(&mut self, rule: &Rule) -> Result<(), CompileError> {
        let rule_name = rule.name.as_str().to_string();

        // Check for duplicate rule names
        if self.rule_names.contains_key(&rule_name) {
            return Err(CompileError::DuplicateRule(rule_name));
        }
        self.rule_names.insert(rule_name.clone(), true);

        self.current_rule = Some(rule_name.clone());
        self.string_map.clear();

        // Compile string patterns
        let string_indices = self.compile_strings(&rule.strings)?;

        // Compile metadata
        let meta = self.compile_meta(rule);

        // Record code start
        let code_start = self.code.len();

        // Compile condition
        self.compile_expression(&rule.condition)?;
        self.emit(Instruction::Simple(Opcode::Halt));

        let code_len = self.code.len() - code_start;

        // Create compiled rule
        let compiled = CompiledRule {
            name: SmolStr::new(&rule_name),
            tags: rule.tags.iter().map(|t| SmolStr::new(t.as_str())).collect(),
            is_private: rule.modifiers.is_private,
            is_global: rule.modifiers.is_global,
            meta,
            strings: string_indices,
            code_start,
            code_len,
        };

        self.rules.push(compiled);
        self.current_rule = None;

        Ok(())
    }

    /// Compile string patterns
    fn compile_strings(&mut self, strings: &[StringDeclaration]) -> Result<Vec<usize>, CompileError> {
        let mut indices = Vec::new();

        for decl in strings {
            let name = decl.name.as_str().to_string();

            // Check for duplicates within this rule
            if self.string_map.contains_key(&name) {
                return Err(CompileError::DuplicateString(name));
            }

            let pattern_id = self.patterns.len();
            self.string_map.insert(name.clone(), pattern_id);
            indices.push(pattern_id);

            // Create pattern based on type
            let (bytes, kind) = match &decl.pattern {
                StringPattern::Text(text) => {
                    let modifiers = &decl.modifiers;
                    let kind = if modifiers.nocase && modifiers.wide {
                        PatternKind::WideNocase
                    } else if modifiers.nocase {
                        PatternKind::LiteralNocase
                    } else if modifiers.wide {
                        PatternKind::Wide
                    } else {
                        PatternKind::Literal
                    };
                    (text.value.as_bytes().to_vec(), kind)
                }
                StringPattern::Hex(hex) => {
                    // For hex patterns, serialize the tokens
                    let bytes = serialize_hex_tokens(&hex.tokens);
                    (bytes, PatternKind::Hex)
                }
                StringPattern::Regex(regex) => {
                    (regex.pattern.as_bytes().to_vec(), PatternKind::Regex)
                }
            };

            let pattern_modifiers = PatternModifiers {
                nocase: decl.modifiers.nocase,
                wide: decl.modifiers.wide,
                ascii: decl.modifiers.ascii,
                fullword: decl.modifiers.fullword,
                xor: decl.modifiers.xor.as_ref().and_then(|x| x.range),
                base64: decl.modifiers.base64.is_some(),
            };

            let pattern = Pattern::with_modifiers(pattern_id, bytes, kind, pattern_modifiers)
                .with_name(name);

            self.patterns.push(pattern);
        }

        Ok(indices)
    }

    /// Compile metadata
    fn compile_meta(&mut self, rule: &Rule) -> IndexMap<SmolStr, MetaValue> {
        let mut meta = IndexMap::new();

        for entry in &rule.meta {
            let value = match &entry.value {
                r_yara_parser::MetaValue::String(s) => MetaValue::String(SmolStr::new(s.as_str())),
                r_yara_parser::MetaValue::Integer(i) => MetaValue::Integer(*i),
                r_yara_parser::MetaValue::Boolean(b) => MetaValue::Boolean(*b),
            };
            meta.insert(SmolStr::new(entry.key.as_str()), value);
        }

        meta
    }

    /// Compile an expression
    fn compile_expression(&mut self, expr: &Expression) -> Result<(), CompileError> {
        match expr {
            Expression::Boolean(true) => {
                self.emit(Instruction::Simple(Opcode::PushTrue));
            }
            Expression::Boolean(false) => {
                self.emit(Instruction::Simple(Opcode::PushFalse));
            }
            Expression::Integer(i) => {
                self.emit(Instruction::PushInt(*i));
            }
            Expression::Float(f) => {
                self.emit(Instruction::PushFloat(*f));
            }
            Expression::String(s) => {
                let idx = self.intern_string(s.as_str());
                self.emit(Instruction::PushString(idx));
            }
            Expression::Filesize => {
                self.emit(Instruction::Simple(Opcode::Filesize));
            }
            Expression::Entrypoint => {
                self.emit(Instruction::Simple(Opcode::Entrypoint));
            }
            Expression::StringRef(name) => {
                let idx = self.resolve_string(name.as_str())?;
                self.emit(Instruction::StringRef(idx));
                self.emit(Instruction::Simple(Opcode::StringMatch));
            }
            Expression::StringCount(count_expr) => {
                let idx = self.resolve_string(count_expr.name.as_str())?;
                if let Some(range) = &count_expr.range {
                    self.compile_expression(&range.start)?;
                    self.compile_expression(&range.end)?;
                    self.emit(Instruction::StringRef(idx));
                    self.emit(Instruction::Simple(Opcode::StringCountIn));
                } else {
                    self.emit(Instruction::StringRef(idx));
                    self.emit(Instruction::Simple(Opcode::StringCount));
                }
            }
            Expression::StringOffset(offset_expr) => {
                let idx = self.resolve_string(offset_expr.name.as_str())?;
                if let Some(index_expr) = &offset_expr.index {
                    self.compile_expression(index_expr)?;
                } else {
                    self.emit(Instruction::PushInt(0));
                }
                self.emit(Instruction::StringRef(idx));
                self.emit(Instruction::Simple(Opcode::StringOffset));
            }
            Expression::StringLength(length_expr) => {
                let idx = self.resolve_string(length_expr.name.as_str())?;
                if let Some(index_expr) = &length_expr.index {
                    self.compile_expression(index_expr)?;
                } else {
                    self.emit(Instruction::PushInt(0));
                }
                self.emit(Instruction::StringRef(idx));
                self.emit(Instruction::Simple(Opcode::StringLength));
            }
            Expression::At(at_expr) => {
                self.compile_at_expression(at_expr)?;
            }
            Expression::In(in_expr) => {
                let idx = self.resolve_string_from_expr(&in_expr.expr)?;
                self.compile_expression(&in_expr.range.start)?;
                self.compile_expression(&in_expr.range.end)?;
                self.emit(Instruction::StringRef(idx));
                self.emit(Instruction::Simple(Opcode::StringMatchIn));
            }
            Expression::Binary(bin_expr) => {
                self.compile_expression(&bin_expr.left)?;
                self.compile_expression(&bin_expr.right)?;
                let opcode = match bin_expr.op {
                    BinaryOp::And => Opcode::And,
                    BinaryOp::Or => Opcode::Or,
                    BinaryOp::Add => Opcode::Add,
                    BinaryOp::Sub => Opcode::Sub,
                    BinaryOp::Mul => Opcode::Mul,
                    BinaryOp::Div => Opcode::Div,
                    BinaryOp::Mod => Opcode::Mod,
                    BinaryOp::Equal => Opcode::Eq,
                    BinaryOp::NotEqual => Opcode::Ne,
                    BinaryOp::LessThan => Opcode::Lt,
                    BinaryOp::LessEqual => Opcode::Le,
                    BinaryOp::GreaterThan => Opcode::Gt,
                    BinaryOp::GreaterEqual => Opcode::Ge,
                    BinaryOp::BitAnd => Opcode::BitAnd,
                    BinaryOp::BitOr => Opcode::BitOr,
                    BinaryOp::BitXor => Opcode::BitXor,
                    BinaryOp::ShiftLeft => Opcode::ShiftLeft,
                    BinaryOp::ShiftRight => Opcode::ShiftRight,
                    BinaryOp::Contains => Opcode::Contains,
                    BinaryOp::IContains => Opcode::IContains,
                    BinaryOp::StartsWith => Opcode::StartsWith,
                    BinaryOp::IStartsWith => Opcode::IStartsWith,
                    BinaryOp::EndsWith => Opcode::EndsWith,
                    BinaryOp::IEndsWith => Opcode::IEndsWith,
                    BinaryOp::Matches => Opcode::Matches,
                    BinaryOp::IEquals => Opcode::IContains, // Map IEquals to IContains for now
                };
                self.emit(Instruction::Simple(opcode));
            }
            Expression::Unary(unary_expr) => {
                self.compile_expression(&unary_expr.operand)?;
                let opcode = match unary_expr.op {
                    UnaryOp::Not => Opcode::Not,
                    UnaryOp::Neg => Opcode::Neg,
                    UnaryOp::BitNot => Opcode::BitNot,
                };
                self.emit(Instruction::Simple(opcode));
            }
            Expression::Paren(inner) => {
                self.compile_expression(inner)?;
            }
            Expression::Of(of_expr) => {
                self.compile_of_expression(of_expr)?;
            }
            Expression::For(for_expr) => {
                self.compile_for_expression(for_expr)?;
            }
            Expression::FunctionCall(call) => {
                self.compile_function_call(call)?;
            }
            Expression::Identifier(ident) => {
                // Could be a module field access like pe.is_pe
                let full_name = ident.parts.join(".");
                let idx = self.intern_string(&full_name);
                self.emit(Instruction::PushString(idx));
            }
            Expression::FieldAccess(field) => {
                // Compile as module.field access
                self.compile_expression(&field.object)?;
                let idx = self.intern_string(field.field.as_str());
                self.emit(Instruction::PushString(idx));
            }
            Expression::Index(index) => {
                self.compile_expression(&index.object)?;
                self.compile_expression(&index.index)?;
            }
            _ => {
                return Err(CompileError::UnsupportedFeature(format!(
                    "Expression type: {:?}",
                    expr
                )));
            }
        }
        Ok(())
    }

    /// Compile an 'at' expression
    fn compile_at_expression(&mut self, at_expr: &AtExpr) -> Result<(), CompileError> {
        let idx = self.resolve_string(at_expr.string.as_str())?;
        self.compile_expression(&at_expr.offset)?;
        self.emit(Instruction::StringRef(idx));
        self.emit(Instruction::Simple(Opcode::StringMatchAt));
        Ok(())
    }

    /// Compile an 'of' expression (quantifier)
    fn compile_of_expression(&mut self, of_expr: &OfExpr) -> Result<(), CompileError> {
        // Collect string set indices
        let string_set = self.resolve_string_set(&of_expr.strings)?;
        self.emit(Instruction::StringSet(string_set));

        // Compile quantifier
        match &of_expr.count {
            QuantifierKind::All => {
                self.emit(Instruction::Simple(Opcode::OfAll));
            }
            QuantifierKind::Any => {
                self.emit(Instruction::Simple(Opcode::OfAny));
            }
            QuantifierKind::None => {
                self.emit(Instruction::Simple(Opcode::OfNone));
            }
            QuantifierKind::Count(expr) => {
                self.compile_expression(expr.as_ref())?;
                self.emit(Instruction::Simple(Opcode::OfCount));
            }
            QuantifierKind::Percentage(expr) => {
                self.compile_expression(expr.as_ref())?;
                self.emit(Instruction::Simple(Opcode::OfPercent));
            }
        }

        Ok(())
    }

    /// Compile a 'for' expression
    fn compile_for_expression(&mut self, for_expr: &ForExpr) -> Result<(), CompileError> {
        // For now, emit a simplified version
        // Full implementation would need loop constructs

        // Compile quantifier
        match &for_expr.quantifier {
            QuantifierKind::All => {
                self.emit(Instruction::Simple(Opcode::PushTrue)); // Placeholder
            }
            QuantifierKind::Any => {
                self.emit(Instruction::Simple(Opcode::PushFalse)); // Placeholder
            }
            _ => {
                self.emit(Instruction::PushInt(0));
            }
        }

        // TODO: Implement full for loop bytecode

        Ok(())
    }

    /// Compile a function call
    fn compile_function_call(&mut self, call: &FunctionCall) -> Result<(), CompileError> {
        // Compile arguments
        for arg in &call.arguments {
            self.compile_expression(arg)?;
        }

        // Look up function
        let func_name = call.function.parts.join(".");
        let function_id = self
            .functions
            .get(&func_name)
            .copied()
            .ok_or_else(|| CompileError::UndefinedIdentifier(func_name))?;

        self.emit(Instruction::Call {
            function_id,
            arg_count: call.arguments.len(),
        });

        Ok(())
    }

    /// Resolve a string pattern name to its index
    fn resolve_string(&self, name: &str) -> Result<usize, CompileError> {
        // Strip leading $, #, @, or ! if present
        let clean_name = name
            .strip_prefix('$')
            .or_else(|| name.strip_prefix('#'))
            .or_else(|| name.strip_prefix('@'))
            .or_else(|| name.strip_prefix('!'))
            .unwrap_or(name);
        let lookup_name = format!("${}", clean_name);

        self.string_map
            .get(&lookup_name)
            .copied()
            .ok_or_else(|| CompileError::UndefinedString(name.to_string()))
    }

    /// Resolve string from an expression
    fn resolve_string_from_expr(&self, expr: &Expression) -> Result<usize, CompileError> {
        match expr {
            Expression::StringRef(name) => self.resolve_string(name.as_str()),
            _ => Err(CompileError::InvalidExpression(
                "Expected string reference".to_string(),
            )),
        }
    }

    /// Resolve a string set
    fn resolve_string_set(&self, set: &r_yara_parser::StringSet) -> Result<Vec<usize>, CompileError> {
        match set {
            r_yara_parser::StringSet::Them => {
                // All strings in the rule
                Ok(self.string_map.values().copied().collect())
            }
            r_yara_parser::StringSet::Explicit(names) => {
                let mut indices = Vec::new();
                for name in names {
                    indices.push(self.resolve_string(name.as_str())?);
                }
                Ok(indices)
            }
            r_yara_parser::StringSet::Wildcard(pattern) => {
                // Match strings by pattern (e.g., "$a*")
                let prefix = pattern.trim_end_matches('*');
                let mut indices = Vec::new();
                for (name, &idx) in &self.string_map {
                    if name.starts_with(prefix) {
                        indices.push(idx);
                    }
                }
                Ok(indices)
            }
        }
    }

    /// Intern a string constant
    fn intern_string(&mut self, s: &str) -> usize {
        if let Some(&idx) = self.const_strings.get(s) {
            idx
        } else {
            let idx = self.string_constants.len();
            self.string_constants.push(s.to_string());
            self.const_strings.insert(s.to_string(), idx);
            idx
        }
    }

    /// Emit an instruction
    fn emit(&mut self, instruction: Instruction) {
        self.code.push(instruction);
    }
}

/// Serialize hex tokens to bytes for pattern matching
fn serialize_hex_tokens(tokens: &[r_yara_parser::HexToken]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for token in tokens {
        match token {
            r_yara_parser::HexToken::Byte(b) => {
                bytes.push(*b);
            }
            r_yara_parser::HexToken::Wildcard => {
                bytes.extend(b"??");
            }
            r_yara_parser::HexToken::NibbleWildcard { high, low } => {
                match (high, low) {
                    (Some(h), None) => bytes.extend(format!("{:X}?", h).as_bytes()),
                    (None, Some(l)) => bytes.extend(format!("?{:X}", l).as_bytes()),
                    _ => bytes.extend(b"??"),
                }
            }
            r_yara_parser::HexToken::Jump { min, max } => {
                match max {
                    Some(m) => bytes.extend(format!("[{}-{}]", min, m).as_bytes()),
                    None => bytes.extend(format!("[{}-]", min).as_bytes()),
                }
            }
            r_yara_parser::HexToken::Alternation(alts) => {
                bytes.push(b'(');
                for (i, alt) in alts.iter().enumerate() {
                    if i > 0 {
                        bytes.push(b'|');
                    }
                    bytes.extend(serialize_hex_tokens(alt));
                }
                bytes.push(b')');
            }
        }
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_yara_parser::parse;

    #[test]
    fn test_compile_simple_rule() {
        let source = r#"
            rule test_rule {
                condition:
                    true
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.rules[0].name.as_str(), "test_rule");
        assert!(!compiled.code.is_empty());
    }

    #[test]
    fn test_compile_rule_with_strings() {
        let source = r#"
            rule test_strings {
                strings:
                    $a = "test"
                    $b = "hello" nocase
                condition:
                    $a or $b
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.patterns.len(), 2);
        assert_eq!(compiled.rules[0].strings.len(), 2);
    }

    #[test]
    fn test_compile_rule_with_meta() {
        let source = r#"
            rule test_meta {
                meta:
                    author = "test"
                    version = 1
                    enabled = true
                condition:
                    true
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        let meta = &compiled.rules[0].meta;
        assert_eq!(meta.len(), 3);
        assert_eq!(meta.get("author"), Some(&MetaValue::String(SmolStr::new("test"))));
        assert_eq!(meta.get("version"), Some(&MetaValue::Integer(1)));
        assert_eq!(meta.get("enabled"), Some(&MetaValue::Boolean(true)));
    }

    #[test]
    fn test_compile_arithmetic() {
        let source = r#"
            rule test_arithmetic {
                condition:
                    1 + 2 * 3 > 5
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        assert!(!compiled.code.is_empty());
    }

    #[test]
    fn test_compile_string_count() {
        let source = r#"
            rule test_count {
                strings:
                    $a = "test"
                condition:
                    #a > 3
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Should have StringCount opcode
        assert!(compiled.code.iter().any(|i| matches!(i, Instruction::Simple(Opcode::StringCount))));
    }

    #[test]
    fn test_compile_string_at() {
        let source = r#"
            rule test_at {
                strings:
                    $a = "MZ"
                condition:
                    $a at 0
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Should have StringMatchAt opcode
        assert!(compiled.code.iter().any(|i| matches!(i, Instruction::Simple(Opcode::StringMatchAt))));
    }

    #[test]
    fn test_compile_quantifier() {
        let source = r#"
            rule test_quantifier {
                strings:
                    $a = "test"
                    $b = "hello"
                condition:
                    any of them
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Should have OfAny opcode
        assert!(compiled.code.iter().any(|i| matches!(i, Instruction::Simple(Opcode::OfAny))));
    }

    #[test]
    fn test_duplicate_rule_error() {
        let source = r#"
            rule test { condition: true }
            rule test { condition: false }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let result = compiler.compile(&ast);

        assert!(matches!(result, Err(CompileError::DuplicateRule(_))));
    }

    #[test]
    fn test_undefined_string_error() {
        let source = r#"
            rule test {
                condition:
                    $undefined
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let result = compiler.compile(&ast);

        assert!(matches!(result, Err(CompileError::UndefinedString(_))));
    }

    #[test]
    fn test_compile_imports() {
        let source = r#"
            import "pe"
            import "hash"

            rule test {
                condition:
                    true
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        assert_eq!(compiled.imports.len(), 2);
        assert!(compiled.imports.contains(&SmolStr::new("pe")));
        assert!(compiled.imports.contains(&SmolStr::new("hash")));
    }

    #[test]
    fn test_compile_tags() {
        let source = r#"
            rule test : tag1 tag2 {
                condition:
                    true
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        assert_eq!(compiled.rules[0].tags.len(), 2);
    }
}
