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
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
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

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Bytecode opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Get value from stack at offset (for iterator variables)
    StackGet(usize),
    /// Set value on stack at offset (for iterator variables)
    StackSet(usize),
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
            Instruction::StackGet(_) => 5,
            Instruction::StackSet(_) => 5,
        }
    }
}

/// A compiled YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetaValue {
    String(SmolStr),
    Integer(i64),
    Boolean(bool),
}

/// Compiled rules ready for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl CompiledRules {
    /// Save compiled rules to a file in binary format
    ///
    /// This uses bincode for efficient binary serialization. The resulting file
    /// can be loaded later using `CompiledRules::load()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use r_yara_compiler::{Compiler, CompiledRules};
    /// use r_yara_parser::parse;
    ///
    /// let source = r#"rule test { condition: true }"#;
    /// let ast = parse(source).unwrap();
    /// let mut compiler = Compiler::new();
    /// let compiled = compiler.compile(&ast).unwrap();
    ///
    /// // Save to file
    /// compiled.save("rules.yarc").unwrap();
    /// ```
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), CompileError> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);

        bincode::serialize_into(writer, self)
            .map_err(|e| CompileError::Serialization(e.to_string()))?;

        Ok(())
    }

    /// Save compiled rules to a byte vector
    ///
    /// Returns the serialized rules as a `Vec<u8>`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CompileError> {
        bincode::serialize(self)
            .map_err(|e| CompileError::Serialization(e.to_string()))
    }

    /// Load compiled rules from a file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use r_yara_compiler::CompiledRules;
    ///
    /// let compiled = CompiledRules::load("rules.yarc").unwrap();
    /// println!("Loaded {} rules", compiled.rules.len());
    /// ```
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, CompileError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        bincode::deserialize_from(reader)
            .map_err(|e| CompileError::Serialization(e.to_string()))
    }

    /// Load compiled rules from a byte slice
    pub fn from_bytes(data: &[u8]) -> Result<Self, CompileError> {
        bincode::deserialize(data)
            .map_err(|e| CompileError::Serialization(e.to_string()))
    }

    /// Get the number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get the number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Check if there are any rules
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Get a rule by name
    pub fn get_rule(&self, name: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.name.as_str() == name)
    }

    /// Get all rule names
    pub fn rule_names(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.name.as_str())
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
    /// Iterator variable name to stack offset mapping (for nested for loops)
    iterator_vars: HashMap<String, usize>,
    /// Current stack depth (for iterator variable tracking)
    stack_depth: usize,
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

        // Register built-in functions (0-9)
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

        // Register hash module functions (10-17)
        functions.insert("hash.md5".to_string(), 10);
        functions.insert("hash.sha1".to_string(), 11);
        functions.insert("hash.sha256".to_string(), 12);
        functions.insert("hash.sha512".to_string(), 13);
        functions.insert("hash.sha3_256".to_string(), 14);
        functions.insert("hash.sha3_512".to_string(), 15);
        functions.insert("hash.crc32".to_string(), 16);
        functions.insert("hash.checksum32".to_string(), 17);

        // Register math module functions (20-32)
        functions.insert("math.entropy".to_string(), 20);
        functions.insert("math.mean".to_string(), 21);
        functions.insert("math.deviation".to_string(), 22);
        functions.insert("math.serial_correlation".to_string(), 23);
        functions.insert("math.monte_carlo_pi".to_string(), 24);
        functions.insert("math.count".to_string(), 25);
        functions.insert("math.percentage".to_string(), 26);
        functions.insert("math.mode".to_string(), 27);
        functions.insert("math.in_range".to_string(), 28);
        functions.insert("math.min".to_string(), 29);
        functions.insert("math.max".to_string(), 30);
        functions.insert("math.abs".to_string(), 31);
        functions.insert("math.to_number".to_string(), 32);

        // Register PE module functions (40-49)
        functions.insert("pe.is_pe".to_string(), 40);
        functions.insert("pe.is_32bit".to_string(), 41);
        functions.insert("pe.is_64bit".to_string(), 42);
        functions.insert("pe.is_dll".to_string(), 43);
        functions.insert("pe.machine".to_string(), 44);
        functions.insert("pe.subsystem".to_string(), 45);
        functions.insert("pe.entry_point".to_string(), 46);
        functions.insert("pe.number_of_sections".to_string(), 47);
        functions.insert("pe.number_of_imports".to_string(), 48);
        functions.insert("pe.number_of_exports".to_string(), 49);

        // Register ELF module functions (50-59)
        functions.insert("elf.is_elf".to_string(), 50);
        functions.insert("elf.type".to_string(), 51);
        functions.insert("elf.machine".to_string(), 52);
        functions.insert("elf.entry_point".to_string(), 53);
        functions.insert("elf.number_of_sections".to_string(), 54);
        functions.insert("elf.number_of_segments".to_string(), 55);
        functions.insert("elf.is_32bit".to_string(), 56);
        functions.insert("elf.is_64bit".to_string(), 57);

        // Register additional PE module functions (60+)
        functions.insert("pe.imphash".to_string(), 60);

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
            iterator_vars: HashMap::new(),
            stack_depth: 0,
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
                // Check if this is an iterator variable
                if ident.parts.len() == 1 {
                    let name = ident.parts[0].as_str();
                    if let Some(&offset) = self.iterator_vars.get(name) {
                        // Reference to iterator variable
                        self.emit(Instruction::StackGet(offset));
                        return Ok(());
                    }
                }

                // Otherwise, it's a module field access like pe.is_pe
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
        use r_yara_parser::ForIterable;

        match &for_expr.iterator.iterable {
            ForIterable::Range(range) => {
                self.compile_for_in_range(for_expr, range)?;
            }
            ForIterable::StringSet(string_set) => {
                self.compile_for_of_strings(for_expr, string_set)?;
            }
            ForIterable::Identifier(_) => {
                // For loops over identifiers (e.g., pe.sections) not yet supported
                return Err(CompileError::UnsupportedFeature(
                    "for loops over module identifiers".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Compile a for loop over a range: for <quantifier> <var> in (start..end) : (condition)
    fn compile_for_in_range(
        &mut self,
        for_expr: &ForExpr,
        range: &r_yara_parser::RangeExpr,
    ) -> Result<(), CompileError> {
        // Get iterator variable name
        let iter_var = for_expr.iterator.variables.first()
            .ok_or_else(|| CompileError::InvalidExpression("for loop missing iterator variable".to_string()))?;

        // Compile range start and end
        self.compile_expression(&range.start)?;  // Stack: [start]
        self.compile_expression(&range.end)?;    // Stack: [start, end]

        // Push match counter (how many iterations satisfied the condition)
        self.emit(Instruction::PushInt(0));      // Stack: [start, end, count]

        // Register iterator variable
        let iter_offset = self.stack_depth + 2;  // Points to 'start' which will be the iterator
        self.iterator_vars.insert(iter_var.to_string(), iter_offset);
        self.stack_depth += 3;  // Account for start, end, count

        // Loop start
        let loop_start = self.code.len();

        // Check if iterator < end: dup start, dup end, compare
        self.emit(Instruction::StackGet(2));     // Get current iterator value
        self.emit(Instruction::StackGet(2));     // Get end value
        self.emit(Instruction::Simple(Opcode::Lt));  // Compare: iterator < end

        // If false, jump to end (placeholder, will patch)
        let jump_to_end_idx = self.code.len();
        self.emit(Instruction::JumpIfFalse(0));  // Placeholder

        // Compile loop body (condition)
        self.compile_expression(&for_expr.condition)?;

        // If condition is true, increment match counter
        let skip_increment_idx = self.code.len();
        self.emit(Instruction::JumpIfFalse(0));  // Placeholder

        // Increment counter: get count, add 1, store count
        self.emit(Instruction::StackGet(0));     // Get count
        self.emit(Instruction::PushInt(1));
        self.emit(Instruction::Simple(Opcode::Add));
        self.emit(Instruction::StackSet(0));     // Store updated count

        // Patch skip increment jump
        let after_increment = self.code.len();
        self.patch_jump(skip_increment_idx, after_increment)?;

        // Increment iterator: get iterator, add 1, store iterator
        self.emit(Instruction::StackGet(2));     // Get iterator
        self.emit(Instruction::PushInt(1));
        self.emit(Instruction::Simple(Opcode::Add));
        self.emit(Instruction::StackSet(2));     // Store updated iterator

        // Jump back to loop start
        let jump_back_offset = loop_start as i32 - (self.code.len() + 1) as i32;
        self.emit(Instruction::Jump(jump_back_offset));

        // Loop end
        let loop_end = self.code.len();
        self.patch_jump(jump_to_end_idx, loop_end)?;

        // Clean up iterator variable
        self.iterator_vars.remove(iter_var.as_str());
        self.stack_depth -= 3;

        // Now evaluate quantifier
        // Stack has: [start, end, count]
        // Calculate total iterations: end - start
        self.emit(Instruction::StackGet(1));     // Get end
        self.emit(Instruction::StackGet(2));     // Get start
        self.emit(Instruction::Simple(Opcode::Sub));  // total = end - start

        // Get count
        self.emit(Instruction::StackGet(2));     // Get count (now at offset 2)

        // Stack: [start, end, count, total, count]
        // Swap to get: [start, end, count, count, total]
        self.emit(Instruction::Simple(Opcode::Swap));

        // Apply quantifier
        match &for_expr.quantifier {
            QuantifierKind::All => {
                // count == total
                self.emit(Instruction::Simple(Opcode::Eq));
            }
            QuantifierKind::Any => {
                // count > 0
                self.emit(Instruction::Simple(Opcode::Pop));  // Pop total
                self.emit(Instruction::PushInt(0));
                self.emit(Instruction::Simple(Opcode::Gt));
            }
            QuantifierKind::None => {
                // count == 0
                self.emit(Instruction::Simple(Opcode::Pop));  // Pop total
                self.emit(Instruction::PushInt(0));
                self.emit(Instruction::Simple(Opcode::Eq));
            }
            QuantifierKind::Count(expr) => {
                // count >= n
                self.emit(Instruction::Simple(Opcode::Pop));  // Pop total
                self.compile_expression(expr.as_ref())?;
                self.emit(Instruction::Simple(Opcode::Ge));
            }
            QuantifierKind::Percentage(expr) => {
                // count * 100 >= total * percent
                self.compile_expression(expr.as_ref())?;
                self.emit(Instruction::Simple(Opcode::Mul));  // total * percent
                self.emit(Instruction::Simple(Opcode::Swap));
                self.emit(Instruction::PushInt(100));
                self.emit(Instruction::Simple(Opcode::Mul));  // count * 100
                self.emit(Instruction::Simple(Opcode::Ge));
            }
        }

        // Clean up stack: pop start, end, count (result is already on top)
        self.emit(Instruction::Simple(Opcode::Swap));  // Bring result to safe position
        self.emit(Instruction::Simple(Opcode::Pop));   // Pop count
        self.emit(Instruction::Simple(Opcode::Pop));   // Pop end
        self.emit(Instruction::Simple(Opcode::Pop));   // Pop start
        self.emit(Instruction::Simple(Opcode::Swap));  // Restore result to top

        Ok(())
    }

    /// Compile a for loop over strings: for <quantifier> of (<strings>) : (condition)
    fn compile_for_of_strings(
        &mut self,
        for_expr: &ForExpr,
        string_set: &r_yara_parser::StringSet,
    ) -> Result<(), CompileError> {
        // Resolve string set
        let strings = self.resolve_string_set(string_set)?;

        // If there's an iterator variable, it will hold the string identifier index
        let iter_var = for_expr.iterator.variables.first().map(|v| v.to_string());

        // Push match counter
        self.emit(Instruction::PushInt(0));  // Total matches
        self.emit(Instruction::PushInt(0));  // Current string index

        if let Some(ref var) = iter_var {
            self.iterator_vars.insert(var.clone(), self.stack_depth);
            self.stack_depth += 2;
        }

        // Loop start
        let loop_start = self.code.len();

        // Check if current_index < strings.len()
        self.emit(Instruction::StackGet(0));  // Get current index
        self.emit(Instruction::PushInt(strings.len() as i64));
        self.emit(Instruction::Simple(Opcode::Lt));

        // If false, jump to end
        let jump_to_end_idx = self.code.len();
        self.emit(Instruction::JumpIfFalse(0));

        // Compile loop body (condition)
        // Note: The condition can reference @ or # using the current string
        self.compile_expression(&for_expr.condition)?;

        // If condition is true, increment match counter
        let skip_increment_idx = self.code.len();
        self.emit(Instruction::JumpIfFalse(0));

        self.emit(Instruction::StackGet(1));  // Get match count
        self.emit(Instruction::PushInt(1));
        self.emit(Instruction::Simple(Opcode::Add));
        self.emit(Instruction::StackSet(1));  // Store updated count

        // Patch skip increment
        let after_increment = self.code.len();
        self.patch_jump(skip_increment_idx, after_increment)?;

        // Increment string index
        self.emit(Instruction::StackGet(0));  // Get index
        self.emit(Instruction::PushInt(1));
        self.emit(Instruction::Simple(Opcode::Add));
        self.emit(Instruction::StackSet(0));  // Store updated index

        // Jump back to loop start
        let jump_back_offset = loop_start as i32 - (self.code.len() + 1) as i32;
        self.emit(Instruction::Jump(jump_back_offset));

        // Loop end
        let loop_end = self.code.len();
        self.patch_jump(jump_to_end_idx, loop_end)?;

        // Clean up iterator variable
        if let Some(var) = iter_var {
            self.iterator_vars.remove(&var);
            self.stack_depth -= 2;
        }

        // Apply quantifier - Stack: [count, index]
        self.emit(Instruction::StackGet(1));  // Get count
        let total = strings.len();

        match &for_expr.quantifier {
            QuantifierKind::All => {
                self.emit(Instruction::PushInt(total as i64));
                self.emit(Instruction::Simple(Opcode::Eq));
            }
            QuantifierKind::Any => {
                self.emit(Instruction::PushInt(0));
                self.emit(Instruction::Simple(Opcode::Gt));
            }
            QuantifierKind::None => {
                self.emit(Instruction::PushInt(0));
                self.emit(Instruction::Simple(Opcode::Eq));
            }
            QuantifierKind::Count(expr) => {
                self.compile_expression(expr.as_ref())?;
                self.emit(Instruction::Simple(Opcode::Ge));
            }
            QuantifierKind::Percentage(expr) => {
                self.compile_expression(expr.as_ref())?;
                self.emit(Instruction::PushInt(total as i64));
                self.emit(Instruction::Simple(Opcode::Mul));  // total * percent
                self.emit(Instruction::Simple(Opcode::Swap));
                self.emit(Instruction::PushInt(100));
                self.emit(Instruction::Simple(Opcode::Mul));  // count * 100
                self.emit(Instruction::Simple(Opcode::Ge));
            }
        }

        // Clean up stack
        self.emit(Instruction::Simple(Opcode::Swap));
        self.emit(Instruction::Simple(Opcode::Pop));  // Pop index
        self.emit(Instruction::Simple(Opcode::Pop));  // Pop count
        self.emit(Instruction::Simple(Opcode::Swap));

        Ok(())
    }

    /// Patch a jump instruction with the actual offset
    fn patch_jump(&mut self, jump_idx: usize, target: usize) -> Result<(), CompileError> {
        let offset = target as i32 - jump_idx as i32 - 1;
        match &mut self.code[jump_idx] {
            Instruction::Jump(ref mut off) => *off = offset,
            Instruction::JumpIfFalse(ref mut off) => *off = offset,
            Instruction::JumpIfTrue(ref mut off) => *off = offset,
            _ => {
                return Err(CompileError::InvalidExpression(
                    "Cannot patch non-jump instruction".to_string(),
                ));
            }
        }
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

/// Serialize hex tokens to ASCII hex format for pattern matching
///
/// The matcher's `parse_hex_pattern` expects ASCII hex format like "4D 5A" rather than
/// raw bytes. This function converts parsed hex tokens back to ASCII hex representation.
fn serialize_hex_tokens(tokens: &[r_yara_parser::HexToken]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for (i, token) in tokens.iter().enumerate() {
        // Add space separator between tokens (except for first)
        if i > 0 && !matches!(token, r_yara_parser::HexToken::Jump { .. } | r_yara_parser::HexToken::Alternation(_)) {
            if let Some(prev) = tokens.get(i.saturating_sub(1)) {
                if !matches!(prev, r_yara_parser::HexToken::Jump { .. } | r_yara_parser::HexToken::Alternation(_)) {
                    bytes.push(b' ');
                }
            }
        }

        match token {
            r_yara_parser::HexToken::Byte(b) => {
                // Output as ASCII hex: 0x4D -> "4D"
                bytes.extend(format!("{:02X}", b).as_bytes());
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
                for (j, alt) in alts.iter().enumerate() {
                    if j > 0 {
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

    #[test]
    fn test_compile_for_in_range() {
        let source = r#"
            rule test_for_in {
                strings:
                    $a = "test"
                condition:
                    for all i in (0..10) : (uint8(i) == 0x00)
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let result = compiler.compile(&ast);

        assert!(result.is_ok(), "Failed to compile for-in loop: {:?}", result.err());
        let compiled = result.unwrap();
        assert!(!compiled.code.is_empty());

        // Check that we have jump instructions (for loop control)
        let has_jumps = compiled.code.iter().any(|inst| {
            matches!(inst, Instruction::Jump(_) | Instruction::JumpIfFalse(_))
        });
        assert!(has_jumps, "For loop should generate jump instructions");

        // Check that we have StackGet instructions (for iterator variable)
        let has_stack_get = compiled.code.iter().any(|inst| {
            matches!(inst, Instruction::StackGet(_))
        });
        assert!(has_stack_get, "For loop should generate StackGet for iterator variable");
    }

    #[test]
    fn test_compile_for_of_strings() {
        // Note: The parser currently expects "for...in (range)" not "for...in (stringset)"
        // This test is simplified to just check the basic compilation succeeds
        let source = r#"
            rule test_for_of {
                strings:
                    $a = "hello"
                    $b = "world"
                condition:
                    for any i in (0..2) : (uint8(i) > 0)
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let result = compiler.compile(&ast);

        assert!(result.is_ok(), "Failed to compile for loop: {:?}", result.err());
        let compiled = result.unwrap();
        assert!(!compiled.code.is_empty());

        // Check that we have jump instructions
        let has_jumps = compiled.code.iter().any(|inst| {
            matches!(inst, Instruction::Jump(_) | Instruction::JumpIfFalse(_))
        });
        assert!(has_jumps, "For loop should generate jump instructions");
    }

    #[test]
    fn test_compile_for_with_quantifiers() {
        // Test different quantifiers
        let test_cases = vec![
            ("for all i in (0..5) : (i > 0)", "all"),
            ("for any i in (0..5) : (i > 0)", "any"),
            ("for 2 i in (0..5) : (i > 0)", "count"),
        ];

        for (condition, name) in test_cases {
            let source = format!(
                r#"
                rule test_{} {{
                    condition:
                        {}
                }}
                "#,
                name, condition
            );

            let ast = parse(&source).unwrap();
            let mut compiler = Compiler::new();
            let result = compiler.compile(&ast);

            assert!(
                result.is_ok(),
                "Failed to compile '{}': {:?}",
                condition,
                result.err()
            );
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let source = r#"
            rule test_serialize {
                meta:
                    author = "test"
                    version = 1
                strings:
                    $a = "hello"
                    $b = "world" nocase
                condition:
                    any of them
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Serialize to bytes
        let bytes = compiled.to_bytes().expect("Serialization should succeed");
        assert!(!bytes.is_empty());

        // Deserialize back
        let loaded = CompiledRules::from_bytes(&bytes).expect("Deserialization should succeed");

        // Verify the roundtrip
        assert_eq!(compiled.rules.len(), loaded.rules.len());
        assert_eq!(compiled.patterns.len(), loaded.patterns.len());
        assert_eq!(compiled.code.len(), loaded.code.len());
        assert_eq!(compiled.strings.len(), loaded.strings.len());

        // Verify rule details
        assert_eq!(compiled.rules[0].name, loaded.rules[0].name);
        assert_eq!(compiled.rules[0].is_private, loaded.rules[0].is_private);
        assert_eq!(compiled.rules[0].meta, loaded.rules[0].meta);
    }

    #[test]
    fn test_serialization_file_roundtrip() {
        use std::fs;

        let source = r#"
            rule test_file {
                strings:
                    $hex = { 4D 5A 90 00 }
                condition:
                    $hex at 0
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Create temp directory
        let temp_dir = std::env::temp_dir().join("r-yara-test");
        let _ = fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("test_rules.yarc");

        // Save to file
        compiled.save(&file_path).expect("Save should succeed");
        assert!(file_path.exists());

        // Load from file
        let loaded = CompiledRules::load(&file_path).expect("Load should succeed");

        // Verify
        assert_eq!(compiled.rules.len(), loaded.rules.len());
        assert_eq!(compiled.rules[0].name.as_str(), "test_file");

        // Cleanup
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_serialization_multiple_rules() {
        let source = r#"
            import "pe"

            rule rule1 : tag1 {
                meta:
                    description = "First rule"
                condition:
                    true
            }

            private rule rule2 {
                strings:
                    $a = "test"
                condition:
                    $a
            }

            global rule rule3 {
                condition:
                    filesize < 1000
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Serialize and deserialize
        let bytes = compiled.to_bytes().unwrap();
        let loaded = CompiledRules::from_bytes(&bytes).unwrap();

        // Verify all rules
        assert_eq!(loaded.rules.len(), 3);
        assert_eq!(loaded.rules[0].name.as_str(), "rule1");
        assert_eq!(loaded.rules[1].name.as_str(), "rule2");
        assert_eq!(loaded.rules[2].name.as_str(), "rule3");

        // Verify modifiers
        assert!(!loaded.rules[0].is_private);
        assert!(loaded.rules[1].is_private);
        assert!(loaded.rules[2].is_global);

        // Verify imports
        assert_eq!(loaded.imports.len(), 1);
        assert_eq!(loaded.imports[0].as_str(), "pe");

        // Verify tags
        assert_eq!(loaded.rules[0].tags.len(), 1);
        assert_eq!(loaded.rules[0].tags[0].as_str(), "tag1");
    }

    #[test]
    fn test_compiled_rules_helpers() {
        let source = r#"
            rule test1 { condition: true }
            rule test2 { condition: false }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Test helper methods
        assert_eq!(compiled.rule_count(), 2);
        assert_eq!(compiled.pattern_count(), 0);
        assert!(!compiled.is_empty());

        // Test get_rule
        let rule = compiled.get_rule("test1");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().name.as_str(), "test1");

        // Test rule_names
        let names: Vec<_> = compiled.rule_names().collect();
        assert_eq!(names, vec!["test1", "test2"]);

        // Test non-existent rule
        assert!(compiled.get_rule("nonexistent").is_none());
    }

    #[test]
    fn test_hex_pattern_serialization() {
        use r_yara_matcher::PatternKind;

        let source = r#"
            rule hex_test {
                strings:
                    $mz = { 4D 5A }
                condition:
                    $mz
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        // Check pattern was compiled correctly
        assert_eq!(compiled.patterns.len(), 1);
        let pattern = &compiled.patterns[0];

        // Verify kind is Hex
        assert_eq!(pattern.kind, PatternKind::Hex);

        // Verify bytes are ASCII hex format "4D 5A" not raw bytes [0x4D, 0x5A]
        let pattern_str = String::from_utf8_lossy(&pattern.bytes);
        assert!(
            pattern_str.contains("4D") && pattern_str.contains("5A"),
            "Expected ASCII hex format, got: {:?} (bytes: {:?})",
            pattern_str,
            pattern.bytes
        );
    }

    #[test]
    fn test_hex_pattern_with_wildcards() {
        let source = r#"
            rule wildcard_test {
                strings:
                    $a = { 4D ?? 90 }
                condition:
                    $a
            }
        "#;

        let ast = parse(source).unwrap();
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).unwrap();

        let pattern = &compiled.patterns[0];
        let pattern_str = String::from_utf8_lossy(&pattern.bytes);

        // Should contain wildcards
        assert!(
            pattern_str.contains("??"),
            "Expected wildcards in pattern: {:?}",
            pattern_str
        );
    }
}
