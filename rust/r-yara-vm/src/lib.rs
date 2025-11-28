//! R-YARA Virtual Machine
//!
//! Executes compiled YARA bytecode to evaluate rule conditions.
//!
//! # Architecture
//!
//! The VM uses a stack-based execution model:
//! - Values are pushed onto a stack
//! - Operations pop operands and push results
//! - Boolean results determine rule matches
//!
//! # Example
//!
//! ```no_run
//! use r_yara_vm::{VM, ScanContext};
//! use r_yara_compiler::CompiledRules;
//! use r_yara_matcher::PatternMatcher;
//!
//! // Assuming compiled rules and matcher are available
//! // let compiled = compiler.compile(&ast)?;
//! // let matcher = PatternMatcher::new(compiled.patterns.clone())?;
//! // let vm = VM::new(&compiled, &matcher);
//! // let ctx = ScanContext::new(data);
//! // let matches = vm.scan(&ctx);
//! ```

use r_yara_compiler::{CompiledRule, CompiledRules, Instruction, Opcode};
use r_yara_matcher::{Match, PatternMatcher};
use r_yara_modules::{elf, hash, math, pe};
use smol_str::SmolStr;
use std::collections::HashMap;
use thiserror::Error;

/// VM execution errors
#[derive(Debug, Error)]
pub enum VMError {
    #[error("Stack underflow")]
    StackUnderflow,

    #[error("Invalid opcode at position {0}")]
    InvalidOpcode(usize),

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },

    #[error("Unknown function: {0}")]
    UnknownFunction(usize),

    #[error("Invalid string reference: {0}")]
    InvalidStringRef(usize),
}

/// Value on the VM stack
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Boolean value
    Bool(bool),
    /// Integer value
    Int(i64),
    /// Float value
    Float(f64),
    /// String value
    String(SmolStr),
    /// Undefined/null value
    Undefined,
}

impl Value {
    /// Convert to boolean
    pub fn as_bool(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::Undefined => false,
        }
    }

    /// Convert to integer
    pub fn as_int(&self) -> i64 {
        match self {
            Value::Bool(b) => if *b { 1 } else { 0 },
            Value::Int(i) => *i,
            Value::Float(f) => *f as i64,
            Value::String(_) => 0,
            Value::Undefined => 0,
        }
    }

    /// Convert to float
    pub fn as_float(&self) -> f64 {
        match self {
            Value::Bool(b) => if *b { 1.0 } else { 0.0 },
            Value::Int(i) => *i as f64,
            Value::Float(f) => *f,
            Value::String(_) => 0.0,
            Value::Undefined => 0.0,
        }
    }

    /// Get type name
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::String(_) => "string",
            Value::Undefined => "undefined",
        }
    }
}

/// Scan context containing target data and match results
pub struct ScanContext<'a> {
    /// Data being scanned
    pub data: &'a [u8],
    /// Matches found by the pattern matcher
    pub matches: Vec<Match>,
    /// Matches indexed by pattern ID
    match_index: HashMap<usize, Vec<Match>>,
    /// File size (usually data.len())
    pub filesize: u64,
    /// Entry point (for PE/ELF files)
    pub entrypoint: u64,
}

impl<'a> ScanContext<'a> {
    /// Create a new scan context
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            matches: Vec::new(),
            match_index: HashMap::new(),
            filesize: data.len() as u64,
            entrypoint: 0,
        }
    }

    /// Set entry point
    pub fn with_entrypoint(mut self, entrypoint: u64) -> Self {
        self.entrypoint = entrypoint;
        self
    }

    /// Add pattern matches
    pub fn with_matches(mut self, matches: Vec<Match>) -> Self {
        // Build match index
        for m in &matches {
            self.match_index
                .entry(m.pattern_id)
                .or_insert_with(Vec::new)
                .push(m.clone());
        }
        self.matches = matches;
        self
    }

    /// Get matches for a pattern
    pub fn get_matches(&self, pattern_id: usize) -> &[Match] {
        self.match_index
            .get(&pattern_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Check if pattern matched at all
    pub fn pattern_matched(&self, pattern_id: usize) -> bool {
        !self.get_matches(pattern_id).is_empty()
    }

    /// Check if pattern matched at specific offset
    pub fn pattern_matched_at(&self, pattern_id: usize, offset: u64) -> bool {
        self.get_matches(pattern_id)
            .iter()
            .any(|m| m.offset as u64 == offset)
    }

    /// Check if pattern matched in range
    pub fn pattern_matched_in(&self, pattern_id: usize, start: u64, end: u64) -> bool {
        self.get_matches(pattern_id)
            .iter()
            .any(|m| m.offset as u64 >= start && (m.offset as u64) < end)
    }

    /// Get match count for pattern
    pub fn pattern_count(&self, pattern_id: usize) -> usize {
        self.get_matches(pattern_id).len()
    }

    /// Get match count in range
    pub fn pattern_count_in(&self, pattern_id: usize, start: u64, end: u64) -> usize {
        self.get_matches(pattern_id)
            .iter()
            .filter(|m| m.offset as u64 >= start && (m.offset as u64) < end)
            .count()
    }

    /// Get offset of nth match
    pub fn pattern_offset(&self, pattern_id: usize, index: usize) -> Option<u64> {
        self.get_matches(pattern_id)
            .get(index)
            .map(|m| m.offset as u64)
    }

    /// Get length of nth match
    pub fn pattern_length(&self, pattern_id: usize, index: usize) -> Option<u64> {
        self.get_matches(pattern_id)
            .get(index)
            .map(|m| m.length as u64)
    }
}

/// Result of rule evaluation
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule name
    pub name: SmolStr,
    /// Rule tags
    pub tags: Vec<SmolStr>,
    /// Matching strings with their offsets
    pub strings: Vec<StringMatch>,
    /// Rule metadata
    pub meta: HashMap<SmolStr, Value>,
}

/// A matched string
#[derive(Debug, Clone)]
pub struct StringMatch {
    /// String identifier (e.g., "$a")
    pub identifier: SmolStr,
    /// Match offsets
    pub offsets: Vec<u64>,
}

/// The virtual machine
pub struct VM<'a> {
    /// Compiled rules
    rules: &'a CompiledRules,
    /// Pattern matcher (for future use in module lookups)
    #[allow(dead_code)]
    matcher: &'a PatternMatcher,
}

impl<'a> VM<'a> {
    /// Create a new VM
    pub fn new(rules: &'a CompiledRules, matcher: &'a PatternMatcher) -> Self {
        Self { rules, matcher }
    }

    /// Scan data and return matching rules
    pub fn scan(&self, ctx: &ScanContext) -> Result<Vec<RuleMatch>, VMError> {
        let mut results = Vec::new();

        for rule in &self.rules.rules {
            if rule.is_private {
                // Private rules don't produce matches
                continue;
            }

            if self.evaluate_rule(rule, ctx)? {
                let rule_match = self.build_rule_match(rule, ctx);
                results.push(rule_match);
            }
        }

        Ok(results)
    }

    /// Evaluate a single rule
    fn evaluate_rule(&self, rule: &CompiledRule, ctx: &ScanContext) -> Result<bool, VMError> {
        let mut stack: Vec<Value> = Vec::new();
        let mut ip = rule.code_start;
        let end = rule.code_start + rule.code_len;

        while ip < end {
            let instruction = &self.rules.code[ip];
            ip += 1;

            match instruction {
                Instruction::Simple(opcode) => {
                    self.execute_simple_opcode(*opcode, &mut stack, ctx)?;
                    if *opcode == Opcode::Halt {
                        break;
                    }
                }
                Instruction::PushInt(i) => {
                    stack.push(Value::Int(*i));
                }
                Instruction::PushFloat(f) => {
                    stack.push(Value::Float(*f));
                }
                Instruction::PushString(idx) => {
                    let s = self.rules.strings.get(*idx).cloned().unwrap_or_default();
                    stack.push(Value::String(SmolStr::new(&s)));
                }
                Instruction::StringRef(pattern_id) => {
                    stack.push(Value::Int(*pattern_id as i64));
                }
                Instruction::StringRefIndex(pattern_id, _) => {
                    stack.push(Value::Int(*pattern_id as i64));
                }
                Instruction::StringSet(set) => {
                    // Push string set for quantifier ops
                    // Push IDs first (in order), then count on top
                    for &id in set.iter() {
                        stack.push(Value::Int(id as i64));
                    }
                    stack.push(Value::Int(set.len() as i64));
                }
                Instruction::Jump(offset) => {
                    ip = (ip as i32 + offset) as usize;
                }
                Instruction::JumpIfFalse(offset) => {
                    let val = self.pop(&mut stack)?;
                    if !val.as_bool() {
                        ip = (ip as i32 + offset) as usize;
                    }
                }
                Instruction::JumpIfTrue(offset) => {
                    let val = self.pop(&mut stack)?;
                    if val.as_bool() {
                        ip = (ip as i32 + offset) as usize;
                    }
                }
                Instruction::Call { function_id, arg_count } => {
                    let result = self.call_function(*function_id, *arg_count, &mut stack, ctx)?;
                    stack.push(result);
                }
                Instruction::StackGet(offset) => {
                    // Get value from stack at offset positions from the top
                    // offset=0 means top, offset=1 means one below top, etc.
                    let stack_len = stack.len();
                    if *offset >= stack_len {
                        return Err(VMError::StackUnderflow);
                    }
                    let val = stack[stack_len - 1 - offset].clone();
                    stack.push(val);
                }
                Instruction::StackSet(offset) => {
                    // Set value on stack at offset positions from the top
                    // Pops the top value and stores it at the offset position
                    let val = self.pop(&mut stack)?;
                    let stack_len = stack.len();
                    if *offset >= stack_len {
                        return Err(VMError::StackUnderflow);
                    }
                    stack[stack_len - 1 - offset] = val;
                }
            }
        }

        // Top of stack should be the result
        let result = stack.pop().unwrap_or(Value::Bool(false));
        Ok(result.as_bool())
    }

    /// Execute a simple opcode
    fn execute_simple_opcode(
        &self,
        opcode: Opcode,
        stack: &mut Vec<Value>,
        ctx: &ScanContext,
    ) -> Result<(), VMError> {
        match opcode {
            Opcode::Nop => {}
            Opcode::Pop => {
                self.pop(stack)?;
            }
            Opcode::Dup => {
                let val = stack.last().cloned().ok_or(VMError::StackUnderflow)?;
                stack.push(val);
            }
            Opcode::Swap => {
                let a = self.pop(stack)?;
                let b = self.pop(stack)?;
                stack.push(a);
                stack.push(b);
            }
            Opcode::PushTrue => {
                stack.push(Value::Bool(true));
            }
            Opcode::PushFalse => {
                stack.push(Value::Bool(false));
            }
            Opcode::PushInt | Opcode::PushFloat | Opcode::PushString => {
                // Handled by Instruction variants
            }

            // Arithmetic
            Opcode::Add => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() + b.as_int()));
            }
            Opcode::Sub => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() - b.as_int()));
            }
            Opcode::Mul => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() * b.as_int()));
            }
            Opcode::Div => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                if b.as_int() == 0 {
                    return Err(VMError::DivisionByZero);
                }
                stack.push(Value::Int(a.as_int() / b.as_int()));
            }
            Opcode::Mod => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                if b.as_int() == 0 {
                    return Err(VMError::DivisionByZero);
                }
                stack.push(Value::Int(a.as_int() % b.as_int()));
            }
            Opcode::Neg => {
                let a = self.pop(stack)?;
                stack.push(Value::Int(-a.as_int()));
            }

            // Bitwise
            Opcode::BitAnd => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() & b.as_int()));
            }
            Opcode::BitOr => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() | b.as_int()));
            }
            Opcode::BitXor => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() ^ b.as_int()));
            }
            Opcode::BitNot => {
                let a = self.pop(stack)?;
                stack.push(Value::Int(!a.as_int()));
            }
            Opcode::ShiftLeft => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() << b.as_int()));
            }
            Opcode::ShiftRight => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Int(a.as_int() >> b.as_int()));
            }

            // Comparison
            Opcode::Eq => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_int() == b.as_int()));
            }
            Opcode::Ne => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_int() != b.as_int()));
            }
            Opcode::Lt => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_int() < b.as_int()));
            }
            Opcode::Le => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_int() <= b.as_int()));
            }
            Opcode::Gt => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_int() > b.as_int()));
            }
            Opcode::Ge => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_int() >= b.as_int()));
            }

            // String operations
            Opcode::Contains => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(haystack), Value::String(needle)) => {
                        haystack.contains(needle.as_str())
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }
            Opcode::IContains => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(haystack), Value::String(needle)) => {
                        haystack.to_lowercase().contains(&needle.to_lowercase())
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }
            Opcode::StartsWith => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(haystack), Value::String(prefix)) => {
                        haystack.starts_with(prefix.as_str())
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }
            Opcode::IStartsWith => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(haystack), Value::String(prefix)) => {
                        haystack.to_lowercase().starts_with(&prefix.to_lowercase())
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }
            Opcode::EndsWith => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(haystack), Value::String(suffix)) => {
                        haystack.ends_with(suffix.as_str())
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }
            Opcode::IEndsWith => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(haystack), Value::String(suffix)) => {
                        haystack.to_lowercase().ends_with(&suffix.to_lowercase())
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }
            Opcode::Matches => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(text), Value::String(pattern)) => {
                        regex::Regex::new(pattern.as_str())
                            .map(|re| re.is_match(text.as_str()))
                            .unwrap_or(false)
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }
            Opcode::IMatches => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                let result = match (&a, &b) {
                    (Value::String(text), Value::String(pattern)) => {
                        // Build case-insensitive regex with (?i) flag
                        let case_insensitive_pattern = format!("(?i){}", pattern);
                        regex::Regex::new(&case_insensitive_pattern)
                            .map(|re| re.is_match(text.as_str()))
                            .unwrap_or(false)
                    }
                    _ => false,
                };
                stack.push(Value::Bool(result));
            }

            // Logical
            Opcode::And => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_bool() && b.as_bool()));
            }
            Opcode::Or => {
                let b = self.pop(stack)?;
                let a = self.pop(stack)?;
                stack.push(Value::Bool(a.as_bool() || b.as_bool()));
            }
            Opcode::Not => {
                let a = self.pop(stack)?;
                stack.push(Value::Bool(!a.as_bool()));
            }

            // String matching
            Opcode::StringMatch => {
                let pattern_id = self.pop(stack)?.as_int() as usize;
                let matched = ctx.pattern_matched(pattern_id);
                stack.push(Value::Bool(matched));
            }
            Opcode::StringMatchAt => {
                let pattern_id = self.pop(stack)?.as_int() as usize;
                let offset = self.pop(stack)?.as_int() as u64;
                let matched = ctx.pattern_matched_at(pattern_id, offset);
                stack.push(Value::Bool(matched));
            }
            Opcode::StringMatchIn => {
                let pattern_id = self.pop(stack)?.as_int() as usize;
                let end = self.pop(stack)?.as_int() as u64;
                let start = self.pop(stack)?.as_int() as u64;
                let matched = ctx.pattern_matched_in(pattern_id, start, end);
                stack.push(Value::Bool(matched));
            }
            Opcode::StringCount => {
                let pattern_id = self.pop(stack)?.as_int() as usize;
                let count = ctx.pattern_count(pattern_id);
                stack.push(Value::Int(count as i64));
            }
            Opcode::StringCountIn => {
                let pattern_id = self.pop(stack)?.as_int() as usize;
                let end = self.pop(stack)?.as_int() as u64;
                let start = self.pop(stack)?.as_int() as u64;
                let count = ctx.pattern_count_in(pattern_id, start, end);
                stack.push(Value::Int(count as i64));
            }
            Opcode::StringOffset => {
                let pattern_id = self.pop(stack)?.as_int() as usize;
                let index = self.pop(stack)?.as_int() as usize;
                let offset = ctx.pattern_offset(pattern_id, index).unwrap_or(0);
                stack.push(Value::Int(offset as i64));
            }
            Opcode::StringLength => {
                let pattern_id = self.pop(stack)?.as_int() as usize;
                let index = self.pop(stack)?.as_int() as usize;
                let length = ctx.pattern_length(pattern_id, index).unwrap_or(0);
                stack.push(Value::Int(length as i64));
            }

            // Quantifiers
            Opcode::OfAll => {
                // Pop string set and check if all matched
                let count = self.pop(stack)?.as_int() as usize;
                let mut all_matched = true;
                for _ in 0..count {
                    let pattern_id = self.pop(stack)?.as_int() as usize;
                    if !ctx.pattern_matched(pattern_id) {
                        all_matched = false;
                    }
                }
                stack.push(Value::Bool(all_matched));
            }
            Opcode::OfAny => {
                let count = self.pop(stack)?.as_int() as usize;
                let mut any_matched = false;
                for _ in 0..count {
                    let pattern_id = self.pop(stack)?.as_int() as usize;
                    if ctx.pattern_matched(pattern_id) {
                        any_matched = true;
                    }
                }
                stack.push(Value::Bool(any_matched));
            }
            Opcode::OfNone => {
                let count = self.pop(stack)?.as_int() as usize;
                let mut none_matched = true;
                for _ in 0..count {
                    let pattern_id = self.pop(stack)?.as_int() as usize;
                    if ctx.pattern_matched(pattern_id) {
                        none_matched = false;
                    }
                }
                stack.push(Value::Bool(none_matched));
            }
            Opcode::OfCount => {
                let required = self.pop(stack)?.as_int() as usize;
                let count = self.pop(stack)?.as_int() as usize;
                let mut matched_count = 0;
                for _ in 0..count {
                    let pattern_id = self.pop(stack)?.as_int() as usize;
                    if ctx.pattern_matched(pattern_id) {
                        matched_count += 1;
                    }
                }
                stack.push(Value::Bool(matched_count >= required));
            }
            Opcode::OfPercent => {
                let percent = self.pop(stack)?.as_int() as usize;
                let count = self.pop(stack)?.as_int() as usize;
                let mut matched_count = 0;
                for _ in 0..count {
                    let pattern_id = self.pop(stack)?.as_int() as usize;
                    if ctx.pattern_matched(pattern_id) {
                        matched_count += 1;
                    }
                }
                let required = (count * percent + 99) / 100; // Ceiling division
                stack.push(Value::Bool(matched_count >= required));
            }

            // For loops (simplified)
            Opcode::ForIn | Opcode::ForOf => {
                // Placeholder - push false for now
                stack.push(Value::Bool(false));
            }

            // Built-in variables
            Opcode::Filesize => {
                stack.push(Value::Int(ctx.filesize as i64));
            }
            Opcode::Entrypoint => {
                stack.push(Value::Int(ctx.entrypoint as i64));
            }

            // Control flow
            Opcode::Jump | Opcode::JumpIfFalse | Opcode::JumpIfTrue => {
                // Handled by Instruction variants
            }

            // Function call
            Opcode::Call => {
                // Handled by Instruction variant
            }

            Opcode::Halt => {
                // Execution complete
            }
        }

        Ok(())
    }

    /// Call a built-in function
    fn call_function(
        &self,
        function_id: usize,
        arg_count: usize,
        stack: &mut Vec<Value>,
        ctx: &ScanContext,
    ) -> Result<Value, VMError> {
        // Pop arguments
        let mut args = Vec::with_capacity(arg_count);
        for _ in 0..arg_count {
            args.push(self.pop(stack)?);
        }
        args.reverse();

        match function_id {
            // Built-in integer reading functions (0-9)
            0 => {
                // uint8(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = ctx.data.get(offset).copied().unwrap_or(0) as i64;
                Ok(Value::Int(value))
            }
            1 => {
                // uint16(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 1 < ctx.data.len() {
                    u16::from_le_bytes([ctx.data[offset], ctx.data[offset + 1]]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }
            2 => {
                // uint32(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 3 < ctx.data.len() {
                    u32::from_le_bytes([
                        ctx.data[offset],
                        ctx.data[offset + 1],
                        ctx.data[offset + 2],
                        ctx.data[offset + 3],
                    ]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }
            3 => {
                // uint16be(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 1 < ctx.data.len() {
                    u16::from_be_bytes([ctx.data[offset], ctx.data[offset + 1]]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }
            4 => {
                // uint32be(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 3 < ctx.data.len() {
                    u32::from_be_bytes([
                        ctx.data[offset],
                        ctx.data[offset + 1],
                        ctx.data[offset + 2],
                        ctx.data[offset + 3],
                    ]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }
            5 => {
                // int8(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = ctx.data.get(offset).copied().unwrap_or(0) as i8 as i64;
                Ok(Value::Int(value))
            }
            6 => {
                // int16(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 1 < ctx.data.len() {
                    i16::from_le_bytes([ctx.data[offset], ctx.data[offset + 1]]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }
            7 => {
                // int32(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 3 < ctx.data.len() {
                    i32::from_le_bytes([
                        ctx.data[offset],
                        ctx.data[offset + 1],
                        ctx.data[offset + 2],
                        ctx.data[offset + 3],
                    ]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }
            8 => {
                // int16be(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 1 < ctx.data.len() {
                    i16::from_be_bytes([ctx.data[offset], ctx.data[offset + 1]]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }
            9 => {
                // int32be(offset)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let value = if offset + 3 < ctx.data.len() {
                    i32::from_be_bytes([
                        ctx.data[offset],
                        ctx.data[offset + 1],
                        ctx.data[offset + 2],
                        ctx.data[offset + 3],
                    ]) as i64
                } else {
                    0
                };
                Ok(Value::Int(value))
            }

            // Hash module functions (10-17)
            10 => {
                // hash.md5(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let hash_str = hash::md5(ctx.data, offset, size);
                Ok(Value::String(SmolStr::new(&hash_str)))
            }
            11 => {
                // hash.sha1(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let hash_str = hash::sha1(ctx.data, offset, size);
                Ok(Value::String(SmolStr::new(&hash_str)))
            }
            12 => {
                // hash.sha256(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let hash_str = hash::sha256(ctx.data, offset, size);
                Ok(Value::String(SmolStr::new(&hash_str)))
            }
            13 => {
                // hash.sha512(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let hash_str = hash::sha512(ctx.data, offset, size);
                Ok(Value::String(SmolStr::new(&hash_str)))
            }
            14 => {
                // hash.sha3_256(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let hash_str = hash::sha3_256(ctx.data, offset, size);
                Ok(Value::String(SmolStr::new(&hash_str)))
            }
            15 => {
                // hash.sha3_512(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let hash_str = hash::sha3_512(ctx.data, offset, size);
                Ok(Value::String(SmolStr::new(&hash_str)))
            }
            16 => {
                // hash.crc32(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let checksum = hash::crc32(ctx.data, offset, size);
                Ok(Value::Int(checksum as i64))
            }
            17 => {
                // hash.checksum32(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let checksum = hash::checksum32(ctx.data, offset, size);
                Ok(Value::Int(checksum as i64))
            }

            // Math module functions (20-32)
            20 => {
                // math.entropy(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let entropy = math::entropy(ctx.data, offset, size);
                Ok(Value::Float(entropy))
            }
            21 => {
                // math.mean(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let mean = math::mean(ctx.data, offset, size);
                Ok(Value::Float(mean))
            }
            22 => {
                // math.deviation(offset, size, mean)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let mean = args.get(2).map(|v| v.as_float()).unwrap_or(0.0);
                let deviation = math::deviation(ctx.data, offset, size, mean);
                Ok(Value::Float(deviation))
            }
            23 => {
                // math.serial_correlation(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let corr = math::serial_correlation(ctx.data, offset, size);
                Ok(Value::Float(corr))
            }
            24 => {
                // math.monte_carlo_pi(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let pi = math::monte_carlo_pi(ctx.data, offset, size);
                Ok(Value::Float(pi))
            }
            25 => {
                // math.count(byte, offset, size)
                let byte = args.get(0).map(|v| v.as_int()).unwrap_or(0) as u8;
                let offset = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(2).map(|v| v.as_int()).unwrap_or(0) as usize;
                let count = math::count(byte, ctx.data, offset, size);
                Ok(Value::Int(count as i64))
            }
            26 => {
                // math.percentage(byte, offset, size)
                let byte = args.get(0).map(|v| v.as_int()).unwrap_or(0) as u8;
                let offset = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(2).map(|v| v.as_int()).unwrap_or(0) as usize;
                let percentage = math::percentage(byte, ctx.data, offset, size);
                Ok(Value::Float(percentage))
            }
            27 => {
                // math.mode(offset, size)
                let offset = args.get(0).map(|v| v.as_int()).unwrap_or(0) as usize;
                let size = args.get(1).map(|v| v.as_int()).unwrap_or(0) as usize;
                let mode = math::mode(ctx.data, offset, size);
                Ok(Value::Int(mode as i64))
            }
            28 => {
                // math.in_range(test, lower, upper)
                let test = args.get(0).map(|v| v.as_float()).unwrap_or(0.0);
                let lower = args.get(1).map(|v| v.as_float()).unwrap_or(0.0);
                let upper = args.get(2).map(|v| v.as_float()).unwrap_or(0.0);
                let in_range = math::in_range(test, lower, upper);
                Ok(Value::Bool(in_range))
            }
            29 => {
                // math.min(a, b)
                let a = args.get(0).map(|v| v.as_int()).unwrap_or(0);
                let b = args.get(1).map(|v| v.as_int()).unwrap_or(0);
                let min = math::min(a, b);
                Ok(Value::Int(min))
            }
            30 => {
                // math.max(a, b)
                let a = args.get(0).map(|v| v.as_int()).unwrap_or(0);
                let b = args.get(1).map(|v| v.as_int()).unwrap_or(0);
                let max = math::max(a, b);
                Ok(Value::Int(max))
            }
            31 => {
                // math.abs(a)
                let a = args.get(0).map(|v| v.as_int()).unwrap_or(0);
                let abs = math::abs(a);
                Ok(Value::Int(abs))
            }
            32 => {
                // math.to_number(bool)
                let b = args.get(0).map(|v| v.as_bool()).unwrap_or(false);
                let num = math::to_number(b);
                Ok(Value::Int(num))
            }

            // PE module functions (40-49)
            40 => {
                // pe.is_pe()
                let is_pe = pe::is_pe(ctx.data);
                Ok(Value::Bool(is_pe))
            }
            41 => {
                // pe.is_32bit()
                let is_32 = pe::is_32bit(ctx.data);
                Ok(Value::Bool(is_32))
            }
            42 => {
                // pe.is_64bit()
                let is_64 = pe::is_64bit(ctx.data);
                Ok(Value::Bool(is_64))
            }
            43 => {
                // pe.is_dll()
                let is_dll = pe::is_dll(ctx.data);
                Ok(Value::Bool(is_dll))
            }
            44 => {
                // pe.machine()
                let machine = pe::get_machine(ctx.data);
                Ok(Value::Int(machine as i64))
            }
            45 => {
                // pe.subsystem()
                let subsystem = pe::get_subsystem(ctx.data);
                Ok(Value::Int(subsystem as i64))
            }
            46 => {
                // pe.entry_point()
                let entry_point = pe::get_entry_point(ctx.data);
                Ok(Value::Int(entry_point as i64))
            }
            47 => {
                // pe.number_of_sections()
                let num_sections = pe::get_number_of_sections(ctx.data);
                Ok(Value::Int(num_sections as i64))
            }
            48 => {
                // pe.number_of_imports()
                let num_imports = pe::get_number_of_imports(ctx.data);
                Ok(Value::Int(num_imports as i64))
            }
            49 => {
                // pe.number_of_exports()
                let num_exports = pe::get_number_of_exports(ctx.data);
                Ok(Value::Int(num_exports as i64))
            }

            // ELF module functions (50-59)
            50 => {
                // elf.is_elf()
                let is_elf = elf::is_elf(ctx.data);
                Ok(Value::Bool(is_elf))
            }
            51 => {
                // elf.type()
                let elf_type = elf::get_type(ctx.data);
                Ok(Value::Int(elf_type as i64))
            }
            52 => {
                // elf.machine()
                let machine = elf::get_machine(ctx.data);
                Ok(Value::Int(machine as i64))
            }
            53 => {
                // elf.entry_point()
                let entry_point = elf::get_entry_point(ctx.data);
                Ok(Value::Int(entry_point as i64))
            }
            54 => {
                // elf.number_of_sections()
                let num_sections = elf::get_number_of_sections(ctx.data);
                Ok(Value::Int(num_sections as i64))
            }
            55 => {
                // elf.number_of_segments()
                let num_segments = elf::get_number_of_segments(ctx.data);
                Ok(Value::Int(num_segments as i64))
            }
            56 => {
                // elf.is_32bit()
                if let Some(elf_info) = elf::ElfInfo::parse(ctx.data) {
                    Ok(Value::Bool(elf_info.is_32bit()))
                } else {
                    Ok(Value::Bool(false))
                }
            }
            57 => {
                // elf.is_64bit()
                if let Some(elf_info) = elf::ElfInfo::parse(ctx.data) {
                    Ok(Value::Bool(elf_info.is_64bit()))
                } else {
                    Ok(Value::Bool(false))
                }
            }

            // PE imphash function (60)
            60 => {
                // pe.imphash()
                let hash = pe::imphash(ctx.data).unwrap_or_default();
                Ok(Value::String(SmolStr::new(&hash)))
            }

            _ => Err(VMError::UnknownFunction(function_id)),
        }
    }

    /// Pop a value from the stack
    fn pop(&self, stack: &mut Vec<Value>) -> Result<Value, VMError> {
        stack.pop().ok_or(VMError::StackUnderflow)
    }

    /// Build a rule match result
    fn build_rule_match(&self, rule: &CompiledRule, ctx: &ScanContext) -> RuleMatch {
        let mut strings = Vec::new();

        // Collect matching strings
        for &pattern_id in &rule.strings {
            let matches = ctx.get_matches(pattern_id);
            if !matches.is_empty() {
                let identifier = self
                    .rules
                    .patterns
                    .get(pattern_id)
                    .and_then(|p| p.name.clone())
                    .unwrap_or_else(|| SmolStr::new(&format!("${}", pattern_id)));

                strings.push(StringMatch {
                    identifier,
                    offsets: matches.iter().map(|m| m.offset as u64).collect(),
                });
            }
        }

        // Convert metadata
        let mut meta = HashMap::new();
        for (key, value) in &rule.meta {
            let val = match value {
                r_yara_compiler::MetaValue::String(s) => Value::String(s.clone()),
                r_yara_compiler::MetaValue::Integer(i) => Value::Int(*i),
                r_yara_compiler::MetaValue::Boolean(b) => Value::Bool(*b),
            };
            meta.insert(key.clone(), val);
        }

        RuleMatch {
            name: rule.name.clone(),
            tags: rule.tags.clone(),
            strings,
            meta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_yara_compiler::Compiler;
    use r_yara_matcher::PatternMatcher;
    use r_yara_parser::parse;

    fn compile_and_run(source: &str, data: &[u8]) -> Vec<RuleMatch> {
        let ast = parse(source).expect("Parse failed");
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&ast).expect("Compile failed");

        let matcher = PatternMatcher::new(compiled.patterns.clone()).expect("Matcher failed");
        let pattern_matches = matcher.scan(data);

        let ctx = ScanContext::new(data).with_matches(pattern_matches);
        let vm = VM::new(&compiled, &matcher);
        vm.scan(&ctx).expect("VM failed")
    }

    #[test]
    fn test_simple_true() {
        let source = r#"
            rule test {
                condition:
                    true
            }
        "#;

        let matches = compile_and_run(source, b"any data");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name.as_str(), "test");
    }

    #[test]
    fn test_simple_false() {
        let source = r#"
            rule test {
                condition:
                    false
            }
        "#;

        let matches = compile_and_run(source, b"any data");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_string_match() {
        let source = r#"
            rule test {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let matches = compile_and_run(source, b"this is a test string");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_string_no_match() {
        let source = r#"
            rule test {
                strings:
                    $a = "missing"
                condition:
                    $a
            }
        "#;

        let matches = compile_and_run(source, b"this is a test string");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_filesize() {
        let source = r#"
            rule test {
                condition:
                    filesize > 10
            }
        "#;

        let matches = compile_and_run(source, b"this is a longer test string");
        assert_eq!(matches.len(), 1);

        let matches_small = compile_and_run(source, b"tiny");
        assert!(matches_small.is_empty());
    }

    #[test]
    fn test_arithmetic() {
        let source = r#"
            rule test {
                condition:
                    2 + 3 > 4
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_logical_and() {
        let source = r#"
            rule test {
                condition:
                    true and true
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);

        let source_false = r#"
            rule test {
                condition:
                    true and false
            }
        "#;

        let matches_false = compile_and_run(source_false, b"data");
        assert!(matches_false.is_empty());
    }

    #[test]
    fn test_logical_or() {
        let source = r#"
            rule test {
                condition:
                    false or true
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_any_of_them() {
        let source = r#"
            rule test {
                strings:
                    $a = "test"
                    $b = "missing"
                condition:
                    any of them
            }
        "#;

        let matches = compile_and_run(source, b"this is a test string");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_all_of_them() {
        let source = r#"
            rule test {
                strings:
                    $a = "test"
                    $b = "string"
                condition:
                    all of them
            }
        "#;

        let matches = compile_and_run(source, b"this is a test string");
        assert_eq!(matches.len(), 1);

        let matches_fail = compile_and_run(source, b"this is a test");
        assert!(matches_fail.is_empty());
    }

    #[test]
    fn test_private_rule() {
        let source = r#"
            private rule helper {
                condition:
                    true
            }
            rule test {
                condition:
                    true
            }
        "#;

        let matches = compile_and_run(source, b"data");
        // Only non-private rule should be returned
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name.as_str(), "test");
    }

    #[test]
    fn test_uint_functions() {
        let source = r#"
            rule test {
                condition:
                    uint16(0) == 0x5A4D
            }
        "#;

        // MZ header in little-endian
        let data = [0x4D, 0x5A, 0x90, 0x00];
        let matches = compile_and_run(source, &data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_string_contains() {
        let source = r#"
            rule test {
                condition:
                    "testing" contains "est"
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);

        let source_false = r#"
            rule test {
                condition:
                    "testing" contains "xyz"
            }
        "#;

        let matches_false = compile_and_run(source_false, b"data");
        assert!(matches_false.is_empty());
    }

    #[test]
    fn test_string_icontains() {
        let source = r#"
            rule test {
                condition:
                    "TESTING" icontains "est"
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);

        let source2 = r#"
            rule test {
                condition:
                    "testing" icontains "EST"
            }
        "#;

        let matches2 = compile_and_run(source2, b"data");
        assert_eq!(matches2.len(), 1);
    }

    #[test]
    fn test_string_startswith() {
        let source = r#"
            rule test {
                condition:
                    "testing" startswith "test"
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);

        let source_false = r#"
            rule test {
                condition:
                    "testing" startswith "ing"
            }
        "#;

        let matches_false = compile_and_run(source_false, b"data");
        assert!(matches_false.is_empty());
    }

    #[test]
    fn test_string_istartswith() {
        let source = r#"
            rule test {
                condition:
                    "TESTING" istartswith "test"
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);

        let source2 = r#"
            rule test {
                condition:
                    "testing" istartswith "TEST"
            }
        "#;

        let matches2 = compile_and_run(source2, b"data");
        assert_eq!(matches2.len(), 1);
    }

    #[test]
    fn test_string_endswith() {
        let source = r#"
            rule test {
                condition:
                    "testing" endswith "ing"
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);

        let source_false = r#"
            rule test {
                condition:
                    "testing" endswith "test"
            }
        "#;

        let matches_false = compile_and_run(source_false, b"data");
        assert!(matches_false.is_empty());
    }

    #[test]
    fn test_string_iendswith() {
        let source = r#"
            rule test {
                condition:
                    "TESTING" iendswith "ing"
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);

        let source2 = r#"
            rule test {
                condition:
                    "testing" iendswith "ING"
            }
        "#;

        let matches2 = compile_and_run(source2, b"data");
        assert_eq!(matches2.len(), 1);
    }

    #[test]
    fn test_hash_md5() {
        let source = r#"
            import "hash"

            rule test {
                condition:
                    hash.md5(0, 4) == "098f6bcd4621d373cade4e832627b4f6"
            }
        "#;

        let matches = compile_and_run(source, b"test");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hash_sha256() {
        let source = r#"
            import "hash"

            rule test {
                condition:
                    hash.sha256(0, filesize) == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            }
        "#;

        let matches = compile_and_run(source, b"test");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_math_entropy() {
        let source = r#"
            import "math"

            rule test {
                condition:
                    math.entropy(0, filesize) > 0
            }
        "#;

        let matches = compile_and_run(source, b"test data with some entropy");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_math_mean() {
        let source = r#"
            import "math"

            rule test {
                condition:
                    math.mean(0, 3) == 1
            }
        "#;

        // Data: [0, 1, 2] has mean of 1
        let data = [0u8, 1, 2];
        let matches = compile_and_run(source, &data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pe_is_pe() {
        let source = r#"
            import "pe"

            rule test {
                condition:
                    not pe.is_pe()
            }
        "#;

        // Non-PE data should return false
        let matches = compile_and_run(source, b"this is not a PE file");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_elf_is_elf() {
        let source = r#"
            import "elf"

            rule test {
                condition:
                    elf.is_elf()
            }
        "#;

        // ELF magic number
        let data = b"\x7fELF";
        let matches = compile_and_run(source, data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_math_min_max() {
        let source = r#"
            import "math"

            rule test {
                condition:
                    math.min(10, 20) == 10 and
                    math.max(10, 20) == 20
            }
        "#;

        let matches = compile_and_run(source, b"data");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_combined_modules() {
        let source = r#"
            import "hash"
            import "math"

            rule test {
                strings:
                    $a = "test"
                condition:
                    $a and
                    math.entropy(0, filesize) > 0 and
                    hash.md5(0, 4) == "098f6bcd4621d373cade4e832627b4f6"
            }
        "#;

        let matches = compile_and_run(source, b"test");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pe_imphash() {
        let source = r#"
            import "pe"

            rule test {
                condition:
                    pe.imphash() == ""
            }
        "#;

        // Non-PE data should return empty string
        let matches = compile_and_run(source, b"this is not a PE file");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pe_imphash_nonexistent() {
        let source = r#"
            import "pe"

            rule test {
                condition:
                    not pe.is_pe() and pe.imphash() == ""
            }
        "#;

        // Non-PE file should return empty imphash
        let matches = compile_and_run(source, b"not a PE");
        assert_eq!(matches.len(), 1);
    }
}
