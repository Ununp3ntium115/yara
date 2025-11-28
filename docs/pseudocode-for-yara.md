# Complete YARA Pseudocode Reference

**Version:** 1.0
**Purpose:** Comprehensive pseudocode documentation for the entire YARA malware detection system.
**Covers:** Lexer, Parser, AST, Compiler, VM, Scanner, Pattern Matching, and all Modules.

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Lexer (Tokenizer)](#2-lexer-tokenizer)
3. [Parser and AST](#3-parser-and-ast)
4. [Pattern Matching Engine](#4-pattern-matching-engine)
5. [Bytecode Compiler](#5-bytecode-compiler)
6. [Virtual Machine](#6-virtual-machine)
7. [Scanner Engine](#7-scanner-engine)
8. [Module System](#8-module-system)
9. [PE Module](#9-pe-module)
10. [ELF Module](#10-elf-module)
11. [Mach-O Module](#11-mach-o-module)
12. [DEX Module](#12-dex-module)
13. [Hash Module](#13-hash-module)
14. [Math Module](#14-math-module)
15. [String/Console/Time Modules](#15-stringconsoletime-modules)

---

## 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         YARA SYSTEM ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐                                                            │
│  │ YARA Rules  │  rule malware_example {                                    │
│  │   (.yar)    │      strings: $a = "malicious"                             │
│  └──────┬──────┘      condition: $a                                         │
│         │          }                                                         │
│         ▼                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        COMPILATION PHASE                             │   │
│  │  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────────────┐  │   │
│  │  │  LEXER  │───▶│ PARSER  │───▶│   AST   │───▶│    COMPILER     │  │   │
│  │  │(Tokens) │    │(Grammar)│    │ (Tree)  │    │   (Bytecode)    │  │   │
│  │  └─────────┘    └─────────┘    └─────────┘    └────────┬────────┘  │   │
│  └─────────────────────────────────────────────────────────┼───────────┘   │
│                                                             │               │
│                                                             ▼               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      COMPILED RULES (YR_RULES)                       │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────────────────┐  │   │
│  │  │ Pattern Table │  │ Bytecode Ops  │  │    Rule Metadata        │  │   │
│  │  │ (AC Automaton)│  │ (Conditions)  │  │ (Names, Tags, Meta)     │  │   │
│  │  └───────────────┘  └───────────────┘  └─────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         SCANNING PHASE                               │   │
│  │                                                                       │   │
│  │  ┌───────────┐    ┌─────────────────────────────────────────────┐   │   │
│  │  │  TARGET   │───▶│              SCANNER ENGINE                  │   │   │
│  │  │(File/Mem) │    │  ┌─────────────────┐  ┌──────────────────┐  │   │   │
│  │  └───────────┘    │  │  Aho-Corasick   │  │  Virtual Machine │  │   │   │
│  │                   │  │  Pattern Match  │─▶│  (Eval Conditions)│  │   │   │
│  │                   │  └─────────────────┘  └──────────────────┘  │   │   │
│  │                   └──────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         MODULE SYSTEM                                │   │
│  │  ┌────┐ ┌────┐ ┌───────┐ ┌─────┐ ┌────┐ ┌────┐ ┌────┐ ┌──────┐    │   │
│  │  │ PE │ │ELF │ │ Macho │ │ DEX │ │Hash│ │Math│ │Time│ │String│    │   │
│  │  └────┘ └────┘ └───────┘ └─────┘ └────┘ └────┘ └────┘ └──────┘    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│                              ┌──────────────┐                               │
│                              │   MATCHES    │                               │
│                              │  (Results)   │                               │
│                              └──────────────┘                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Lexer (Tokenizer)

### 2.1 Token Types

```pseudocode
ENUM TokenType:
    // Keywords
    RULE, META, STRINGS, CONDITION
    IMPORT, INCLUDE, PRIVATE, GLOBAL
    TRUE, FALSE, AND, OR, NOT
    ALL, ANY, NONE, OF, THEM
    FOR, IN, AT, FILESIZE, ENTRYPOINT

    // Literals
    STRING_LITERAL      // "text" or 'text'
    HEX_STRING         // { AB CD ?? EF }
    REGEX              // /pattern/modifiers
    INTEGER            // 123, 0x7B, 0o173
    FLOAT              // 3.14

    // Identifiers
    IDENTIFIER         // rule_name, $string_id
    STRING_ID          // $a, $str1
    STRING_COUNT       // #a, #str1
    STRING_OFFSET      // @a, @str1
    STRING_LENGTH      // !a, !str1

    // Operators
    EQ, NE, LT, LE, GT, GE           // ==, !=, <, <=, >, >=
    PLUS, MINUS, MUL, DIV, MOD       // +, -, *, /, %
    BITWISE_AND, BITWISE_OR, XOR     // &, |, ^
    SHIFT_LEFT, SHIFT_RIGHT          // <<, >>
    CONTAINS, ICONTAINS              // contains, icontains
    STARTSWITH, ISTARTSWITH          // startswith, istartswith
    ENDSWITH, IENDSWITH              // endswith, iendswith
    MATCHES                          // matches

    // Punctuation
    LPAREN, RPAREN                   // ( )
    LBRACE, RBRACE                   // { }
    LBRACKET, RBRACKET               // [ ]
    COLON, COMMA, DOT, DOTDOT        // : , . ..
    ASSIGN                           // =

    // Special
    NEWLINE, COMMENT, WHITESPACE
    EOF, ERROR
```

### 2.2 Lexer Implementation

```pseudocode
STRUCT Lexer:
    source: String
    position: usize
    line: usize
    column: usize

FUNCTION Lexer::new(source: String) -> Lexer:
    RETURN Lexer {
        source: source,
        position: 0,
        line: 1,
        column: 1
    }

FUNCTION Lexer::next_token() -> Token:
    self.skip_whitespace_and_comments()

    IF self.is_at_end():
        RETURN Token(EOF, "", self.line, self.column)

    char = self.peek()

    // Keywords and Identifiers
    IF is_alpha(char) OR char == '_':
        RETURN self.scan_identifier_or_keyword()

    // String identifiers ($a, #a, @a, !a)
    IF char IN ['$', '#', '@', '!']:
        RETURN self.scan_string_identifier()

    // Numbers
    IF is_digit(char):
        RETURN self.scan_number()

    // String literals
    IF char == '"' OR char == '\'':
        RETURN self.scan_string_literal()

    // Hex strings
    IF char == '{':
        RETURN self.scan_hex_string()

    // Regex
    IF char == '/':
        RETURN self.scan_regex()

    // Operators and punctuation
    RETURN self.scan_operator_or_punctuation()

FUNCTION Lexer::scan_identifier_or_keyword() -> Token:
    start = self.position

    WHILE NOT self.is_at_end() AND (is_alphanumeric(self.peek()) OR self.peek() == '_'):
        self.advance()

    text = self.source[start..self.position]

    // Check if it's a keyword
    token_type = MATCH text:
        "rule"      => RULE
        "meta"      => META
        "strings"   => STRINGS
        "condition" => CONDITION
        "import"    => IMPORT
        "include"   => INCLUDE
        "private"   => PRIVATE
        "global"    => GLOBAL
        "true"      => TRUE
        "false"     => FALSE
        "and"       => AND
        "or"        => OR
        "not"       => NOT
        "all"       => ALL
        "any"       => ANY
        "none"      => NONE
        "of"        => OF
        "them"      => THEM
        "for"       => FOR
        "in"        => IN
        "at"        => AT
        "filesize"  => FILESIZE
        "entrypoint"=> ENTRYPOINT
        "contains"  => CONTAINS
        "icontains" => ICONTAINS
        "startswith"=> STARTSWITH
        "endswith"  => ENDSWITH
        "matches"   => MATCHES
        _           => IDENTIFIER

    RETURN Token(token_type, text, self.line, self.column)

FUNCTION Lexer::scan_hex_string() -> Token:
    // Hex string: { AB CD ?? [2-4] ( EE | FF ) }
    self.advance()  // consume '{'
    start = self.position

    WHILE NOT self.is_at_end() AND self.peek() != '}':
        self.advance()

    IF self.is_at_end():
        RETURN Token(ERROR, "Unterminated hex string", self.line, self.column)

    content = self.source[start..self.position]
    self.advance()  // consume '}'

    RETURN Token(HEX_STRING, content, self.line, self.column)

FUNCTION Lexer::scan_regex() -> Token:
    // Regex: /pattern/modifiers
    self.advance()  // consume '/'
    start = self.position

    WHILE NOT self.is_at_end() AND self.peek() != '/':
        IF self.peek() == '\\':
            self.advance()  // escape next char
        self.advance()

    IF self.is_at_end():
        RETURN Token(ERROR, "Unterminated regex", self.line, self.column)

    pattern = self.source[start..self.position]
    self.advance()  // consume closing '/'

    // Scan modifiers (i, s, etc.)
    modifiers = ""
    WHILE NOT self.is_at_end() AND is_alpha(self.peek()):
        modifiers += self.advance()

    RETURN Token(REGEX, pattern + "/" + modifiers, self.line, self.column)
```

---

## 3. Parser and AST

### 3.1 AST Node Types

```pseudocode
// Top-level AST
STRUCT RuleSet:
    imports: Vec<Import>
    rules: Vec<Rule>

STRUCT Import:
    module_name: String

STRUCT Rule:
    name: String
    tags: Vec<String>
    is_private: bool
    is_global: bool
    meta: Vec<MetaEntry>
    strings: Vec<StringDecl>
    condition: Expression

STRUCT MetaEntry:
    key: String
    value: MetaValue

ENUM MetaValue:
    String(String)
    Integer(i64)
    Boolean(bool)

// String declarations
ENUM StringDecl:
    Text(TextString)
    Hex(HexString)
    Regex(RegexString)

STRUCT TextString:
    id: String              // $a
    value: String           // "malicious"
    modifiers: StringModifiers

STRUCT StringModifiers:
    nocase: bool
    wide: bool
    ascii: bool
    fullword: bool
    xor: Option<XorRange>
    base64: Option<Base64Alphabet>
    private: bool

STRUCT HexString:
    id: String
    tokens: Vec<HexToken>

ENUM HexToken:
    Byte(u8)                // AB
    Wildcard                // ??
    NibbleWildcard(u8)      // A? or ?B
    Jump(usize, usize)      // [2-4]
    Alternative(Vec<Vec<HexToken>>)  // (AB | CD | EF)

STRUCT RegexString:
    id: String
    pattern: String
    modifiers: RegexModifiers

// Expressions (for condition)
ENUM Expression:
    // Literals
    True
    False
    Integer(i64)
    Float(f64)
    String(String)

    // String references
    StringMatch(String)         // $a
    StringMatchAt(String, Box<Expression>)  // $a at 100
    StringMatchIn(String, Box<Expression>, Box<Expression>)  // $a in (0..100)
    StringCount(String)         // #a
    StringOffset(String, Option<Box<Expression>>)  // @a, @a[1]
    StringLength(String, Option<Box<Expression>>)  // !a, !a[1]

    // Special values
    Filesize
    Entrypoint

    // Binary operations
    And(Box<Expression>, Box<Expression>)
    Or(Box<Expression>, Box<Expression>)
    Eq(Box<Expression>, Box<Expression>)
    Ne(Box<Expression>, Box<Expression>)
    Lt(Box<Expression>, Box<Expression>)
    Le(Box<Expression>, Box<Expression>)
    Gt(Box<Expression>, Box<Expression>)
    Ge(Box<Expression>, Box<Expression>)
    Add(Box<Expression>, Box<Expression>)
    Sub(Box<Expression>, Box<Expression>)
    Mul(Box<Expression>, Box<Expression>)
    Div(Box<Expression>, Box<Expression>)
    Mod(Box<Expression>, Box<Expression>)
    BitwiseAnd(Box<Expression>, Box<Expression>)
    BitwiseOr(Box<Expression>, Box<Expression>)
    BitwiseXor(Box<Expression>, Box<Expression>)
    ShiftLeft(Box<Expression>, Box<Expression>)
    ShiftRight(Box<Expression>, Box<Expression>)
    Contains(Box<Expression>, Box<Expression>)
    Matches(Box<Expression>, Box<Expression>)

    // Unary operations
    Not(Box<Expression>)
    Neg(Box<Expression>)
    BitwiseNot(Box<Expression>)

    // Quantifiers
    OfThem(Quantifier)                      // all of them, any of them
    OfStrings(Quantifier, Vec<String>)      // 2 of ($a, $b, $c)
    OfRules(Quantifier, Vec<String>)        // any of (rule1, rule2)

    // For loops
    ForOf(String, Quantifier, Vec<String>, Box<Expression>)
    ForIn(String, Box<Expression>, Box<Expression>, Box<Expression>)

    // Function calls (module functions)
    FunctionCall(String, Vec<Expression>)   // pe.is_dll()

    // Member access
    MemberAccess(Box<Expression>, String)   // pe.number_of_sections
    ArrayAccess(Box<Expression>, Box<Expression>)  // pe.sections[0]

ENUM Quantifier:
    All
    Any
    None
    Exactly(usize)
    AtLeast(usize)
    Percentage(usize)
```

### 3.2 Parser Implementation

```pseudocode
STRUCT Parser:
    lexer: Lexer
    current: Token
    previous: Token

FUNCTION Parser::new(source: String) -> Parser:
    lexer = Lexer::new(source)
    first_token = lexer.next_token()
    RETURN Parser {
        lexer: lexer,
        current: first_token,
        previous: Token::default()
    }

FUNCTION Parser::parse() -> Result<RuleSet>:
    imports = []
    rules = []

    WHILE NOT self.is_at_end():
        IF self.check(IMPORT):
            imports.push(self.parse_import())
        ELSE IF self.check(INCLUDE):
            self.parse_include()  // Process includes
        ELSE:
            rules.push(self.parse_rule())

    RETURN Ok(RuleSet { imports, rules })

FUNCTION Parser::parse_rule() -> Result<Rule>:
    is_private = self.match_token(PRIVATE)
    is_global = self.match_token(GLOBAL)

    self.expect(RULE)?
    name = self.expect(IDENTIFIER)?.text

    // Parse optional tags
    tags = []
    IF self.match_token(COLON):
        WHILE self.check(IDENTIFIER):
            tags.push(self.advance().text)

    self.expect(LBRACE)?

    // Parse sections
    meta = []
    strings = []
    condition = Expression::True

    IF self.match_token(META):
        self.expect(COLON)?
        meta = self.parse_meta_section()

    IF self.match_token(STRINGS):
        self.expect(COLON)?
        strings = self.parse_strings_section()

    self.expect(CONDITION)?
    self.expect(COLON)?
    condition = self.parse_expression()

    self.expect(RBRACE)?

    RETURN Ok(Rule {
        name, tags, is_private, is_global,
        meta, strings, condition
    })

FUNCTION Parser::parse_expression() -> Result<Expression>:
    RETURN self.parse_or_expression()

FUNCTION Parser::parse_or_expression() -> Result<Expression>:
    left = self.parse_and_expression()?

    WHILE self.match_token(OR):
        right = self.parse_and_expression()?
        left = Expression::Or(Box::new(left), Box::new(right))

    RETURN Ok(left)

FUNCTION Parser::parse_and_expression() -> Result<Expression>:
    left = self.parse_comparison()?

    WHILE self.match_token(AND):
        right = self.parse_comparison()?
        left = Expression::And(Box::new(left), Box::new(right))

    RETURN Ok(left)

FUNCTION Parser::parse_comparison() -> Result<Expression>:
    left = self.parse_additive()?

    IF self.match_token(EQ):
        right = self.parse_additive()?
        RETURN Ok(Expression::Eq(Box::new(left), Box::new(right)))
    ELSE IF self.match_token(NE):
        right = self.parse_additive()?
        RETURN Ok(Expression::Ne(Box::new(left), Box::new(right)))
    ELSE IF self.match_token(LT):
        right = self.parse_additive()?
        RETURN Ok(Expression::Lt(Box::new(left), Box::new(right)))
    ELSE IF self.match_token(LE):
        right = self.parse_additive()?
        RETURN Ok(Expression::Le(Box::new(left), Box::new(right)))
    ELSE IF self.match_token(GT):
        right = self.parse_additive()?
        RETURN Ok(Expression::Gt(Box::new(left), Box::new(right)))
    ELSE IF self.match_token(GE):
        right = self.parse_additive()?
        RETURN Ok(Expression::Ge(Box::new(left), Box::new(right)))
    ELSE IF self.match_token(CONTAINS):
        right = self.parse_additive()?
        RETURN Ok(Expression::Contains(Box::new(left), Box::new(right)))

    RETURN Ok(left)

FUNCTION Parser::parse_primary() -> Result<Expression>:
    IF self.match_token(TRUE):
        RETURN Ok(Expression::True)

    IF self.match_token(FALSE):
        RETURN Ok(Expression::False)

    IF self.match_token(INTEGER):
        value = parse_integer(self.previous.text)
        RETURN Ok(Expression::Integer(value))

    IF self.match_token(STRING_ID):
        id = self.previous.text
        IF self.match_token(AT):
            offset = self.parse_expression()?
            RETURN Ok(Expression::StringMatchAt(id, Box::new(offset)))
        IF self.match_token(IN):
            self.expect(LPAREN)?
            start = self.parse_expression()?
            self.expect(DOTDOT)?
            end = self.parse_expression()?
            self.expect(RPAREN)?
            RETURN Ok(Expression::StringMatchIn(id, Box::new(start), Box::new(end)))
        RETURN Ok(Expression::StringMatch(id))

    IF self.match_token(STRING_COUNT):
        RETURN Ok(Expression::StringCount(self.previous.text))

    IF self.match_token(STRING_OFFSET):
        id = self.previous.text
        IF self.match_token(LBRACKET):
            index = self.parse_expression()?
            self.expect(RBRACKET)?
            RETURN Ok(Expression::StringOffset(id, Some(Box::new(index))))
        RETURN Ok(Expression::StringOffset(id, None))

    IF self.match_token(FILESIZE):
        RETURN Ok(Expression::Filesize)

    IF self.match_token(ENTRYPOINT):
        RETURN Ok(Expression::Entrypoint)

    IF self.match_token(ALL):
        RETURN self.parse_of_expression(Quantifier::All)

    IF self.match_token(ANY):
        RETURN self.parse_of_expression(Quantifier::Any)

    IF self.match_token(NONE):
        RETURN self.parse_of_expression(Quantifier::None)

    IF self.match_token(LPAREN):
        expr = self.parse_expression()?
        self.expect(RPAREN)?
        RETURN Ok(expr)

    IF self.check(IDENTIFIER):
        RETURN self.parse_identifier_expression()

    RETURN Err("Expected expression")
```

---

## 4. Pattern Matching Engine

### 4.1 Aho-Corasick Automaton

```pseudocode
// Aho-Corasick algorithm for multi-pattern matching
// Used to find all string patterns in a single pass through the data

STRUCT AhoCorasickState:
    id: StateId
    transitions: HashMap<u8, StateId>    // Byte -> Next state
    failure: StateId                      // Failure link
    output: Vec<PatternId>               // Patterns that match at this state
    depth: usize                          // Distance from root

STRUCT AhoCorasickAutomaton:
    states: Vec<AhoCorasickState>
    patterns: Vec<Pattern>

FUNCTION AhoCorasickAutomaton::build(patterns: Vec<Pattern>) -> AhoCorasickAutomaton:
    automaton = AhoCorasickAutomaton {
        states: [AhoCorasickState::root()],
        patterns: patterns
    }

    // Phase 1: Build trie (goto function)
    FOR pattern_id, pattern IN enumerate(patterns):
        automaton.add_pattern(pattern_id, pattern)

    // Phase 2: Build failure links using BFS
    automaton.build_failure_links()

    RETURN automaton

FUNCTION AhoCorasickAutomaton::add_pattern(pattern_id: PatternId, pattern: &[u8]):
    state = ROOT_STATE

    FOR byte IN pattern:
        IF state.transitions.contains(byte):
            state = state.transitions[byte]
        ELSE:
            new_state = self.create_state(state.depth + 1)
            state.transitions[byte] = new_state
            state = new_state

    // Mark this state as accepting for this pattern
    self.states[state].output.push(pattern_id)

FUNCTION AhoCorasickAutomaton::build_failure_links():
    // BFS to compute failure links
    queue = Queue::new()

    // States at depth 1 have failure link to root
    FOR next_state IN self.states[ROOT_STATE].transitions.values():
        self.states[next_state].failure = ROOT_STATE
        queue.push(next_state)

    WHILE NOT queue.is_empty():
        current = queue.pop()

        FOR byte, next_state IN self.states[current].transitions:
            queue.push(next_state)

            // Follow failure links to find longest proper suffix
            failure = self.states[current].failure
            WHILE failure != ROOT_STATE AND NOT self.states[failure].transitions.contains(byte):
                failure = self.states[failure].failure

            IF self.states[failure].transitions.contains(byte):
                self.states[next_state].failure = self.states[failure].transitions[byte]
            ELSE:
                self.states[next_state].failure = ROOT_STATE

            // Merge output from failure state
            failure_output = self.states[self.states[next_state].failure].output.clone()
            self.states[next_state].output.extend(failure_output)

FUNCTION AhoCorasickAutomaton::search(data: &[u8]) -> Vec<Match>:
    matches = []
    state = ROOT_STATE

    FOR position, byte IN enumerate(data):
        // Follow failure links until we find a transition or reach root
        WHILE state != ROOT_STATE AND NOT self.states[state].transitions.contains(byte):
            state = self.states[state].failure

        // Take transition if exists
        IF self.states[state].transitions.contains(byte):
            state = self.states[state].transitions[byte]

        // Report all patterns that match at this position
        FOR pattern_id IN self.states[state].output:
            pattern_length = self.patterns[pattern_id].len()
            match_start = position - pattern_length + 1
            matches.push(Match {
                pattern_id: pattern_id,
                offset: match_start,
                length: pattern_length
            })

    RETURN matches
```

### 4.2 Atom Extraction

```pseudocode
// Atoms are fixed literal subsequences extracted from patterns
// Used to pre-filter potential matches before full verification

STRUCT Atom:
    bytes: Vec<u8>
    pattern_id: PatternId
    offset_in_pattern: usize

FUNCTION extract_atoms(pattern: &Pattern) -> Vec<Atom>:
    MATCH pattern:
        Pattern::Text(text, modifiers) =>
            atoms = []

            IF modifiers.nocase:
                // Generate case-insensitive atoms
                atoms.push(Atom {
                    bytes: text.to_lowercase().bytes(),
                    pattern_id: pattern.id,
                    offset_in_pattern: 0
                })
            ELSE IF modifiers.wide:
                // Generate wide (UTF-16LE) atoms
                wide_bytes = to_utf16le(text)
                atoms.push(Atom {
                    bytes: wide_bytes,
                    pattern_id: pattern.id,
                    offset_in_pattern: 0
                })
            ELSE:
                atoms.push(Atom {
                    bytes: text.bytes(),
                    pattern_id: pattern.id,
                    offset_in_pattern: 0
                })

            RETURN atoms

        Pattern::Hex(tokens) =>
            // Find longest literal runs in hex pattern
            RETURN extract_hex_atoms(tokens)

        Pattern::Regex(regex) =>
            // Extract literal prefixes/infixes from regex
            RETURN extract_regex_atoms(regex)

FUNCTION extract_hex_atoms(tokens: &[HexToken]) -> Vec<Atom>:
    atoms = []
    current_run = []
    current_offset = 0

    FOR token IN tokens:
        MATCH token:
            HexToken::Byte(b) =>
                current_run.push(b)

            HexToken::Wildcard | HexToken::NibbleWildcard(_) =>
                // End current literal run, save as atom if long enough
                IF current_run.len() >= MIN_ATOM_LENGTH:
                    atoms.push(Atom {
                        bytes: current_run.clone(),
                        offset_in_pattern: current_offset,
                        ...
                    })
                current_run.clear()
                current_offset = position + 1

            HexToken::Jump(min, max) =>
                // Variable-length jump, end run
                IF current_run.len() >= MIN_ATOM_LENGTH:
                    atoms.push(...)
                current_run.clear()
                current_offset = position + max

            HexToken::Alternative(alts) =>
                // Pick best alternative for atoms
                // End current run first
                IF current_run.len() >= MIN_ATOM_LENGTH:
                    atoms.push(...)
                current_run.clear()

    // Don't forget last run
    IF current_run.len() >= MIN_ATOM_LENGTH:
        atoms.push(...)

    RETURN atoms
```

---

## 5. Bytecode Compiler

### 5.1 Bytecode Instruction Set

```pseudocode
ENUM Opcode:
    // Stack operations
    PUSH_INT(i64)           // Push integer onto stack
    PUSH_FLOAT(f64)         // Push float onto stack
    PUSH_STRING(StringId)   // Push string reference
    PUSH_TRUE               // Push boolean true
    PUSH_FALSE              // Push boolean false
    PUSH_UNDEFINED          // Push undefined value
    POP                     // Discard top of stack
    DUP                     // Duplicate top of stack
    SWAP                    // Swap top two stack values

    // Arithmetic
    ADD                     // a + b
    SUB                     // a - b
    MUL                     // a * b
    DIV                     // a / b
    MOD                     // a % b
    NEG                     // -a

    // Bitwise
    BITWISE_AND             // a & b
    BITWISE_OR              // a | b
    BITWISE_XOR             // a ^ b
    BITWISE_NOT             // ~a
    SHIFT_LEFT              // a << b
    SHIFT_RIGHT             // a >> b

    // Comparison
    EQ                      // a == b
    NE                      // a != b
    LT                      // a < b
    LE                      // a <= b
    GT                      // a > b
    GE                      // a >= b

    // Logical
    AND                     // a && b (short-circuit)
    OR                      // a || b (short-circuit)
    NOT                     // !a

    // String operations
    CONTAINS                // string contains substring
    ICONTAINS               // case-insensitive contains
    STARTSWITH              // string starts with prefix
    ENDSWITH                // string ends with suffix
    MATCHES                 // regex match

    // String pattern operations
    STRING_MATCH(StringId)        // Check if $a matched
    STRING_MATCH_AT(StringId)     // $a at offset
    STRING_MATCH_IN(StringId)     // $a in (start..end)
    STRING_COUNT(StringId)        // #a (count of matches)
    STRING_OFFSET(StringId, idx)  // @a[idx] (offset of match)
    STRING_LENGTH(StringId, idx)  // !a[idx] (length of match)

    // Special values
    FILESIZE                // Push file size
    ENTRYPOINT              // Push entry point

    // Quantifiers
    OF_THEM(Quantifier)     // X of them
    OF(Quantifier, count)   // X of ($a, $b, ...)

    // Control flow
    JUMP(offset)            // Unconditional jump
    JUMP_IF_FALSE(offset)   // Jump if top is false
    JUMP_IF_TRUE(offset)    // Jump if top is true

    // Function calls
    CALL_FUNC(ModuleId, FuncId, argc)  // Call module function

    // Memory access
    READ_INT8(offset)       // int8(offset)
    READ_INT16(offset)      // int16(offset)
    READ_INT32(offset)      // int32(offset)
    READ_UINT8(offset)      // uint8(offset)
    READ_UINT16(offset)     // uint16(offset)
    READ_UINT32(offset)     // uint32(offset)
    READ_INT8_BE(offset)    // int8be(offset)
    READ_INT16_BE(offset)   // int16be(offset)
    READ_INT32_BE(offset)   // int32be(offset)

    // Module member access
    MEMBER_ACCESS(MemberId) // module.member
    ARRAY_ACCESS            // module.array[idx]

    // Iteration
    FOR_INIT                // Initialize for loop
    FOR_NEXT                // Next iteration
    FOR_END                 // End for loop

    // Result
    HALT                    // End execution, top of stack is result
```

### 5.2 Compiler Implementation

```pseudocode
STRUCT Compiler:
    bytecode: Vec<u8>
    strings: StringTable
    rules: Vec<CompiledRule>
    current_rule: RuleId

STRUCT CompiledRule:
    name: String
    condition_offset: usize
    string_ids: Vec<StringId>

FUNCTION Compiler::compile(ruleset: &RuleSet) -> CompiledRules:
    compiler = Compiler::new()

    // First pass: Register all strings and build pattern table
    FOR rule IN ruleset.rules:
        compiler.register_strings(rule)

    // Build Aho-Corasick automaton from all patterns
    automaton = compiler.build_pattern_matcher()

    // Second pass: Compile conditions to bytecode
    FOR rule IN ruleset.rules:
        compiler.compile_rule(rule)

    RETURN CompiledRules {
        bytecode: compiler.bytecode,
        strings: compiler.strings,
        rules: compiler.rules,
        automaton: automaton
    }

FUNCTION Compiler::compile_rule(rule: &Rule):
    compiled = CompiledRule {
        name: rule.name.clone(),
        condition_offset: self.bytecode.len(),
        string_ids: self.get_rule_string_ids(rule)
    }

    self.compile_expression(&rule.condition)
    self.emit(HALT)

    self.rules.push(compiled)

FUNCTION Compiler::compile_expression(expr: &Expression):
    MATCH expr:
        Expression::True =>
            self.emit(PUSH_TRUE)

        Expression::False =>
            self.emit(PUSH_FALSE)

        Expression::Integer(n) =>
            self.emit(PUSH_INT(*n))

        Expression::And(left, right) =>
            // Short-circuit AND
            self.compile_expression(left)
            jump_addr = self.emit_jump(JUMP_IF_FALSE)
            self.emit(POP)
            self.compile_expression(right)
            self.patch_jump(jump_addr)

        Expression::Or(left, right) =>
            // Short-circuit OR
            self.compile_expression(left)
            jump_addr = self.emit_jump(JUMP_IF_TRUE)
            self.emit(POP)
            self.compile_expression(right)
            self.patch_jump(jump_addr)

        Expression::Not(inner) =>
            self.compile_expression(inner)
            self.emit(NOT)

        Expression::Eq(left, right) =>
            self.compile_expression(left)
            self.compile_expression(right)
            self.emit(EQ)

        Expression::Add(left, right) =>
            self.compile_expression(left)
            self.compile_expression(right)
            self.emit(ADD)

        Expression::StringMatch(id) =>
            string_id = self.get_string_id(id)
            self.emit(STRING_MATCH(string_id))

        Expression::StringCount(id) =>
            string_id = self.get_string_id(id)
            self.emit(STRING_COUNT(string_id))

        Expression::StringMatchAt(id, offset) =>
            self.compile_expression(offset)
            string_id = self.get_string_id(id)
            self.emit(STRING_MATCH_AT(string_id))

        Expression::Filesize =>
            self.emit(FILESIZE)

        Expression::FunctionCall(name, args) =>
            FOR arg IN args:
                self.compile_expression(arg)
            module_id, func_id = self.resolve_function(name)
            self.emit(CALL_FUNC(module_id, func_id, args.len()))

        Expression::OfThem(quantifier) =>
            self.emit(OF_THEM(quantifier))

        // ... more expression types
```

---

## 6. Virtual Machine

### 6.1 VM State

```pseudocode
STRUCT VirtualMachine:
    stack: Vec<Value>
    ip: usize                      // Instruction pointer
    bytecode: &[u8]
    scan_context: &ScanContext
    modules: &ModuleRegistry

ENUM Value:
    Undefined
    Boolean(bool)
    Integer(i64)
    Float(f64)
    String(StringRef)

STRUCT ScanContext:
    data: &[u8]                    // Data being scanned
    filesize: usize
    entry_point: Option<usize>
    string_matches: HashMap<StringId, Vec<Match>>
    module_data: HashMap<ModuleId, ModuleData>
```

### 6.2 VM Execution

```pseudocode
FUNCTION VirtualMachine::execute(rule: &CompiledRule, context: &ScanContext) -> bool:
    vm = VirtualMachine {
        stack: [],
        ip: rule.condition_offset,
        bytecode: context.bytecode,
        scan_context: context,
        modules: context.modules
    }

    LOOP:
        opcode = vm.fetch_opcode()

        MATCH opcode:
            PUSH_INT(n) =>
                vm.stack.push(Value::Integer(n))

            PUSH_TRUE =>
                vm.stack.push(Value::Boolean(true))

            PUSH_FALSE =>
                vm.stack.push(Value::Boolean(false))

            POP =>
                vm.stack.pop()

            ADD =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                result = MATCH (a, b):
                    (Integer(x), Integer(y)) => Integer(x + y)
                    (Float(x), Float(y)) => Float(x + y)
                    (Integer(x), Float(y)) => Float(x as f64 + y)
                    (Float(x), Integer(y)) => Float(x + y as f64)
                    _ => Undefined
                vm.stack.push(result)

            SUB =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                vm.stack.push(Integer(a.as_int() - b.as_int()))

            MUL =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                vm.stack.push(Integer(a.as_int() * b.as_int()))

            DIV =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                IF b.as_int() == 0:
                    vm.stack.push(Undefined)
                ELSE:
                    vm.stack.push(Integer(a.as_int() / b.as_int()))

            EQ =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                vm.stack.push(Boolean(a == b))

            LT =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                vm.stack.push(Boolean(a.as_int() < b.as_int()))

            AND =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                vm.stack.push(Boolean(a.as_bool() && b.as_bool()))

            OR =>
                b = vm.stack.pop()
                a = vm.stack.pop()
                vm.stack.push(Boolean(a.as_bool() || b.as_bool()))

            NOT =>
                a = vm.stack.pop()
                vm.stack.push(Boolean(!a.as_bool()))

            STRING_MATCH(string_id) =>
                matches = context.string_matches.get(string_id)
                vm.stack.push(Boolean(matches.is_some() && !matches.is_empty()))

            STRING_COUNT(string_id) =>
                matches = context.string_matches.get(string_id)
                count = IF matches.is_some() THEN matches.len() ELSE 0
                vm.stack.push(Integer(count as i64))

            STRING_OFFSET(string_id, idx) =>
                matches = context.string_matches.get(string_id)
                IF matches.is_some() AND idx < matches.len():
                    vm.stack.push(Integer(matches[idx].offset as i64))
                ELSE:
                    vm.stack.push(Undefined)

            STRING_MATCH_AT(string_id) =>
                offset = vm.stack.pop().as_int() as usize
                matches = context.string_matches.get(string_id)
                found = matches.iter().any(|m| m.offset == offset)
                vm.stack.push(Boolean(found))

            FILESIZE =>
                vm.stack.push(Integer(context.filesize as i64))

            ENTRYPOINT =>
                IF context.entry_point.is_some():
                    vm.stack.push(Integer(context.entry_point.unwrap() as i64))
                ELSE:
                    vm.stack.push(Undefined)

            READ_UINT8 =>
                offset = vm.stack.pop().as_int() as usize
                IF offset < context.data.len():
                    vm.stack.push(Integer(context.data[offset] as i64))
                ELSE:
                    vm.stack.push(Undefined)

            READ_UINT16 =>
                offset = vm.stack.pop().as_int() as usize
                IF offset + 2 <= context.data.len():
                    value = u16::from_le_bytes([context.data[offset], context.data[offset+1]])
                    vm.stack.push(Integer(value as i64))
                ELSE:
                    vm.stack.push(Undefined)

            READ_UINT32 =>
                offset = vm.stack.pop().as_int() as usize
                IF offset + 4 <= context.data.len():
                    value = u32::from_le_bytes(context.data[offset..offset+4])
                    vm.stack.push(Integer(value as i64))
                ELSE:
                    vm.stack.push(Undefined)

            CALL_FUNC(module_id, func_id, argc) =>
                args = []
                FOR _ IN 0..argc:
                    args.insert(0, vm.stack.pop())
                module = vm.modules.get(module_id)
                result = module.call_function(func_id, args, context)
                vm.stack.push(result)

            JUMP(offset) =>
                vm.ip = offset

            JUMP_IF_FALSE(offset) =>
                IF NOT vm.stack.top().as_bool():
                    vm.ip = offset

            JUMP_IF_TRUE(offset) =>
                IF vm.stack.top().as_bool():
                    vm.ip = offset

            OF_THEM(quantifier) =>
                // Count how many strings matched
                count = 0
                FOR string_id IN rule.string_ids:
                    IF context.string_matches.contains(string_id):
                        count += 1
                total = rule.string_ids.len()

                result = MATCH quantifier:
                    Quantifier::All => count == total
                    Quantifier::Any => count > 0
                    Quantifier::None => count == 0
                    Quantifier::Exactly(n) => count == n
                    Quantifier::AtLeast(n) => count >= n
                    Quantifier::Percentage(p) => count * 100 >= total * p

                vm.stack.push(Boolean(result))

            HALT =>
                RETURN vm.stack.pop().as_bool()
```

---

## 7. Scanner Engine

### 7.1 Scanner Implementation

```pseudocode
STRUCT Scanner:
    rules: CompiledRules
    automaton: AhoCorasickAutomaton
    modules: ModuleRegistry
    timeout: Duration
    max_strings_per_rule: usize

STRUCT ScanResult:
    matching_rules: Vec<RuleMatch>
    scan_time: Duration
    bytes_scanned: usize

STRUCT RuleMatch:
    rule_name: String
    tags: Vec<String>
    meta: Vec<(String, MetaValue)>
    strings: Vec<StringMatch>

STRUCT StringMatch:
    identifier: String
    offset: usize
    length: usize
    data: Vec<u8>

FUNCTION Scanner::scan_file(path: &Path) -> Result<ScanResult>:
    data = read_file(path)?
    RETURN self.scan_data(&data)

FUNCTION Scanner::scan_data(data: &[u8]) -> Result<ScanResult>:
    start_time = Instant::now()

    // Step 1: Run Aho-Corasick pattern matching
    raw_matches = self.automaton.search(data)

    // Step 2: Group matches by pattern and verify
    verified_matches = self.verify_matches(raw_matches, data)

    // Step 3: Build scan context
    context = ScanContext {
        data: data,
        filesize: data.len(),
        entry_point: self.detect_entry_point(data),
        string_matches: verified_matches,
        module_data: self.load_module_data(data)
    }

    // Step 4: Evaluate each rule's condition
    matching_rules = []
    FOR rule IN self.rules.rules:
        IF self.evaluate_rule(rule, &context):
            match_info = self.build_rule_match(rule, &context)
            matching_rules.push(match_info)

    RETURN Ok(ScanResult {
        matching_rules: matching_rules,
        scan_time: start_time.elapsed(),
        bytes_scanned: data.len()
    })

FUNCTION Scanner::verify_matches(raw_matches: Vec<Match>, data: &[u8]) -> HashMap<StringId, Vec<Match>>:
    // Verify that raw atom matches are actual full pattern matches
    verified = HashMap::new()

    FOR raw_match IN raw_matches:
        pattern = self.rules.patterns[raw_match.pattern_id]

        // For text strings, atom match = full match (if no modifiers)
        IF pattern.is_simple_text():
            verified.entry(raw_match.pattern_id).or_default().push(raw_match)
            CONTINUE

        // For hex patterns, verify full pattern at this position
        IF pattern.is_hex():
            IF self.verify_hex_pattern(pattern, data, raw_match.offset):
                actual_length = self.measure_hex_match(pattern, data, raw_match.offset)
                verified.entry(raw_match.pattern_id).or_default().push(Match {
                    offset: raw_match.offset,
                    length: actual_length,
                    pattern_id: raw_match.pattern_id
                })

        // For regex patterns, run regex engine at this position
        IF pattern.is_regex():
            IF let Some(match_len) = self.match_regex(pattern, data, raw_match.offset):
                verified.entry(raw_match.pattern_id).or_default().push(Match {
                    offset: raw_match.offset,
                    length: match_len,
                    pattern_id: raw_match.pattern_id
                })

    RETURN verified

FUNCTION Scanner::verify_hex_pattern(pattern: &HexPattern, data: &[u8], offset: usize) -> bool:
    pos = offset

    FOR token IN pattern.tokens:
        IF pos >= data.len():
            RETURN false

        MATCH token:
            HexToken::Byte(expected) =>
                IF data[pos] != expected:
                    RETURN false
                pos += 1

            HexToken::Wildcard =>
                pos += 1

            HexToken::NibbleWildcard(nibble) =>
                actual = data[pos]
                IF nibble.is_high() AND (actual >> 4) != nibble.value():
                    RETURN false
                IF nibble.is_low() AND (actual & 0x0F) != nibble.value():
                    RETURN false
                pos += 1

            HexToken::Jump(min, max) =>
                // Try to match rest of pattern at various offsets
                FOR jump IN min..=max:
                    IF self.verify_remaining(pattern, remaining_tokens, data, pos + jump):
                        RETURN true
                RETURN false

            HexToken::Alternative(alts) =>
                // Try each alternative
                matched = false
                FOR alt IN alts:
                    IF self.verify_alternative(alt, data, pos):
                        pos += alt.len()
                        matched = true
                        BREAK
                IF NOT matched:
                    RETURN false

    RETURN true

FUNCTION Scanner::evaluate_rule(rule: &CompiledRule, context: &ScanContext) -> bool:
    // Check if rule has any string matches (optimization)
    IF rule.requires_strings():
        has_any_match = false
        FOR string_id IN rule.string_ids:
            IF context.string_matches.contains(string_id):
                has_any_match = true
                BREAK
        IF NOT has_any_match:
            RETURN false

    // Execute bytecode condition
    vm = VirtualMachine::new(self.rules.bytecode, context, self.modules)
    RETURN vm.execute(rule)

FUNCTION Scanner::load_module_data(data: &[u8]) -> HashMap<ModuleId, ModuleData>:
    module_data = HashMap::new()

    // Load PE module data if file is PE
    IF pe::is_pe(data):
        module_data.insert(PE_MODULE_ID, pe::parse(data))

    // Load ELF module data if file is ELF
    IF elf::is_elf(data):
        module_data.insert(ELF_MODULE_ID, elf::parse(data))

    // Load Mach-O module data if file is Mach-O
    IF macho::is_macho(data):
        module_data.insert(MACHO_MODULE_ID, macho::parse(data))

    // Load DEX module data if file is DEX
    IF dex::is_dex(data):
        module_data.insert(DEX_MODULE_ID, dex::parse(data))

    RETURN module_data
```

---

## 8. Module System

### 8.1 Module Interface

```pseudocode
TRAIT Module:
    // Get module name (e.g., "pe", "elf", "hash")
    FUNCTION name() -> &str

    // Get declarations (functions, constants, structures)
    FUNCTION declarations() -> Vec<Declaration>

    // Load module data from scanned file
    FUNCTION load(data: &[u8]) -> Result<ModuleData>

    // Call a module function
    FUNCTION call(func_id: FuncId, args: &[Value], context: &ScanContext) -> Value

    // Access a module member
    FUNCTION get_member(member_id: MemberId, context: &ScanContext) -> Value

ENUM Declaration:
    Constant(name: String, value: Value)
    Function(name: String, params: Vec<ParamType>, return_type: ValueType)
    Structure(name: String, fields: Vec<Field>)
    Array(name: String, element_type: ValueType)

STRUCT ModuleRegistry:
    modules: HashMap<String, Box<dyn Module>>

FUNCTION ModuleRegistry::register(module: Box<dyn Module>):
    self.modules.insert(module.name().to_string(), module)

FUNCTION ModuleRegistry::get(name: &str) -> Option<&dyn Module>:
    self.modules.get(name)

FUNCTION ModuleRegistry::resolve_member(path: &str) -> Option<(ModuleId, MemberId)>:
    // Parse "pe.number_of_sections" -> (PE_MODULE, MEMBER_NUMBER_OF_SECTIONS)
    parts = path.split('.')
    module_name = parts[0]
    member_name = parts[1..]

    IF let Some(module) = self.modules.get(module_name):
        IF let Some(member_id) = module.resolve_member(member_name):
            RETURN Some((module.id(), member_id))

    RETURN None
```

---

## 9. PE Module

### 9.1 PE Data Structures

```pseudocode
STRUCT PeInfo:
    is_pe: bool
    is_32bit: bool
    is_64bit: bool
    is_dll: bool

    // DOS Header
    dos_header: DosHeader

    // PE Header
    machine: u16
    number_of_sections: u16
    timestamp: u32
    characteristics: u16

    // Optional Header
    magic: u16
    linker_version: Version
    entry_point: u32
    image_base: u64
    section_alignment: u32
    file_alignment: u32
    os_version: Version
    image_version: Version
    subsystem_version: Version
    subsystem: u16
    dll_characteristics: u16
    size_of_image: u32
    size_of_headers: u32
    checksum: u32

    // Sections
    sections: Vec<Section>

    // Import/Export
    imports: Vec<Import>
    exports: Vec<Export>

    // Resources
    resources: Vec<Resource>

    // Rich header
    rich_signature: Option<RichSignature>

STRUCT Section:
    name: String
    virtual_address: u32
    virtual_size: u32
    raw_data_offset: u32
    raw_data_size: u32
    characteristics: u32

STRUCT Import:
    dll_name: String
    functions: Vec<ImportFunction>

STRUCT ImportFunction:
    name: Option<String>
    ordinal: Option<u16>

STRUCT Export:
    name: Option<String>
    ordinal: u16
    address: u32
```

### 9.2 PE Module Implementation

```pseudocode
STRUCT PeModule

IMPL Module FOR PeModule:
    FUNCTION name() -> &str:
        RETURN "pe"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            // Constants
            Constant("MACHINE_I386", 0x014c),
            Constant("MACHINE_AMD64", 0x8664),
            Constant("MACHINE_ARM", 0x01c0),
            Constant("MACHINE_ARM64", 0xaa64),

            Constant("SUBSYSTEM_NATIVE", 1),
            Constant("SUBSYSTEM_WINDOWS_GUI", 2),
            Constant("SUBSYSTEM_WINDOWS_CUI", 3),

            Constant("DLL_CHARACTERISTICS_DYNAMIC_BASE", 0x0040),
            Constant("DLL_CHARACTERISTICS_NX_COMPAT", 0x0100),
            Constant("DLL_CHARACTERISTICS_NO_SEH", 0x0400),

            Constant("SECTION_CNT_CODE", 0x00000020),
            Constant("SECTION_CNT_INITIALIZED_DATA", 0x00000040),
            Constant("SECTION_MEM_EXECUTE", 0x20000000),
            Constant("SECTION_MEM_READ", 0x40000000),
            Constant("SECTION_MEM_WRITE", 0x80000000),

            // Members
            Structure("machine", Integer),
            Structure("number_of_sections", Integer),
            Structure("timestamp", Integer),
            Structure("characteristics", Integer),
            Structure("entry_point", Integer),
            Structure("image_base", Integer),
            Structure("subsystem", Integer),
            Structure("dll_characteristics", Integer),
            Structure("checksum", Integer),

            // Arrays
            Array("sections", SectionType),
            Array("imports", ImportType),
            Array("exports", ExportType),

            // Functions
            Function("is_pe", [], Boolean),
            Function("is_32bit", [], Boolean),
            Function("is_64bit", [], Boolean),
            Function("is_dll", [], Boolean),
            Function("section_index", [String], Integer),
            Function("imports", [String], Integer),
            Function("exports", [String], Integer),
            Function("imphash", [], String),
            Function("calculate_checksum", [], Integer),
            Function("rva_to_offset", [Integer], Integer),
        ]

    FUNCTION load(data: &[u8]) -> Result<ModuleData>:
        IF NOT is_pe(data):
            RETURN Ok(ModuleData::empty())

        pe = parse_pe(data)?
        RETURN Ok(ModuleData::Pe(pe))

    FUNCTION call(func_id: FuncId, args: &[Value], context: &ScanContext) -> Value:
        pe = context.module_data.get(PE_MODULE_ID)?

        MATCH func_id:
            FUNC_IS_PE => Boolean(pe.is_pe)
            FUNC_IS_32BIT => Boolean(pe.is_32bit)
            FUNC_IS_64BIT => Boolean(pe.is_64bit)
            FUNC_IS_DLL => Boolean(pe.is_dll)

            FUNC_SECTION_INDEX =>
                name = args[0].as_string()
                FOR i, section IN enumerate(pe.sections):
                    IF section.name == name:
                        RETURN Integer(i)
                RETURN Undefined

            FUNC_IMPORTS =>
                dll_or_func = args[0].as_string()
                // Check if any import matches
                FOR import IN pe.imports:
                    IF import.dll_name.contains(dll_or_func):
                        RETURN Integer(1)
                    FOR func IN import.functions:
                        IF func.name.map(|n| n.contains(dll_or_func)).unwrap_or(false):
                            RETURN Integer(1)
                RETURN Integer(0)

            FUNC_IMPHASH =>
                // Calculate import hash (MD5 of normalized import list)
                import_list = ""
                FOR import IN pe.imports:
                    dll = import.dll_name.to_lowercase().replace(".dll", "")
                    FOR func IN import.functions:
                        IF let Some(name) = func.name:
                            import_list += format!("{}.{},", dll, name.to_lowercase())
                RETURN String(md5(import_list))

            FUNC_RVA_TO_OFFSET =>
                rva = args[0].as_int() as u32
                FOR section IN pe.sections:
                    IF rva >= section.virtual_address AND
                       rva < section.virtual_address + section.virtual_size:
                        offset = rva - section.virtual_address + section.raw_data_offset
                        RETURN Integer(offset as i64)
                RETURN Undefined

    FUNCTION get_member(member_id: MemberId, context: &ScanContext) -> Value:
        pe = context.module_data.get(PE_MODULE_ID)?

        MATCH member_id:
            MEMBER_MACHINE => Integer(pe.machine as i64)
            MEMBER_NUMBER_OF_SECTIONS => Integer(pe.number_of_sections as i64)
            MEMBER_TIMESTAMP => Integer(pe.timestamp as i64)
            MEMBER_CHARACTERISTICS => Integer(pe.characteristics as i64)
            MEMBER_ENTRY_POINT => Integer(pe.entry_point as i64)
            MEMBER_IMAGE_BASE => Integer(pe.image_base as i64)
            MEMBER_SUBSYSTEM => Integer(pe.subsystem as i64)
            MEMBER_DLL_CHARACTERISTICS => Integer(pe.dll_characteristics as i64)
            MEMBER_CHECKSUM => Integer(pe.checksum as i64)
            _ => Undefined

FUNCTION parse_pe(data: &[u8]) -> Result<PeInfo>:
    IF data.len() < 64:
        RETURN Err("File too small for PE")

    // Check DOS header magic "MZ"
    IF data[0..2] != [0x4D, 0x5A]:
        RETURN Err("Invalid DOS signature")

    // Get PE header offset
    pe_offset = u32::from_le_bytes(data[60..64]) as usize

    IF pe_offset + 24 > data.len():
        RETURN Err("Invalid PE offset")

    // Check PE signature
    IF data[pe_offset..pe_offset+4] != [0x50, 0x45, 0x00, 0x00]:
        RETURN Err("Invalid PE signature")

    // Parse COFF header
    coff_offset = pe_offset + 4
    machine = u16::from_le_bytes(data[coff_offset..coff_offset+2])
    number_of_sections = u16::from_le_bytes(data[coff_offset+2..coff_offset+4])
    timestamp = u32::from_le_bytes(data[coff_offset+4..coff_offset+8])
    characteristics = u16::from_le_bytes(data[coff_offset+18..coff_offset+20])

    // Parse Optional header
    optional_offset = coff_offset + 20
    magic = u16::from_le_bytes(data[optional_offset..optional_offset+2])

    is_32bit = magic == 0x10b
    is_64bit = magic == 0x20b

    // Parse based on PE type
    IF is_32bit:
        entry_point = u32::from_le_bytes(data[optional_offset+16..])
        image_base = u32::from_le_bytes(data[optional_offset+28..]) as u64
    ELSE IF is_64bit:
        entry_point = u32::from_le_bytes(data[optional_offset+16..])
        image_base = u64::from_le_bytes(data[optional_offset+24..])

    // Parse sections
    sections = parse_sections(data, optional_offset, number_of_sections)

    // Parse imports
    imports = parse_imports(data, optional_offset, is_64bit, sections)

    // Parse exports
    exports = parse_exports(data, optional_offset, is_64bit, sections)

    RETURN Ok(PeInfo {
        is_pe: true,
        is_32bit, is_64bit,
        is_dll: (characteristics & 0x2000) != 0,
        machine, number_of_sections, timestamp, characteristics,
        entry_point, image_base,
        sections, imports, exports,
        // ... more fields
    })
```

---

## 10. ELF Module

### 10.1 ELF Data Structures

```pseudocode
STRUCT ElfInfo:
    is_elf: bool
    is_32bit: bool
    is_64bit: bool

    // ELF Header
    type: u16           // ET_EXEC, ET_DYN, etc.
    machine: u16        // EM_386, EM_X86_64, etc.
    version: u32
    entry_point: u64
    flags: u32

    // Sections
    sections: Vec<ElfSection>

    // Segments
    segments: Vec<ElfSegment>

    // Symbols
    symbols: Vec<ElfSymbol>

    // Dynamic info
    dynamic: Vec<DynamicEntry>
    needed_libraries: Vec<String>

STRUCT ElfSection:
    name: String
    type: u32
    flags: u64
    address: u64
    offset: u64
    size: u64

STRUCT ElfSegment:
    type: u32           // PT_LOAD, PT_DYNAMIC, etc.
    flags: u32          // PF_X, PF_W, PF_R
    offset: u64
    virtual_address: u64
    physical_address: u64
    file_size: u64
    memory_size: u64

STRUCT ElfSymbol:
    name: String
    value: u64
    size: u64
    type: u8
    bind: u8
    section_index: u16
```

### 10.2 ELF Module Implementation

```pseudocode
STRUCT ElfModule

IMPL Module FOR ElfModule:
    FUNCTION name() -> &str:
        RETURN "elf"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            // Type constants
            Constant("ET_NONE", 0),
            Constant("ET_REL", 1),
            Constant("ET_EXEC", 2),
            Constant("ET_DYN", 3),
            Constant("ET_CORE", 4),

            // Machine constants
            Constant("EM_386", 3),
            Constant("EM_X86_64", 62),
            Constant("EM_ARM", 40),
            Constant("EM_AARCH64", 183),

            // Section types
            Constant("SHT_NULL", 0),
            Constant("SHT_PROGBITS", 1),
            Constant("SHT_SYMTAB", 2),
            Constant("SHT_STRTAB", 3),
            Constant("SHT_DYNAMIC", 6),
            Constant("SHT_DYNSYM", 11),

            // Segment types
            Constant("PT_NULL", 0),
            Constant("PT_LOAD", 1),
            Constant("PT_DYNAMIC", 2),
            Constant("PT_INTERP", 3),
            Constant("PT_GNU_STACK", 0x6474e551),
            Constant("PT_GNU_RELRO", 0x6474e552),

            // Segment flags
            Constant("PF_X", 1),
            Constant("PF_W", 2),
            Constant("PF_R", 4),

            // Members
            Structure("type", Integer),
            Structure("machine", Integer),
            Structure("entry_point", Integer),
            Structure("number_of_sections", Integer),
            Structure("number_of_segments", Integer),

            // Arrays
            Array("sections", SectionType),
            Array("segments", SegmentType),
            Array("symbols", SymbolType),
            Array("dynamic", DynamicType),

            // Functions
            Function("is_elf", [], Boolean),
        ]

    FUNCTION load(data: &[u8]) -> Result<ModuleData>:
        IF NOT is_elf(data):
            RETURN Ok(ModuleData::empty())

        elf = parse_elf(data)?
        RETURN Ok(ModuleData::Elf(elf))

FUNCTION is_elf(data: &[u8]) -> bool:
    IF data.len() < 4:
        RETURN false
    // Check ELF magic: 0x7F 'E' 'L' 'F'
    RETURN data[0..4] == [0x7F, 0x45, 0x4C, 0x46]

FUNCTION parse_elf(data: &[u8]) -> Result<ElfInfo>:
    IF data.len() < 52:
        RETURN Err("File too small for ELF")

    // Parse ELF identification
    ei_class = data[4]    // 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]     // 1 = little-endian, 2 = big-endian

    is_32bit = ei_class == 1
    is_64bit = ei_class == 2
    is_little_endian = ei_data == 1

    // Parse header based on class
    IF is_32bit:
        type = read_u16(data, 16, is_little_endian)
        machine = read_u16(data, 18, is_little_endian)
        version = read_u32(data, 20, is_little_endian)
        entry_point = read_u32(data, 24, is_little_endian) as u64
        ph_offset = read_u32(data, 28, is_little_endian) as u64
        sh_offset = read_u32(data, 32, is_little_endian) as u64
        ph_entry_size = read_u16(data, 42, is_little_endian)
        ph_num = read_u16(data, 44, is_little_endian)
        sh_entry_size = read_u16(data, 46, is_little_endian)
        sh_num = read_u16(data, 48, is_little_endian)
    ELSE:
        type = read_u16(data, 16, is_little_endian)
        machine = read_u16(data, 18, is_little_endian)
        version = read_u32(data, 20, is_little_endian)
        entry_point = read_u64(data, 24, is_little_endian)
        ph_offset = read_u64(data, 32, is_little_endian)
        sh_offset = read_u64(data, 40, is_little_endian)
        ph_entry_size = read_u16(data, 54, is_little_endian)
        ph_num = read_u16(data, 56, is_little_endian)
        sh_entry_size = read_u16(data, 58, is_little_endian)
        sh_num = read_u16(data, 60, is_little_endian)

    // Parse sections
    sections = parse_elf_sections(data, sh_offset, sh_num, sh_entry_size, is_64bit, is_little_endian)

    // Parse segments
    segments = parse_elf_segments(data, ph_offset, ph_num, ph_entry_size, is_64bit, is_little_endian)

    // Parse symbols
    symbols = parse_elf_symbols(data, sections, is_64bit, is_little_endian)

    RETURN Ok(ElfInfo {
        is_elf: true,
        is_32bit, is_64bit,
        type, machine, version, entry_point,
        sections, segments, symbols,
        // ... more fields
    })
```

---

## 11. Mach-O Module

### 11.1 Mach-O Data Structures

```pseudocode
STRUCT MachoInfo:
    is_macho: bool
    is_64bit: bool
    is_fat: bool

    // Header
    magic: u32
    cpu_type: u32
    cpu_subtype: u32
    file_type: u32
    ncmds: u32
    sizeofcmds: u32
    flags: u32

    // Entry point
    entry_point: u64

    // Segments
    segments: Vec<MachoSegment>

    // Sections
    sections: Vec<MachoSection>

    // Libraries
    libraries: Vec<String>

    // Symbols
    symbols: Vec<MachoSymbol>

STRUCT MachoSegment:
    segname: String
    vmaddr: u64
    vmsize: u64
    fileoff: u64
    filesize: u64
    maxprot: u32
    initprot: u32
    nsects: u32
    flags: u32

STRUCT MachoSection:
    sectname: String
    segname: String
    addr: u64
    size: u64
    offset: u32
    align: u32
    reloff: u32
    nreloc: u32
    flags: u32
```

### 11.2 Mach-O Module Implementation

```pseudocode
STRUCT MachoModule

IMPL Module FOR MachoModule:
    FUNCTION name() -> &str:
        RETURN "macho"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            // CPU Types
            Constant("CPU_TYPE_X86", 0x00000007),
            Constant("CPU_TYPE_X86_64", 0x01000007),
            Constant("CPU_TYPE_ARM", 0x0000000C),
            Constant("CPU_TYPE_ARM64", 0x0100000C),

            // File Types
            Constant("MH_OBJECT", 0x1),
            Constant("MH_EXECUTE", 0x2),
            Constant("MH_DYLIB", 0x6),
            Constant("MH_BUNDLE", 0x8),
            Constant("MH_KEXT_BUNDLE", 0xB),

            // Flags
            Constant("MH_PIE", 0x00200000),
            Constant("MH_NO_HEAP_EXECUTION", 0x01000000),
            Constant("MH_ALLOW_STACK_EXECUTION", 0x00020000),

            // Members
            Structure("cputype", Integer),
            Structure("cpusubtype", Integer),
            Structure("filetype", Integer),
            Structure("ncmds", Integer),
            Structure("flags", Integer),
            Structure("entry_point", Integer),

            // Arrays
            Array("segments", SegmentType),
            Array("sections", SectionType),

            // Functions
            Function("is_macho", [], Boolean),
            Function("is_64bit", [], Boolean),
            Function("is_fat", [], Boolean),
        ]

FUNCTION is_macho(data: &[u8]) -> bool:
    IF data.len() < 4:
        RETURN false
    magic = u32::from_le_bytes(data[0..4])
    // Check for Mach-O magics
    RETURN magic IN [
        0xFEEDFACE,  // MH_MAGIC (32-bit)
        0xFEEDFACF,  // MH_MAGIC_64 (64-bit)
        0xCEFAEDFE,  // MH_CIGAM (32-bit, byte-swapped)
        0xCFFAEDFE,  // MH_CIGAM_64 (64-bit, byte-swapped)
        0xCAFEBABE,  // FAT_MAGIC (universal)
        0xBEBAFECA   // FAT_CIGAM (universal, byte-swapped)
    ]
```

---

## 12. DEX Module

### 12.1 DEX Data Structures

```pseudocode
STRUCT DexInfo:
    is_dex: bool
    version: String

    // Header
    checksum: u32
    signature: [u8; 20]
    file_size: u32
    header_size: u32

    // Counts
    string_ids_size: u32
    type_ids_size: u32
    proto_ids_size: u32
    field_ids_size: u32
    method_ids_size: u32
    class_defs_size: u32

    // Strings
    strings: Vec<String>

    // Classes
    classes: Vec<DexClass>

STRUCT DexClass:
    class_name: String
    access_flags: u32
    superclass: Option<String>
    source_file: Option<String>
    methods: Vec<DexMethod>
    fields: Vec<DexField>

STRUCT DexMethod:
    name: String
    class_name: String
    prototype: String
    access_flags: u32

STRUCT DexField:
    name: String
    class_name: String
    type_name: String
    access_flags: u32
```

### 12.2 DEX Module Implementation

```pseudocode
STRUCT DexModule

IMPL Module FOR DexModule:
    FUNCTION name() -> &str:
        RETURN "dex"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            // Access flags
            Constant("ACC_PUBLIC", 0x0001),
            Constant("ACC_PRIVATE", 0x0002),
            Constant("ACC_PROTECTED", 0x0004),
            Constant("ACC_STATIC", 0x0008),
            Constant("ACC_FINAL", 0x0010),
            Constant("ACC_SYNCHRONIZED", 0x0020),
            Constant("ACC_NATIVE", 0x0100),
            Constant("ACC_INTERFACE", 0x0200),
            Constant("ACC_ABSTRACT", 0x0400),

            // Members
            Structure("version", String),
            Structure("number_of_strings", Integer),
            Structure("number_of_classes", Integer),

            // Functions
            Function("is_dex", [], Boolean),
            Function("has_class", [String], Boolean),
            Function("has_method", [String], Boolean),
            Function("has_string", [String], Boolean),
        ]

FUNCTION is_dex(data: &[u8]) -> bool:
    IF data.len() < 8:
        RETURN false
    // Check DEX magic: "dex\n"
    RETURN data[0..4] == [0x64, 0x65, 0x78, 0x0A]

FUNCTION parse_dex(data: &[u8]) -> Result<DexInfo>:
    IF data.len() < 112:
        RETURN Err("File too small for DEX")

    // Extract version (bytes 4-7)
    version = String::from_utf8(data[4..7].to_vec())?

    // Parse header
    checksum = u32::from_le_bytes(data[8..12])
    signature = data[12..32].try_into()?
    file_size = u32::from_le_bytes(data[32..36])
    header_size = u32::from_le_bytes(data[36..40])

    // Parse counts
    string_ids_size = u32::from_le_bytes(data[56..60])
    string_ids_offset = u32::from_le_bytes(data[60..64])
    type_ids_size = u32::from_le_bytes(data[64..68])
    class_defs_size = u32::from_le_bytes(data[96..100])

    // Parse strings
    strings = parse_dex_strings(data, string_ids_size, string_ids_offset)

    RETURN Ok(DexInfo {
        is_dex: true,
        version,
        checksum, signature, file_size, header_size,
        string_ids_size, type_ids_size, class_defs_size,
        strings,
        // ... more fields
    })

FUNCTION parse_dex_strings(data: &[u8], count: u32, offset: u32) -> Vec<String>:
    strings = []

    FOR i IN 0..count:
        // Read string_id (offset to string_data_item)
        id_offset = offset + i * 4
        string_data_offset = u32::from_le_bytes(data[id_offset..id_offset+4]) as usize

        // Read ULEB128 length
        (length, bytes_read) = read_uleb128(data, string_data_offset)

        // Read MUTF-8 string
        string_start = string_data_offset + bytes_read
        string_bytes = data[string_start..string_start + length]
        string = decode_mutf8(string_bytes)

        strings.push(string)

    RETURN strings

FUNCTION read_uleb128(data: &[u8], offset: usize) -> (u32, usize):
    result = 0
    shift = 0
    pos = offset

    LOOP:
        byte = data[pos]
        pos += 1
        result |= ((byte & 0x7F) as u32) << shift

        IF (byte & 0x80) == 0:
            BREAK

        shift += 7

    RETURN (result, pos - offset)
```

---

## 13. Hash Module

### 13.1 Hash Functions

```pseudocode
STRUCT HashModule

IMPL Module FOR HashModule:
    FUNCTION name() -> &str:
        RETURN "hash"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            Function("md5", [Integer, Integer], String),      // md5(offset, size)
            Function("md5", [], String),                       // md5() - whole file
            Function("sha1", [Integer, Integer], String),
            Function("sha1", [], String),
            Function("sha256", [Integer, Integer], String),
            Function("sha256", [], String),
            Function("sha512", [Integer, Integer], String),
            Function("sha512", [], String),
            Function("checksum32", [Integer, Integer], Integer),
            Function("crc32", [Integer, Integer], Integer),
        ]

    FUNCTION call(func_id: FuncId, args: &[Value], context: &ScanContext) -> Value:
        data = context.data

        // Determine range
        (offset, size) = IF args.len() == 2:
            (args[0].as_int() as usize, args[1].as_int() as usize)
        ELSE:
            (0, data.len())

        // Validate range
        IF offset + size > data.len():
            RETURN Undefined

        slice = &data[offset..offset + size]

        MATCH func_id:
            FUNC_MD5 =>
                hash = md5::compute(slice)
                RETURN String(hex::encode(hash))

            FUNC_SHA1 =>
                hash = sha1::compute(slice)
                RETURN String(hex::encode(hash))

            FUNC_SHA256 =>
                hash = sha256::compute(slice)
                RETURN String(hex::encode(hash))

            FUNC_SHA512 =>
                hash = sha512::compute(slice)
                RETURN String(hex::encode(hash))

            FUNC_CHECKSUM32 =>
                sum = 0u32
                FOR byte IN slice:
                    sum = sum.wrapping_add(byte as u32)
                RETURN Integer(sum as i64)

            FUNC_CRC32 =>
                crc = crc32::compute(slice)
                RETURN Integer(crc as i64)
```

---

## 14. Math Module

### 14.1 Math Functions

```pseudocode
STRUCT MathModule

IMPL Module FOR MathModule:
    FUNCTION name() -> &str:
        RETURN "math"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            Function("entropy", [Integer, Integer], Float),
            Function("entropy", [], Float),
            Function("mean", [Integer, Integer], Float),
            Function("deviation", [Integer, Integer, Float], Float),
            Function("serial_correlation", [Integer, Integer], Float),
            Function("monte_carlo_pi", [Integer, Integer], Float),
            Function("count", [Integer, Integer, Integer], Integer),
            Function("percentage", [Integer, Integer, Integer], Float),
            Function("mode", [Integer, Integer], Integer),
            Function("in_range", [Float, Float, Float], Boolean),
            Function("min", [Integer, Integer], Integer),
            Function("max", [Integer, Integer], Integer),
            Function("abs", [Integer], Integer),
        ]

    FUNCTION call(func_id: FuncId, args: &[Value], context: &ScanContext) -> Value:
        MATCH func_id:
            FUNC_ENTROPY =>
                (offset, size) = get_range(args, context.data.len())
                slice = &context.data[offset..offset + size]
                RETURN Float(calculate_entropy(slice))

            FUNC_MEAN =>
                (offset, size) = get_range(args, context.data.len())
                slice = &context.data[offset..offset + size]
                sum = slice.iter().map(|b| *b as f64).sum()
                RETURN Float(sum / slice.len() as f64)

            FUNC_DEVIATION =>
                offset = args[0].as_int() as usize
                size = args[1].as_int() as usize
                mean = args[2].as_float()
                slice = &context.data[offset..offset + size]

                variance = slice.iter()
                    .map(|b| (*b as f64 - mean).powi(2))
                    .sum::<f64>() / slice.len() as f64

                RETURN Float(variance.sqrt())

            FUNC_SERIAL_CORRELATION =>
                (offset, size) = get_range(args, context.data.len())
                slice = &context.data[offset..offset + size]
                RETURN Float(calculate_serial_correlation(slice))

            FUNC_MONTE_CARLO_PI =>
                (offset, size) = get_range(args, context.data.len())
                slice = &context.data[offset..offset + size]
                RETURN Float(monte_carlo_pi(slice))

            FUNC_COUNT =>
                byte = args[0].as_int() as u8
                offset = args[1].as_int() as usize
                size = args[2].as_int() as usize
                slice = &context.data[offset..offset + size]
                count = slice.iter().filter(|b| **b == byte).count()
                RETURN Integer(count as i64)

            FUNC_PERCENTAGE =>
                byte = args[0].as_int() as u8
                offset = args[1].as_int() as usize
                size = args[2].as_int() as usize
                slice = &context.data[offset..offset + size]
                count = slice.iter().filter(|b| **b == byte).count()
                RETURN Float(count as f64 / slice.len() as f64 * 100.0)

            FUNC_MODE =>
                (offset, size) = get_range(args, context.data.len())
                slice = &context.data[offset..offset + size]

                // Count byte frequencies
                counts = [0u32; 256]
                FOR byte IN slice:
                    counts[byte as usize] += 1

                // Find most frequent
                max_count = 0
                mode = 0
                FOR i IN 0..256:
                    IF counts[i] > max_count:
                        max_count = counts[i]
                        mode = i

                RETURN Integer(mode as i64)

            FUNC_IN_RANGE =>
                test = args[0].as_float()
                lower = args[1].as_float()
                upper = args[2].as_float()
                RETURN Boolean(test >= lower && test <= upper)

FUNCTION calculate_entropy(data: &[u8]) -> f64:
    IF data.is_empty():
        RETURN 0.0

    // Count byte frequencies
    counts = [0u32; 256]
    FOR byte IN data:
        counts[byte as usize] += 1

    // Calculate Shannon entropy
    n = data.len() as f64
    entropy = 0.0
    FOR count IN counts:
        IF count > 0:
            p = count as f64 / n
            entropy -= p * p.log2()

    RETURN entropy

FUNCTION monte_carlo_pi(data: &[u8]) -> f64:
    IF data.len() < 6:
        RETURN 0.0

    inside = 0
    total = 0

    // Use consecutive pairs of 3-byte values as x,y coordinates
    FOR i IN (0..data.len() - 5).step_by(6):
        x = (data[i] as u32 | (data[i+1] as u32) << 8 | (data[i+2] as u32) << 16) as f64 / 16777216.0
        y = (data[i+3] as u32 | (data[i+4] as u32) << 8 | (data[i+5] as u32) << 16) as f64 / 16777216.0

        // Check if point is inside unit circle
        IF x*x + y*y <= 1.0:
            inside += 1
        total += 1

    IF total == 0:
        RETURN 0.0

    RETURN 4.0 * inside as f64 / total as f64
```

---

## 15. String/Console/Time Modules

### 15.1 Time Module

```pseudocode
STRUCT TimeModule

IMPL Module FOR TimeModule:
    FUNCTION name() -> &str:
        RETURN "time"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            Function("now", [], Integer),  // Current Unix timestamp
        ]

    FUNCTION call(func_id: FuncId, args: &[Value], context: &ScanContext) -> Value:
        MATCH func_id:
            FUNC_NOW =>
                timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                RETURN Integer(timestamp as i64)
```

### 15.2 Console Module

```pseudocode
STRUCT ConsoleModule

IMPL Module FOR ConsoleModule:
    FUNCTION name() -> &str:
        RETURN "console"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            Function("log", [String], Boolean),
            Function("log", [Integer], Boolean),
            Function("hex", [Integer], Boolean),
        ]

    FUNCTION call(func_id: FuncId, args: &[Value], context: &ScanContext) -> Value:
        MATCH func_id:
            FUNC_LOG =>
                message = args[0].to_string()
                println!("[YARA] {}", message)
                RETURN Boolean(true)

            FUNC_HEX =>
                value = args[0].as_int()
                println!("[YARA] 0x{:X}", value)
                RETURN Boolean(true)
```

### 15.3 String Module

```pseudocode
STRUCT StringModule

IMPL Module FOR StringModule:
    FUNCTION name() -> &str:
        RETURN "string"

    FUNCTION declarations() -> Vec<Declaration>:
        RETURN [
            Function("to_int", [String], Integer),
            Function("to_int", [String, Integer], Integer),  // with base
            Function("length", [String], Integer),
        ]

    FUNCTION call(func_id: FuncId, args: &[Value], context: &ScanContext) -> Value:
        MATCH func_id:
            FUNC_TO_INT =>
                s = args[0].as_string()
                base = IF args.len() > 1 THEN args[1].as_int() as u32 ELSE 10

                IF let Ok(n) = i64::from_str_radix(&s, base):
                    RETURN Integer(n)
                ELSE:
                    RETURN Undefined

            FUNC_LENGTH =>
                s = args[0].as_string()
                RETURN Integer(s.len() as i64)
```

---

## Appendix A: Complete YARA Rule Example

```yara
import "pe"
import "hash"
import "math"

rule Suspicious_PE_High_Entropy {
    meta:
        description = "Detects PE files with suspicious characteristics"
        author = "Security Team"
        severity = "high"

    strings:
        $mz = { 4D 5A }                          // MZ header
        $pe = { 50 45 00 00 }                    // PE signature
        $str1 = "CreateRemoteThread" ascii wide
        $str2 = "VirtualAllocEx" ascii wide
        $str3 = "WriteProcessMemory" ascii wide
        $hex_pattern = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 }

    condition:
        $mz at 0 and
        $pe and
        pe.is_dll() and
        pe.number_of_sections >= 3 and
        pe.number_of_sections <= 10 and
        (
            all of ($str*) or
            (2 of ($str*) and $hex_pattern)
        ) and
        math.entropy(0, filesize) > 7.0 and
        for any section in pe.sections : (
            section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.5
        )
}
```

---

## Appendix B: Execution Flow Summary

```
1. COMPILATION:
   Source (.yar) → Lexer → Tokens → Parser → AST → Compiler → Bytecode + Pattern Table

2. PATTERN MATCHING:
   Patterns → Atom Extraction → Aho-Corasick Automaton Build
   Target Data → AC Search → Raw Matches → Verification → Confirmed Matches

3. SCANNING:
   Target File → Load into Memory
   → Run AC Pattern Matcher (find all string matches)
   → Load Module Data (PE/ELF/etc. parsing)
   → For each rule:
       → Execute Bytecode Condition (VM)
       → If true, add to results

4. RESULTS:
   Matching Rules + String Matches + Metadata → Output
```

---

**Document Version:** 1.0
**Last Updated:** 2025-11-28
**Total Pages:** ~50 pages of pseudocode
**Covers:** Complete YARA implementation from lexer to all modules
