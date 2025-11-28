# R-YARA Complete Pseudocode Documentation

**Generated from Source Code Analysis**
**Date:** 2025-11-28
**Version:** v0.3.0-alpha
**Total Source Lines:** ~25,700 Rust

This document provides complete pseudocode representations of all R-YARA components,
suitable for training data, auditing, and verification purposes.

---

## Table of Contents

1. [Lexer Module](#1-lexer-module)
2. [AST Definitions](#2-ast-definitions)
3. [Parser Module](#3-parser-module)
4. [Pattern Matcher](#4-pattern-matcher)
5. [Bytecode Compiler](#5-bytecode-compiler)
6. [Virtual Machine](#6-virtual-machine)
7. [File Format Modules](#7-file-format-modules)
8. [Scanner Pipeline](#8-scanner-pipeline)
9. [Gateway & Load Balancing](#9-gateway--load-balancing)
10. [MCP Server Integration](#10-mcp-server-integration)

---

## 1. Lexer Module

**Source:** `r-yara-parser/src/lexer.rs` (~614 lines)

### Token Types
```pseudocode
ENUM Token {
    // Keywords
    Rule, Private, Global, Meta, Strings, Condition
    Import, Include, True, False
    Not, And, Or, All, Any, None, Of, Them
    For, In, At, Filesize, Entrypoint
    Contains, IContains, StartsWith, IStartsWith
    EndsWith, IEndsWith, IEquals, Matches, Defined

    // String modifiers
    Nocase, Wide, Ascii, Fullword, Xor, Base64, Base64Wide

    // Operators
    Assign(=), Equal(==), NotEqual(!=)
    LessThan(<), LessEqual(<=), GreaterThan(>), GreaterEqual(>=)
    Plus(+), Minus(-), Star(*), Percent(%)
    Ampersand(&), Pipe(|), Caret(^), Tilde(~)
    ShiftLeft(<<), ShiftRight(>>)
    DotDot(..), Dot(.)

    // Delimiters
    LBrace({), RBrace(}), LParen((), RParen())
    LBracket([), RBracket(]), Colon(:), Comma(,)

    // Identifiers and literals
    Identifier(String)           // my_rule
    StringIdentifier(String)     // $my_string
    StringCount(String)          // #count
    StringOffset(String)         // @offset
    StringLength(String)         // !length
    Number(NumberValue)          // 42, 0x1F, 3.14
    SizeValue(i64)               // 10KB, 5MB, 2GB
    StringLiteral(String)        // "hello"
    Regex(String)                // /pattern/flags
    LineComment(String)          // // comment
    BlockComment(String)         // /* comment */
}
```

### Lexer Algorithm
```pseudocode
CLASS Lexer:
    source: String
    position: Int

    FUNCTION tokenize(source) -> List<SpannedToken>:
        tokens = []
        position = 0

        WHILE position < source.length:
            skip_whitespace()
            IF at_end(): BREAK

            char = peek()

            // Keywords and identifiers
            IF is_alpha(char) OR char == '_':
                token = scan_identifier_or_keyword()

            // String identifiers ($name, #count, @offset, !length)
            ELSE IF char == '$':
                token = scan_string_identifier()
            ELSE IF char == '#':
                token = scan_string_count()
            ELSE IF char == '@':
                token = scan_string_offset()
            ELSE IF char == '!':
                token = scan_string_length()

            // Numbers (decimal, hex, octal)
            ELSE IF is_digit(char):
                token = scan_number()

            // String literals
            ELSE IF char == '"':
                token = scan_string_literal()

            // Regular expressions
            ELSE IF char == '/':
                token = scan_regex()

            // Comments
            ELSE IF char == '/' AND peek_next() == '/':
                token = scan_line_comment()
            ELSE IF char == '/' AND peek_next() == '*':
                token = scan_block_comment()

            // Operators and delimiters
            ELSE:
                token = scan_operator_or_delimiter()

            tokens.append(SpannedToken(token, Span(start, position)))

        RETURN tokens

    FUNCTION scan_number() -> Token:
        start = position

        IF peek() == '0' AND peek_next() IN ['x', 'X']:
            advance(2)
            value = parse_hex_digits()
            RETURN Token::Number(Integer(value))

        IF peek() == '0' AND peek_next() IN ['o', 'O']:
            advance(2)
            value = parse_octal_digits()
            RETURN Token::Number(Integer(value))

        // Decimal (possibly with float/exponent)
        value = parse_decimal()
        IF peek() == '.':
            advance()
            frac = parse_decimal()
            value = combine_float(value, frac)
        IF peek() IN ['e', 'E']:
            exp = parse_exponent()
            value = apply_exponent(value, exp)

        // Check for size suffix (KB, MB, GB)
        IF peek_str(2) == "KB":
            advance(2)
            RETURN Token::SizeValue(value * 1024)
        IF peek_str(2) == "MB":
            advance(2)
            RETURN Token::SizeValue(value * 1024 * 1024)
        IF peek_str(2) == "GB":
            advance(2)
            RETURN Token::SizeValue(value * 1024 * 1024 * 1024)

        RETURN Token::Number(value)

    FUNCTION unescape_string(s) -> String:
        result = ""
        i = 0
        WHILE i < s.length:
            IF s[i] == '\\':
                i += 1
                MATCH s[i]:
                    'n' -> result += '\n'
                    'r' -> result += '\r'
                    't' -> result += '\t'
                    '\\' -> result += '\\'
                    '"' -> result += '"'
                    'x' ->
                        hex = s[i+1:i+3]
                        result += chr(parse_hex(hex))
                        i += 2
                    _ -> result += s[i]
            ELSE:
                result += s[i]
            i += 1
        RETURN result
```

---

## 2. AST Definitions

**Source:** `r-yara-parser/src/ast.rs` (~538 lines)

### Core Structures
```pseudocode
STRUCT SourceFile:
    imports: List<Import>      // import "pe"
    includes: List<Include>    // include "other.yar"
    rules: List<Rule>          // rule definitions

STRUCT Rule:
    name: SmolStr
    modifiers: RuleModifiers   // private, global
    tags: List<SmolStr>        // rule Name : tag1 tag2
    meta: List<MetaEntry>      // meta: author = "..."
    strings: List<StringDeclaration>
    condition: Expression
    span: Span

STRUCT RuleModifiers:
    is_private: Bool
    is_global: Bool

STRUCT MetaEntry:
    key: SmolStr
    value: MetaValue           // String | Integer | Boolean

STRUCT StringDeclaration:
    name: SmolStr              // "$a"
    pattern: StringPattern     // Text | Hex | Regex
    modifiers: StringModifiers
    span: Span

ENUM StringPattern:
    Text(TextString)           // "hello"
    Hex(HexString)             // { 4D 5A }
    Regex(RegexString)         // /pattern/

STRUCT StringModifiers:
    nocase: Bool
    wide: Bool
    ascii: Bool
    fullword: Bool
    xor: Option<XorModifier>   // xor or xor(0x00-0xFF)
    base64: Option<Base64Modifier>
    private: Bool

STRUCT HexString:
    tokens: List<HexToken>
    span: Span

ENUM HexToken:
    Byte(u8)                   // 4D
    Wildcard                   // ??
    NibbleWildcard(high?, low?) // ?A or A?
    Jump(min, max?)            // [n] or [n-m]
    Alternation(List<List<HexToken>>) // (AA | BB)
```

### Expression Types
```pseudocode
ENUM Expression:
    Boolean(bool)              // true, false
    Integer(i64)               // 42
    Float(f64)                 // 3.14
    String(SmolStr)            // "text"
    Identifier(Identifier)     // pe.is_pe
    StringRef(SmolStr)         // $a
    StringCount(StringCountExpr)   // #a
    StringOffset(StringOffsetExpr) // @a or @a[n]
    StringLength(StringLengthExpr) // !a or !a[n]
    Filesize                   // filesize
    Entrypoint                 // entrypoint
    Binary(BinaryExpr)         // a + b
    Unary(UnaryExpr)           // not a
    Range(RangeExpr)           // (0..100)
    FunctionCall(FunctionCall) // pe.is_pe()
    Index(IndexExpr)           // array[index]
    FieldAccess(FieldAccess)   // obj.field
    Quantifier(Quantifier)     // any of them
    For(ForExpr)               // for any i in (...)
    Of(OfExpr)                 // 2 of them
    At(AtExpr)                 // $a at 0
    In(InExpr)                 // $a in (0..100)
    Matches(MatchesExpr)       // str matches /regex/
    Contains(ContainsExpr)     // str contains "sub"
    Defined(Expression)        // defined(expr)

ENUM BinaryOp:
    // Logical
    And, Or
    // Comparison
    Equal, NotEqual, LessThan, LessEqual, GreaterThan, GreaterEqual
    // Arithmetic
    Add, Sub, Mul, Div, Mod
    // Bitwise
    BitAnd, BitOr, BitXor, ShiftLeft, ShiftRight
    // String
    Contains, IContains, StartsWith, IStartsWith
    EndsWith, IEndsWith, IEquals, Matches

ENUM UnaryOp:
    Not, Neg, BitNot

STRUCT Quantifier:
    kind: QuantifierKind       // All, Any, None, Count(n), Percentage(%)
    strings: StringSet         // Them, Explicit(list), Wildcard($a*)

STRUCT ForExpr:
    quantifier: QuantifierKind
    iterator: ForIterator      // variables, iterable
    condition: Expression
```

---

## 3. Parser Module

**Source:** `r-yara-parser/src/parser.rs` (~1,636 lines)

### Parser Structure
```pseudocode
CLASS Parser:
    tokens: List<SpannedToken>
    current: Int
    source: String

    FUNCTION parse(source) -> Result<SourceFile>:
        lexer = Lexer::new(source)
        tokens = collect_non_comment_tokens(lexer)

        file = SourceFile::new()

        WHILE NOT at_end():
            IF check(Token::Import):
                file.imports.append(parse_import())
            ELSE IF check(Token::Include):
                file.includes.append(parse_include())
            ELSE IF check(Token::Rule) OR check(Token::Private) OR check(Token::Global):
                file.rules.append(parse_rule())
            ELSE:
                RAISE ParseError("Expected import, include, or rule")

        RETURN file

    FUNCTION parse_rule() -> Rule:
        modifiers = RuleModifiers::default()

        // Parse modifiers
        WHILE check(Token::Private) OR check(Token::Global):
            IF match(Token::Private):
                modifiers.is_private = true
            IF match(Token::Global):
                modifiers.is_global = true

        expect(Token::Rule)
        name = expect_identifier()

        // Parse tags
        tags = []
        IF match(Token::Colon):
            WHILE check(Token::Identifier):
                tags.append(advance().as_identifier())

        expect(Token::LBrace)

        // Parse sections
        meta = []
        strings = []
        condition = Expression::Boolean(true)

        WHILE NOT check(Token::RBrace):
            IF match(Token::Meta):
                expect(Token::Colon)
                meta = parse_meta_section()
            ELSE IF match(Token::Strings):
                expect(Token::Colon)
                strings = parse_strings_section()
            ELSE IF match(Token::Condition):
                expect(Token::Colon)
                condition = parse_expression()

        expect(Token::RBrace)

        RETURN Rule(name, modifiers, tags, meta, strings, condition)

    FUNCTION parse_strings_section() -> List<StringDeclaration>:
        strings = []

        WHILE check(Token::StringIdentifier):
            name = advance().as_string_identifier()
            expect(Token::Assign)

            pattern = parse_string_pattern()
            modifiers = parse_string_modifiers()

            strings.append(StringDeclaration(name, pattern, modifiers))

        RETURN strings

    FUNCTION parse_string_pattern() -> StringPattern:
        IF check(Token::StringLiteral):
            value = advance().as_string_literal()
            RETURN StringPattern::Text(TextString(value))

        IF check(Token::LBrace):
            // Hex string: { 4D 5A ?? }
            RETURN parse_hex_string()

        IF check(Token::Regex):
            regex_str = advance().as_regex()
            pattern, modifiers = parse_regex_with_modifiers(regex_str)
            RETURN StringPattern::Regex(RegexString(pattern, modifiers))

        RAISE ParseError("Expected string pattern")

    FUNCTION parse_hex_string() -> StringPattern:
        expect(Token::LBrace)

        // Use span-based extraction to get raw hex content
        // This avoids lexer tokenization issues with hex bytes
        start_pos = current_span().start
        depth = 1

        WHILE depth > 0:
            IF check(Token::LBrace):
                advance()
                depth += 1
            ELSE IF check(Token::RBrace):
                depth -= 1
                IF depth > 0:
                    advance()
            ELSE IF at_end():
                RAISE ParseError("Unterminated hex string")
            ELSE:
                advance()

        end_pos = current_span().start
        advance()  // consume final RBrace

        // Extract raw hex content and parse it
        hex_content = source[start_pos:end_pos]
        tokens = parse_hex_tokens(hex_content)

        RETURN StringPattern::Hex(HexString(tokens))

    FUNCTION parse_expression() -> Expression:
        RETURN parse_or_expression()

    FUNCTION parse_or_expression() -> Expression:
        left = parse_and_expression()

        WHILE match(Token::Or):
            right = parse_and_expression()
            left = Expression::Binary(BinaryExpr(left, BinaryOp::Or, right))

        RETURN left

    FUNCTION parse_and_expression() -> Expression:
        left = parse_comparison()

        WHILE match(Token::And):
            right = parse_comparison()
            left = Expression::Binary(BinaryExpr(left, BinaryOp::And, right))

        RETURN left

    FUNCTION parse_comparison() -> Expression:
        left = parse_addition()

        WHILE check_comparison_operator():
            op = get_comparison_operator()
            advance()
            right = parse_addition()
            left = Expression::Binary(BinaryExpr(left, op, right))

        RETURN left

    FUNCTION parse_primary() -> Expression:
        IF match(Token::True):
            RETURN Expression::Boolean(true)
        IF match(Token::False):
            RETURN Expression::Boolean(false)
        IF check(Token::Number):
            value = advance().as_number()
            RETURN number_to_expression(value)
        IF check(Token::StringLiteral):
            value = advance().as_string_literal()
            RETURN Expression::String(value)
        IF check(Token::StringIdentifier):
            name = advance().as_string_identifier()
            RETURN Expression::StringRef(name)
        IF check(Token::StringCount):
            RETURN parse_string_count_expr()
        IF check(Token::StringOffset):
            RETURN parse_string_offset_expr()
        IF check(Token::StringLength):
            RETURN parse_string_length_expr()
        IF match(Token::Filesize):
            RETURN Expression::Filesize
        IF match(Token::Entrypoint):
            RETURN Expression::Entrypoint
        IF match(Token::LParen):
            expr = parse_expression()
            expect(Token::RParen)
            RETURN Expression::Paren(expr)
        IF check(Token::All) OR check(Token::Any) OR check(Token::None):
            RETURN parse_quantifier()
        IF match(Token::For):
            RETURN parse_for_expression()
        IF check(Token::Identifier):
            RETURN parse_identifier_or_call()

        RAISE ParseError("Expected expression")
```

---

## 4. Pattern Matcher

**Source:** `r-yara-matcher/src/lib.rs` (~927 lines)

### Matcher Architecture
```pseudocode
CLASS PatternMatcher:
    ac: DoubleArrayAhoCorasick    // Aho-Corasick automaton
    ac_pattern_map: List<PatternId>
    regexes: List<(PatternId, Regex)>
    hex_patterns: List<(PatternId, HexPattern)>
    patterns: List<Pattern>

    FUNCTION new(patterns) -> PatternMatcher:
        ac_patterns = []
        regexes = []
        hex_patterns = []

        FOR pattern IN patterns:
            MATCH pattern.kind:
                Literal | Wide:
                    bytes = pattern.bytes
                    IF kind == Wide:
                        bytes = to_utf16le(bytes)
                    ac_patterns.append((bytes, pattern.id))

                LiteralNocase | WideNocase:
                    bytes = pattern.bytes
                    IF kind == WideNocase:
                        bytes = to_utf16le(bytes)
                    ac_patterns.append((lowercase(bytes), pattern.id))
                    ac_patterns.append((uppercase(bytes), pattern.id))

                Hex:
                    hex_pattern = parse_hex_pattern(pattern.bytes)
                    FOR atom IN hex_pattern.atoms:
                        IF atom.length >= 2:
                            ac_patterns.append((atom, pattern.id))
                    hex_patterns.append((pattern.id, hex_pattern))

                Regex:
                    regex = Regex::new(pattern.bytes)
                    regexes.append((pattern.id, regex))

        // Build Aho-Corasick automaton
        ac = AhoCorasickBuilder::build(ac_patterns)
        pattern_map = extract_pattern_ids(ac_patterns)

        RETURN PatternMatcher(ac, pattern_map, regexes, hex_patterns)

    FUNCTION scan(data) -> List<Match>:
        matches = []
        seen = HashMap::new()

        // Phase 1: Aho-Corasick multi-pattern matching
        IF ac IS NOT None:
            FOR m IN ac.find_overlapping(data):
                pattern_id = ac_pattern_map[m.value]
                offset = m.start
                length = m.end - m.start

                key = (pattern_id, offset)
                IF key NOT IN seen:
                    seen.insert(key)
                    matches.append(Match(pattern_id, offset, length))

        // Phase 2: Hex pattern verification with backtracking
        FOR (pattern_id, hex_pattern) IN hex_patterns:
            FOR m IN match_hex_pattern(data, hex_pattern):
                key = (pattern_id, m.offset)
                IF key NOT IN seen:
                    seen.insert(key)
                    matches.append(Match(pattern_id, m.offset, m.length))

        // Phase 3: Regex matching
        FOR (pattern_id, regex) IN regexes:
            FOR m IN regex.find_iter(data):
                key = (pattern_id, m.start)
                IF key NOT IN seen:
                    seen.insert(key)
                    matches.append(Match(pattern_id, m.start, m.end - m.start))

        // Sort by offset
        matches.sort_by(|m| (m.offset, m.pattern_id))
        RETURN matches
```

### Hex Pattern Matching with Backtracking
```pseudocode
FUNCTION match_hex_pattern_recursive(data, tokens, pos, token_idx) -> Option<Int>:
    // Base case: all tokens matched
    IF token_idx >= tokens.length:
        RETURN Some(pos)

    // Out of data but still have tokens
    IF pos >= data.length:
        RETURN None

    token = tokens[token_idx]

    MATCH token:
        Byte(b):
            IF data[pos] == b:
                RETURN match_hex_pattern_recursive(data, tokens, pos + 1, token_idx + 1)
            RETURN None

        Wildcard:
            RETURN match_hex_pattern_recursive(data, tokens, pos + 1, token_idx + 1)

        NibbleWildcard(high, low):
            byte = data[pos]
            IF high IS Some AND (byte >> 4) != high:
                RETURN None
            IF low IS Some AND (byte & 0x0F) != low:
                RETURN None
            RETURN match_hex_pattern_recursive(data, tokens, pos + 1, token_idx + 1)

        Jump(min, max):
            // BACKTRACKING: try all possible skip amounts
            max_skip = IF max IS Some THEN min(max, data.length - pos) ELSE data.length - pos

            FOR skip IN min..=max_skip:
                new_pos = pos + skip
                IF new_pos <= data.length:
                    result = match_hex_pattern_recursive(data, tokens, new_pos, token_idx + 1)
                    IF result IS Some:
                        RETURN result
            RETURN None

        Alternation(alternatives):
            // Try each alternative with backtracking
            FOR alt IN alternatives:
                result = match_alternation_tokens(data, alt, pos)
                IF result IS Some(end_pos):
                    final = match_hex_pattern_recursive(data, tokens, end_pos, token_idx + 1)
                    IF final IS Some:
                        RETURN final
            RETURN None

FUNCTION generate_xor_variants(pattern, min_key, max_key) -> List<Bytes>:
    variants = []
    FOR key IN min_key..=max_key:
        variant = pattern.map(|b| b XOR key)
        variants.append(variant)
    RETURN variants

FUNCTION generate_base64_variants(pattern) -> List<Bytes>:
    variants = []
    // Standard base64
    variants.append(base64_encode(pattern))
    // URL-safe base64
    variants.append(base64_url_encode(pattern))
    RETURN variants
```

---

## 5. Bytecode Compiler

**Source:** `r-yara-compiler/src/lib.rs` (~1,772 lines)

### Opcode Definitions
```pseudocode
ENUM Opcode:
    // Stack operations
    Nop, Halt, Pop, Dup, Swap

    // Push values
    PushBool(bool), PushInt(i64), PushFloat(f64)
    PushString(index), PushUndefined

    // Arithmetic
    Add, Sub, Mul, Div, Mod, Neg

    // Bitwise
    BitAnd, BitOr, BitXor, BitNot, Shl, Shr

    // Comparison
    Eq, Ne, Lt, Le, Gt, Ge

    // Logical
    And, Or, Not

    // String operations
    StringMatch(pattern_id)      // Check if pattern matched
    StringAt(pattern_id, offset) // Check at specific offset
    StringIn(pattern_id)         // Check in range
    StringCount(pattern_id)      // Get match count
    StringOffset(pattern_id, n)  // Get nth offset
    StringLength(pattern_id, n)  // Get nth length

    // Quantifiers
    OfLiteral(count)             // N of them
    OfPercent(percent)           // %N of them
    OfAll, OfAny, OfNone

    // Built-in functions
    Filesize, Entrypoint
    Uint8(offset), Uint16(offset), Uint32(offset)
    Int8(offset), Int16(offset), Int32(offset)
    Uint8BE(offset), Uint16BE(offset), Uint32BE(offset)

    // Control flow
    Jump(offset), JumpIfFalse(offset), JumpIfTrue(offset)

    // Module calls
    ModuleCall(module_id, function_id)

    // For loops
    ForInit, ForNext, ForEnd
    IteratorInit, IteratorNext, IteratorHasNext

    // String operations
    Contains, IContains, StartsWith, IStartsWith
    EndsWith, IEndsWith, IEquals, Matches
```

### Compiler Structure
```pseudocode
CLASS Compiler:
    code: List<Opcode>
    patterns: List<CompiledPattern>
    strings: List<String>
    rules: List<CompiledRule>
    imports: List<SmolStr>
    pattern_map: HashMap<SmolStr, PatternId>
    string_map: HashMap<String, Int>

    FUNCTION compile(ast: SourceFile) -> CompiledRules:
        compiler = Compiler::new()

        // Collect imports
        FOR import IN ast.imports:
            compiler.imports.append(import.module_name)

        // Compile each rule
        FOR rule IN ast.rules:
            compiler.compile_rule(rule)

        RETURN CompiledRules(
            code: compiler.code,
            patterns: compiler.patterns,
            strings: compiler.strings,
            rules: compiler.rules,
            imports: compiler.imports
        )

    FUNCTION compile_rule(rule: Rule):
        compiled = CompiledRule(
            name: rule.name,
            tags: rule.tags,
            metadata: compile_metadata(rule.meta),
            is_private: rule.modifiers.is_private,
            is_global: rule.modifiers.is_global,
            code_start: code.length,
            pattern_ids: []
        )

        // Compile strings into patterns
        FOR string_decl IN rule.strings:
            pattern_id = compile_string_pattern(string_decl)
            pattern_map.insert(string_decl.name, pattern_id)
            compiled.pattern_ids.append(pattern_id)

        // Compile condition
        compile_expression(rule.condition)
        emit(Opcode::Halt)

        compiled.code_len = code.length - compiled.code_start
        rules.append(compiled)

    FUNCTION compile_string_pattern(decl: StringDeclaration) -> PatternId:
        pattern_id = patterns.length

        MATCH decl.pattern:
            Text(text):
                bytes = serialize_text_pattern(text, decl.modifiers)
                kind = determine_pattern_kind(decl.modifiers)
                patterns.append(CompiledPattern(pattern_id, bytes, kind, decl.modifiers))

            Hex(hex):
                // Serialize hex tokens to ASCII hex format for matcher
                bytes = serialize_hex_tokens(hex.tokens)
                patterns.append(CompiledPattern(pattern_id, bytes, PatternKind::Hex, decl.modifiers))

            Regex(regex):
                bytes = regex.pattern.as_bytes()
                patterns.append(CompiledPattern(pattern_id, bytes, PatternKind::Regex, decl.modifiers))

        RETURN pattern_id

    FUNCTION serialize_hex_tokens(tokens) -> Bytes:
        // Output ASCII hex format: "4D 5A ?? [2-4] AA"
        result = []

        FOR token IN tokens:
            IF result.is_not_empty():
                result.append(' ')

            MATCH token:
                Byte(b):
                    result.extend(format("{:02X}", b).as_bytes())

                Wildcard:
                    result.extend("??".as_bytes())

                NibbleWildcard(high, low):
                    IF high IS Some:
                        result.extend(format("{}?", to_hex_char(high)).as_bytes())
                    ELSE:
                        result.extend(format("?{}", to_hex_char(low)).as_bytes())

                Jump(min, max):
                    IF max IS Some:
                        IF min == max:
                            result.extend(format("[{}]", min).as_bytes())
                        ELSE:
                            result.extend(format("[{}-{}]", min, max).as_bytes())
                    ELSE:
                        result.extend(format("[{}-]", min).as_bytes())

                Alternation(alts):
                    result.append('(')
                    FOR i, alt IN enumerate(alts):
                        IF i > 0:
                            result.append('|')
                        result.extend(serialize_hex_tokens(alt))
                    result.append(')')

        RETURN result

    FUNCTION compile_expression(expr: Expression):
        MATCH expr:
            Boolean(b):
                emit(Opcode::PushBool(b))

            Integer(n):
                emit(Opcode::PushInt(n))

            Float(f):
                emit(Opcode::PushFloat(f))

            String(s):
                idx = intern_string(s)
                emit(Opcode::PushString(idx))

            StringRef(name):
                pattern_id = pattern_map.get(name)
                emit(Opcode::StringMatch(pattern_id))

            StringCount(expr):
                pattern_id = pattern_map.get(expr.name)
                emit(Opcode::StringCount(pattern_id))

            StringOffset(expr):
                pattern_id = pattern_map.get(expr.name)
                IF expr.index IS Some:
                    compile_expression(expr.index)
                    emit(Opcode::StringOffset(pattern_id, -1))  // -1 = from stack
                ELSE:
                    emit(Opcode::StringOffset(pattern_id, 0))

            Filesize:
                emit(Opcode::Filesize)

            Entrypoint:
                emit(Opcode::Entrypoint)

            Binary(bin):
                compile_expression(bin.left)

                // Short-circuit for AND/OR
                IF bin.op == And:
                    jump_addr = emit(Opcode::JumpIfFalse(0))  // placeholder
                    emit(Opcode::Pop)
                    compile_expression(bin.right)
                    patch_jump(jump_addr)
                ELSE IF bin.op == Or:
                    jump_addr = emit(Opcode::JumpIfTrue(0))
                    emit(Opcode::Pop)
                    compile_expression(bin.right)
                    patch_jump(jump_addr)
                ELSE:
                    compile_expression(bin.right)
                    emit(binary_op_to_opcode(bin.op))

            Unary(un):
                compile_expression(un.operand)
                emit(unary_op_to_opcode(un.op))

            FunctionCall(call):
                // Push arguments
                FOR arg IN call.arguments:
                    compile_expression(arg)

                // Emit call
                IF is_builtin_function(call.function):
                    emit(builtin_to_opcode(call.function, call.arguments.length))
                ELSE:
                    module_id = get_module_id(call.function.parts[0])
                    func_id = get_function_id(call.function)
                    emit(Opcode::ModuleCall(module_id, func_id))

            Quantifier(q):
                compile_quantifier(q)

            For(for_expr):
                compile_for_expression(for_expr)

            At(at_expr):
                pattern_id = pattern_map.get(at_expr.string)
                compile_expression(at_expr.offset)
                emit(Opcode::StringAt(pattern_id))

            In(in_expr):
                compile_expression(in_expr.expr)
                compile_expression(in_expr.range.start)
                compile_expression(in_expr.range.end)
                emit(Opcode::InRange)
```

### Binary Serialization
```pseudocode
IMPL CompiledRules:
    FUNCTION save(path: Path) -> Result:
        file = File::create(path)
        writer = BufWriter::new(file)
        bincode::serialize_into(writer, self)

    FUNCTION load(path: Path) -> Result<CompiledRules>:
        file = File::open(path)
        reader = BufReader::new(file)
        RETURN bincode::deserialize_from(reader)

    FUNCTION to_bytes() -> Result<Bytes>:
        RETURN bincode::serialize(self)

    FUNCTION from_bytes(data: Bytes) -> Result<CompiledRules>:
        RETURN bincode::deserialize(data)
```

---

## 6. Virtual Machine

**Source:** `r-yara-vm/src/lib.rs` (~1,655 lines)

### VM Structure
```pseudocode
CLASS VM:
    code: List<Opcode>
    strings: List<String>
    stack: List<Value>
    pc: Int                    // Program counter

    FUNCTION execute(rules: CompiledRules, context: ScanContext) -> List<RuleMatch>:
        matches = []

        FOR rule IN rules.rules:
            IF evaluate_rule(rule, context):
                match = RuleMatch(
                    rule_name: rule.name,
                    tags: rule.tags,
                    metadata: rule.metadata,
                    strings: get_string_matches(rule, context)
                )
                matches.append(match)

        RETURN matches

    FUNCTION evaluate_rule(rule: CompiledRule, context: ScanContext) -> Bool:
        stack.clear()
        pc = rule.code_start

        WHILE pc < rule.code_start + rule.code_len:
            opcode = code[pc]
            pc += 1

            MATCH opcode:
                Halt:
                    BREAK

                Nop:
                    CONTINUE

                Pop:
                    stack.pop()

                Dup:
                    stack.push(stack.top())

                Swap:
                    a = stack.pop()
                    b = stack.pop()
                    stack.push(a)
                    stack.push(b)

                // Push operations
                PushBool(b):
                    stack.push(Value::Bool(b))

                PushInt(n):
                    stack.push(Value::Int(n))

                PushFloat(f):
                    stack.push(Value::Float(f))

                PushString(idx):
                    stack.push(Value::String(strings[idx]))

                PushUndefined:
                    stack.push(Value::Undefined)

                // Arithmetic
                Add:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(a + b)

                Sub:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(a - b)

                Mul:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(a * b)

                Div:
                    b = stack.pop()
                    a = stack.pop()
                    IF b == 0:
                        stack.push(Value::Undefined)
                    ELSE:
                        stack.push(a / b)

                Mod:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(a % b)

                Neg:
                    a = stack.pop()
                    stack.push(-a)

                // Bitwise operations
                BitAnd:
                    b = stack.pop().as_int()
                    a = stack.pop().as_int()
                    stack.push(Value::Int(a & b))

                BitOr:
                    b = stack.pop().as_int()
                    a = stack.pop().as_int()
                    stack.push(Value::Int(a | b))

                BitXor:
                    b = stack.pop().as_int()
                    a = stack.pop().as_int()
                    stack.push(Value::Int(a ^ b))

                BitNot:
                    a = stack.pop().as_int()
                    stack.push(Value::Int(!a))

                Shl:
                    b = stack.pop().as_int()
                    a = stack.pop().as_int()
                    stack.push(Value::Int(a << b))

                Shr:
                    b = stack.pop().as_int()
                    a = stack.pop().as_int()
                    stack.push(Value::Int(a >> b))

                // Comparison
                Eq:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(Value::Bool(a == b))

                Ne:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(Value::Bool(a != b))

                Lt:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(Value::Bool(a < b))

                Le:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(Value::Bool(a <= b))

                Gt:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(Value::Bool(a > b))

                Ge:
                    b = stack.pop()
                    a = stack.pop()
                    stack.push(Value::Bool(a >= b))

                // Logical
                And:
                    b = stack.pop().as_bool()
                    a = stack.pop().as_bool()
                    stack.push(Value::Bool(a AND b))

                Or:
                    b = stack.pop().as_bool()
                    a = stack.pop().as_bool()
                    stack.push(Value::Bool(a OR b))

                Not:
                    a = stack.pop().as_bool()
                    stack.push(Value::Bool(NOT a))

                // String matching
                StringMatch(pattern_id):
                    matched = context.pattern_matches(pattern_id)
                    stack.push(Value::Bool(matched))

                StringAt(pattern_id):
                    offset = stack.pop().as_int()
                    matched = context.pattern_matches_at(pattern_id, offset)
                    stack.push(Value::Bool(matched))

                StringIn(pattern_id):
                    end = stack.pop().as_int()
                    start = stack.pop().as_int()
                    matched = context.pattern_matches_in(pattern_id, start, end)
                    stack.push(Value::Bool(matched))

                StringCount(pattern_id):
                    count = context.pattern_match_count(pattern_id)
                    stack.push(Value::Int(count))

                StringOffset(pattern_id, n):
                    idx = IF n < 0 THEN stack.pop().as_int() ELSE n
                    offset = context.pattern_offset(pattern_id, idx)
                    IF offset IS Some:
                        stack.push(Value::Int(offset))
                    ELSE:
                        stack.push(Value::Undefined)

                StringLength(pattern_id, n):
                    idx = IF n < 0 THEN stack.pop().as_int() ELSE n
                    length = context.pattern_length(pattern_id, idx)
                    IF length IS Some:
                        stack.push(Value::Int(length))
                    ELSE:
                        stack.push(Value::Undefined)

                // Built-in functions
                Filesize:
                    stack.push(Value::Int(context.data.length))

                Entrypoint:
                    ep = context.entrypoint()
                    IF ep IS Some:
                        stack.push(Value::Int(ep))
                    ELSE:
                        stack.push(Value::Undefined)

                Uint8(offset):
                    off = IF offset < 0 THEN stack.pop().as_int() ELSE offset
                    IF off >= 0 AND off < context.data.length:
                        stack.push(Value::Int(context.data[off]))
                    ELSE:
                        stack.push(Value::Undefined)

                Uint16(offset):
                    off = IF offset < 0 THEN stack.pop().as_int() ELSE offset
                    IF off >= 0 AND off + 1 < context.data.length:
                        val = context.data[off] | (context.data[off+1] << 8)
                        stack.push(Value::Int(val))
                    ELSE:
                        stack.push(Value::Undefined)

                Uint32(offset):
                    off = IF offset < 0 THEN stack.pop().as_int() ELSE offset
                    IF off >= 0 AND off + 3 < context.data.length:
                        val = read_u32_le(context.data[off:off+4])
                        stack.push(Value::Int(val))
                    ELSE:
                        stack.push(Value::Undefined)

                // Control flow
                Jump(offset):
                    pc = rule.code_start + offset

                JumpIfFalse(offset):
                    cond = stack.top().as_bool()
                    IF NOT cond:
                        pc = rule.code_start + offset

                JumpIfTrue(offset):
                    cond = stack.top().as_bool()
                    IF cond:
                        pc = rule.code_start + offset

                // Module calls
                ModuleCall(module_id, func_id):
                    result = call_module_function(module_id, func_id, stack, context)
                    stack.push(result)

                // Quantifiers
                OfAll:
                    count = stack.pop().as_int()
                    patterns = stack.pop().as_pattern_list()
                    matched = 0
                    FOR p IN patterns:
                        IF context.pattern_matches(p):
                            matched += 1
                    stack.push(Value::Bool(matched == patterns.length))

                OfAny:
                    patterns = stack.pop().as_pattern_list()
                    result = false
                    FOR p IN patterns:
                        IF context.pattern_matches(p):
                            result = true
                            BREAK
                    stack.push(Value::Bool(result))

                OfNone:
                    patterns = stack.pop().as_pattern_list()
                    result = true
                    FOR p IN patterns:
                        IF context.pattern_matches(p):
                            result = false
                            BREAK
                    stack.push(Value::Bool(result))

                OfLiteral(n):
                    patterns = stack.pop().as_pattern_list()
                    matched = 0
                    FOR p IN patterns:
                        IF context.pattern_matches(p):
                            matched += 1
                    stack.push(Value::Bool(matched >= n))

                OfPercent(percent):
                    patterns = stack.pop().as_pattern_list()
                    matched = 0
                    FOR p IN patterns:
                        IF context.pattern_matches(p):
                            matched += 1
                    required = (patterns.length * percent) / 100
                    stack.push(Value::Bool(matched >= required))

                // String operations
                Contains:
                    needle = stack.pop().as_string()
                    haystack = stack.pop().as_string()
                    stack.push(Value::Bool(haystack.contains(needle)))

                IContains:
                    needle = stack.pop().as_string().to_lowercase()
                    haystack = stack.pop().as_string().to_lowercase()
                    stack.push(Value::Bool(haystack.contains(needle)))

                StartsWith:
                    prefix = stack.pop().as_string()
                    str = stack.pop().as_string()
                    stack.push(Value::Bool(str.starts_with(prefix)))

                IStartsWith:
                    prefix = stack.pop().as_string().to_lowercase()
                    str = stack.pop().as_string().to_lowercase()
                    stack.push(Value::Bool(str.starts_with(prefix)))

                EndsWith:
                    suffix = stack.pop().as_string()
                    str = stack.pop().as_string()
                    stack.push(Value::Bool(str.ends_with(suffix)))

                IEndsWith:
                    suffix = stack.pop().as_string().to_lowercase()
                    str = stack.pop().as_string().to_lowercase()
                    stack.push(Value::Bool(str.ends_with(suffix)))

                Matches:
                    pattern = stack.pop().as_string()
                    str = stack.pop().as_string()
                    regex = Regex::new(pattern)
                    stack.push(Value::Bool(regex.is_match(str)))

        // Result is on top of stack
        IF stack.is_empty():
            RETURN false
        RETURN stack.pop().as_bool()
```

---

## 7. File Format Modules

**Source:** `r-yara-modules/src/*.rs` (~4,530 lines)

### PE Module
```pseudocode
MODULE pe:
    FUNCTION is_pe(data) -> Bool:
        IF data.length < 64:
            RETURN false

        // Check DOS header magic "MZ"
        IF data[0:2] != [0x4D, 0x5A]:
            RETURN false

        // Get PE header offset from e_lfanew
        pe_offset = read_u32_le(data[60:64])
        IF pe_offset + 4 > data.length:
            RETURN false

        // Check PE signature "PE\0\0"
        RETURN data[pe_offset:pe_offset+4] == [0x50, 0x45, 0x00, 0x00]

    FUNCTION is_dll(data) -> Bool:
        IF NOT is_pe(data):
            RETURN false

        characteristics = get_characteristics(data)
        RETURN (characteristics & 0x2000) != 0  // IMAGE_FILE_DLL

    FUNCTION is_64bit(data) -> Bool:
        IF NOT is_pe(data):
            RETURN false

        pe_offset = read_u32_le(data[60:64])
        machine = read_u16_le(data[pe_offset + 4:pe_offset + 6])
        RETURN machine == 0x8664  // IMAGE_FILE_MACHINE_AMD64

    FUNCTION machine(data) -> Int:
        IF NOT is_pe(data):
            RETURN 0
        pe_offset = read_u32_le(data[60:64])
        RETURN read_u16_le(data[pe_offset + 4:pe_offset + 6])

    FUNCTION number_of_sections(data) -> Int:
        IF NOT is_pe(data):
            RETURN 0
        pe_offset = read_u32_le(data[60:64])
        RETURN read_u16_le(data[pe_offset + 6:pe_offset + 8])

    FUNCTION timestamp(data) -> Int:
        IF NOT is_pe(data):
            RETURN 0
        pe_offset = read_u32_le(data[60:64])
        RETURN read_u32_le(data[pe_offset + 8:pe_offset + 12])

    FUNCTION section_name(data, index) -> String:
        sections = get_section_headers(data)
        IF index < sections.length:
            RETURN sections[index].name
        RETURN ""

    FUNCTION get_imports(data) -> List<Import>:
        IF NOT is_pe(data):
            RETURN []

        pe_offset = read_u32_le(data[60:64])
        optional_hdr_offset = pe_offset + 24

        // Get import directory RVA
        import_rva = read_u32_le(data[optional_hdr_offset + 104:])
        import_size = read_u32_le(data[optional_hdr_offset + 108:])

        IF import_rva == 0 OR import_size == 0:
            RETURN []

        // Convert RVA to file offset and parse import descriptors
        import_offset = rva_to_offset(data, import_rva)
        imports = []

        WHILE true:
            descriptor = read_import_descriptor(data, import_offset)
            IF descriptor.name_rva == 0:
                BREAK

            dll_name = read_string(data, rva_to_offset(data, descriptor.name_rva))
            functions = parse_import_functions(data, descriptor)
            imports.append(Import(dll_name, functions))

            import_offset += 20  // sizeof(IMAGE_IMPORT_DESCRIPTOR)

        RETURN imports
```

### ELF Module
```pseudocode
MODULE elf:
    FUNCTION is_elf(data) -> Bool:
        IF data.length < 16:
            RETURN false

        // Check ELF magic: 0x7F 'E' 'L' 'F'
        RETURN data[0:4] == [0x7F, 0x45, 0x4C, 0x46]

    FUNCTION is_64bit(data) -> Bool:
        IF NOT is_elf(data):
            RETURN false
        RETURN data[4] == 2  // ELFCLASS64

    FUNCTION machine(data) -> Int:
        IF NOT is_elf(data):
            RETURN 0

        offset = IF is_64bit(data) THEN 18 ELSE 18
        RETURN read_u16(data[offset:offset+2], is_big_endian(data))

    FUNCTION type(data) -> Int:
        IF NOT is_elf(data):
            RETURN 0
        RETURN read_u16(data[16:18], is_big_endian(data))

    FUNCTION entry_point(data) -> Int:
        IF NOT is_elf(data):
            RETURN 0

        IF is_64bit(data):
            RETURN read_u64(data[24:32], is_big_endian(data))
        ELSE:
            RETURN read_u32(data[24:28], is_big_endian(data))

    FUNCTION number_of_sections(data) -> Int:
        IF NOT is_elf(data):
            RETURN 0

        IF is_64bit(data):
            RETURN read_u16(data[60:62], is_big_endian(data))
        ELSE:
            RETURN read_u16(data[48:50], is_big_endian(data))

    FUNCTION get_symbols(data) -> List<Symbol>:
        // Parse .symtab and .dynsym sections
        sections = get_section_headers(data)
        symbols = []

        FOR section IN sections:
            IF section.type == SHT_SYMTAB OR section.type == SHT_DYNSYM:
                symbols.extend(parse_symbol_table(data, section))

        RETURN symbols
```

### Hash Module
```pseudocode
MODULE hash:
    FUNCTION md5(data, offset, size) -> String:
        slice = validate_range(data, offset, size)
        digest = MD5::digest(slice)
        RETURN hex_encode(digest)

    FUNCTION sha1(data, offset, size) -> String:
        slice = validate_range(data, offset, size)
        digest = SHA1::digest(slice)
        RETURN hex_encode(digest)

    FUNCTION sha256(data, offset, size) -> String:
        slice = validate_range(data, offset, size)
        digest = SHA256::digest(slice)
        RETURN hex_encode(digest)

    FUNCTION sha512(data, offset, size) -> String:
        slice = validate_range(data, offset, size)
        digest = SHA512::digest(slice)
        RETURN hex_encode(digest)

    FUNCTION crc32(data, offset, size) -> Int:
        slice = validate_range(data, offset, size)
        RETURN CRC32::checksum(slice)

    FUNCTION checksum32(data, offset, size) -> Int:
        slice = validate_range(data, offset, size)
        sum = 0
        FOR byte IN slice:
            sum = (sum + byte) & 0xFFFFFFFF
        RETURN sum
```

### Math Module
```pseudocode
MODULE math:
    FUNCTION entropy(data, offset, size) -> Float:
        slice = validate_range(data, offset, size)

        // Count byte frequencies
        freq = Array[256] of 0
        FOR byte IN slice:
            freq[byte] += 1

        // Calculate Shannon entropy
        entropy = 0.0
        FOR count IN freq:
            IF count > 0:
                p = count / slice.length
                entropy -= p * log2(p)

        RETURN entropy

    FUNCTION mean(data, offset, size) -> Float:
        slice = validate_range(data, offset, size)
        sum = 0
        FOR byte IN slice:
            sum += byte
        RETURN sum / slice.length

    FUNCTION deviation(data, offset, size, mean_value) -> Float:
        slice = validate_range(data, offset, size)

        variance = 0.0
        FOR byte IN slice:
            diff = byte - mean_value
            variance += diff * diff
        variance /= slice.length

        RETURN sqrt(variance)

    FUNCTION serial_correlation(data, offset, size) -> Float:
        slice = validate_range(data, offset, size)
        IF slice.length < 2:
            RETURN 0.0

        mean_val = mean(data, offset, size)

        numerator = 0.0
        denominator = 0.0
        FOR i IN 0..slice.length-1:
            xi = slice[i] - mean_val
            xi1 = slice[i+1] - mean_val
            numerator += xi * xi1
            denominator += xi * xi

        IF denominator == 0:
            RETURN 0.0
        RETURN numerator / denominator

    FUNCTION monte_carlo_pi(data, offset, size) -> Float:
        slice = validate_range(data, offset, size)

        // Interpret consecutive byte pairs as (x, y) coordinates
        inside_circle = 0
        total_points = slice.length / 2

        FOR i IN 0..total_points:
            x = slice[i * 2] / 255.0
            y = slice[i * 2 + 1] / 255.0
            IF x*x + y*y <= 1.0:
                inside_circle += 1

        RETURN 4.0 * inside_circle / total_points

    FUNCTION count(byte, data, offset, size) -> Int:
        slice = validate_range(data, offset, size)
        count = 0
        FOR b IN slice:
            IF b == byte:
                count += 1
        RETURN count

    FUNCTION percentage(byte, data, offset, size) -> Float:
        slice = validate_range(data, offset, size)
        IF slice.length == 0:
            RETURN 0.0
        RETURN count(byte, data, offset, size) * 100.0 / slice.length
```

---

## 8. Scanner Pipeline

**Source:** `r-yara-scanner/src/*.rs` (~3,510 lines)

### Complete Scan Pipeline
```pseudocode
FUNCTION scan_bytes(rules_source, data) -> List<RuleMatch>:
    // Step 1: Parse rules
    ast = parse(rules_source)

    // Step 2: Compile to bytecode
    compiled = Compiler::compile(ast)

    // Step 3: Build pattern matcher
    patterns = compiled.patterns.map(|p| Pattern(p.id, p.bytes, p.kind, p.modifiers))
    matcher = PatternMatcher::new(patterns)

    // Step 4: Scan for pattern matches
    matches = matcher.scan(data)

    // Step 5: Build scan context
    context = ScanContext::new(data, matches, compiled)

    // Step 6: Execute VM for each rule
    vm = VM::new(compiled.code, compiled.strings)
    rule_matches = vm.execute(compiled.rules, context)

    RETURN rule_matches

CLASS Scanner:
    compiled: CompiledRules
    matcher: PatternMatcher

    FUNCTION new(rules_source) -> Scanner:
        ast = parse(rules_source)
        compiled = Compiler::compile(ast)
        patterns = compiled.patterns.map(to_pattern)
        matcher = PatternMatcher::new(patterns)
        RETURN Scanner(compiled, matcher)

    FUNCTION scan_bytes(data) -> List<RuleMatch>:
        matches = matcher.scan(data)
        context = ScanContext::new(data, matches, compiled)
        vm = VM::new(compiled.code, compiled.strings)
        RETURN vm.execute(compiled.rules, context)

    FUNCTION scan_file(path) -> List<RuleMatch>:
        data = read_file(path)
        RETURN scan_bytes(data)

    FUNCTION scan_directory(path, recursive) -> List<DirectoryScanResult>:
        results = []

        walker = IF recursive THEN WalkDir::new(path) ELSE WalkDir::new(path).max_depth(1)

        FOR entry IN walker:
            IF entry.is_file():
                TRY:
                    matches = scan_file(entry.path)
                    results.append(DirectoryScanResult(entry.path, matches, None))
                CATCH e:
                    results.append(DirectoryScanResult(entry.path, [], Some(e)))

        RETURN results
```

### Process Memory Scanning (Linux)
```pseudocode
CLASS ProcessScanner:
    scanner: Scanner

    FUNCTION scan_process(pid: Int, options: ProcessScanOptions) -> ProcessScanResult:
        // Open process memory
        mem_path = format("/proc/{}/mem", pid)
        mem_file = File::open(mem_path)

        // Read memory maps
        maps_path = format("/proc/{}/maps", pid)
        maps = parse_proc_maps(read_file(maps_path))

        // Filter regions based on options
        regions = []
        FOR region IN maps:
            IF should_scan_region(region, options):
                regions.append(region)

        // Scan each region
        matches = []
        FOR region IN regions:
            TRY:
                mem_file.seek(region.start)
                data = mem_file.read(region.size)
                region_matches = scanner.scan_bytes(data)

                FOR m IN region_matches:
                    matches.append(ProcessRuleMatch(
                        rule_match: m,
                        region: region,
                        absolute_offset: region.start + m.offset
                    ))
            CATCH e:
                // Skip unreadable regions
                CONTINUE

        RETURN ProcessScanResult(pid, matches, regions)

    FUNCTION parse_proc_maps(content: String) -> List<MemoryRegion>:
        regions = []

        FOR line IN content.lines():
            // Format: address perms offset dev inode pathname
            // Example: 00400000-00452000 r-xp 00000000 08:01 123456 /bin/cat
            parts = line.split_whitespace()

            addresses = parts[0].split('-')
            start = parse_hex(addresses[0])
            end = parse_hex(addresses[1])

            perms = parts[1]
            readable = perms[0] == 'r'
            writable = perms[1] == 'w'
            executable = perms[2] == 'x'

            pathname = IF parts.length > 5 THEN parts[5] ELSE ""

            regions.append(MemoryRegion(
                start, end,
                readable, writable, executable,
                pathname
            ))

        RETURN regions
```

### Streaming Scanner
```pseudocode
CLASS StreamingScanner:
    scanner: Scanner

    ASYNC FUNCTION scan_directory_stream(path, sender: Channel<ScanEvent>):
        walker = WalkDir::new(path)
        total_files = 0
        matched_files = 0

        FOR entry IN walker:
            IF entry.is_file():
                total_files += 1
                file_path = entry.path

                sender.send(ScanEvent::FileStart(file_path))

                TRY:
                    matches = scanner.scan_file(file_path)

                    FOR m IN matches:
                        sender.send(ScanEvent::Match(file_path, m.rule_name))

                    IF matches.is_not_empty():
                        matched_files += 1

                    sender.send(ScanEvent::FileComplete(file_path, matches.length))
                CATCH e:
                    sender.send(ScanEvent::Error(file_path, e))

        sender.send(ScanEvent::Complete(total_files, matched_files))

    FUNCTION scan_with_progress(data, callback: ProgressCallback) -> List<RuleMatch>:
        // Pre-scan progress
        callback(ScanProgress::Matching(0, data.length))

        matches = matcher.scan(data)
        callback(ScanProgress::Matching(data.length, data.length))

        // Evaluation progress
        callback(ScanProgress::Evaluating(0, compiled.rules.length))

        rule_matches = []
        FOR i, rule IN enumerate(compiled.rules):
            result = evaluate_rule(rule, matches, data)
            IF result:
                rule_matches.append(result)
            callback(ScanProgress::Evaluating(i + 1, compiled.rules.length))

        callback(ScanProgress::Complete(rule_matches.length))
        RETURN rule_matches
```

---

## 9. Gateway & Load Balancing

**Source:** `r-yara-pyro/src/gateway/*.rs` (~1,142 lines)

### Circuit Breaker Pattern
```pseudocode
ENUM CircuitState:
    Closed      // Normal operation, requests flow through
    Open        // Failures exceeded threshold, reject all requests
    HalfOpen    // Testing if service recovered

STRUCT CircuitBreakerConfig:
    failure_threshold: Int      // Failures before opening (default: 5)
    reset_timeout_secs: Int     // Time before testing recovery (default: 30)
    success_threshold: Int      // Successes to close from half-open (default: 3)
    window_secs: Int            // Time window for counting failures (default: 60)

CLASS CircuitBreaker:
    config: CircuitBreakerConfig
    state: AtomicState
    failures: AtomicU64
    successes: AtomicU64
    last_failure: Option<Instant>
    last_state_change: Instant

    FUNCTION should_allow() -> Bool:
        MATCH state:
            Closed:
                RETURN true

            Open:
                // Check if timeout elapsed
                IF last_state_change.elapsed() >= config.reset_timeout_secs:
                    transition_to(HalfOpen)
                    RETURN true
                RETURN false

            HalfOpen:
                RETURN true

    FUNCTION record_success():
        MATCH state:
            Closed:
                failures.store(0)

            HalfOpen:
                successes.fetch_add(1)
                IF successes >= config.success_threshold:
                    transition_to(Closed)

            Open:
                // Ignore

    FUNCTION record_failure():
        last_failure = Instant::now()

        MATCH state:
            Closed:
                failures.fetch_add(1)
                IF failures >= config.failure_threshold:
                    transition_to(Open)

            HalfOpen:
                // Single failure reopens circuit
                transition_to(Open)

            Open:
                // Already open

    FUNCTION transition_to(new_state: CircuitState):
        IF state != new_state:
            state = new_state
            last_state_change = Instant::now()
            failures.store(0)
            successes.store(0)
```

### Load Balancing
```pseudocode
ENUM LoadBalanceStrategy:
    RoundRobin
    Random
    LeastConnections

CLASS Router:
    routes: List<Route>
    services: HashMap<String, List<ServiceInstance>>
    strategy: LoadBalanceStrategy
    round_robin_indices: HashMap<String, AtomicUsize>

    FUNCTION get_service_url(service_name) -> Option<String>:
        instances = services.get(service_name)
        IF instances IS None OR instances.is_empty():
            RETURN None

        // Filter healthy instances
        healthy = instances.filter(|i| i.healthy)
        IF healthy.is_empty():
            RETURN None

        // Select instance based on strategy
        MATCH strategy:
            RoundRobin:
                idx = round_robin_indices.get(service_name).fetch_add(1)
                instance = healthy[idx % healthy.length]

            Random:
                instance = healthy[random(0, healthy.length)]

            LeastConnections:
                instance = healthy.min_by(|i| i.connection_count())

        RETURN Some(instance.url)

    FUNCTION route_request(path, method) -> Option<Route>:
        FOR route IN routes:
            IF route.matches(path, method):
                RETURN Some(route)
        RETURN None

STRUCT RetryConfig:
    max_retries: Int            // Default: 3
    base_delay_ms: Int          // Default: 100
    max_delay_ms: Int           // Default: 5000
    backoff_multiplier: Float   // Default: 2.0

    FUNCTION delay_for_attempt(attempt: Int) -> Duration:
        delay = base_delay_ms * (backoff_multiplier ^ attempt)
        RETURN min(delay, max_delay_ms)

ASYNC FUNCTION execute_with_retry(request, config: RetryConfig) -> Result<Response>:
    FOR attempt IN 0..config.max_retries:
        TRY:
            response = send_request(request)
            RETURN Ok(response)
        CATCH e:
            IF attempt < config.max_retries - 1:
                delay = config.delay_for_attempt(attempt)
                sleep(delay)
            ELSE:
                RETURN Err(e)
```

### Gateway Core
```pseudocode
CLASS Gateway:
    config: RYaraConfig
    services: HashMap<String, ServiceEndpoint>
    stats: GatewayStats
    scanner: ScannerWorker
    transcoder: TranscoderWorker

    ASYNC FUNCTION route_request(service, method, path, data) -> JsonValue:
        stats.requests_total += 1

        // Handle local services
        MATCH service:
            "scanner":
                result = handle_scanner_request(path, data)
            "transcoder":
                result = handle_transcoder_request(path, data)
            _:
                // Proxy to external service
                result = TRY proxy_to_service(service, method, path, data)
                       CATCH e RETURN error_response(e)

        IF result.success:
            stats.requests_success += 1
        ELSE:
            stats.requests_failed += 1

        RETURN result

    ASYNC FUNCTION handle_scanner_request(path, data) -> JsonValue:
        task_type = MATCH path:
            "/scan/file" -> TaskType::ScanFile
            "/scan/data" -> TaskType::ScanData
            "/validate" -> TaskType::ValidateRule
            "/compile" -> TaskType::CompileRules
            _ -> RETURN error("Unknown scanner path")

        task = WorkerTask::new(task_type, data)
        result = scanner.process_task(task)

        RETURN json({
            "success": result.success,
            "data": result.data,
            "error": result.error
        })

    ASYNC FUNCTION proxy_to_service(service, method, path, data) -> Result<JsonValue>:
        endpoint = services.get(service)?

        IF NOT endpoint.healthy:
            RETURN Err("Service unhealthy")

        url = format("{}{}", endpoint.url, path)

        response = MATCH method:
            "GET" -> http_client.get(url).send()
            "POST" -> http_client.post(url).json(data).send()
            "PUT" -> http_client.put(url).json(data).send()
            "DELETE" -> http_client.delete(url).send()

        RETURN response.json()
```

---

## 10. MCP Server Integration

**Source:** `mcp_server_ryara/server.py` (~610 lines)

### MCP Server Structure
```pseudocode
CLASS RYaraMCPServer:
    name: "r-yara-mcp"
    version: "0.1.0"

    capabilities:
        resources: true
        tools: true
        prompts: true

    resources:
        "r-yara://dictionary": R-YARA function mapping dictionary
        "r-yara://rules/*": YARA rule files
        "r-yara://config": Server configuration

    tools:
        "r-yara-lookup": Look up symbol in dictionary
        "r-yara-search": Search dictionary entries
        "r-yara-scan-feeds": Scan web feeds for YARA rules
        "r-yara-validate-rule": Validate YARA rule syntax
        "r-yara-transcode": Transcode rules to/from codenames
        "r-yara-stream-rules": Stream rules for workers
        "r-yara-stats": Get system statistics

    prompts:
        "analyze-malware": Analyze file for malware
        "generate-rule": Generate YARA rule for threat

    ASYNC FUNCTION handle_call_tool(name, arguments):
        MATCH name:
            "r-yara-lookup":
                query = arguments["query"]
                entry = dictionary.find(query)
                RETURN entry OR "Not found"

            "r-yara-search":
                query = arguments["query"]
                limit = arguments.get("limit", 20)
                results = dictionary.search(query, limit)
                RETURN results

            "r-yara-validate-rule":
                rule_content = arguments["rule_content"]
                errors = []
                IF "rule " NOT IN rule_content:
                    errors.append("Missing 'rule' keyword")
                IF "condition:" NOT IN rule_content:
                    errors.append("Missing condition section")
                RETURN { valid: errors.is_empty(), errors: errors }

            "r-yara-transcode":
                rule = arguments["rule_content"]
                direction = arguments.get("direction", "to_codename")

                FOR mapping IN dictionary:
                    IF direction == "to_codename":
                        rule = rule.replace(mapping.symbol, mapping.codename)
                    ELSE:
                        rule = rule.replace(mapping.codename, mapping.symbol)

                RETURN { transcoded: rule }

            "r-yara-scan-feeds":
                use_case = arguments.get("use_case", "all")
                // Execute Rust binary if available
                IF rust_binary_exists():
                    result = execute("r-yara-feed", use_case)
                    RETURN parse_json(result)
                RETURN { status: "binary_not_available" }

            "r-yara-stream-rules":
                source = arguments.get("source", "all")
                format = arguments.get("format", "json")
                RETURN {
                    stream_endpoint: "/api/v2/r-yara/stream/rules",
                    protocol: "websocket",
                    status: "ready"
                }

            "r-yara-stats":
                RETURN {
                    dictionary: {
                        total_entries: dictionary.length,
                        functions: dictionary.count_by_kind("function"),
                        modules: dictionary.count_by_kind("module")
                    },
                    system: {
                        rust_available: file_exists("r-yara"),
                        api_available: file_exists("r-yara-server")
                    },
                    timestamp: now()
                }

    ASYNC FUNCTION run_stdio():
        WHILE true:
            request = read_json_line(stdin)
            method = request["method"]
            params = request["params"]

            MATCH method:
                "initialize":
                    response = handle_initialize(params)
                "resources/list":
                    response = handle_list_resources(params)
                "resources/read":
                    response = handle_read_resource(params)
                "tools/list":
                    response = handle_list_tools(params)
                "tools/call":
                    response = handle_call_tool(params)
                "prompts/list":
                    response = handle_list_prompts(params)
                _:
                    response = error("Unknown method")

            write_json_line(stdout, response)
```

---

## Appendix: Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           R-YARA SCAN PIPELINE                           │
└──────────────────────────────────────────────────────────────────────────┘

┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   YARA      │    │   Lexer     │    │   Parser    │    │    AST      │
│   Rules     │───▶│  (Logos)    │───▶│ (Recursive  │───▶│  (Typed     │
│   Source    │    │  Tokenizer  │    │  Descent)   │    │   Tree)     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                                │
                                                                ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Match     │◀───│  Compiled   │◀───│  Compiler   │◀───│   Symbol    │
│  Results    │    │   Rules     │    │ (Bytecode   │    │  Resolution │
│             │    │  (Bincode)  │    │  Generation)│    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                  │
      │                  ▼
      │           ┌─────────────┐
      │           │   Pattern   │
      │           │   Matcher   │
      │           │ (Aho-Corasick│
      │           │  + Regex)   │
      │           └─────────────┘
      │                  │
      ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Scan      │───▶│     VM      │───▶│   Module    │───▶│   Rule      │
│  Context    │    │  (Stack     │    │   Calls     │    │  Matches    │
│             │    │   Machine)  │    │ (PE/ELF/Hash│    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      ▲
      │
┌─────────────┐
│   Target    │
│   Data      │
│  (File/Mem) │
└─────────────┘
```

---

## Document Metadata

- **Generation Method:** Manual analysis of Rust source code
- **Crates Analyzed:** 11 (parser, matcher, compiler, vm, modules, scanner, store, api, feed-scanner, cli, pyro)
- **Total Lines Documented:** ~25,700
- **Pseudocode Style:** Language-agnostic, implementation-focused
- **Use Cases:** Training data, audit verification, documentation, reimplementation reference

---

*End of Document*
