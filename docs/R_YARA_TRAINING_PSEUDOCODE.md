# R-YARA Training: Pattern Matching Engine Pseudocode

**Purpose:** Document YARA and YARA-X internals as pseudocode to train R-YARA to surpass both implementations.

**Goal:** Build a superior Rust-native pattern matching engine with:
- Faster Aho-Corasick implementation
- More efficient bytecode VM
- Better module extensibility
- Superior parallelization

---

## Part 1: Core Architecture Overview

### YARA Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        YARA PROCESSING PIPELINE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────────┐ │
│   │  RULES   │───▶│  LEXER   │───▶│  PARSER  │───▶│     COMPILER     │ │
│   │  (.yar)  │    │  (Flex)  │    │  (Bison) │    │  (Bytecode Gen)  │ │
│   └──────────┘    └──────────┘    └──────────┘    └────────┬─────────┘ │
│                                                             │           │
│                                                             ▼           │
│   ┌──────────┐    ┌──────────────────────────────────────────────────┐ │
│   │  TARGET  │───▶│              SCANNER ENGINE                       │ │
│   │  (file)  │    │  ┌────────────────┐  ┌─────────────────────────┐ │ │
│   └──────────┘    │  │  Aho-Corasick  │──│  Bytecode Interpreter   │ │ │
│                   │  │  Atom Matcher  │  │  (Condition Evaluator)  │ │ │
│                   │  └────────────────┘  └─────────────────────────┘ │ │
│                   └──────────────────────────────────────────────────┘ │
│                                      │                                  │
│                                      ▼                                  │
│                              ┌──────────────┐                          │
│                              │   MATCHES    │                          │
│                              │   (Results)  │                          │
│                              └──────────────┘                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### R-YARA Target Architecture (Superior Design)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     R-YARA SUPERIOR ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────┐    ┌─────────────────────────────────────────────────┐  │
│   │  RULES   │───▶│            RUST COMPILER FRONTEND                │  │
│   │  (.yar)  │    │  ┌─────────┐ ┌─────────┐ ┌───────────────────┐  │  │
│   └──────────┘    │  │ Lexer   │▶│ Parser  │▶│  HIR (High-level  │  │  │
│                   │  │ (Logos) │ │ (Lalrpop)│ │  IR) Generator    │  │  │
│                   │  └─────────┘ └─────────┘ └───────────────────┘  │  │
│                   └────────────────────┬────────────────────────────┘  │
│                                        ▼                                │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                    OPTIMIZATION PIPELINE                         │  │
│   │  ┌───────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐ │  │
│   │  │ Constant  │▶▶│   Dead    │▶▶│   Atom    │▶▶│  Bytecode  │ │  │
│   │  │ Folding   │  │  Code     │  │  Selector │  │  Generator │ │  │
│   │  └───────────┘  └────────────┘  └────────────┘  └────────────┘ │  │
│   └────────────────────────────────────┬────────────────────────────┘  │
│                                        ▼                                │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │              PARALLEL SCANNING ENGINE (Rayon)                    │  │
│   │  ┌──────────────────┐    ┌───────────────────────────────────┐ │  │
│   │  │ Daachorse AC     │    │  Register-based VM (faster)       │ │  │
│   │  │ (Double-Array)   │───▶│  + SIMD vectorization             │ │  │
│   │  │ Pattern Matcher  │    │  + JIT compilation (optional)     │ │  │
│   │  └──────────────────┘    └───────────────────────────────────┘ │  │
│   └────────────────────────────────────┬────────────────────────────┘  │
│                                        ▼                                │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                      MODULE SYSTEM                               │  │
│   │  ┌────┐ ┌────┐ ┌──────┐ ┌─────┐ ┌────┐ ┌──────┐ ┌───────────┐ │  │
│   │  │ PE │ │ELF │ │Dotnet│ │Macho│ │DEX │ │ Hash │ │  Custom   │ │  │
│   │  └────┘ └────┘ └──────┘ └─────┘ └────┘ └──────┘ └───────────┘ │  │
│   └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Part 2: Aho-Corasick Pattern Matching

### 2.1 YARA's Current Implementation

```pseudocode
// YARA uses a traditional Aho-Corasick NFA with failure links

STRUCT AhoCorasickState:
    transitions: Map<byte, StateId>     // Sparse transitions
    failure_link: StateId               // Fallback on mismatch
    output: List<PatternId>             // Patterns ending at this state
    depth: int                          // Distance from root

STRUCT AhoCorasickAutomaton:
    states: Array<AhoCorasickState>
    root: StateId = 0

FUNCTION build_automaton(patterns: List<String>) -> Automaton:
    automaton = new AhoCorasickAutomaton()

    // Phase 1: Build trie (prefix tree)
    FOR pattern IN patterns:
        current_state = automaton.root
        FOR byte IN pattern.bytes:
            IF byte NOT IN current_state.transitions:
                new_state = automaton.create_state()
                current_state.transitions[byte] = new_state
            current_state = current_state.transitions[byte]
        current_state.output.append(pattern.id)

    // Phase 2: Build failure links using BFS
    queue = Queue()

    // First level - failure links point to root
    FOR child IN automaton.root.transitions.values():
        child.failure_link = automaton.root
        queue.enqueue(child)

    // BFS for deeper levels
    WHILE NOT queue.empty():
        current = queue.dequeue()

        FOR (byte, child) IN current.transitions:
            queue.enqueue(child)

            // Find failure link by walking up failure chain
            failure = current.failure_link
            WHILE failure != root AND byte NOT IN failure.transitions:
                failure = failure.failure_link

            IF byte IN failure.transitions:
                child.failure_link = failure.transitions[byte]
            ELSE:
                child.failure_link = root

            // Merge outputs from failure chain
            child.output.extend(child.failure_link.output)

    RETURN automaton

FUNCTION scan(automaton: Automaton, data: Bytes) -> List<Match>:
    matches = []
    state = automaton.root

    FOR (offset, byte) IN enumerate(data):
        // Follow failure links until we find a transition or reach root
        WHILE state != root AND byte NOT IN state.transitions:
            state = state.failure_link

        IF byte IN state.transitions:
            state = state.transitions[byte]

        // Report all patterns ending at this state
        FOR pattern_id IN state.output:
            matches.append(Match(pattern_id, offset))

    RETURN matches
```

### 2.2 R-YARA Superior Implementation: Double-Array Trie (Daachorse)

```pseudocode
// R-YARA uses Double-Array Aho-Corasick for O(1) transitions
// Reference: https://github.com/daac-tools/daachorse

STRUCT DoubleArrayAC:
    base: Array<int32>      // Base values for state transitions
    check: Array<int32>     // Validation array
    fail: Array<int32>      // Failure transitions
    output: Array<BitSet>   // Pattern matches at each state

    // Double-array formula:
    // next_state = base[current_state] + input_byte
    // valid if check[next_state] == current_state

FUNCTION transition(state: int, byte: int) -> int:
    // O(1) transition lookup
    next = base[state] + byte
    IF check[next] == state:
        RETURN next
    ELSE:
        RETURN INVALID

FUNCTION build_double_array(patterns: List<String>) -> DoubleArrayAC:
    // First build standard AC automaton
    nfa = build_nfa_automaton(patterns)

    // Convert NFA to Double-Array representation
    // This is the key optimization - compact memory + O(1) lookup

    states_by_depth = group_states_by_depth(nfa)

    // Allocate base/check arrays
    size = estimate_size(nfa)
    base = Array<int32>(size, fill=0)
    check = Array<int32>(size, fill=-1)
    fail = Array<int32>(size)
    output = Array<BitSet>(size)

    // Process states in BFS order
    FOR depth IN 0..max_depth:
        FOR state IN states_by_depth[depth]:
            // Find a valid base value for this state
            base_value = find_base(state.transitions, base, check)
            base[state.id] = base_value

            // Set check values for all transitions
            FOR (byte, target) IN state.transitions:
                pos = base_value + byte
                check[pos] = state.id
                // Recursively process target

            fail[state.id] = state.failure_link
            output[state.id] = state.output_patterns

    RETURN DoubleArrayAC(base, check, fail, output)

FUNCTION find_base(transitions: Map, base: Array, check: Array) -> int:
    // Find smallest base value where all transitions fit
    candidate = 1  // Start at 1, 0 reserved for root

    WHILE TRUE:
        valid = TRUE
        FOR byte IN transitions.keys():
            pos = candidate + byte
            IF check[pos] != -1:  // Position occupied
                valid = FALSE
                BREAK

        IF valid:
            RETURN candidate
        candidate += 1

FUNCTION scan_double_array(da: DoubleArrayAC, data: Bytes) -> List<Match>:
    matches = []
    state = ROOT_STATE

    FOR (offset, byte) IN enumerate(data):
        // O(1) transition with failure fallback
        LOOP:
            next = da.base[state] + byte
            IF da.check[next] == state:
                state = next
                BREAK
            ELIF state == ROOT_STATE:
                BREAK
            ELSE:
                state = da.fail[state]  // Follow failure link

        // Check for pattern matches
        IF da.output[state].any():
            FOR pattern_id IN da.output[state]:
                matches.append(Match(pattern_id, offset))

    RETURN matches
```

### 2.3 R-YARA SIMD-Accelerated Scanning

```pseudocode
// Use SIMD for parallel byte matching (AVX2/AVX-512)

FUNCTION scan_simd(patterns: CompiledPatterns, data: Bytes) -> List<Match>:
    matches = []

    // Process 32 bytes at a time with AVX2
    chunk_size = 32

    FOR chunk_start IN range(0, data.len(), chunk_size):
        chunk = data[chunk_start..chunk_start + chunk_size]

        // Load 32 bytes into SIMD register
        data_vec = simd_load_256(chunk)

        // For each short pattern (4 bytes or less), use SIMD comparison
        FOR pattern IN patterns.short_patterns:
            pattern_vec = simd_broadcast_32(pattern.bytes)

            // Compare all 32 positions simultaneously
            matches_mask = simd_cmpeq_epi8(data_vec, pattern_vec)

            // Extract match positions from mask
            WHILE matches_mask != 0:
                pos = trailing_zeros(matches_mask)

                // Verify full pattern match
                IF verify_full_match(data, chunk_start + pos, pattern):
                    matches.append(Match(pattern.id, chunk_start + pos))

                matches_mask &= matches_mask - 1  // Clear lowest bit

    // Fall back to AC for longer patterns
    matches.extend(scan_double_array(patterns.ac_automaton, data))

    RETURN matches
```

---

## Part 3: Bytecode Virtual Machine

### 3.1 YARA's Stack-Based VM

```pseudocode
// YARA uses a stack-based virtual machine for condition evaluation

ENUM Opcode:
    // Stack operations
    OP_PUSH_INT     = 0x01    // Push integer constant
    OP_PUSH_STR     = 0x02    // Push string reference
    OP_PUSH_M       = 0x03    // Push from memory slot
    OP_POP_M        = 0x04    // Pop to memory slot

    // Arithmetic
    OP_ADD          = 0x10
    OP_SUB          = 0x11
    OP_MUL          = 0x12
    OP_DIV          = 0x13
    OP_MOD          = 0x14

    // Comparison
    OP_LT           = 0x20
    OP_LE           = 0x21
    OP_GT           = 0x22
    OP_GE           = 0x23
    OP_EQ           = 0x24
    OP_NE           = 0x25

    // Logic
    OP_AND          = 0x30
    OP_OR           = 0x31
    OP_NOT          = 0x32

    // Control flow
    OP_JMP          = 0x40    // Unconditional jump
    OP_JZ           = 0x41    // Jump if zero
    OP_JNZ          = 0x42    // Jump if not zero

    // String operations
    OP_STR_MATCH    = 0x50    // Check if string matched
    OP_STR_COUNT    = 0x51    // Count of string matches
    OP_STR_OFFSET   = 0x52    // Offset of match
    OP_STR_LENGTH   = 0x53    // Length of match

    // Module operations
    OP_IMPORT       = 0x60    // Import module
    OP_OBJ_LOAD     = 0x61    // Load object field
    OP_CALL         = 0x62    // Call module function

    // Special
    OP_HALT         = 0xFF    // End execution

STRUCT YaraVM:
    stack: Array<Value>      // Operand stack (16KB default)
    sp: int                  // Stack pointer
    memory: Array<Value>     // Local memory slots (16 slots)
    ip: int                  // Instruction pointer
    bytecode: Bytes          // Compiled bytecode

CONST UNDEFINED = 0xFFFABADAFABADAFF  // Special undefined value

FUNCTION execute(vm: YaraVM, context: ScanContext) -> bool:
    WHILE TRUE:
        opcode = vm.bytecode[vm.ip++]

        SWITCH opcode:
            CASE OP_PUSH_INT:
                value = read_i64(vm.bytecode, vm.ip)
                vm.ip += 8
                vm.stack[vm.sp++] = value

            CASE OP_ADD:
                b = vm.stack[--vm.sp]
                a = vm.stack[--vm.sp]
                IF a == UNDEFINED OR b == UNDEFINED:
                    vm.stack[vm.sp++] = UNDEFINED
                ELSE:
                    vm.stack[vm.sp++] = a + b

            CASE OP_STR_MATCH:
                string_id = read_i32(vm.bytecode, vm.ip)
                vm.ip += 4
                string = context.strings[string_id]
                matched = string.match_count > 0
                vm.stack[vm.sp++] = matched ? 1 : 0

            CASE OP_AND:
                b = vm.stack[--vm.sp]
                a = vm.stack[--vm.sp]
                // Short-circuit evaluation
                IF a == 0:
                    vm.stack[vm.sp++] = 0
                ELIF b == 0:
                    vm.stack[vm.sp++] = 0
                ELSE:
                    vm.stack[vm.sp++] = 1

            CASE OP_JZ:
                offset = read_i16(vm.bytecode, vm.ip)
                vm.ip += 2
                IF vm.stack[--vm.sp] == 0:
                    vm.ip += offset

            CASE OP_HALT:
                result = vm.stack[--vm.sp]
                RETURN result != 0 AND result != UNDEFINED

            // ... other opcodes

    RETURN FALSE
```

### 3.2 R-YARA Superior: Register-Based VM with JIT

```pseudocode
// R-YARA uses a register-based VM for better performance
// Fewer stack operations = faster execution

STRUCT RegisterVM:
    registers: Array<Value, 32>   // 32 general-purpose registers
    pc: int                       // Program counter
    bytecode: Bytes

ENUM RegOpcode:
    // Register operations: op rd, rs1, rs2
    ADD_RRR     = 0x01    // rd = rs1 + rs2
    SUB_RRR     = 0x02
    MUL_RRR     = 0x03

    // Immediate operations: op rd, rs1, imm16
    ADD_RRI     = 0x11    // rd = rs1 + imm

    // Load/Store: op rd, imm32
    LOAD_IMM    = 0x20    // rd = imm32
    LOAD_STR    = 0x21    // rd = string_match_count[imm]

    // Comparison: op rd, rs1, rs2
    CMP_LT      = 0x30
    CMP_EQ      = 0x31

    // Control: op rs, offset
    JZ          = 0x40    // if rs == 0, pc += offset
    JNZ         = 0x41
    JMP         = 0x42    // unconditional

    // Function call
    CALL        = 0x50    // call module function

// Instruction encoding (32-bit fixed width for efficient decoding)
// [8-bit opcode][4-bit rd][4-bit rs1][4-bit rs2][12-bit imm/unused]

FUNCTION decode_instruction(word: u32) -> Instruction:
    RETURN Instruction(
        opcode = (word >> 24) & 0xFF,
        rd     = (word >> 20) & 0x0F,
        rs1    = (word >> 16) & 0x0F,
        rs2    = (word >> 12) & 0x0F,
        imm    = word & 0x0FFF
    )

FUNCTION execute_register_vm(vm: RegisterVM, context: ScanContext) -> bool:
    WHILE TRUE:
        inst = decode_instruction(vm.bytecode[vm.pc])
        vm.pc += 4

        SWITCH inst.opcode:
            CASE ADD_RRR:
                vm.registers[inst.rd] =
                    vm.registers[inst.rs1] + vm.registers[inst.rs2]

            CASE CMP_LT:
                vm.registers[inst.rd] =
                    (vm.registers[inst.rs1] < vm.registers[inst.rs2]) ? 1 : 0

            CASE LOAD_STR:
                string_id = read_u32(vm.bytecode, vm.pc)
                vm.pc += 4
                vm.registers[inst.rd] = context.strings[string_id].match_count

            CASE JZ:
                IF vm.registers[inst.rs1] == 0:
                    vm.pc += sign_extend(inst.imm, 12) * 4

            CASE HALT:
                RETURN vm.registers[0] != 0  // r0 holds result

// JIT Compilation for hot paths
STRUCT JITCompiler:
    code_buffer: ExecutableMemory

FUNCTION jit_compile(bytecode: Bytes) -> NativeFunction:
    // Translate bytecode to native x86-64 instructions

    FOR inst IN decode_all(bytecode):
        SWITCH inst.opcode:
            CASE ADD_RRR:
                // mov rax, [rbx + inst.rs1*8]
                // add rax, [rbx + inst.rs2*8]
                // mov [rbx + inst.rd*8], rax
                emit_mov_reg_mem(RAX, RBX, inst.rs1 * 8)
                emit_add_reg_mem(RAX, RBX, inst.rs2 * 8)
                emit_mov_mem_reg(RBX, inst.rd * 8, RAX)

            // ... other instructions

    RETURN make_executable(code_buffer)
```

---

## Part 4: Atom Selection and Optimization

### 4.1 YARA Atom Extraction

```pseudocode
// YARA extracts "atoms" - short byte sequences for AC matching
// This is critical for performance

CONST MAX_ATOM_LENGTH = 4
CONST MIN_ATOM_QUALITY = 3  // Avoid common bytes

FUNCTION extract_atoms(pattern: String) -> List<Atom>:
    atoms = []

    IF pattern.is_literal():
        // For literal strings, extract best atoms
        best_atom = find_best_atom(pattern.bytes)
        atoms.append(best_atom)

    ELIF pattern.is_regex():
        // For regex, find literal sequences
        literal_sequences = extract_literals(pattern.regex_ast)
        FOR seq IN literal_sequences:
            IF seq.length >= MIN_ATOM_LENGTH:
                atoms.append(Atom(seq, position))

    ELIF pattern.is_hex():
        // For hex patterns with wildcards
        // Find longest non-wildcard sequences
        atoms = extract_hex_atoms(pattern.hex_bytes, pattern.wildcards)

    RETURN atoms

FUNCTION find_best_atom(bytes: Bytes) -> Atom:
    best_score = -1
    best_atom = None

    // Slide window to find best atom
    FOR i IN range(0, bytes.len() - MAX_ATOM_LENGTH + 1):
        candidate = bytes[i..i + MAX_ATOM_LENGTH]
        score = calculate_atom_quality(candidate)

        IF score > best_score:
            best_score = score
            best_atom = Atom(candidate, offset=i)

    RETURN best_atom

FUNCTION calculate_atom_quality(bytes: Bytes) -> int:
    // Higher score = more unique = better
    score = 0

    FOR byte IN bytes:
        // Penalize common bytes (0x00, 0xFF, spaces, etc.)
        IF byte == 0x00 OR byte == 0xFF:
            score += 1
        ELIF byte == 0x20 OR byte == 0x0A:  // space, newline
            score += 2
        ELIF is_alphanumeric(byte):
            score += 5
        ELSE:
            score += 10  // Rare bytes are best

    // Bonus for byte diversity
    unique_bytes = len(set(bytes))
    score += unique_bytes * 5

    RETURN score
```

### 4.2 R-YARA Improved Atom Selection

```pseudocode
// R-YARA uses statistical analysis of real-world data

STRUCT AtomStats:
    byte_frequency: Array<float, 256>    // Global byte frequencies
    bigram_frequency: Array<float, 65536>  // Byte pair frequencies
    trigram_bloom: BloomFilter            // Common 3-byte sequences

FUNCTION build_atom_stats(corpus: List<File>) -> AtomStats:
    stats = AtomStats()
    total_bytes = 0

    FOR file IN corpus:
        FOR i IN range(file.len()):
            stats.byte_frequency[file[i]] += 1
            total_bytes += 1

            IF i < file.len() - 1:
                bigram = (file[i] << 8) | file[i+1]
                stats.bigram_frequency[bigram] += 1

            IF i < file.len() - 2:
                trigram = file[i..i+3]
                stats.trigram_bloom.insert(trigram)

    // Normalize frequencies
    FOR i IN range(256):
        stats.byte_frequency[i] /= total_bytes

    RETURN stats

FUNCTION select_optimal_atoms(pattern: Pattern, stats: AtomStats) -> List<Atom>:
    candidates = generate_all_candidate_atoms(pattern)

    // Score each candidate using statistical analysis
    FOR candidate IN candidates:
        candidate.score = calculate_statistical_quality(candidate, stats)

    // Use ILP (Integer Linear Programming) for optimal selection
    // Goal: minimize expected false positive rate while covering pattern

    selected = solve_atom_covering_ilp(candidates, pattern)

    RETURN selected

FUNCTION calculate_statistical_quality(atom: Atom, stats: AtomStats) -> float:
    // Lower probability = better (more selective)
    probability = 1.0

    // Single byte probabilities
    FOR byte IN atom.bytes:
        probability *= stats.byte_frequency[byte]

    // Adjust for bigram correlations
    FOR i IN range(atom.len() - 1):
        bigram = (atom.bytes[i] << 8) | atom.bytes[i+1]
        bigram_prob = stats.bigram_frequency[bigram]
        // Use conditional probability
        probability *= bigram_prob / stats.byte_frequency[atom.bytes[i]]

    // Inverse log for score (higher = better)
    RETURN -log2(probability)
```

---

## Part 5: Module System

### 5.1 YARA Module Architecture

```pseudocode
// YARA modules provide domain-specific functionality

STRUCT Module:
    name: String
    declarations: List<Declaration>  // Types and functions
    load_fn: Function               // Called on import
    unload_fn: Function             // Cleanup

STRUCT Declaration:
    type: DeclarationType  // INTEGER, STRING, FUNCTION, STRUCT
    name: String
    value: Any

// Example: PE Module implementation
MODULE pe:
    STRUCT pe:
        machine: INTEGER
        subsystem: INTEGER
        characteristics: INTEGER
        entry_point: INTEGER
        image_base: INTEGER

        sections: ARRAY<Section>
        imports: ARRAY<Import>
        exports: ARRAY<Export>

        FUNCTION is_dll() -> BOOLEAN
        FUNCTION is_pe() -> BOOLEAN
        FUNCTION imphash() -> STRING
        FUNCTION section_index(name: STRING) -> INTEGER

FUNCTION pe_module_load(module: Module, data: Bytes) -> Object:
    IF NOT is_pe_file(data):
        RETURN UNDEFINED

    pe_obj = Object()

    // Parse DOS header
    dos_header = parse_dos_header(data)
    IF dos_header.magic != 0x5A4D:  // "MZ"
        RETURN UNDEFINED

    // Parse PE header
    pe_offset = dos_header.e_lfanew
    pe_header = parse_pe_header(data, pe_offset)

    pe_obj.machine = pe_header.machine
    pe_obj.subsystem = pe_header.subsystem
    pe_obj.entry_point = pe_header.entry_point
    pe_obj.image_base = pe_header.image_base

    // Parse sections
    pe_obj.sections = parse_sections(data, pe_header)

    // Parse imports
    pe_obj.imports = parse_imports(data, pe_header)

    // Parse exports
    pe_obj.exports = parse_exports(data, pe_header)

    RETURN pe_obj
```

### 5.2 R-YARA Superior Module System

```pseudocode
// R-YARA uses trait-based modules with lazy parsing

TRAIT RYaraModule:
    fn name() -> &str
    fn parse(data: &[u8]) -> Result<ModuleData>
    fn get_field(data: &ModuleData, field: &str) -> Value
    fn call_function(data: &ModuleData, name: &str, args: &[Value]) -> Value

// Lazy parsing - only parse what's needed
STRUCT LazyPEModule:
    raw_data: Bytes
    dos_header: Option<DosHeader>      // Parsed on demand
    pe_header: Option<PeHeader>        // Parsed on demand
    sections: Option<Vec<Section>>     // Parsed on demand
    imports: Option<Vec<Import>>       // Parsed on demand
    exports: Option<Vec<Export>>       // Parsed on demand
    imphash: Option<String>            // Cached once computed

IMPL RYaraModule FOR LazyPEModule:
    fn get_field(&mut self, field: &str) -> Value:
        MATCH field:
            "machine" => {
                self.ensure_pe_header_parsed()
                Value::Integer(self.pe_header.unwrap().machine)
            }
            "sections" => {
                self.ensure_sections_parsed()
                Value::Array(self.sections.clone())
            }
            "imphash" => {
                // Only compute imphash when actually requested
                IF self.imphash.is_none():
                    self.ensure_imports_parsed()
                    self.imphash = Some(compute_imphash(&self.imports))
                Value::String(self.imphash.clone())
            }
            _ => Value::Undefined

// Zero-copy parsing with memory mapping
STRUCT ZeroCopyPE<'data>:
    data: &'data [u8]
    dos_header: &'data DosHeader      // Points into data
    pe_header: &'data PeHeader        // Points into data
    section_table: &'data [SectionHeader]

FUNCTION parse_pe_zero_copy<'a>(data: &'a [u8]) -> Result<ZeroCopyPE<'a>>:
    // All headers are references, not copies
    dos = transmute::<&[u8], &DosHeader>(&data[0..64])

    IF dos.magic != 0x5A4D:
        RETURN Err(NotPE)

    pe_offset = dos.e_lfanew as usize
    pe = transmute::<&[u8], &PeHeader>(&data[pe_offset..])

    section_offset = pe_offset + size_of::<PeHeader>()
    sections = transmute::<&[u8], &[SectionHeader]>(
        &data[section_offset..section_offset + pe.number_of_sections * 40]
    )

    RETURN Ok(ZeroCopyPE { data, dos, pe, sections })

// Parallel module loading
FUNCTION load_modules_parallel(data: Bytes, modules: List<Module>) -> Results:
    // Use rayon for parallel execution
    results = modules
        .par_iter()
        .map(|module| {
            IF module.can_handle(data):
                module.parse(data)
            ELSE:
                ModuleResult::NotApplicable
        })
        .collect()

    RETURN results
```

---

## Part 6: R-YARA Optimization Strategies

### 6.1 Memory Layout Optimization

```pseudocode
// Cache-friendly data structures

// BAD: Array of Structs (poor cache locality)
STRUCT PatternBad:
    id: u32
    flags: u32
    length: u32
    data: [u8; 256]    // Large, infrequent access
    match_count: u32
    last_offset: u64

// GOOD: Struct of Arrays (excellent cache locality)
STRUCT PatternStore:
    // Hot data - accessed every scan iteration
    ids: Vec<u32>
    flags: Vec<u32>
    lengths: Vec<u32>

    // Cold data - accessed only on matches
    data: Vec<[u8; 256]>
    match_counts: Vec<u32>
    last_offsets: Vec<u64>

// Prefetching for scanning
FUNCTION scan_with_prefetch(patterns: PatternStore, data: Bytes):
    FOR i IN range(patterns.len()):
        // Prefetch next pattern's hot data
        IF i + 4 < patterns.len():
            prefetch(&patterns.flags[i + 4])
            prefetch(&patterns.lengths[i + 4])

        // Process current pattern
        check_pattern(patterns, i, data)
```

### 6.2 SIMD String Comparison

```pseudocode
// Use SIMD for string comparison verification

FUNCTION verify_match_simd(data: &[u8], offset: usize, pattern: &[u8]) -> bool:
    IF pattern.len() <= 32:
        // Single SIMD comparison for short patterns
        data_vec = simd_load_256(&data[offset..])
        pattern_vec = simd_load_256(pattern)
        mask = simd_cmpeq_epi8(data_vec, pattern_vec)

        // Check if all pattern bytes matched
        expected_mask = (1 << pattern.len()) - 1
        RETURN (mask & expected_mask) == expected_mask

    ELSE:
        // Multiple SIMD comparisons for long patterns
        FOR chunk IN range(0, pattern.len(), 32):
            chunk_len = min(32, pattern.len() - chunk)

            data_vec = simd_load_256(&data[offset + chunk..])
            pattern_vec = simd_load_256(&pattern[chunk..])
            mask = simd_cmpeq_epi8(data_vec, pattern_vec)

            expected_mask = (1 << chunk_len) - 1
            IF (mask & expected_mask) != expected_mask:
                RETURN FALSE

        RETURN TRUE
```

### 6.3 Parallel Scanning Architecture

```pseudocode
// Multi-threaded scanning with work stealing

STRUCT ParallelScanner:
    thread_pool: ThreadPool
    work_queue: WorkStealingQueue<ScanTask>
    results: ConcurrentVec<Match>

STRUCT ScanTask:
    data_slice: (usize, usize)  // Start and end offsets
    rules_slice: (usize, usize) // Range of rules to check

FUNCTION scan_parallel(scanner: ParallelScanner, data: Bytes, rules: CompiledRules):
    chunk_size = max(data.len() / scanner.thread_pool.size(), 64 * 1024)

    // Create initial tasks
    FOR start IN range(0, data.len(), chunk_size):
        end = min(start + chunk_size, data.len())
        task = ScanTask((start, end), (0, rules.len()))
        scanner.work_queue.push(task)

    // Worker threads execute tasks
    scanner.thread_pool.execute(|| {
        WHILE let Some(task) = scanner.work_queue.steal():
            local_matches = scan_chunk(data, task, rules)
            scanner.results.extend(local_matches)
    })

    // Wait for completion and merge results
    scanner.thread_pool.join()

    RETURN scanner.results.into_sorted()

// Avoid false negatives at chunk boundaries
FUNCTION scan_chunk(data: Bytes, task: ScanTask, rules: CompiledRules) -> Vec<Match>:
    (start, end) = task.data_slice

    // Extend end to include patterns that might span boundary
    extended_end = min(end + MAX_PATTERN_LENGTH, data.len())

    chunk = data[start..extended_end]
    matches = perform_scan(chunk, rules)

    // Filter matches to only those starting in our chunk
    matches.retain(|m| m.offset >= start AND m.offset < end)

    RETURN matches
```

---

## Part 7: R-YARA vs Competition Comparison

```
┌─────────────────────┬───────────────────┬───────────────────┬───────────────────┐
│      Feature        │      YARA (C)     │    YARA-X (Rust)  │   R-YARA (Goal)   │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Aho-Corasick Impl   │ NFA (slower)      │ BurntSushi AC     │ Daachorse (faster)│
│                     │ O(m) transitions  │ NFA-based         │ Double-Array O(1) │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ VM Type             │ Stack-based       │ Stack-based       │ Register-based    │
│                     │ (more operations) │ (Rust safety)     │ + JIT (fastest)   │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Module Parsing      │ Eager (always)    │ Eager             │ Lazy (on-demand)  │
│                     │                   │                   │ + Zero-copy       │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Parallelization     │ None (sequential) │ Limited           │ Full Rayon        │
│                     │                   │                   │ + Work stealing   │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ SIMD Usage          │ None              │ Via aho-corasick  │ Full SIMD for:    │
│                     │                   │ crate             │ - Pattern match   │
│                     │                   │                   │ - Hash compute    │
│                     │                   │                   │ - String compare  │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Memory Layout       │ AoS (cache miss)  │ Mixed             │ SoA (cache-opt)   │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Atom Selection      │ Fixed heuristics  │ Improved          │ Statistical +     │
│                     │                   |                   │ ILP optimization  │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ API                 │ C library only    │ Rust + C + Py     │ REST + WS + gRPC  │
│                     │                   │                   │ + Distributed     │
├─────────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Memory Safety       │ Manual (CVEs)     │ Rust safe         │ Rust safe         │
└─────────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

---

## Part 8: Implementation Roadmap

### Phase 1: Core Engine (4-6 weeks)
1. Implement Daachorse-based Aho-Corasick
2. Build register-based bytecode VM
3. Create LALRPOP grammar for YARA rules
4. Implement atom selector with statistics

### Phase 2: Modules (4-6 weeks)
1. PE module with lazy/zero-copy parsing
2. ELF module with telfhash
3. Dotnet module
4. Hash/Math/Time modules

### Phase 3: Optimization (2-4 weeks)
1. SIMD acceleration
2. Parallel scanning
3. JIT compilation (optional)
4. Memory layout optimization

### Phase 4: Integration (2-4 weeks)
1. C API compatibility
2. Python bindings
3. REST/WebSocket API
4. Distributed worker system

---

## References

- [YARA Internals: Bytecode](https://bnbdr.github.io/posts/extracheese/)
- [YARA Internals: Compiled Rule Format](https://bnbdr.github.io/posts/swisscheese/)
- [Pattern Matching in YARA: Improved Aho-Corasick](https://ieeexplore.ieee.org/document/9410267/)
- [Daachorse: Double-Array Aho-Corasick](https://github.com/daac-tools/daachorse)
- [YARA-X GitHub](https://github.com/VirusTotal/yara-x)
- [YaraNG: Reinventing the YARA Scanner](https://engineering.avast.io/yarang-reinventing-the-yara-scanner/)
