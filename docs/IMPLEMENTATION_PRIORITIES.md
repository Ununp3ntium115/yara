# R-YARA Implementation Priorities

**Based on Cryptext Dictionary Audit**
**Generated:** 2025-11-28

---

## Critical Bugs (P0 - Fix Immediately)

### 1. XOR/Base64 Modifiers Not Connected

**Status:** BROKEN - Functions exist but not called during pattern matching
**Impact:** Users writing rules with `xor` or `base64` modifiers get NO MATCHES

**Files to Fix:**
- `/home/user/yara/rust/r-yara-matcher/src/lib.rs` (lines 220-307)

**Required Changes:**
```rust
// Add after line 237 in PatternMatcher::new()
if let Some((min, max)) = pattern.modifiers.xor {
    for variant in generate_xor_variants(&pattern.bytes, min, max) {
        ac_patterns.push((variant, pattern.id));
    }
}

if pattern.modifiers.base64 {
    for variant in generate_base64_variants(&pattern.bytes) {
        ac_patterns.push((variant, pattern.id));
    }
}
```

**Effort:** 30 minutes
**Priority:** P0 - CRITICAL

---

## High Priority (P1 - Should Implement)

### 2. pe.imphash()

**What:** MD5 hash of normalized import function names
**Why Important:** Essential for malware classification and threat intelligence
**Effort:** Medium (80-120 lines)
**Location:** `/home/user/yara/rust/r-yara-modules/src/pe.rs`

**Algorithm:**
1. Iterate imports
2. Normalize DLL names (lowercase, strip extension)
3. Concatenate as "dll.function,dll.function,..."
4. MD5 hash the result

### 3. pe.version_info

**What:** Dictionary access to PE version information strings
**Why Important:** Commonly used in rules to identify software vendors/versions
**Effort:** High (200-300 lines)
**Location:** `/home/user/yara/rust/r-yara-modules/src/pe.rs`

**Required Strings:**
- FileVersion, ProductVersion, CompanyName
- FileDescription, InternalName, OriginalFilename
- LegalCopyright, LegalTrademarks, ProductName

### 4. pe.resources[n]

**What:** Array access to PE resources
**Why Important:** Resource analysis for icons, manifests, dialogs
**Effort:** High (300-500 lines)
**Location:** `/home/user/yara/rust/r-yara-modules/src/pe.rs`

**Required Fields:**
- type, type_string, id, id_string
- language, language_string, offset, length

### 5. ELF Module Array Access

**What:** Expose sections[n], segments[n], symtab[n], dynsym[n] to YARA rules
**Why Important:** ELF analysis rules need indexed access
**Effort:** Medium (2-3 hours total)
**Location:** `/home/user/yara/rust/r-yara-modules/src/elf.rs`

**Note:** Parsing already exists, just needs YARA module declaration bindings

---

## Medium Priority (P2 - Nice to Have)

### 6. pe.rich_signature Functions

**What:** Rich header parsing and lookup
**Why Important:** Compiler/toolchain identification
**Effort:** Medium (80-120 lines)
**Location:** `/home/user/yara/rust/r-yara-modules/src/pe.rs`

**Required Functions:**
- rich_signature.version(tool_id)
- rich_signature.toolid(version)
- rich_signature.clear_data, rich_signature.key

### 7. Fullword Boundary Detection

**What:** Only match patterns at word boundaries
**Why Important:** Reduces false positives
**Effort:** Low (50-80 lines)
**Location:** `/home/user/yara/rust/r-yara-matcher/src/lib.rs`

**Algorithm:**
1. Check byte before match: not alphanumeric/underscore or BOF
2. Check byte after match: not alphanumeric/underscore or EOF

### 8. pe.import_rva() / pe.delayed_import_rva()

**What:** Get RVA of imported function
**Why Important:** Hook detection and API monitoring
**Effort:** Medium (60-100 lines each)
**Location:** `/home/user/yara/rust/r-yara-modules/src/pe.rs`

### 9. For Loop over Module Arrays

**What:** `for section in pe.sections: (condition)`
**Why Important:** Complex rules need iteration
**Effort:** High (needs VM changes)
**Location:** `/home/user/yara/rust/r-yara-vm/src/lib.rs`

---

## Low Priority (P3 - Future)

### 10. Macho/DEX Module Completion

**What:** Complete macOS and Android file format support
**Effort:** High (each module 500+ lines)
**Location:** `/home/user/yara/rust/r-yara-modules/src/macho.rs`, `dex.rs`

### 11. dotnet Module

**What:** .NET assembly parsing
**Effort:** Very High (1000+ lines)
**Not Started**

### 12. magic Module

**What:** File type detection via libmagic
**Effort:** High (requires external dependency)
**Not Started**

### 13. cuckoo Module

**What:** Cuckoo sandbox integration
**Effort:** High (API integration)
**Not Started**

### 14. Authenticode Signatures

**What:** PE signature verification
**Effort:** Very High (requires crypto library)
**Location:** `/home/user/yara/rust/r-yara-modules/src/pe.rs`

---

## Implementation Order Recommendation

```
Week 1:
├── P0: Fix XOR/Base64 integration (30 min) ← DO FIRST
├── P1: pe.imphash() (2-3 hours)
└── P1: Fullword detection (1-2 hours)

Week 2:
├── P1: pe.version_info (4-6 hours)
├── P1: ELF array access (2-3 hours)
└── P2: pe.rich_signature (2-3 hours)

Week 3:
├── P1: pe.resources[n] (6-8 hours)
├── P2: pe.import_rva() (2 hours)
└── P2: pe.delayed_import_rva() (2 hours)

Future:
├── P3: For loop over module arrays
├── P3: Macho/DEX completion
├── P3: dotnet module
├── P3: magic module
└── P3: Authenticode
```

---

## Verification Tests Needed

| Feature | Test Description |
|---------|------------------|
| XOR modifier | Rule with `$a = "test" xor` matches XOR-encoded data |
| Base64 modifier | Rule with `$a = "test" base64` matches Base64-encoded data |
| pe.imphash() | Known PE returns correct imphash value |
| pe.version_info | Extract CompanyName from known PE |
| ELF sections[n] | Access section by index in rule |
| Fullword | Pattern "test" doesn't match "testing" |

---

## Code Coverage Gaps

| Component | Current | Target |
|-----------|---------|--------|
| Lexer | 100% | 100% |
| Parser | ~95% | 100% |
| Compiler | ~90% | 95% |
| VM | ~85% | 95% |
| Matcher | ~80% | 95% |
| PE Module | ~65% | 90% |
| ELF Module | ~70% | 90% |
| Macho Module | ~30% | 70% |
| DEX Module | ~30% | 70% |

---

## Summary

**Total Missing Items:** ~45 features/functions
**Critical Bugs:** 1 (XOR/Base64 integration)
**Estimated Total Effort:** 80-120 hours

**Recommended Focus:**
1. Fix XOR/Base64 bug immediately
2. Complete PE module (imphash, version_info, resources)
3. Enable ELF array access
4. Add comprehensive integration tests

---

*Document Version: 1.0*
*Last Updated: 2025-11-28*
