# R-YARA Module Reference

Complete reference for all R-YARA modules.

## Table of Contents

1. [Overview](#overview)
2. [PE Module](#pe-module)
3. [ELF Module](#elf-module)
4. [Mach-O Module](#macho-module)
5. [DEX Module](#dex-module)
6. [Hash Module](#hash-module)
7. [Math Module](#math-module)
8. [Time Module](#time-module)
9. [Console Module](#console-module)
10. [Using Modules](#using-modules)

## Overview

Modules extend YARA with specialized functionality for analyzing different file formats and performing calculations. R-YARA implements compatibility with standard YARA modules.

### Import Statement

```yara
import "pe"      // PE module
import "elf"     // ELF module
import "macho"   // Mach-O module
import "dex"     // DEX module
import "hash"    // Hash module
import "math"    // Math module
import "time"    // Time module
import "console" // Console module
```

### Module Types

- **File Format Modules**: Parse and analyze executable files (PE, ELF, Mach-O, DEX)
- **Utility Modules**: Provide helper functions (hash, math, time, console)

## PE Module

Analyze PE (Portable Executable) files - Windows executables, DLLs, and drivers.

### Import

```yara
import "pe"
```

### Constants

#### Machine Types

```yara
pe.MACHINE_I386         // 0x14c - Intel 386
pe.MACHINE_AMD64        // 0x8664 - x64
pe.MACHINE_ARM          // 0x1c0 - ARM
pe.MACHINE_ARM64        // 0xaa64 - ARM64
pe.MACHINE_IA64         // 0x200 - Intel Itanium
```

#### Characteristics

```yara
pe.RELOCS_STRIPPED              // 0x0001
pe.EXECUTABLE_IMAGE             // 0x0002
pe.LINE_NUMS_STRIPPED           // 0x0004
pe.LOCAL_SYMS_STRIPPED          // 0x0008
pe.AGGRESSIVE_WS_TRIM           // 0x0010
pe.LARGE_ADDRESS_AWARE          // 0x0020
pe.MACHINE_32BIT                // 0x0100
pe.DEBUG_STRIPPED               // 0x0200
pe.REMOVABLE_RUN_FROM_SWAP      // 0x0400
pe.NET_RUN_FROM_SWAP            // 0x0800
pe.SYSTEM                       // 0x1000
pe.DLL                          // 0x2000
```

#### Subsystems

```yara
pe.SUBSYSTEM_UNKNOWN            // 0
pe.SUBSYSTEM_NATIVE             // 1
pe.SUBSYSTEM_WINDOWS_GUI        // 2
pe.SUBSYSTEM_WINDOWS_CUI        // 3
pe.SUBSYSTEM_WINDOWS_CE_GUI     // 9
pe.SUBSYSTEM_EFI_APPLICATION    // 10
```

#### Section Characteristics

```yara
pe.SECTION_CNT_CODE             // 0x00000020
pe.SECTION_CNT_INITIALIZED_DATA // 0x00000040
pe.SECTION_MEM_EXECUTE          // 0x20000000
pe.SECTION_MEM_READ             // 0x40000000
pe.SECTION_MEM_WRITE            // 0x80000000
```

### Functions

#### is_pe() -> bool

Check if file is a valid PE file.

```yara
rule IsPE {
    condition:
        pe.is_pe()
}
```

#### is_64bit() -> bool

Check if PE is 64-bit.

```yara
rule Is64Bit {
    condition:
        pe.is_pe() and pe.is_64bit()
}
```

#### is_32bit() -> bool

Check if PE is 32-bit.

```yara
rule Is32Bit {
    condition:
        pe.is_pe() and pe.is_32bit()
}
```

#### is_dll() -> bool

Check if PE is a DLL.

```yara
rule IsDLL {
    condition:
        pe.is_pe() and pe.is_dll()
}
```

### Properties

#### machine -> int

CPU architecture.

```yara
rule x64Binary {
    condition:
        pe.machine == pe.MACHINE_AMD64
}
```

#### number_of_sections -> int

Number of sections in PE.

```yara
rule FewSections {
    condition:
        pe.is_pe() and pe.number_of_sections < 3
}
```

#### timestamp -> int

Compilation timestamp (Unix epoch).

```yara
rule CompiledAfter2020 {
    condition:
        pe.is_pe() and pe.timestamp > 1577836800
}
```

#### entry_point -> int

Entry point RVA (Relative Virtual Address).

```yara
rule SuspiciousEntryPoint {
    condition:
        pe.is_pe() and pe.entry_point < 0x1000
}
```

#### entry_point_raw -> int

Entry point raw file offset.

```yara
rule LowEntryPoint {
    condition:
        pe.is_pe() and pe.entry_point_raw < 1000
}
```

#### characteristics -> int

File characteristics flags.

```yara
rule IsExecutable {
    condition:
        pe.is_pe() and
        (pe.characteristics & pe.EXECUTABLE_IMAGE) != 0
}
```

#### subsystem -> int

Subsystem type.

```yara
rule WindowsGUI {
    condition:
        pe.is_pe() and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI
}
```

#### image_base -> int

Preferred load address.

```yara
rule NonStandardBase {
    condition:
        pe.is_pe() and pe.image_base != 0x400000
}
```

### Sections

Access PE sections by index.

#### sections[N].name -> string

Section name.

```yara
rule HasTextSection {
    condition:
        pe.is_pe() and
        pe.sections[0].name == ".text"
}
```

#### sections[N].virtual_address -> int

Section RVA.

#### sections[N].virtual_size -> int

Section virtual size.

#### sections[N].raw_data_size -> int

Section size in file.

#### sections[N].raw_data_offset -> int

Section file offset.

#### sections[N].characteristics -> int

Section flags.

```yara
rule ExecutableSection {
    condition:
        for any section in pe.sections : (
            section.characteristics & pe.SECTION_MEM_EXECUTE
        )
}
```

### Imports

Access imported DLLs and functions.

#### number_of_imports -> int

Number of imported DLLs.

```yara
rule ManyImports {
    condition:
        pe.is_pe() and pe.number_of_imports > 10
}
```

#### imports(dll_name) -> int

Count imports from specific DLL.

```yara
rule UsesWinSock {
    condition:
        pe.imports("ws2_32.dll") > 0
}
```

#### imports(dll_name, function_name) -> bool

Check for specific import.

```yara
rule UsesVirtualAlloc {
    condition:
        pe.imports("kernel32.dll", "VirtualAlloc")
}
```

### Exports

Access exported functions.

#### number_of_exports -> int

Number of exported functions.

#### exports(function_name) -> bool

Check if function is exported.

```yara
rule ExportsDllMain {
    condition:
        pe.is_pe() and pe.exports("DllMain")
}
```

### Resources

Access PE resources.

#### number_of_resources -> int

Number of resources.

#### resources[N].type -> int

Resource type.

#### resources[N].id -> int

Resource ID.

#### resources[N].language -> int

Resource language.

### Examples

#### Detect Packed Executables

```yara
import "pe"

rule PackedExecutable {
    meta:
        description = "Detects potentially packed executables"

    condition:
        pe.is_pe() and
        pe.number_of_sections < 3 and
        pe.entry_point_raw < 1000
}
```

#### Detect Suspicious DLL

```yara
import "pe"

rule SuspiciousDLL {
    condition:
        pe.is_dll() and
        pe.exports("DllRegisterServer") and
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "VirtualProtect")
}
```

#### Detect .NET Assembly

```yara
import "pe"

rule DotNetAssembly {
    condition:
        pe.is_pe() and
        for any section in pe.sections : (
            section.name == ".text" and
            section.virtual_address == pe.entry_point
        )
}
```

## ELF Module

Analyze ELF (Executable and Linkable Format) files - Linux executables and shared libraries.

### Import

```yara
import "elf"
```

### Constants

#### ELF Types

```yara
elf.ET_NONE         // 0 - No file type
elf.ET_REL          // 1 - Relocatable
elf.ET_EXEC         // 2 - Executable
elf.ET_DYN          // 3 - Shared object
elf.ET_CORE         // 4 - Core file
```

#### Machine Types

```yara
elf.EM_386          // 3 - Intel x86
elf.EM_X86_64       // 62 - AMD x86-64
elf.EM_ARM          // 40 - ARM
elf.EM_AARCH64      // 183 - ARM 64-bit
elf.EM_MIPS         // 8 - MIPS
```

### Functions

#### is_elf() -> bool

Check if file is valid ELF.

```yara
rule IsELF {
    condition:
        elf.is_elf()
}
```

#### is_64bit() -> bool

Check if ELF is 64-bit.

```yara
rule Is64BitELF {
    condition:
        elf.is_elf() and elf.is_64bit()
}
```

#### is_32bit() -> bool

Check if ELF is 32-bit.

### Properties

#### type -> int

ELF type (executable, shared library, etc.).

```yara
rule Executable {
    condition:
        elf.is_elf() and elf.type == elf.ET_EXEC
}
```

#### machine -> int

CPU architecture.

```yara
rule x86_64Binary {
    condition:
        elf.is_elf() and elf.machine == elf.EM_X86_64
}
```

#### entry_point -> int

Entry point address.

```yara
rule CustomEntryPoint {
    condition:
        elf.is_elf() and elf.entry_point != 0x400000
}
```

#### number_of_sections -> int

Number of sections.

```yara
rule ManySections {
    condition:
        elf.is_elf() and elf.number_of_sections > 20
}
```

#### number_of_segments -> int

Number of program segments.

### Sections

#### sections[N].name -> string

Section name.

```yara
rule HasInitSection {
    condition:
        elf.is_elf() and
        elf.sections[0].name == ".init"
}
```

#### sections[N].type -> int

Section type.

#### sections[N].flags -> int

Section flags.

#### sections[N].address -> int

Section virtual address.

#### sections[N].size -> int

Section size.

### Dynamic Symbols

#### dynsym_entries -> int

Number of dynamic symbols.

#### dynamic_section_entries -> int

Number of dynamic section entries.

### Examples

#### Detect Stripped Binary

```yara
import "elf"

rule StrippedBinary {
    condition:
        elf.is_elf() and
        not elf.sections[".symtab"]
}
```

#### Detect Position Independent Executable

```yara
import "elf"

rule PIE {
    condition:
        elf.is_elf() and
        elf.type == elf.ET_DYN
}
```

## Mach-O Module

Analyze Mach-O files - macOS and iOS executables.

### Import

```yara
import "macho"
```

### Constants

#### File Types

```yara
macho.MH_OBJECT         // 0x1 - Object file
macho.MH_EXECUTE        // 0x2 - Executable
macho.MH_DYLIB          // 0x6 - Dynamic library
macho.MH_BUNDLE         // 0x8 - Bundle
```

#### CPU Types

```yara
macho.CPU_TYPE_X86      // 7 - x86
macho.CPU_TYPE_X86_64   // 0x01000007 - x86-64
macho.CPU_TYPE_ARM      // 12 - ARM
macho.CPU_TYPE_ARM64    // 0x0100000c - ARM64
```

### Functions

#### is_macho() -> bool

Check if file is valid Mach-O.

```yara
rule IsMachO {
    condition:
        macho.is_macho()
}
```

#### is_64bit() -> bool

Check if Mach-O is 64-bit.

#### is_32bit() -> bool

Check if Mach-O is 32-bit.

### Properties

#### file_type -> int

File type.

```yara
rule Executable {
    condition:
        macho.is_macho() and
        macho.file_type == macho.MH_EXECUTE
}
```

#### cpu_type -> int

CPU architecture.

```yara
rule ARM64Binary {
    condition:
        macho.is_macho() and
        macho.cpu_type == macho.CPU_TYPE_ARM64
}
```

#### number_of_segments -> int

Number of segments.

### Examples

#### Detect Universal Binary

```yara
import "macho"

rule UniversalBinary {
    condition:
        macho.is_macho() and
        macho.number_of_segments > 2
}
```

## DEX Module

Analyze DEX (Dalvik Executable) files - Android applications.

### Import

```yara
import "dex"
```

### Functions

#### is_dex() -> bool

Check if file is valid DEX.

```yara
rule IsDEX {
    condition:
        dex.is_dex()
}
```

### Properties

#### version -> int

DEX version number.

```yara
rule DEXVersion {
    condition:
        dex.is_dex() and dex.version >= 35
}
```

#### number_of_classes -> int

Number of classes.

```yara
rule ManyClasses {
    condition:
        dex.is_dex() and dex.number_of_classes > 1000
}
```

#### number_of_methods -> int

Number of methods.

```yara
rule ManyMethods {
    condition:
        dex.is_dex() and dex.number_of_methods > 5000
}
```

#### number_of_strings -> int

Number of strings.

### Examples

#### Detect Obfuscated DEX

```yara
import "dex"

rule ObfuscatedDEX {
    condition:
        dex.is_dex() and
        dex.number_of_classes > 100 and
        dex.number_of_methods > 1000
}
```

## Hash Module

Calculate cryptographic hashes.

### Import

```yara
import "hash"
```

### Functions

All hash functions take offset and size parameters:
- `offset`: Starting position in file
- `size`: Number of bytes to hash

#### md5(offset, size) -> string

Calculate MD5 hash.

```yara
import "hash"

rule KnownMalwareMD5 {
    condition:
        hash.md5(0, filesize) == "5d41402abc4b2a76b9719d911017c592"
}
```

#### sha1(offset, size) -> string

Calculate SHA-1 hash.

```yara
import "hash"

rule KnownMalwareSHA1 {
    condition:
        hash.sha1(0, filesize) == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
}
```

#### sha256(offset, size) -> string

Calculate SHA-256 hash.

```yara
import "hash"

rule KnownMalwareSHA256 {
    condition:
        hash.sha256(0, filesize) ==
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
}
```

#### sha512(offset, size) -> string

Calculate SHA-512 hash.

#### crc32(offset, size) -> int

Calculate CRC32 checksum.

```yara
import "hash"

rule CRC32Check {
    condition:
        hash.crc32(0, 100) == 0x12345678
}
```

### Examples

#### Hash Specific Section

```yara
import "pe"
import "hash"

rule HashTextSection {
    condition:
        pe.is_pe() and
        hash.sha256(
            pe.sections[0].raw_data_offset,
            pe.sections[0].raw_data_size
        ) == "known_hash_value"
}
```

#### Partial File Hash

```yara
import "hash"

rule FirstKBHash {
    condition:
        filesize > 1KB and
        hash.md5(0, 1KB) == "expected_hash"
}
```

## Math Module

Mathematical and statistical functions.

### Import

```yara
import "math"
```

### Functions

All math functions operate on byte ranges:
- `offset`: Starting position
- `size`: Number of bytes

#### entropy(offset, size) -> float

Calculate Shannon entropy (0.0 to 8.0).

```yara
import "math"

rule HighEntropy {
    meta:
        description = "Detects high entropy (potentially encrypted/packed)"

    condition:
        math.entropy(0, filesize) > 7.5
}
```

**Interpretation:**
- **0.0 - 3.0**: Very low entropy (repetitive data)
- **3.0 - 5.0**: Low entropy (structured data)
- **5.0 - 6.5**: Medium entropy (normal executables)
- **6.5 - 7.5**: High entropy (compressed data)
- **7.5 - 8.0**: Very high entropy (encrypted/packed)

#### mean(offset, size) -> float

Calculate arithmetic mean of bytes.

```yara
import "math"

rule LowMean {
    condition:
        math.mean(0, 1KB) < 50
}
```

#### min(offset, size) -> int

Find minimum byte value (0-255).

```yara
import "math"

rule ContainsNullBytes {
    condition:
        math.min(0, filesize) == 0
}
```

#### max(offset, size) -> int

Find maximum byte value (0-255).

```yara
import "math"

rule OnlyASCII {
    condition:
        math.max(0, filesize) < 128
}
```

#### deviation(offset, size) -> float

Calculate standard deviation.

```yara
import "math"

rule HighDeviation {
    condition:
        math.deviation(0, filesize) > 100
}
```

#### serial_correlation(offset, size) -> float

Calculate serial correlation.

#### monte_carlo_pi(offset, size) -> float

Estimate pi using Monte Carlo method (randomness test).

### Examples

#### Detect Encrypted Section

```yara
import "pe"
import "math"

rule EncryptedSection {
    condition:
        pe.is_pe() and
        for any section in pe.sections : (
            math.entropy(
                section.raw_data_offset,
                section.raw_data_size
            ) > 7.8
        )
}
```

#### Detect Padding

```yara
import "math"

rule HasPadding {
    condition:
        filesize > 1MB and
        math.entropy(filesize - 1KB, 1KB) < 1.0
}
```

## Time Module

Time-related functions.

### Import

```yara
import "time"
```

### Functions

#### now() -> int

Current time (Unix timestamp).

```yara
import "time"

rule RecentScan {
    condition:
        time.now() > 1704067200  // After 2024-01-01
}
```

### Examples

#### Time-Based Rules

```yara
import "time"
import "pe"

rule OldCompilation {
    condition:
        pe.is_pe() and
        pe.timestamp < time.now() - 365 * 24 * 60 * 60  // Older than 1 year
}
```

## Console Module

Debug output functions.

### Import

```yara
import "console"
```

### Functions

#### log(format, ...) -> void

Print debug message.

```yara
import "console"

rule Debug {
    condition:
        console.log("Checking file: ", filename) and
        filesize > 1KB
}
```

#### hex(value) -> void

Print value in hexadecimal.

```yara
import "console"
import "pe"

rule DebugEntryPoint {
    condition:
        pe.is_pe() and
        console.hex(pe.entry_point)
}
```

## Using Modules

### Basic Usage

```yara
import "pe"
import "hash"

rule Example {
    meta:
        description = "Example using multiple modules"

    condition:
        pe.is_pe() and
        pe.is_64bit() and
        hash.md5(0, filesize) == "expected_hash"
}
```

### Combining Modules

```yara
import "pe"
import "math"
import "hash"

rule SuspiciousExecutable {
    meta:
        description = "Detects suspicious characteristics"

    condition:
        pe.is_pe() and
        pe.number_of_sections < 3 and
        math.entropy(0, filesize) > 7.5 and
        not hash.sha256(0, filesize) in (
            "known_good_hash_1",
            "known_good_hash_2"
        )
}
```

### Module in Loops

```yara
import "pe"
import "math"

rule HighEntropySections {
    condition:
        pe.is_pe() and
        for any section in pe.sections : (
            math.entropy(
                section.raw_data_offset,
                section.raw_data_size
            ) > 7.5
        )
}
```

### Conditional Module Usage

```yara
import "pe"
import "elf"
import "hash"

rule CrossPlatformHash {
    condition:
        (pe.is_pe() or elf.is_elf()) and
        hash.sha256(0, filesize) == "target_hash"
}
```

## Best Practices

### 1. Check File Type First

```yara
// Good
import "pe"

rule Good {
    condition:
        pe.is_pe() and          // Check first
        pe.number_of_sections < 3
}

// Bad (crashes on non-PE files)
import "pe"

rule Bad {
    condition:
        pe.number_of_sections < 3  // No type check!
}
```

### 2. Use Specific Checks

```yara
// Good - specific
import "pe"

rule Specific {
    condition:
        pe.is_pe() and
        pe.imports("kernel32.dll", "VirtualAlloc")
}

// Bad - too generic
import "pe"

rule Generic {
    condition:
        pe.number_of_imports > 0
}
```

### 3. Optimize Performance

```yara
// Good - cheap checks first
import "pe"
import "hash"

rule Optimized {
    condition:
        filesize < 1MB and       // Fast
        pe.is_pe() and          // Fast
        hash.sha256(0, filesize) == "..."  // Slow
}

// Bad - expensive check first
import "hash"
import "pe"

rule Slow {
    condition:
        hash.sha256(0, filesize) == "..." and  // Slow first!
        filesize < 1MB
}
```

### 4. Handle Edge Cases

```yara
import "pe"
import "math"

rule SafeEntropy {
    condition:
        pe.is_pe() and
        pe.number_of_sections > 0 and
        for any section in pe.sections : (
            section.raw_data_size > 0 and  // Check size!
            math.entropy(
                section.raw_data_offset,
                section.raw_data_size
            ) > 7.5
        )
}
```

## Troubleshooting

### Module Not Available

```yara
import "nonexistent"  // Error: Unknown module

rule Test {
    condition:
        true
}
```

**Solution**: Check module name spelling and availability.

### Type Mismatch

```yara
import "pe"

rule Bad {
    condition:
        pe.entry_point == "string"  // Error: entry_point is int, not string
}
```

**Solution**: Use correct type for comparison.

### Crash on Non-Matching Files

```yara
import "pe"

rule Crash {
    condition:
        pe.sections[0].name == ".text"  // Crashes on non-PE!
}
```

**Solution**: Always check file type first.

```yara
import "pe"

rule Safe {
    condition:
        pe.is_pe() and
        pe.sections[0].name == ".text"
}
```

## See Also

- [Getting Started](GETTING_STARTED.md)
- [API Reference](API_REFERENCE.md)
- [CLI Guide](CLI_GUIDE.md)
- [YARA Modules Documentation](https://yara.readthedocs.io/en/stable/modules.html)
