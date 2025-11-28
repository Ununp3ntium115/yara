# Getting Started with R-YARA

This guide will help you get up and running with R-YARA quickly.

## Table of Contents

1. [Installation](#installation)
2. [Basic Concepts](#basic-concepts)
3. [Your First Rule](#your-first-rule)
4. [Running Your First Scan](#running-your-first-scan)
5. [Understanding Results](#understanding-results)
6. [Next Steps](#next-steps)

## Installation

### Prerequisites

- **Rust**: Version 1.70 or later
- **Cargo**: Rust's package manager (comes with Rust)

### Installing Rust

If you don't have Rust installed:

```bash
# On Linux/macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# On Windows
# Download and run rustup-init.exe from https://rustup.rs/
```

### Building R-YARA

Clone the repository and build:

```bash
# Clone the repository
git clone https://github.com/your-org/yara.git
cd yara/rust

# Build all crates
cargo build --release

# The binaries will be in target/release/
ls target/release/r-yara*
```

### Verify Installation

```bash
# Check r-yara CLI
./target/release/r-yara --help

# Check version
./target/release/r-yara --version
```

### Adding to PATH (Optional)

```bash
# Linux/macOS
export PATH="$PATH:$(pwd)/target/release"

# Or copy to system directory
sudo cp target/release/r-yara /usr/local/bin/
```

## Basic Concepts

### What is YARA?

YARA is a pattern matching tool used to identify and classify files based on textual or binary patterns. It's widely used in:
- Malware research and detection
- Incident response
- Threat hunting
- File classification

### Key Components

1. **Rules**: Define patterns and conditions for matching
2. **Strings**: Patterns to search for (text, hex, regex)
3. **Conditions**: Logic that determines if a file matches
4. **Modules**: Extended functionality (PE parsing, hash calculation, etc.)

### Rule Structure

A YARA rule has three main sections:

```yara
rule RuleName {
    meta:
        // Metadata about the rule
        description = "What this rule detects"
        author = "Your Name"

    strings:
        // Patterns to search for
        $string1 = "malicious"
        $hex1 = { 4D 5A }

    condition:
        // Logic to determine match
        $string1 or $hex1
}
```

## Your First Rule

Let's create a simple rule to detect PDF files.

### Create the Rule File

Create a file named `detect_pdf.yar`:

```yara
rule DetectPDF {
    meta:
        description = "Detects PDF files"
        author = "Security Team"
        reference = "PDF signature"

    strings:
        // PDF magic bytes at start of file
        $pdf_header = { 25 50 44 46 }  // %PDF

        // Alternative: text string
        $pdf_text = "%PDF-"

    condition:
        // Must appear at the beginning of file
        $pdf_header at 0 or $pdf_text at 0
}
```

### Understanding the Rule

- **Meta section**: Provides information about the rule
- **Strings section**:
  - `$pdf_header`: Hex bytes for "%PDF"
  - `$pdf_text`: Text string "%PDF-"
- **Condition section**: Matches if either pattern appears at offset 0 (file start)

## Running Your First Scan

### Create a Test File

```bash
# Create a sample PDF file
echo "%PDF-1.4" > sample.pdf
echo "This is a fake PDF file" >> sample.pdf

# Create a non-PDF file
echo "Just a text file" > sample.txt
```

### Scan Single File

```bash
# Scan a single file
r-yara detect_pdf.yar sample.pdf

# Expected output:
# DetectPDF sample.pdf
```

### Scan Multiple Files

```bash
# Scan all files in current directory
r-yara detect_pdf.yar .

# Expected output:
# DetectPDF ./sample.pdf
```

### Scan with Details

```bash
# Show matched strings
r-yara -s detect_pdf.yar sample.pdf

# Expected output:
# DetectPDF ./sample.pdf
#   0x0:$pdf_text: %PDF-
```

## Understanding Results

### Basic Output Format

```
RuleName FilePath
```

Example:
```
DetectPDF ./sample.pdf
MalwareSignature ./suspicious.exe
```

### Detailed Output (-s flag)

```
RuleName FilePath
  offset:$string_name: matched_content
```

Example:
```
DetectPDF ./sample.pdf
  0x0:$pdf_text: %PDF-
```

### JSON Output (-j flag)

```bash
r-yara -j detect_pdf.yar sample.pdf
```

Output:
```json
{
  "rules": [
    {
      "rule": "DetectPDF",
      "namespace": "default",
      "tags": [],
      "meta": {
        "description": "Detects PDF files",
        "author": "Security Team"
      },
      "strings": [
        {
          "name": "$pdf_text",
          "offset": 0,
          "match": "%PDF-"
        }
      ]
    }
  ],
  "file": "./sample.pdf"
}
```

## More Examples

### Example 1: Detecting Suspicious Strings

```yara
rule SuspiciousStrings {
    meta:
        description = "Detects potentially malicious strings"

    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $net = "net user" nocase
        $download = "DownloadFile" nocase

    condition:
        any of them
}
```

### Example 2: File Size Check

```yara
rule SmallExecutable {
    meta:
        description = "Detects small executable files"

    strings:
        $mz = "MZ"

    condition:
        $mz at 0 and filesize < 10KB
}
```

### Example 3: Using Hash Module

```yara
import "hash"

rule KnownMalwareHash {
    meta:
        description = "Detects file by MD5 hash"

    condition:
        hash.md5(0, filesize) == "5d41402abc4b2a76b9719d911017c592"
}
```

### Example 4: Multiple String Matches

```yara
rule MultipleIndicators {
    meta:
        description = "Requires multiple indicators"

    strings:
        $a = "indicator1"
        $b = "indicator2"
        $c = "indicator3"

    condition:
        // Require at least 2 of 3 strings
        2 of ($a, $b, $c)
}
```

### Example 5: Using PE Module

```yara
import "pe"

rule SuspiciousPE {
    meta:
        description = "Detects suspicious PE characteristics"

    condition:
        pe.is_pe and
        pe.number_of_sections < 2 and
        pe.entry_point_raw < 1000
}
```

## Common Use Cases

### 1. Malware Detection

```yara
rule GenericMalware {
    strings:
        $str1 = "malicious_function"
        $str2 = "decrypt_payload"
        $hex1 = { E8 ?? ?? ?? ?? }  // CALL instruction

    condition:
        all of them
}
```

### 2. File Type Identification

```yara
rule DetectELF {
    strings:
        $elf = { 7F 45 4C 46 }  // .ELF

    condition:
        $elf at 0
}
```

### 3. Credential Harvesting

```yara
rule CredentialStrings {
    strings:
        $pwd = /password\s*=\s*['"][^'"]{8,}['"]/
        $key = /api[_-]?key\s*=\s*['"][^'"]{16,}['"]/

    condition:
        any of them
}
```

## Command Line Tips

### Recursive Scanning

```bash
# Scan directory recursively
r-yara -r detect_pdf.yar /path/to/directory
```

### Fast Scan Mode

```bash
# Stop after first match per file
r-yara -f detect_pdf.yar /path/to/files
```

### Timeout

```bash
# Set timeout per file (in seconds)
r-yara -a 30 rules.yar /path/to/scan
```

### Multiple Rule Files

```bash
# Scan with multiple rule files
r-yara rule1.yar rule2.yar rule3.yar target.bin
```

## Troubleshooting

### Rule Won't Compile

**Error**: "syntax error, unexpected STRING_IDENTIFIER"

**Solution**: Check for:
- Missing quotes around strings
- Invalid hex patterns
- Typos in keywords

### No Matches When Expected

**Checklist**:
1. Verify string is in file: `hexdump -C file | grep pattern`
2. Check file encoding (ASCII vs Unicode)
3. Use `nocase` for case-insensitive matching
4. Verify hex bytes are correct

### Performance Issues

**Tips**:
- Use more specific patterns
- Avoid regex when possible
- Use `filesize` checks early in condition
- Limit regex complexity

## Best Practices

### 1. Clear Metadata

Always include descriptive metadata:
```yara
meta:
    description = "Clear description of what is detected"
    author = "Your Name"
    date = "2025-01-15"
    reference = "https://link-to-analysis"
    hash = "sample_hash_if_applicable"
```

### 2. Specific Strings

Prefer specific over generic:
```yara
// Bad: Too generic
$bad = "http"

// Good: More specific
$good = "http://malicious-domain.com/payload"
```

### 3. Optimize Conditions

Put cheap checks first:
```yara
condition:
    filesize < 1MB and        // Fast
    $string1 and              // Fast
    hash.md5(0, filesize) ... // Slower
```

### 4. Test Rules

Always test on:
- Known positive samples
- Known negative samples
- Large datasets

### 5. Document Assumptions

```yara
meta:
    description = "Detects XYZ malware"
    assumption = "PE file format, unpacked"
    fp_risk = "low"
```

## Next Steps

Now that you understand the basics, explore:

1. **[CLI Guide](CLI_GUIDE.md)**: Complete command-line reference
2. **[Module Reference](MODULES.md)**: Using PE, ELF, hash, and math modules
3. **[API Reference](API_REFERENCE.md)**: Integrating R-YARA into applications
4. **[Architecture](ARCHITECTURE.md)**: Understanding R-YARA internals

## Additional Resources

### Learning YARA

- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA Rule Writing Guide](https://yara.readthedocs.io/en/stable/writingrules.html)
- [Awesome YARA](https://github.com/InQuest/awesome-yara)

### Rule Collections

- [YARA Rules Repository](https://github.com/Yara-Rules/rules)
- [Signature Base](https://github.com/Neo23x0/signature-base)
- [CAPE Sandbox Rules](https://github.com/kevoreilly/CAPEv2/tree/master/data/yara)

### Community

- GitHub Issues for bug reports
- Security community forums
- Malware research communities

## Quick Reference Card

```bash
# Compile and check rule
r-yara check rules.yar

# Scan single file
r-yara rules.yar file.bin

# Scan directory recursively
r-yara -r rules.yar /path/

# Show matched strings
r-yara -s rules.yar file.bin

# JSON output
r-yara -j rules.yar file.bin

# Fast mode (stop after first match)
r-yara -f rules.yar file.bin

# Multiple threads
r-yara -p 4 rules.yar /path/

# Timeout per file
r-yara -a 60 rules.yar /path/
```

## Getting Help

```bash
# General help
r-yara --help

# Subcommand help
r-yara dict --help
r-yara feed --help
r-yara server --help
```

Happy hunting!
