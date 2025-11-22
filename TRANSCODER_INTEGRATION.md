# Rule Transcoder Integration

## Overview

The rule transcoder system allows you to add YARA rules (including zipped collections) and automatically transcode them to use Cryptex codenames on-the-fly. This ensures compatibility with the Cryptex dictionary while maintaining full YARA functionality.

## Quick Start

### Add a YARA Rule File

```python
from tools.rule_transcoder import add_rule_file

# Add single rule file (automatically transcoded)
result = add_rule_file("rules/malware.yar", transcode=True)
print(result)
# Output: {'type': 'single', 'original': 'rules/malware.yar', 'transcoded': 'rules/malware_cryptex.yar'}
```

### Add a Zipped Rule Collection

```python
from tools.rule_transcoder import RuleTranscoder

transcoder = RuleTranscoder()

# Transcode all rules in zip file
files = transcoder.transcode_zip_file(
    Path("yara-rules.zip"),
    Path("transcoded_rules/")
)

print(f"Transcoded {len(files)} rule files")
```

### Use with Scanner

```python
from tools.rule_loader import CryptexRuleLoader

loader = CryptexRuleLoader(auto_transcode=True)

# Load rules (automatically transcoded to Cryptex)
rules = loader.load_rule_file(Path("rules/malware.yar"), use_cryptex=True)

# Scan files
matches = loader.scan_file(rules, Path("target.exe"))

# Cleanup
loader.cleanup()
```

### Command Line Usage

```bash
# Transcode single file
python tools/rule_transcoder.py rules/malware.yar -o rules/malware_cryptex.yar

# Transcode zip file
python tools/rule_transcoder.py yara-rules.zip -o transcoded_rules/

# Add rule without transcoding
python tools/rule_transcoder.py rules/malware.yar --no-transcode
```

### Integration with yara_scanner.py

The scanner now supports Cryptex transcoding:

```bash
# Scan with Cryptex transcoding enabled
python yara_scanner.py -d C:\temp -r yara-rules/malware_index.yar --cryptex

# Scan with standard rules (no transcoding)
python yara_scanner.py -d C:\temp -r yara-rules/malware_index.yar
```

## How It Works

1. **Rule Loading**: When a rule file is loaded with `--cryptex` flag, it's automatically transcoded
2. **Module Translation**: Standard YARA modules (pe, elf, etc.) are translated to Cryptex codenames
3. **Function Translation**: Function calls are mapped to Cryptex codenames when available
4. **Temporary Files**: Transcoded rules are stored temporarily during scanning
5. **Cleanup**: Temporary files are automatically cleaned up after scanning

## Module Mappings

| Standard | Cryptex |
|----------|---------|
| `pe` | `IronCurtain` |
| `elf` | `Ghostwire` |
| `dotnet` | `Netrunner` |
| `macho` | `Machinist` |
| `dex` | `Android` |
| `hash` | `Digest` |
| `math` | `Calculator` |
| `time` | `Chronometer` |
| `string` | `TextProcessor` |
| `console` | `Terminal` |
| `cuckoo` | `Sandbox` |
| `magic` | `FileType` |

## Example

### Input Rule (Standard YARA)
```yara
rule SuspiciousPE {
    condition:
        pe.number_of_sections > 10 and
        hash.md5("data") == "abc123"
}
```

### Output Rule (Cryptex Format)
```yara
rule SuspiciousPE {
    condition:
        // Original: pe.number_of_sections > 10 and
        IronCurtain.number_of_sections > 10 and
        // Original: hash.md5("data") == "abc123"
        Digest.md5("data") == "abc123"
}
```

## Benefits

1. **Seamless Integration**: Works with existing YARA rules
2. **On-the-Fly**: No need to pre-process rules
3. **Bidirectional**: Can translate back to standard format
4. **Zip Support**: Handles zipped rule collections
5. **Compatible**: Maintains full YARA functionality

## Notes

- Transcoded rules are fully compatible with YARA
- Original rule logic is preserved
- Comments show original code for reference
- Can be translated back to standard format if needed
- Works with all YARA rule features

