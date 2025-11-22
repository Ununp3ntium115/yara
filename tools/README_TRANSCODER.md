# YARA Rule Transcoder

On-the-fly translation system for YARA rules to/from Cryptex codename format.

## Features

- **Automatic Translation**: Converts standard YARA rules to use Cryptex codenames
- **Zip Support**: Handles zipped rule collections
- **Bidirectional**: Can translate to Cryptex or back to standard format
- **On-the-Fly**: Integrates with yara-python for seamless rule loading
- **Module Mapping**: Translates module references (pe, elf, dotnet, etc.)

## Usage

### Command Line

```bash
# Transcode a single rule file to Cryptex format
python tools/rule_transcoder.py rules/malware.yar -o rules/malware_cryptex.yar

# Transcode a zip file
python tools/rule_transcoder.py rules.zip -o transcoded_rules/

# Translate back from Cryptex to standard
python tools/rule_transcoder.py rules/malware_cryptex.yar -o rules/malware.yar -m from_cryptex

# Add rule file without transcoding
python tools/rule_transcoder.py rules/malware.yar --no-transcode
```

### Python API

```python
from tools.rule_transcoder import RuleTranscoder, add_rule_file
from tools.rule_loader import CryptexRuleLoader, scan_with_rules

# Create transcoder
transcoder = RuleTranscoder()

# Transcode a rule file
transcoded = transcoder.transcode_rule_file(
    Path("rules/malware.yar"),
    Path("rules/malware_cryptex.yar")
)

# Transcode a zip file
files = transcoder.transcode_zip_file(
    Path("rules.zip"),
    Path("transcoded_rules/")
)

# Add rule file with automatic transcoding
result = add_rule_file("rules/malware.yar", transcode=True)
print(result)

# Load and scan with transcoded rules
loader = CryptexRuleLoader(auto_transcode=True)
rules = loader.load_rule_file(Path("rules/malware.yar"), use_cryptex=True)
matches = loader.scan_file(rules, Path("target.exe"))

# Or use convenience function
matches = scan_with_rules("rules/malware.yar", "target.exe", use_cryptex=True)
```

## Module Mappings

Standard YARA modules are mapped to Cryptex codenames:

| YARA Module | Cryptex Codename |
|------------|------------------|
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

## Example Translation

### Standard YARA Rule
```yara
rule ExampleRule {
    condition:
        pe.number_of_sections > 5 and
        hash.md5("data") == "abc123"
}
```

### Transcoded to Cryptex
```yara
rule ExampleRule {
    condition:
        // Original: pe.number_of_sections > 5 and
        IronCurtain.number_of_sections > 5 and
        // Original: hash.md5("data") == "abc123"
        Digest.md5("data") == "abc123"
}
```

## Integration with Scanner

The transcoder integrates seamlessly with the YARA scanner:

```python
from tools.rule_loader import CryptexRuleLoader

loader = CryptexRuleLoader(auto_transcode=True)

# Load rules (automatically transcoded)
rules = loader.load_rule_file(Path("yara-rules/malware_index.yar"))

# Scan files
matches = loader.scan_file(rules, Path("suspicious.exe"))

# Cleanup temporary files
loader.cleanup()
```

## Zip File Support

```python
from tools.rule_transcoder import RuleTranscoder

transcoder = RuleTranscoder()

# Extract and transcode all rules from zip
files = transcoder.transcode_zip_file(
    Path("yara-rules.zip"),
    Path("transcoded_rules/")
)

# Or load directly
from tools.rule_loader import CryptexRuleLoader
loader = CryptexRuleLoader()
rules_dict = loader.load_zip_file(Path("yara-rules.zip"), use_cryptex=True)

# Use rules
for filename, rules in rules_dict.items():
    matches = loader.scan_file(rules, Path("target.exe"))
```

## Notes

- Transcoded rules maintain full compatibility with YARA
- Original rule logic is preserved
- Comments show original code for reference
- Can translate back to standard format if needed
- Works with all YARA rule features (strings, conditions, meta, etc.)

