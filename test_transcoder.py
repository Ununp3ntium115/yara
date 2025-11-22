"""Test the rule transcoder with sample YARA rules."""

from pathlib import Path
from tools.rule_transcoder import RuleTranscoder, add_rule_file

# Create sample rule
sample_rule = """
rule TestRule {
    meta:
        description = "Test rule for transcoding"
        author = "Test"
    
    strings:
        $a = "test string"
        $b = { 6A 40 68 00 30 }
    
    condition:
        pe.number_of_sections > 5 and
        hash.md5("data") == "abc123" and
        $a or $b
}
"""

# Write sample rule
test_rule_file = Path("test_rule.yar")
test_rule_file.write_text(sample_rule)

print("=" * 60)
print("Testing YARA Rule Transcoder")
print("=" * 60)

# Test transcoder
transcoder = RuleTranscoder()

print("\n1. Testing rule file transcoding...")
transcoded = transcoder.transcode_rule_file(test_rule_file, mode="to_cryptex")
print("✓ Rule transcoded successfully")
print("\nTranscoded rule:")
print("-" * 60)
print(transcoded)
print("-" * 60)

# Test reverse
print("\n2. Testing reverse transcoding...")
reversed_rule = transcoder.transcode_rule_content(transcoded, mode="from_cryptex")
print("✓ Reverse transcoding successful")
print("\nReversed rule:")
print("-" * 60)
print(reversed_rule)
print("-" * 60)

# Test adding rule file
print("\n3. Testing add_rule_file...")
result = add_rule_file(str(test_rule_file), transcode=True)
print(f"✓ Rule file added: {result}")

# Cleanup
test_rule_file.unlink()
if Path("test_rule_cryptex.yar").exists():
    Path("test_rule_cryptex.yar").unlink()

print("\n" + "=" * 60)
print("All tests passed!")
print("=" * 60)

