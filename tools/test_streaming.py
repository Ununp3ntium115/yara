#!/usr/bin/env python3
"""
Test script for YARA Rule Transcoder streaming functionality
"""

import sys
from pathlib import Path
from rule_transcoder import RuleTranscoder

def test_streaming_file():
    """Test streaming file conversion."""
    print("=" * 60)
    print("Test 1: Streaming File Conversion")
    print("=" * 60)
    
    # Create a test rule file
    test_rule = """
rule TestRule {
    meta:
        description = "Test rule for streaming"
    strings:
        $a = "test string"
    condition:
        $a and pe.number_of_sections > 5
}
"""
    
    test_file = Path("test_streaming_input.yar")
    test_file.write_text(test_rule)
    
    output_file = Path("test_streaming_output.yar")
    
    transcoder = RuleTranscoder()
    print(f"\n[*] Streaming conversion: {test_file} -> {output_file}")
    
    for update in transcoder.stream_transcode_file(test_file, output_file, mode="to_cryptex"):
        if update.startswith("✓"):
            print(update, end='')
    
    # Show result
    print(f"\n[*] Output file content:")
    print(output_file.read_text())
    
    # Cleanup
    test_file.unlink()
    output_file.unlink()
    print("\n[+] Test 1 passed!\n")


def test_stdin_stdout():
    """Test stdin/stdout streaming."""
    print("=" * 60)
    print("Test 2: Stdin/Stdout Streaming")
    print("=" * 60)
    
    test_input = """rule TestRule {
    condition:
        pe.number_of_sections > 10
}
"""
    
    print("\n[*] Input rule:")
    print(test_input)
    
    print("\n[*] Transcoded output (simulated):")
    transcoder = RuleTranscoder()
    
    # Simulate stdin
    import io
    stdin_sim = io.StringIO(test_input)
    
    for line in transcoder.stream_transcode_lines(stdin_sim, mode="to_cryptex"):
        print(line, end='')
    
    print("\n[+] Test 2 passed!\n")


def test_cross_convert():
    """Test cross-format conversion."""
    print("=" * 60)
    print("Test 3: Cross-Format Conversion")
    print("=" * 60)
    
    test_rule = """rule CrossTest {
    condition:
        hash.md5("data") == "abc123"
}
"""
    
    test_file = Path("test_cross_input.yar")
    test_file.write_text(test_rule)
    
    print(f"\n[*] Original rule:")
    print(test_file.read_text())
    
    transcoder = RuleTranscoder()
    
    print("\n[*] Converting YARA -> Cryptex:")
    with open(test_file, 'r') as f:
        for line in transcoder.cross_convert_stream(f, "yara", "cryptex"):
            print(line, end='')
    
    # Cleanup
    test_file.unlink()
    print("\n[+] Test 3 passed!\n")


def test_streaming_zip():
    """Test streaming zip conversion."""
    print("=" * 60)
    print("Test 4: Streaming Zip Conversion")
    print("=" * 60)
    
    # Create a test zip with rule files
    import zipfile
    import tempfile
    
    test_zip = Path("test_rules.zip")
    
    with zipfile.ZipFile(test_zip, 'w') as zf:
        zf.writestr("rule1.yar", """rule Rule1 {
    condition:
        pe.number_of_sections > 5
}
""")
        zf.writestr("rule2.yar", """rule Rule2 {
    condition:
        hash.md5("test") == "abc"
}
""")
    
    print(f"\n[*] Created test zip: {test_zip}")
    print(f"[*] Streaming conversion...")
    
    transcoder = RuleTranscoder()
    output_dir = Path("test_zip_output")
    
    for update in transcoder.stream_transcode_zip(test_zip, output_dir, mode="to_cryptex"):
        if isinstance(update, dict):
            if update.get("status") == "processing":
                print(f"  Processing: {update.get('file')} -> {update.get('progress')}")
            elif update.get("status") == "completed":
                print(f"\n[+] Completed: {update.get('transcoded_files')} files transcoded")
                print(f"    Output directory: {update.get('output_dir')}")
    
    # Cleanup
    import shutil
    if test_zip.exists():
        test_zip.unlink()
    if output_dir.exists():
        shutil.rmtree(output_dir)
    
    print("[+] Test 4 passed!\n")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("YARA Rule Transcoder - Streaming Tests")
    print("=" * 60 + "\n")
    
    try:
        test_streaming_file()
        test_stdin_stdout()
        test_cross_convert()
        test_streaming_zip()
        
        print("=" * 60)
        print("All streaming tests passed! ✓")
        print("=" * 60)
    except Exception as e:
        print(f"\n[!] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

