# YARA Cross Converter Streaming Guide

## Overview

The YARA Rule Transcoder now includes **streaming support** for processing large rule files and collections in real-time without loading everything into memory. This enables efficient cross-format conversion between YARA, Cryptex, and other formats.

## Features

- ✅ **Streaming File Processing** - Process large files in chunks
- ✅ **Stdin/Stdout Support** - Real-time pipeline processing
- ✅ **Streaming Zip Conversion** - Process zip archives without extracting
- ✅ **Cross-Format Conversion** - Convert between YARA, Cryptex, JSON formats
- ✅ **Progress Updates** - Real-time progress updates
- ✅ **Memory Efficient** - Process files without loading entire content

## Usage Examples

### 1. Streaming File Conversion

```bash
# Stream convert a single file
python tools/rule_transcoder.py input.yar -o output.yar --stream

# Stream convert with progress updates
python tools/rule_transcoder.py large_rules.yar --stream
```

### 2. Stdin/Stdout Streaming

```bash
# Pipe input from stdin to stdout
cat rules.yar | python tools/rule_transcoder.py - --stdin

# Or use the shorthand
python tools/rule_transcoder.py - --stdin

# Convert and pipe to another tool
python tools/rule_transcoder.py - --stdin | yara - rules.yar -
```

### 3. Streaming Zip Conversion

```bash
# Stream convert all rules in a zip file
python tools/rule_transcoder.py rules.zip -o output_dir/ --stream

# Get JSON progress updates
python tools/rule_transcoder.py rules.zip --stream | jq .
```

### 4. Cross-Format Conversion

```bash
# Convert YARA to Cryptex format
python tools/rule_transcoder.py input.yar --cross-convert yara cryptex -o output.yar

# Convert Cryptex back to YARA
python tools/rule_transcoder.py cryptex_rules.yar --cross-convert cryptex yara -o standard.yar
```

## Python API

### Streaming File Conversion

```python
from tools.rule_transcoder import RuleTranscoder
from pathlib import Path

transcoder = RuleTranscoder()

# Stream convert a file
for update in transcoder.stream_transcode_file(
    Path("input.yar"), 
    Path("output.yar"),
    mode="to_cryptex"
):
    print(update, end='')  # Progress updates
```

### Stdin/Stdout Streaming

```python
from tools.rule_transcoder import RuleTranscoder

transcoder = RuleTranscoder()

# Stream from stdin to stdout
transcoder.stream_transcode_stdin_stdout(mode="to_cryptex")
```

### Line-by-Line Streaming

```python
from tools.rule_transcoder import RuleTranscoder

transcoder = RuleTranscoder()

# Process lines one at a time
with open("input.yar", 'r') as f:
    for line in transcoder.stream_transcode_lines(f, mode="to_cryptex"):
        print(line, end='')
```

### Streaming Zip Conversion

```python
from tools.rule_transcoder import RuleTranscoder
from pathlib import Path
import json

transcoder = RuleTranscoder()

# Stream convert zip file with progress updates
for update in transcoder.stream_transcode_zip(
    Path("rules.zip"),
    Path("output_dir"),
    mode="to_cryptex"
):
    if isinstance(update, dict):
        print(json.dumps(update, indent=2))
```

### Cross-Format Conversion

```python
from tools.rule_transcoder import RuleTranscoder

transcoder = RuleTranscoder()

# Cross-format conversion
with open("input.yar", 'r') as f:
    for line in transcoder.cross_convert_stream(
        f,
        source_format="yara",
        target_format="cryptex"
    ):
        print(line, end='')
```

## Command-Line Options

```
usage: rule_transcoder.py [-h] [-o OUTPUT] [-m {to_cryptex,from_cryptex}]
                          [--no-transcode] [--stream] [--stdin]
                          [--cross-convert SOURCE TARGET]
                          [input]

positional arguments:
  input                 Input rule file, zip file, or '-' for stdin

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file or directory (default: stdout)
  -m {to_cryptex,from_cryptex}, --mode {to_cryptex,from_cryptex}
                        Transcode mode (default: to_cryptex)
  --no-transcode        Don't transcode, just add file
  --stream              Use streaming mode for large files
  --stdin               Read from stdin and write to stdout
  --cross-convert SOURCE TARGET
                        Cross-format conversion (formats: yara, cryptex, json)
```

## Performance Benefits

### Memory Usage

- **Standard Mode**: Loads entire file into memory
  - Memory: ~file_size × 2 (input + output)
  
- **Streaming Mode**: Processes line-by-line
  - Memory: ~constant (only current line in memory)

### Processing Speed

- **Small files (< 1MB)**: Minimal difference
- **Large files (> 100MB)**: Streaming avoids memory pressure
- **Very large files (> 1GB)**: Streaming is essential

## Use Cases

1. **Large Rule Collections**: Process thousands of rules without memory issues
2. **Real-time Processing**: Convert rules as they arrive via stdin
3. **Pipeline Integration**: Integrate with other tools via pipes
4. **Batch Processing**: Process multiple files efficiently
5. **Memory-Constrained Environments**: Run on systems with limited RAM

## Examples

### Example 1: Process Large Rule File

```bash
# Stream convert a 500MB rule file
python tools/rule_transcoder.py huge_rules.yar -o converted.yar --stream
```

### Example 2: Pipeline with YARA Scanner

```bash
# Convert and scan in one pipeline
python tools/rule_transcoder.py rules.yar --stdin | \
    yara - converted_rules.yar target_file.exe
```

### Example 3: Batch Convert Zip Archive

```bash
# Convert all rules in zip with progress
python tools/rule_transcoder.py malware_rules.zip \
    -o converted_rules/ --stream
```

### Example 4: Real-time Rule Processing

```bash
# Watch for new rules and convert on-the-fly
watch -n 1 'find rules/ -name "*.yar" -newer last_run | \
    xargs -I {} python tools/rule_transcoder.py {} --stdin'
```

## Error Handling

Streaming mode includes robust error handling:

- **File Not Found**: Raises `FileNotFoundError` immediately
- **Encoding Errors**: Uses `errors='ignore'` to handle invalid characters
- **Interrupted Streams**: Handles `KeyboardInterrupt` gracefully
- **Partial Processing**: Continues processing remaining files on error

## Limitations

1. **Zip Files**: Must be read entirely (but output is streamed)
2. **Multi-line Patterns**: Some complex patterns may span multiple lines
3. **JSON Format**: Full JSON support coming in future version

## Testing

Run the test suite:

```bash
cd tools
python test_streaming.py
```

This will test:
- Streaming file conversion
- Stdin/stdout streaming
- Cross-format conversion
- Streaming zip conversion

## Future Enhancements

- [ ] Parallel streaming for multiple files
- [ ] JSON format streaming support
- [ ] WebSocket streaming for remote processing
- [ ] Progress bars for better UX
- [ ] Compression support for streaming output

