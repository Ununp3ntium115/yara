"""
YARA Rule Transcoder - Translates standard YARA rules to Cryptex codename format.
Handles rule files, zipped rule collections, and on-the-fly translation.
Now with streaming support for large files and real-time processing.
"""

import re
import json
import zipfile
import tempfile
import sys
import io
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterator, Generator
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent
CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class RuleTranscoder:
    """Transcodes YARA rules to use Cryptex codenames."""
    
    def __init__(self, cryptex_file: Path = None):
        self.cryptex_file = cryptex_file or CRYPTEX_FILE
        self.cryptex_dict = self._load_cryptex()
        self.symbol_to_codename = self._build_symbol_map()
        self.codename_to_symbol = {v: k for k, v in self.symbol_to_codename.items()}
        
        # Module name mappings (YARA module names to Cryptex codenames)
        self.module_mappings = {
            'pe': 'IronCurtain',
            'elf': 'Ghostwire',
            'dotnet': 'Netrunner',
            'macho': 'Machinist',
            'dex': 'Android',
            'hash': 'Digest',
            'math': 'Calculator',
            'time': 'Chronometer',
            'string': 'TextProcessor',
            'console': 'Terminal',
            'cuckoo': 'Sandbox',
            'magic': 'FileType',
        }
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if self.cryptex_file.exists():
            with open(self.cryptex_file, 'r') as f:
                return json.load(f)
        return {"entries": [], "metadata": {}}
    
    def _build_symbol_map(self) -> Dict[str, str]:
        """Build mapping from symbols to codenames."""
        symbol_map = {}
        for entry in self.cryptex_dict.get("entries", []):
            symbol = entry.get("symbol", "")
            codename = entry.get("pyro_name", "")
            if symbol and codename:
                symbol_map[symbol] = codename
        return symbol_map
    
    def translate_module_reference(self, module_name: str) -> str:
        """Translate module name to Cryptex codename."""
        return self.module_mappings.get(module_name.lower(), f"Module-{module_name.title()}")
    
    def translate_function_call(self, function_call: str) -> str:
        """Translate function call to use Cryptex codename."""
        # Match function calls like: pe.sections[0].name
        # or: hash.md5("data")
        
        # Extract module name if present
        if '.' in function_call:
            parts = function_call.split('.', 1)
            module = parts[0].strip()
            rest = parts[1] if len(parts) > 1 else ""
            
            # Translate module name
            codename_module = self.translate_module_reference(module)
            
            # Check if rest contains function calls
            if '(' in rest:
                # Function call: module.function(...)
                func_match = re.match(r'(\w+)\s*\(', rest)
                if func_match:
                    func_name = func_match.group(1)
                    # Try to find in Cryptex
                    full_symbol = f"{module}_{func_name}" if module else func_name
                    if full_symbol in self.symbol_to_codename:
                        codename_func = self.symbol_to_codename[full_symbol]
                        # Replace function name
                        rest = rest.replace(func_name, codename_func.split('-')[-1], 1)
            
            return f"{codename_module}.{rest}"
        
        # Check if it's a direct function call
        func_match = re.match(r'(\w+)\s*\(', function_call)
        if func_match:
            func_name = func_match.group(1)
            if func_name in self.symbol_to_codename:
                codename = self.symbol_to_codename[func_name]
                return function_call.replace(func_name, codename.split('-')[-1], 1)
        
        return function_call
    
    def transcode_rule_content(self, rule_content: str, mode: str = "to_cryptex") -> str:
        """
        Transcode rule content between standard YARA and Cryptex format.
        
        Args:
            rule_content: YARA rule content
            mode: "to_cryptex" (translate to codenames) or "from_cryptex" (translate back)
        """
        if mode == "from_cryptex":
            return self._transcode_from_cryptex(rule_content)
        else:
            return self._transcode_to_cryptex(rule_content)
    
    def _transcode_to_cryptex(self, content: str) -> str:
        """Translate standard YARA rules to Cryptex format."""
        lines = content.split('\n')
        transcoded = []
        in_condition = False
        in_strings = False
        
        for line in lines:
            original_line = line
            
            # Detect sections
            if re.match(r'^\s*condition:\s*$', line, re.IGNORECASE):
                in_condition = True
                in_strings = False
            elif re.match(r'^\s*strings:\s*$', line, re.IGNORECASE):
                in_strings = True
                in_condition = False
            elif re.match(r'^\s*(meta|rule):', line, re.IGNORECASE):
                in_condition = False
                in_strings = False
            
            # Translate module references in condition
            if in_condition:
                # Match module.field patterns
                line = re.sub(
                    r'\b(\w+)\.(\w+)',
                    lambda m: f"{self.translate_module_reference(m.group(1))}.{m.group(2)}",
                    line
                )
                
                # Match function calls
                line = re.sub(
                    r'\b(\w+)\.(\w+)\s*\(',
                    lambda m: f"{self.translate_module_reference(m.group(1))}.{m.group(2)}(",
                    line
                )
            
            # Add comment with original if changed
            if line != original_line and not line.strip().startswith('//'):
                transcoded.append(f"    // Original: {original_line.strip()}")
            
            transcoded.append(line)
        
        return '\n'.join(transcoded)
    
    def _transcode_from_cryptex(self, content: str) -> str:
        """Translate Cryptex format back to standard YARA."""
        lines = content.split('\n')
        transcoded = []
        
        # Build reverse module mapping
        reverse_module_map = {v: k for k, v in self.module_mappings.items()}
        
        for line in lines:
            # Skip comment lines with "Original:"
            if '// Original:' in line:
                # Extract original line
                original_match = re.search(r'// Original:\s*(.+)', line)
                if original_match:
                    transcoded.append(original_match.group(1))
                continue
            
            # Reverse module translations (check full codename first)
            for codename, module in reverse_module_map.items():
                if codename in line:
                    line = line.replace(codename, module)
            
            # Reverse function translations
            for codename, symbol in self.codename_to_symbol.items():
                if codename in line:
                    # Replace last part of codename (function name)
                    func_name = codename.split('-')[-1]
                    if func_name in line and symbol:
                        # Try to extract original function name
                        original_func = symbol.split('_')[-1] if '_' in symbol else symbol
                        line = line.replace(func_name, original_func)
            
            transcoded.append(line)
        
        return '\n'.join(transcoded)
    
    def transcode_rule_file(self, rule_file: Path, output_file: Path = None, mode: str = "to_cryptex") -> str:
        """Transcode a YARA rule file."""
        if not rule_file.exists():
            raise FileNotFoundError(f"Rule file not found: {rule_file}")
        
        content = rule_file.read_text(encoding='utf-8', errors='ignore')
        transcoded = self.transcode_rule_content(content, mode)
        
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(transcoded, encoding='utf-8')
            return str(output_file)
        
        return transcoded
    
    def transcode_zip_file(self, zip_path: Path, output_dir: Path = None, mode: str = "to_cryptex") -> List[Path]:
        """Transcode all YARA rules in a zip file."""
        if not zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}")
        
        if output_dir is None:
            output_dir = zip_path.parent / f"{zip_path.stem}_transcoded"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        transcoded_files = []
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for file_info in zip_ref.namelist():
                if file_info.endswith('.yar') or file_info.endswith('.yara'):
                    # Extract to temp file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp:
                        content = zip_ref.read(file_info).decode('utf-8', errors='ignore')
                        transcoded = self.transcode_rule_content(content, mode)
                        tmp.write(transcoded)
                        tmp_path = Path(tmp.name)
                    
                    # Move to output directory
                    output_file = output_dir / Path(file_info).name
                    output_file.write_text(transcoded, encoding='utf-8')
                    transcoded_files.append(output_file)
                    tmp_path.unlink()
        
        return transcoded_files
    
    def add_rule_file(self, rule_file: Path, transcode: bool = True) -> Dict:
        """
        Add a YARA rule file, optionally transcoding to Cryptex format.
        
        Returns metadata about the added rules.
        """
        if rule_file.suffix == '.zip':
            files = self.transcode_zip_file(rule_file) if transcode else []
            return {
                "type": "zip",
                "files_processed": len(files),
                "files": [str(f) for f in files]
            }
        else:
            if transcode:
                transcoded = self.transcode_rule_file(rule_file)
                output_file = rule_file.parent / f"{rule_file.stem}_cryptex.yar"
                output_file.write_text(transcoded, encoding='utf-8')
                return {
                    "type": "single",
                    "original": str(rule_file),
                    "transcoded": str(output_file)
                }
            else:
                return {
                    "type": "single",
                    "file": str(rule_file)
                }
    
    # ========== STREAMING METHODS ==========
    
    def stream_transcode_lines(self, input_stream: Iterator[str], mode: str = "to_cryptex") -> Generator[str, None, None]:
        """
        Stream transcode YARA rules line by line.
        
        Args:
            input_stream: Iterator of lines from input
            mode: "to_cryptex" or "from_cryptex"
            
        Yields:
            Transcoded lines
        """
        buffer = []
        in_condition = False
        in_strings = False
        reverse_module_map = {v: k for k, v in self.module_mappings.items()} if mode == "from_cryptex" else None
        
        for line in input_stream:
            original_line = line.rstrip('\n\r')
            processed_line = original_line
            
            # Detect sections
            if re.match(r'^\s*condition:\s*$', original_line, re.IGNORECASE):
                in_condition = True
                in_strings = False
            elif re.match(r'^\s*strings:\s*$', original_line, re.IGNORECASE):
                in_strings = True
                in_condition = False
            elif re.match(r'^\s*(meta|rule):', original_line, re.IGNORECASE):
                in_condition = False
                in_strings = False
            
            # Process line based on mode
            if mode == "to_cryptex" and in_condition:
                # Translate module references
                processed_line = re.sub(
                    r'\b(\w+)\.(\w+)',
                    lambda m: f"{self.translate_module_reference(m.group(1))}.{m.group(2)}",
                    processed_line
                )
                # Translate function calls
                processed_line = re.sub(
                    r'\b(\w+)\.(\w+)\s*\(',
                    lambda m: f"{self.translate_module_reference(m.group(1))}.{m.group(2)}(",
                    processed_line
                )
            elif mode == "from_cryptex":
                # Skip comment lines with "Original:"
                if '// Original:' in processed_line:
                    original_match = re.search(r'// Original:\s*(.+)', processed_line)
                    if original_match:
                        yield original_match.group(1) + '\n'
                    continue
                
                # Reverse module translations
                if reverse_module_map:
                    for codename, module in reverse_module_map.items():
                        if codename in processed_line:
                            processed_line = processed_line.replace(codename, module)
                
                # Reverse function translations
                for codename, symbol in self.codename_to_symbol.items():
                    if codename in processed_line:
                        func_name = codename.split('-')[-1]
                        if func_name in processed_line and symbol:
                            original_func = symbol.split('_')[-1] if '_' in symbol else symbol
                            processed_line = processed_line.replace(func_name, original_func)
            
            # Add comment if line was changed
            if processed_line != original_line and not processed_line.strip().startswith('//'):
                yield f"    // Original: {original_line}\n"
            
            yield processed_line + '\n'
    
    def stream_transcode_file(self, input_file: Path, output_file: Path = None, 
                             mode: str = "to_cryptex", chunk_size: int = 8192) -> Generator[str, None, None]:
        """
        Stream transcode a file in chunks for memory efficiency.
        
        Args:
            input_file: Input rule file
            output_file: Optional output file path (if None, yields lines)
            mode: "to_cryptex" or "from_cryptex"
            chunk_size: Size of chunks to read (bytes)
            
        Yields:
            Progress updates or transcoded content
        """
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Use line-by-line streaming for rule files
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f_in:
            if output_file:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w', encoding='utf-8') as f_out:
                    for line in self.stream_transcode_lines(f_in, mode):
                        f_out.write(line)
                        yield f"Processed line: {len(line)} bytes\n"
                yield f"✓ Transcoded file saved to: {output_file}\n"
            else:
                for line in self.stream_transcode_lines(f_in, mode):
                    yield line
    
    def stream_transcode_stdin_stdout(self, mode: str = "to_cryptex"):
        """
        Stream transcode from stdin to stdout for real-time processing.
        
        Args:
            mode: "to_cryptex" or "from_cryptex"
        """
        try:
            for line in self.stream_transcode_lines(sys.stdin, mode):
                sys.stdout.write(line)
                sys.stdout.flush()
        except KeyboardInterrupt:
            sys.stderr.write("\n[!] Interrupted by user\n")
            sys.exit(1)
        except Exception as e:
            sys.stderr.write(f"[!] Error: {e}\n")
            sys.exit(1)
    
    def stream_transcode_zip(self, zip_path: Path, output_dir: Path = None, 
                             mode: str = "to_cryptex") -> Generator[Dict, None, None]:
        """
        Stream transcode all YARA rules in a zip file, yielding progress updates.
        
        Args:
            zip_path: Path to zip file
            output_dir: Output directory (created if None)
            mode: "to_cryptex" or "from_cryptex"
            
        Yields:
            Progress dictionaries with file info
        """
        if not zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}")
        
        if output_dir is None:
            output_dir = zip_path.parent / f"{zip_path.stem}_transcoded"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        transcoded_count = 0
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            file_list = [f for f in zip_ref.namelist() 
                        if f.endswith('.yar') or f.endswith('.yara')]
            total_files = len(file_list)
            
            yield {"status": "started", "total_files": total_files, "zip_path": str(zip_path)}
            
            for file_info in file_list:
                try:
                    # Read and transcode in streaming fashion
                    content = zip_ref.read(file_info).decode('utf-8', errors='ignore')
                    lines = content.split('\n')
                    transcoded_lines = list(self.stream_transcode_lines(iter(lines), mode))
                    transcoded_content = ''.join(transcoded_lines)
                    
                    # Write to output
                    output_file = output_dir / Path(file_info).name
                    output_file.write_text(transcoded_content, encoding='utf-8')
                    transcoded_count += 1
                    
                    yield {
                        "status": "processing",
                        "file": file_info,
                        "output": str(output_file),
                        "progress": f"{transcoded_count}/{total_files}"
                    }
                except Exception as e:
                    yield {
                        "status": "error",
                        "file": file_info,
                        "error": str(e)
                    }
            
            yield {
                "status": "completed",
                "total_files": total_files,
                "transcoded_files": transcoded_count,
                "output_dir": str(output_dir)
            }
    
    def cross_convert_stream(self, input_stream: Iterator[str], 
                            source_format: str, target_format: str) -> Generator[str, None, None]:
        """
        Cross-format converter with streaming support.
        Converts between different YARA rule formats in real-time.
        
        Args:
            input_stream: Iterator of input lines
            source_format: Source format ("yara", "cryptex", "json")
            target_format: Target format ("yara", "cryptex", "json")
            
        Yields:
            Converted lines
        """
        # Determine conversion mode
        if source_format == "yara" and target_format == "cryptex":
            mode = "to_cryptex"
        elif source_format == "cryptex" and target_format == "yara":
            mode = "from_cryptex"
        else:
            # For other formats, use standard transcoding as base
            mode = "to_cryptex" if target_format == "cryptex" else "from_cryptex"
        
        # Stream convert
        for line in self.stream_transcode_lines(input_stream, mode):
            yield line


def transcode_rule_file(rule_file: str, output_file: str = None, mode: str = "to_cryptex"):
    """Convenience function to transcode a rule file."""
    transcoder = RuleTranscoder()
    rule_path = Path(rule_file)
    
    if rule_path.suffix == '.zip':
        output_dir = Path(output_file) if output_file else None
        return transcoder.transcode_zip_file(rule_path, output_dir, mode)
    else:
        output_path = Path(output_file) if output_file else None
        return transcoder.transcode_rule_file(rule_path, output_path, mode)


def add_rule_file(rule_file: str, transcode: bool = True):
    """Convenience function to add a rule file."""
    transcoder = RuleTranscoder()
    return transcoder.add_rule_file(Path(rule_file), transcode)


def stream_transcode(input_file: str = None, output_file: str = None, 
                    mode: str = "to_cryptex", use_stdin: bool = False):
    """
    Stream transcode YARA rules with streaming support.
    
    Args:
        input_file: Input file path (None for stdin)
        output_file: Output file path (None for stdout)
        mode: "to_cryptex" or "from_cryptex"
        use_stdin: Use stdin/stdout for streaming
    """
    transcoder = RuleTranscoder()
    
    if use_stdin or input_file is None:
        transcoder.stream_transcode_stdin_stdout(mode)
    else:
        input_path = Path(input_file)
        output_path = Path(output_file) if output_file else None
        
        for update in transcoder.stream_transcode_file(input_path, output_path, mode):
            if output_path is None:
                # Yield to stdout if no output file
                sys.stdout.write(update)
                sys.stdout.flush()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Transcode YARA rules to/from Cryptex format with streaming support"
    )
    parser.add_argument("input", nargs='?', help="Input rule file, zip file, or '-' for stdin")
    parser.add_argument("-o", "--output", help="Output file or directory (default: stdout)")
    parser.add_argument("-m", "--mode", choices=["to_cryptex", "from_cryptex"], 
                       default="to_cryptex", help="Transcode mode")
    parser.add_argument("--no-transcode", action="store_true", 
                       help="Don't transcode, just add file")
    parser.add_argument("--stream", action="store_true",
                       help="Use streaming mode for large files")
    parser.add_argument("--stdin", action="store_true",
                       help="Read from stdin and write to stdout")
    parser.add_argument("--cross-convert", nargs=2, metavar=("SOURCE", "TARGET"),
                       help="Cross-format conversion (formats: yara, cryptex, json)")
    
    args = parser.parse_args()
    
    transcoder = RuleTranscoder()
    
    # Handle stdin/stdout streaming
    if args.stdin or (args.input == '-'):
        transcoder.stream_transcode_stdin_stdout(args.mode)
        sys.exit(0)
    
    if not args.input:
        parser.print_help()
        sys.exit(1)
    
    input_path = Path(args.input)
    
    if args.no_transcode:
        result = transcoder.add_rule_file(input_path, transcode=False)
        print(json.dumps(result, indent=2))
    elif args.cross_convert:
        # Cross-format conversion
        source_format, target_format = args.cross_convert
        if input_path.suffix == '.zip':
            print("Cross-convert for zip files not yet implemented")
            sys.exit(1)
        else:
            with open(input_path, 'r', encoding='utf-8') as f_in:
                for line in transcoder.cross_convert_stream(f_in, source_format, target_format):
                    if args.output:
                        with open(args.output, 'a', encoding='utf-8') as f_out:
                            f_out.write(line)
                    else:
                        sys.stdout.write(line)
    elif args.stream or input_path.suffix == '.zip':
        # Streaming mode
        if input_path.suffix == '.zip':
            output_dir = Path(args.output) if args.output else None
            for update in transcoder.stream_transcode_zip(input_path, output_dir, args.mode):
                if isinstance(update, dict):
                    print(json.dumps(update))
                else:
                    print(update, end='')
        else:
            output_path = Path(args.output) if args.output else None
            for update in transcoder.stream_transcode_file(input_path, output_path, args.mode):
                if output_path is None:
                    sys.stdout.write(update)
                    sys.stdout.flush()
                else:
                    # Progress updates
                    if update.startswith("✓"):
                        print(update, end='')
    else:
        # Standard mode
        if input_path.suffix == '.zip':
            files = transcoder.transcode_zip_file(input_path, Path(args.output) if args.output else None, args.mode)
            print(f"Transcoded {len(files)} files:")
            for f in files:
                print(f"  {f}")
        else:
            output_path = Path(args.output) if args.output else None
            result = transcoder.transcode_rule_file(input_path, output_path, args.mode)
            if output_path:
                print(f"Transcoded rule saved to: {result}")
            else:
                print(result)

