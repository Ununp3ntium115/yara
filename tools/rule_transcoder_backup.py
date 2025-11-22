"""
YARA Rule Transcoder - Translates standard YARA rules to Cryptex codename format.
Handles rule files, zipped rule collections, and on-the-fly translation.
"""

import re
import json
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
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


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Transcode YARA rules to/from Cryptex format")
    parser.add_argument("input", help="Input rule file or zip file")
    parser.add_argument("-o", "--output", help="Output file or directory")
    parser.add_argument("-m", "--mode", choices=["to_cryptex", "from_cryptex"], 
                       default="to_cryptex", help="Transcode mode")
    parser.add_argument("--no-transcode", action="store_true", 
                       help="Don't transcode, just add file")
    
    args = parser.parse_args()
    
    transcoder = RuleTranscoder()
    input_path = Path(args.input)
    
    if args.no_transcode:
        result = transcoder.add_rule_file(input_path, transcode=False)
        print(json.dumps(result, indent=2))
    else:
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


