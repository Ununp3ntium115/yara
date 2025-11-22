"""
YARA Rule Loader with on-the-fly transcoding support.
Integrates with yara-python to load and scan with transcoded rules.
"""

import yara
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Union
from tools.rule_transcoder import RuleTranscoder


class CryptexRuleLoader:
    """Loads YARA rules with automatic Cryptex transcoding."""
    
    def __init__(self, cryptex_file: Path = None, auto_transcode: bool = True):
        self.transcoder = RuleTranscoder(cryptex_file)
        self.auto_transcode = auto_transcode
        self.loaded_rules = {}
    
    def load_rule_file(self, rule_file: Path, use_cryptex: bool = True) -> yara.Rules:
        """
        Load a YARA rule file, optionally transcoding to Cryptex format.
        
        Args:
            rule_file: Path to rule file
            use_cryptex: If True, transcode to Cryptex format before loading
        
        Returns:
            Compiled YARA rules
        """
        if use_cryptex and self.auto_transcode:
            # Transcode on-the-fly
            transcoded_content = self.transcoder.transcode_rule_file(rule_file, mode="to_cryptex")
            
            # Create temporary file with transcoded content
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp:
                tmp.write(transcoded_content)
                tmp_path = Path(tmp.name)
            
            try:
                # Compile transcoded rules
                rules = yara.compile(filepath=str(tmp_path))
                self.loaded_rules[str(rule_file)] = {
                    "rules": rules,
                    "transcoded": True,
                    "temp_file": tmp_path
                }
                return rules
            except Exception as e:
                tmp_path.unlink()
                raise RuntimeError(f"Failed to compile transcoded rules: {e}")
        else:
            # Load standard rules
            rules = yara.compile(filepath=str(rule_file))
            self.loaded_rules[str(rule_file)] = {
                "rules": rules,
                "transcoded": False
            }
            return rules
    
    def load_rule_string(self, rule_content: str, use_cryptex: bool = True) -> yara.Rules:
        """
        Load YARA rules from string, optionally transcoding.
        
        Args:
            rule_content: YARA rule content as string
            use_cryptex: If True, transcode to Cryptex format
        
        Returns:
            Compiled YARA rules
        """
        if use_cryptex and self.auto_transcode:
            transcoded = self.transcoder.transcode_rule_content(rule_content, mode="to_cryptex")
        else:
            transcoded = rule_content
        
        return yara.compile(source=transcoded)
    
    def load_zip_file(self, zip_path: Path, use_cryptex: bool = True) -> Dict[str, yara.Rules]:
        """
        Load all YARA rules from a zip file.
        
        Returns:
            Dictionary mapping filenames to compiled rules
        """
        import zipfile
        
        rules_dict = {}
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for file_info in zip_ref.namelist():
                if file_info.endswith('.yar') or file_info.endswith('.yara'):
                    content = zip_ref.read(file_info).decode('utf-8', errors='ignore')
                    
                    if use_cryptex and self.auto_transcode:
                        content = self.transcoder.transcode_rule_content(content, mode="to_cryptex")
                    
                    try:
                        rules = yara.compile(source=content)
                        rules_dict[file_info] = rules
                    except Exception as e:
                        print(f"Warning: Failed to compile {file_info}: {e}")
                        continue
        
        return rules_dict
    
    def scan_file(self, rules: yara.Rules, target_file: Path) -> List[Dict]:
        """
        Scan a file with compiled rules.
        
        Returns:
            List of match dictionaries
        """
        try:
            matches = rules.match(str(target_file))
            return [
                {
                    "rule": m.rule,
                    "tags": m.tags,
                    "meta": dict(m.meta),
                    "strings": [
                        {
                            "identifier": s.identifier,
                            "offset": s.offset,
                            "data": s.string.decode('utf-8', errors='ignore') if isinstance(s.string, bytes) else s.string
                        }
                        for s in m.strings
                    ]
                }
                for m in matches
            ]
        except Exception as e:
            raise RuntimeError(f"Scan failed: {e}")
    
    def cleanup(self):
        """Clean up temporary files."""
        for rule_info in self.loaded_rules.values():
            if "temp_file" in rule_info and rule_info["temp_file"].exists():
                rule_info["temp_file"].unlink()


# Convenience functions
def load_rule_file(rule_file: str, use_cryptex: bool = True) -> yara.Rules:
    """Load a rule file with optional Cryptex transcoding."""
    loader = CryptexRuleLoader(auto_transcode=use_cryptex)
    return loader.load_rule_file(Path(rule_file), use_cryptex)


def load_zip_rules(zip_file: str, use_cryptex: bool = True) -> Dict[str, yara.Rules]:
    """Load rules from zip file with optional transcoding."""
    loader = CryptexRuleLoader(auto_transcode=use_cryptex)
    return loader.load_zip_file(Path(zip_file), use_cryptex)


def scan_with_rules(rule_file: str, target_file: str, use_cryptex: bool = True) -> List[Dict]:
    """Scan a file with rules, optionally using Cryptex format."""
    loader = CryptexRuleLoader(auto_transcode=use_cryptex)
    try:
        rules = loader.load_rule_file(Path(rule_file), use_cryptex)
        return loader.scan_file(rules, Path(target_file))
    finally:
        loader.cleanup()

