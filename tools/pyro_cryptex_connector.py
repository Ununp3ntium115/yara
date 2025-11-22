"""
PYRO Platform - YARA Cryptex Dictionary Connector
Connects YARA Cryptex dictionary to PYRO Platform's existing Cryptex translator.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).parent.parent
PYRO_PLATFORM_DIR = PROJECT_ROOT / "pyro-platform"
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')

if (WORKSPACE / "data" / "cryptex.json").exists():
    YARA_CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
else:
    YARA_CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class PyroCryptexConnector:
    """Connects YARA Cryptex dictionary to PYRO Platform."""
    
    def __init__(self):
        self.yara_cryptex = self._load_yara_cryptex()
        self.pyro_translator_path = PYRO_PLATFORM_DIR / "pyro" / "src" / "integrations" / "yara" / "cryptex_translator.rs"
    
    def _load_yara_cryptex(self) -> Dict:
        """Load YARA Cryptex dictionary."""
        if YARA_CRYPTEX_FILE.exists():
            with open(YARA_CRYPTEX_FILE, 'r') as f:
                return json.load(f)
        return {"entries": []}
    
    def generate_rust_dictionary_code(self) -> str:
        """Generate Rust code for Cryptex dictionary lookup."""
        entries = self.yara_cryptex.get("entries", [])
        
        code = []
        code.append("// Auto-generated from YARA Cryptex Dictionary")
        code.append("// Total entries: {}".format(len(entries)))
        code.append("")
        code.append("use std::collections::HashMap;")
        code.append("use serde::{Serialize, Deserialize};")
        code.append("")
        code.append("#[derive(Debug, Clone, Serialize, Deserialize)]")
        code.append("pub struct CryptexEntry {")
        code.append("    pub symbol: String,")
        code.append("    pub pyro_name: String,")
        code.append("    pub kind: String,")
        code.append("    pub location: String,")
        code.append("    pub signature: String,")
        code.append("    pub summary: String,")
        code.append("    pub pseudocode: String,")
        code.append("}")
        code.append("")
        code.append("/// YARA Cryptex Dictionary")
        code.append("pub struct YaraCryptexDictionary {")
        code.append("    symbol_to_codename: HashMap<String, String>,")
        code.append("    codename_to_entry: HashMap<String, CryptexEntry>,")
        code.append("}")
        code.append("")
        code.append("impl YaraCryptexDictionary {")
        code.append("    pub fn new() -> Self {")
        code.append("        let mut symbol_to_codename = HashMap::new();")
        code.append("        let mut codename_to_entry = HashMap::new();")
        code.append("")
        
        # Add entries
        for entry in entries[:100]:  # Limit for code generation
            symbol = entry.get("symbol", "").replace('"', '\\"')
            codename = entry.get("pyro_name", "").replace('"', '\\"')
            summary = entry.get("summary", "").replace('"', '\\"')[:100]
            
            if symbol and codename:
                code.append(f'        symbol_to_codename.insert("{symbol}".to_string(), "{codename}".to_string());')
                code.append(f'        codename_to_entry.insert("{codename}".to_string(), CryptexEntry {{')
                code.append(f'            symbol: "{symbol}".to_string(),')
                code.append(f'            pyro_name: "{codename}".to_string(),')
                kind = entry.get("kind", "function")
                location = entry.get("location", "").replace('"', '\\"')
                signature = entry.get("signature", "").replace('"', '\\"')[:200]
                code.append(f'            kind: "{kind}".to_string(),')
                code.append(f'            location: "{location}".to_string(),')
                code.append(f'            signature: "{signature}".to_string(),')
                code.append(f'            summary: "{summary}".to_string(),')
                pseudocode = entry.get("pseudocode", "").replace('"', '\\"').replace('\n', '\\n')[:500]
                code.append(f'            pseudocode: "{pseudocode}".to_string(),')
                code.append('        });')
                code.append("")
        
        code.append("        Self {")
        code.append("            symbol_to_codename,")
        code.append("            codename_to_entry,")
        code.append("        }")
        code.append("    }")
        code.append("")
        code.append("    pub fn lookup_codename(&self, symbol: &str) -> Option<&String> {")
        code.append("        self.symbol_to_codename.get(symbol)")
        code.append("    }")
        code.append("")
        code.append("    pub fn lookup_entry(&self, codename: &str) -> Option<&CryptexEntry> {")
        code.append("        self.codename_to_entry.get(codename)")
        code.append("    }")
        code.append("")
        code.append("    pub fn get_all_entries(&self) -> Vec<&CryptexEntry> {")
        code.append("        self.codename_to_entry.values().collect()")
        code.append("    }")
        code.append("}")
        code.append("")
        code.append("impl Default for YaraCryptexDictionary {")
        code.append("    fn default() -> Self {")
        code.append("        Self::new()")
        code.append("    }")
        code.append("}")
        
        return "\n".join(code)
    
    def generate_json_dictionary(self) -> Dict:
        """Generate JSON format for PYRO Platform."""
        entries = self.yara_cryptex.get("entries", [])
        
        return {
            "metadata": {
                "source": "YARA Cryptex Dictionary",
                "version": "1.0",
                "total_entries": len(entries),
                "generated_from": str(YARA_CRYPTEX_FILE)
            },
            "entries": [
                {
                    "symbol": e.get("symbol"),
                    "pyro_name": e.get("pyro_name"),
                    "kind": e.get("kind"),
                    "location": e.get("location"),
                    "signature": e.get("signature"),
                    "summary": e.get("summary"),
                    "pseudocode": e.get("pseudocode"),
                    "line_references": e.get("line_references", []),
                    "dependencies": e.get("dependencies", [])
                }
                for e in entries
            ]
        }
    
    def export_to_pyro(self, output_dir: Optional[Path] = None) -> List[Path]:
        """Export Cryptex dictionary to PYRO Platform format."""
        if output_dir is None:
            output_dir = PYRO_PLATFORM_DIR / "pyro" / "src" / "integrations" / "yara" / "cryptex"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        exported_files = []
        
        # Generate Rust code
        rust_code = self.generate_rust_dictionary_code()
        rust_file = output_dir / "yara_cryptex_dictionary.rs"
        rust_file.write_text(rust_code, encoding='utf-8')
        exported_files.append(rust_file)
        
        # Generate JSON dictionary
        json_dict = self.generate_json_dictionary()
        json_file = output_dir / "yara_cryptex_dictionary.json"
        with open(json_file, 'w') as f:
            json.dump(json_dict, f, indent=2)
        exported_files.append(json_file)
        
        # Generate integration module
        mod_code = """// YARA Cryptex Dictionary Integration Module
pub mod yara_cryptex_dictionary;

pub use yara_cryptex_dictionary::*;
"""
        mod_file = output_dir / "mod.rs"
        mod_file.write_text(mod_code, encoding='utf-8')
        exported_files.append(mod_file)
        
        return exported_files
    
    def create_integration_patch(self) -> str:
        """Create integration patch for PYRO's cryptex_translator.rs."""
        entries = self.yara_cryptex.get("entries", [])
        
        patch = []
        patch.append("// Integration patch for cryptex_translator.rs")
        patch.append("// Add this to use YARA Cryptex Dictionary")
        patch.append("")
        patch.append("use crate::integrations::yara::cryptex::YaraCryptexDictionary;")
        patch.append("")
        patch.append("impl FireMarshalCryptexTranslator {")
        patch.append("    pub fn with_yara_dictionary() -> Self {")
        patch.append("        let dictionary = YaraCryptexDictionary::new();")
        patch.append("        // Initialize translator with dictionary")
        patch.append("        Self::new()")
        patch.append("    }")
        patch.append("")
        patch.append("    pub fn translate_yara_symbol(&self, symbol: &str) -> Option<String> {")
        patch.append("        // Lookup in YARA Cryptex Dictionary")
        patch.append("        self.dictionary.lookup_codename(symbol)")
        patch.append("            .map(|codename| codename.clone())")
        patch.append("    }")
        patch.append("}")
        patch.append("")
        patch.append("// Dictionary contains {} entries".format(len(entries)))
        
        return "\n".join(patch)


def export_cryptex_to_pyro():
    """Convenience function to export Cryptex to PYRO."""
    connector = PyroCryptexConnector()
    files = connector.export_to_pyro()
    return files


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Connect YARA Cryptex to PYRO Platform")
    parser.add_argument("--export", action="store_true", help="Export to PYRO Platform")
    parser.add_argument("--rust-code", action="store_true", help="Generate Rust code")
    parser.add_argument("--json", action="store_true", help="Generate JSON dictionary")
    parser.add_argument("--patch", action="store_true", help="Generate integration patch")
    
    args = parser.parse_args()
    
    connector = PyroCryptexConnector()
    
    if args.export:
        files = connector.export_to_pyro()
        print("=" * 60)
        print("Exported to PYRO Platform:")
        for f in files:
            print(f"  [OK] {f}")
        print("=" * 60)
    elif args.rust_code:
        print(connector.generate_rust_dictionary_code())
    elif args.json:
        json_dict = connector.generate_json_dictionary()
        print(json.dumps(json_dict, indent=2))
    elif args.patch:
        print(connector.create_integration_patch())
    else:
        print("Use --export to export to PYRO Platform")
        print("Use --rust-code to generate Rust code")
        print("Use --json to generate JSON dictionary")
        print("Use --patch to generate integration patch")

