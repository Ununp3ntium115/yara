"""
Export Cryptex dictionary to Rust format.
Generates Rust code structures from Cryptex entries.
"""

import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime

# Try workspace path first
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')
PROJECT_ROOT = Path(__file__).parent.parent

if (WORKSPACE / "data" / "cryptex.json").exists():
    CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
    PROJECT_ROOT = WORKSPACE
else:
    CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


class RustExporter:
    """Exports Cryptex dictionary to Rust format."""
    
    def __init__(self, cryptex_file: Path = None):
        self.cryptex_file = cryptex_file or CRYPTEX_FILE
        self.data = self._load_cryptex()
    
    def _load_cryptex(self) -> Dict:
        """Load Cryptex dictionary."""
        if self.cryptex_file.exists():
            with open(self.cryptex_file, 'r') as f:
                return json.load(f)
        return {"entries": []}
    
    def generate_rust_struct(self) -> str:
        """Generate Rust struct definition for Cryptex entry."""
        return """/// Cryptex dictionary entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptexEntry {
    pub symbol: String,
    pub pyro_name: String,
    pub kind: EntryKind,
    pub location: String,
    pub signature: String,
    pub summary: String,
    pub pseudocode: String,
    pub line_references: Vec<LineReference>,
    pub dependencies: Vec<String>,
    pub owner: String,
    pub risk: RiskLevel,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntryKind {
    Function,
    Struct,
    Module,
    Cli,
    Rule,
    Script,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Standard,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineReference {
    pub file: String,
    pub start: u32,
    pub end: u32,
}
"""
    
    def generate_rust_lookup_table(self) -> str:
        """Generate Rust lookup table for symbol to codename mapping."""
        entries = self.data.get("entries", [])
        
        lines = ["// Auto-generated symbol to codename lookup table"]
        lines.append("// Generated from Cryptex dictionary")
        lines.append(f"// Total entries: {len(entries)}")
        lines.append("")
        lines.append("use std::collections::HashMap;")
        lines.append("")
        lines.append("pub fn create_symbol_map() -> HashMap<&'static str, &'static str> {")
        lines.append("    let mut map = HashMap::new();")
        lines.append("")
        
        for entry in entries:
            symbol = entry.get("symbol", "").replace('"', '\\"')
            codename = entry.get("pyro_name", "").replace('"', '\\"')
            if symbol and codename:
                lines.append(f'    map.insert("{symbol}", "{codename}");')
        
        lines.append("")
        lines.append("    map")
        lines.append("}")
        
        return "\n".join(lines)
    
    def generate_rust_module_structure(self) -> str:
        """Generate Rust module structure organized by component."""
        entries = self.data.get("entries", [])
        
        # Group by owner/component
        by_component = {}
        for entry in entries:
            owner = entry.get("owner", "unknown")
            if owner not in by_component:
                by_component[owner] = []
            by_component[owner].append(entry)
        
        lines = ["// Auto-generated module structure"]
        lines.append("// Organized by component/owner")
        lines.append("")
        
        for component, comp_entries in sorted(by_component.items()):
            module_name = component.replace("/", "_").replace("-", "_").lower()
            lines.append(f"// Module: {component}")
            lines.append(f"pub mod {module_name} {{")
            lines.append("    use super::*;")
            lines.append("")
            
            for entry in comp_entries[:10]:  # Limit per module
                symbol = entry.get("symbol", "")
                codename = entry.get("pyro_name", "")
                lines.append(f"    // {symbol} → {codename}")
            
            lines.append("}")
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_rust_pseudocode_comments(self, entry: Dict) -> str:
        """Generate Rust code with pseudocode as comments."""
        symbol = entry.get("symbol", "")
        pseudocode = entry.get("pseudocode", "")
        signature = entry.get("signature", "")
        
        lines = []
        lines.append(f"/// {entry.get('summary', '')}")
        lines.append(f"/// Original: {symbol}")
        lines.append(f"/// Cryptex: {entry.get('pyro_name', '')}")
        lines.append("///")
        lines.append("/// Pseudocode:")
        for line in pseudocode.split('\n'):
            lines.append(f"/// {line}")
        lines.append("///")
        lines.append(f"pub fn {symbol.replace('yr_', '')}() {{")
        lines.append("    // TODO: Implement based on pseudocode")
        lines.append("    // See original implementation for reference")
        lines.append("}")
        lines.append("")
        
        return "\n".join(lines)
    
    def export_to_rust_file(self, output_dir: Path) -> List[Path]:
        """Export Cryptex dictionary to Rust files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        exported_files = []
        
        # Generate main lookup table
        lookup_code = self.generate_rust_lookup_table()
        lookup_file = output_dir / "symbol_map.rs"
        lookup_file.write_text(lookup_code, encoding='utf-8')
        exported_files.append(lookup_file)
        
        # Generate struct definitions
        struct_code = self.generate_rust_struct()
        struct_file = output_dir / "cryptex_types.rs"
        struct_file.write_text(struct_code, encoding='utf-8')
        exported_files.append(struct_file)
        
        # Generate module structure
        module_code = self.generate_rust_module_structure()
        module_file = output_dir / "modules.rs"
        module_file.write_text(module_code, encoding='utf-8')
        exported_files.append(module_file)
        
        # Generate pseudocode implementations (sample)
        entries = self.data.get("entries", [])
        impl_lines = ["// Auto-generated function stubs with pseudocode"]
        impl_lines.append("// Sample implementations based on Cryptex dictionary")
        impl_lines.append("")
        
        for entry in entries[:50]:  # Limit to first 50
            if entry.get("kind") == "function":
                impl_lines.append(self.generate_rust_pseudocode_comments(entry))
        
        impl_file = output_dir / "function_stubs.rs"
        impl_file.write_text("\n".join(impl_lines), encoding='utf-8')
        exported_files.append(impl_file)
        
        # Generate Cargo.toml
        cargo_toml = f"""[package]
name = "yara-cryptex"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
redb = "1.0"
"""
        cargo_file = output_dir / "Cargo.toml"
        cargo_file.write_text(cargo_toml, encoding='utf-8')
        exported_files.append(cargo_file)
        
        return exported_files


def export_cryptex_to_rust(output_dir: str = "rust/cryptex"):
    """Convenience function to export Cryptex to Rust."""
    exporter = RustExporter()
    output_path = PROJECT_ROOT / output_dir
    files = exporter.export_to_rust_file(output_path)
    return files


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Export Cryptex dictionary to Rust format")
    parser.add_argument("-o", "--output", default="rust/cryptex", help="Output directory")
    
    args = parser.parse_args()
    
    exporter = RustExporter()
    files = exporter.export_to_rust_file(PROJECT_ROOT / args.output)
    
    print("=" * 60)
    print("Cryptex Dictionary Rust Export")
    print("=" * 60)
    print(f"Exported {len(files)} files:")
    for f in files:
        print(f"  ✓ {f.relative_to(PROJECT_ROOT)}")
    print("=" * 60)

