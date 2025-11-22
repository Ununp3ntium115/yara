"""
Generate PYRO Platform API endpoints for Cryptex dictionary.
"""

import json
from pathlib import Path
from typing import Dict

PROJECT_ROOT = Path(__file__).parent.parent
PYRO_PLATFORM_DIR = PROJECT_ROOT / "pyro-platform"
WORKSPACE = Path(r'C:\Users\xservera\.cursor\worktrees\yara__Workspace_\H3Err')

if (WORKSPACE / "data" / "cryptex.json").exists():
    YARA_CRYPTEX_FILE = WORKSPACE / "data" / "cryptex.json"
else:
    YARA_CRYPTEX_FILE = PROJECT_ROOT / "data" / "cryptex.json"


def generate_api_endpoints() -> str:
    """Generate Rust API endpoint code for Cryptex dictionary."""
    
    code = []
    code.append("// Auto-generated API endpoints for YARA Cryptex Dictionary")
    code.append("// Add to pyro/src/api/yara.rs")
    code.append("")
    code.append("use crate::integrations::yara::cryptex::{YaraCryptexDictionary, CryptexEntry};")
    code.append("use rocket::serde::json::Json;")
    code.append("use rocket::get;")
    code.append("use std::sync::Arc;")
    code.append("")
    code.append("lazy_static! {")
    code.append("    static ref CRYPTEX_DICTIONARY: Arc<YaraCryptexDictionary> = Arc::new(YaraCryptexDictionary::new());")
    code.append("}")
    code.append("")
    code.append("/// Lookup Cryptex entry by symbol")
    code.append("#[get(\"/api/v2/yara/cryptex/lookup?<symbol>\")]")
    code.append("pub async fn cryptex_lookup(symbol: String) -> Option<Json<CryptexEntry>> {")
    code.append("    CRYPTEX_DICTIONARY")
    code.append("        .lookup_entry(&symbol)")
    code.append("        .or_else(|| {")
    code.append("            // Try lookup by codename")
    code.append("            CRYPTEX_DICTIONARY.lookup_entry(&symbol)")
    code.append("        })")
    code.append("        .map(|entry| Json(entry.clone()))")
    code.append("}")
    code.append("")
    code.append("/// Get all Cryptex entries")
    code.append("#[get(\"/api/v2/yara/cryptex/entries\")]")
    code.append("pub async fn cryptex_entries() -> Json<Vec<CryptexEntry>> {")
    code.append("    let entries: Vec<CryptexEntry> = CRYPTEX_DICTIONARY")
    code.append("        .get_all_entries()")
    code.append("        .iter()")
    code.append("        .map(|e| (*e).clone())")
    code.append("        .collect();")
    code.append("    Json(entries)")
    code.append("}")
    code.append("")
    code.append("/// Search Cryptex entries")
    code.append("#[get(\"/api/v2/yara/cryptex/search?<query>\")]")
    code.append("pub async fn cryptex_search(query: String) -> Json<Vec<CryptexEntry>> {")
    code.append("    let query_lower = query.to_lowercase();")
    code.append("    let entries: Vec<CryptexEntry> = CRYPTEX_DICTIONARY")
    code.append("        .get_all_entries()")
    code.append("        .iter()")
    code.append("        .filter(|e| {")
    code.append("            e.symbol.to_lowercase().contains(&query_lower) ||")
    code.append("            e.pyro_name.to_lowercase().contains(&query_lower) ||")
    code.append("            e.summary.to_lowercase().contains(&query_lower)")
    code.append("        })")
    code.append("        .map(|e| (*e).clone())")
    code.append("        .collect();")
    code.append("    Json(entries)")
    code.append("}")
    code.append("")
    code.append("/// Get Cryptex statistics")
    code.append("#[get(\"/api/v2/yara/cryptex/stats\")]")
    code.append("pub async fn cryptex_stats() -> Json<serde_json::Value> {")
    code.append("    let entries = CRYPTEX_DICTIONARY.get_all_entries();")
    code.append("    let total = entries.len();")
    code.append("    let functions = entries.iter().filter(|e| e.kind == \"function\").count();")
    code.append("    let cli_tools = entries.iter().filter(|e| e.kind == \"cli\").count();")
    code.append("    ")
    code.append("    Json(json!({")
    code.append("        \"total_entries\": total,")
    code.append("        \"functions\": functions,")
    code.append("        \"cli_tools\": cli_tools,")
    code.append("        \"last_updated\": \"2025-11-22\"")
    code.append("    }))")
    code.append("}")
    
    return "\n".join(code)


def generate_frontend_api_client() -> str:
    """Generate JavaScript API client for frontend."""
    
    code = []
    code.append("// Auto-generated YARA Cryptex API client")
    code.append("// Add to frontend-svelte/src/lib/services/cryptexAPI.js")
    code.append("")
    code.append("const API_BASE = '/api/v2/yara/cryptex';")
    code.append("")
    code.append("export const cryptexAPI = {")
    code.append("    /**")
    code.append("     * Lookup Cryptex entry by symbol or codename")
    code.append("     */")
    code.append("    async lookup(symbol) {")
    code.append("        const response = await fetch(`${API_BASE}/lookup?symbol=${encodeURIComponent(symbol)}`);")
    code.append("        if (!response.ok) return null;")
    code.append("        return await response.json();")
    code.append("    },")
    code.append("")
    code.append("    /**")
    code.append("     * Get all Cryptex entries")
    code.append("     */")
    code.append("    async getAllEntries() {")
    code.append("        const response = await fetch(`${API_BASE}/entries`);")
    code.append("        if (!response.ok) return [];")
    code.append("        return await response.json();")
    code.append("    },")
    code.append("")
    code.append("    /**")
    code.append("     * Search Cryptex entries")
    code.append("     */")
    code.append("    async search(query) {")
    code.append("        const response = await fetch(`${API_BASE}/search?query=${encodeURIComponent(query)}`);")
    code.append("        if (!response.ok) return [];")
    code.append("        return await response.json();")
    code.append("    },")
    code.append("")
    code.append("    /**")
    code.append("     * Get Cryptex statistics")
    code.append("     */")
    code.append("    async getStats() {")
    code.append("        const response = await fetch(`${API_BASE}/stats`);")
    code.append("        if (!response.ok) return null;")
    code.append("        return await response.json();")
    code.append("    }")
    code.append("};")
    
    return "\n".join(code)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate API endpoints for Cryptex")
    parser.add_argument("--rust", action="store_true", help="Generate Rust API endpoints")
    parser.add_argument("--frontend", action="store_true", help="Generate frontend API client")
    parser.add_argument("--output", type=str, help="Output directory")
    
    args = parser.parse_args()
    
    if args.rust:
        code = generate_api_endpoints()
        if args.output:
            output_file = Path(args.output) / "cryptex_api_endpoints.rs"
            output_file.write_text(code, encoding='utf-8')
            print(f"✓ Generated: {output_file}")
        else:
            print(code)
    elif args.frontend:
        code = generate_frontend_api_client()
        if args.output:
            output_file = Path(args.output) / "cryptexAPI.js"
            output_file.write_text(code, encoding='utf-8')
            print(f"✓ Generated: {output_file}")
        else:
            print(code)
    else:
        print("Use --rust to generate Rust API endpoints")
        print("Use --frontend to generate frontend API client")
        print("Use --output <dir> to save to file")

