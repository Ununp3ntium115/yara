# PYRO Platform - YARA Cryptex Integration Map

## 🎯 Integration Overview

The PYRO Platform already has extensive YARA integration. This document maps how the YARA Cryptex Dictionary system integrates with existing PYRO Platform components.

## 📊 Current PYRO Platform YARA Integration

### Statistics
- **YARA References**: 541 files found
- **Rust YARA Modules**: Extensive integration in `pyro/src/integrations/yara/`
- **Frontend YARA UI**: `frontend-svelte/src/routes/tools/yara/`
- **Cryptex Translator**: Already exists at `pyro/src/integrations/yara/cryptex_translator.rs`

### Key PYRO Platform Components

#### 1. Backend Rust Integration
- **Location**: `pyro/src/integrations/yara/`
- **Files**:
  - `cryptex_translator.rs` - Cryptex translation (already exists!)
  - `detonator_integration.rs` - Detonator system integration
  - `evidence_scanner.rs` - Evidence scanning
  - `pattern_engine.rs` - Pattern matching engine
  - `fire_marshal_compliance.rs` - Compliance checking
  - `mod.rs` - Module exports

#### 2. Frontend Svelte Integration
- **Location**: `frontend-svelte/src/routes/tools/yara/`
- **Components**:
  - `+page.svelte` - Main YARA tools page
  - `agents/+page.svelte` - YARA agents interface
  - `scan/+page.svelte` - Scanning interface
- **API**: `frontend-svelte/src/lib/services/yaraAPI.js`

#### 3. Native Tools Integration
- **Location**: `pyro/src/native_tools/yara_engine.rs`
- **Purpose**: Native YARA execution engine

#### 4. YARA Rules Management
- **Location**: `pyro/src/tools/yara_rules/`
- **Components**:
  - `database.rs` - Rule storage
  - `github_collections.rs` - GitHub rule imports
  - `stream.rs` - Streaming rules
  - `pql_integration.rs` - PQL query integration
  - `mcp_integration.rs` - MCP server integration

## 🔗 Integration Points

### 1. Cryptex Dictionary Integration

**Current State**: PYRO Platform has `cryptex_translator.rs`  
**Integration**: Connect YARA Cryptex Dictionary (587 entries) to PYRO translator

**Action Items**:
- Update `cryptex_translator.rs` to use YARA Cryptex Dictionary
- Add MCP server connection for dictionary lookup
- Integrate with PYRO's existing Cryptex system

### 2. MCP Server Integration

**Current State**: PYRO Platform has MCP configurations  
**Integration**: Connect YARA MCP server and PYRO Platform MCP server

**Action Items**:
- Add YARA MCP server to PYRO's `.claude/mcp-servers.json`
- Connect `mcp_server_pyro/` to PYRO Platform
- Enable unified MCP access

### 3. API Integration

**Current State**: PYRO Platform has YARA API endpoints  
**Integration**: Add Cryptex dictionary endpoints

**Action Items**:
- Add `/api/v2/yara/cryptex/lookup` endpoint
- Add `/api/v2/yara/cryptex/entries` endpoint
- Integrate with existing `pyro/src/api/yara.rs`

### 4. Frontend Integration

**Current State**: PYRO Platform has YARA UI components  
**Integration**: Add Cryptex dictionary browser

**Action Items**:
- Add Cryptex dictionary viewer to `frontend-svelte/src/routes/tools/yara/`
- Display codenames in YARA tool interfaces
- Add lookup functionality

### 5. Rule Transcoder Integration

**Current State**: YARA Cryptex has rule transcoder  
**Integration**: Connect to PYRO's rule management

**Action Items**:
- Integrate `tools/rule_transcoder.py` with PYRO rule system
- Add transcoding to PYRO's rule import pipeline
- Enable on-the-fly transcoding in scans

## 📋 Integration Roadmap

### Phase 1: Dictionary Connection ✅
- [x] Create PYRO Platform MCP server
- [x] Create integration analyzer
- [x] Map existing integration points
- [ ] Connect Cryptex dictionary to PYRO translator

### Phase 2: API Integration
- [ ] Add Cryptex endpoints to PYRO API
- [ ] Integrate with existing YARA endpoints
- [ ] Add frontend API calls

### Phase 3: Frontend Integration
- [ ] Add Cryptex dictionary browser
- [ ] Display codenames in UI
- [ ] Add lookup/search functionality

### Phase 4: Rule Transcoder Integration
- [ ] Integrate transcoder with PYRO rule system
- [ ] Add to rule import pipeline
- [ ] Enable on-the-fly transcoding

### Phase 5: MCP Server Unification
- [ ] Connect YARA MCP server
- [ ] Connect PYRO Platform MCP server
- [ ] Enable unified access

## 🛠️ Implementation Details

### Cryptex Translator Update

Update `pyro/src/integrations/yara/cryptex_translator.rs`:

```rust
// Add connection to YARA Cryptex Dictionary
use crate::mcp::yara_cryptex::CryptexDictionary;

pub struct CryptexTranslator {
    dictionary: CryptexDictionary,
}

impl CryptexTranslator {
    pub fn new() -> Self {
        Self {
            dictionary: CryptexDictionary::load_from_mcp(),
        }
    }
    
    pub fn translate(&self, symbol: &str) -> Option<String> {
        self.dictionary.lookup_codename(symbol)
    }
}
```

### API Endpoint Addition

Add to `pyro/src/api/yara.rs`:

```rust
#[get("/api/v2/yara/cryptex/lookup")]
pub async fn cryptex_lookup(symbol: String) -> Json<CryptexEntry> {
    // Lookup in dictionary
}

#[get("/api/v2/yara/cryptex/entries")]
pub async fn cryptex_entries() -> Json<Vec<CryptexEntry>> {
    // Return all entries
}
```

### Frontend Component

Add to `frontend-svelte/src/routes/tools/yara/cryptex/+page.svelte`:

```svelte
<script>
  import { onMount } from 'svelte';
  import { yaraAPI } from '$lib/services/yaraAPI';
  
  let entries = [];
  
  onMount(async () => {
    entries = await yaraAPI.getCryptexEntries();
  });
</script>

<h1>YARA Cryptex Dictionary</h1>
<!-- Display entries -->
```

## 📁 File Mapping

| YARA Cryptex | PYRO Platform | Integration Type |
|-------------|---------------|------------------|
| `data/cryptex.json` | `pyro/src/integrations/yara/cryptex_translator.rs` | Dictionary source |
| `mcp_server/` | `.claude/mcp-servers.json` | MCP server config |
| `tools/rule_transcoder.py` | `pyro/src/tools/yara_rules/` | Rule processing |
| `tools/pyro_integration_analyzer.py` | Analysis tool | Integration analysis |

## 🎯 Next Steps

1. **Review Existing Integration**
   - Study `pyro/src/integrations/yara/cryptex_translator.rs`
   - Understand PYRO's Cryptex system
   - Map dictionary format compatibility

2. **Connect Dictionary**
   - Load YARA Cryptex Dictionary into PYRO
   - Update translator to use dictionary
   - Test integration

3. **Add API Endpoints**
   - Implement Cryptex lookup endpoints
   - Add to existing YARA API
   - Test endpoints

4. **Frontend Integration**
   - Create Cryptex dictionary browser
   - Add to YARA tools page
   - Test UI

5. **Rule Transcoder**
   - Integrate with PYRO rule system
   - Add transcoding to import pipeline
   - Test transcoding

## ✨ Benefits

1. **Unified Dictionary**: Single source of truth for YARA function codenames
2. **Seamless Integration**: Works with existing PYRO YARA infrastructure
3. **Enhanced UI**: Cryptex dictionary browser in PYRO frontend
4. **Rule Compatibility**: On-the-fly transcoding for rule compatibility
5. **MCP Access**: Unified MCP server access to both systems

## 📊 Integration Status

- **PYRO Platform Analysis**: ✅ Complete
- **Integration Mapping**: ✅ Complete
- **MCP Server Setup**: ✅ Complete
- **Dictionary Connection**: 📋 Pending
- **API Integration**: 📋 Pending
- **Frontend Integration**: 📋 Pending

**The integration infrastructure is ready. Next step: Connect the Cryptex dictionary to PYRO's existing translator!**

