# Next Phase Plan - Cryptex Dictionary & Rust Migration

## Current Status ✅

### Completed
1. ✅ **MCP Server Infrastructure** - Exposes YARA source code as resources
2. ✅ **Cryptex Dictionary** - 587 entries (543 functions + 44 CLI tools)
3. ✅ **Agent-Based Audit System** - Automated function analysis
4. ✅ **Rule Transcoder** - On-the-fly translation to Cryptex format
5. ✅ **Validation Tools** - Quality checking and gap analysis
6. ✅ **Refinement Tools** - Improved pseudocode and dependencies

## Phase 1: Refinement & Quality Assurance 🔄

### Goals
- Improve pseudocode quality for all entries
- Add dependency mappings
- Validate all 587 entries
- Achieve 100% coverage

### Tasks
1. **Run Refinement**
   ```bash
   python tools/refine_cryptex.py
   ```

2. **Validate Dictionary**
   ```bash
   python tools/validate_cryptex.py
   ```

3. **Analyze Gaps**
   ```bash
   python tools/gap_analyzer.py --directory libyara
   ```

4. **Iterative Improvement**
   - Review entries with short pseudocode
   - Add missing dependencies
   - Fix line references
   - Enhance summaries

## Phase 2: Rust Migration Planning 📋

### Goals
- Map C functions to Rust equivalents
- Identify migration priorities
- Create Rust workspace structure
- Plan incremental migration

### Tasks
1. **Export Cryptex to Rust Format**
   - Generate Rust module structure
   - Create function mapping table
   - Export pseudocode as Rust comments

2. **Create Rust Workspace**
   ```bash
   cargo new --workspace rust
   cd rust
   cargo new cryptex-store
   cargo new yara-runner
   cargo new mcp-gateway
   ```

3. **Migration Priorities**
   - High: Core scanning functions
   - Medium: Module system
   - Low: Utility functions

## Phase 3: MCP Server Enhancement 🚀

### Goals
- Full MCP SDK integration
- Agent-based refinement
- Real-time dictionary updates
- WebSocket support

### Tasks
1. **Install MCP SDK**
   ```bash
   pip install mcp
   ```

2. **Enhance Server**
   - Add WebSocket transport
   - Implement agent tools
   - Add real-time updates

3. **Agent Integration**
   - Connect to Claude/other agents
   - Enable automated refinement
   - Set up feedback loop

## Phase 4: UI Development 🎨

### Goals
- Electron/Svelte interface
- Dictionary browser
- Rule transcoder UI
- Real-time validation

### Tasks
1. **SvelteKit Setup**
   ```bash
   npm create svelte@latest ui
   cd ui
   npm install
   ```

2. **Electron Wrapper**
   - Package Svelte app
   - Add native features
   - Cross-platform builds

3. **Features**
   - Dictionary viewer
   - Entry editor
   - Validation dashboard
   - Rule transcoder interface

## Phase 5: Node-RED Integration 🔌

### Goals
- Custom Node-RED nodes
- Automation workflows
- API integration
- Event-driven processing

### Tasks
1. **Create Custom Nodes**
   - `yara-scan` node
   - `cryptex-lookup` node
   - `rule-transcode` node

2. **Workflows**
   - Automated scanning
   - Rule processing
   - Dictionary updates

## Phase 6: redb Migration 💾

### Goals
- Move from JSON to redb
- Fast lookups
- ACID transactions
- Zero-copy reads

### Tasks
1. **Create redb Schema**
   ```rust
   // cryptex-store/src/schema.rs
   define_table!(entries, Symbol, Entry);
   define_table!(codename_index, Codename, Symbol);
   ```

2. **Migration Script**
   - Import JSON to redb
   - Verify data integrity
   - Performance testing

## Immediate Next Steps

### This Week
1. ✅ Run refinement on all entries
2. ✅ Validate dictionary
3. ✅ Analyze gaps
4. ✅ Fix critical issues

### Next Week
1. Create Rust workspace
2. Export Cryptex to Rust format
3. Start core function migration
4. Set up CI/CD

### This Month
1. Complete refinement phase
2. Begin Rust migration
3. Enhance MCP server
4. Start UI development

## Tools Available

### Analysis
- `tools/audit_agent.py` - Function analysis
- `tools/gap_analyzer.py` - Gap detection
- `tools/validate_cryptex.py` - Validation

### Refinement
- `tools/refine_cryptex.py` - Entry improvement
- `tools/rule_transcoder.py` - Rule translation

### Utilities
- `show_stats.py` - Dictionary statistics
- `mcp_server/api.py` - Python API

## Success Metrics

- **Coverage**: 100% of functions mapped
- **Quality**: All entries have quality pseudocode
- **Dependencies**: All dependencies mapped
- **Validation**: Zero critical issues
- **Rust Progress**: Core functions migrated

## Documentation

- `WORKFLOW.md` - SDLC workflow
- `USAGE_GUIDE.md` - Usage reference
- `FINAL_STATUS.md` - Current status
- `RULE_TRANSCODER_SUMMARY.md` - Transcoder docs
- `NEXT_PHASE_PLAN.md` - This file

