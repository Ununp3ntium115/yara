# YARA Cryptex Dictionary SDLC Workflow

This document describes the iterative development cycle for building the complete Cryptex dictionary mapping all YARA functions to anarchist codenames.

## Overview

1. **MCP Server** exposes YARA source code as resources
2. **Agent-based Audit** analyzes functions and generates Cryptex entries
3. **Iterative Refinement** improves entries through SDLC cycles
4. **Validation** ensures complete coverage
5. **Rust Migration** uses completed dictionary for implementation

## Phase 1: MCP Server Setup ✓

The MCP server is now set up to expose:
- All YARA source files (`libyara/**/*.c`, `libyara/**/*.h`)
- CLI source files (`cli/**/*.c`)
- YARA rules (`yara-rules/**/*.yar`)
- Cryptex dictionary (`data/cryptex.json`)

## Phase 2: Initial Audit

### Step 1: Run Audit Agent

```bash
# Start with core library functions
python tools/audit_agent.py --directory libyara --extensions .c

# Then audit headers for declarations
python tools/audit_agent.py --directory libyara/include --extensions .h

# Audit CLI tools
python tools/audit_agent.py --directory cli --extensions .c
```

### Step 2: Review Generated Entries

Check `data/cryptex.json` for:
- Correct function signatures
- Appropriate codenames
- Accurate pseudocode
- Complete line references

### Step 3: Refine Entries

Use MCP tools or direct editing to:
- Fix incorrect pseudocode
- Add missing dependencies
- Improve summaries
- Add notes

## Phase 3: Iterative SDLC Cycle

### Cycle Steps

1. **Audit** - Run audit agent on new/modified files
   ```bash
   python tools/audit_agent.py --file libyara/new_file.c
   ```

2. **Review** - Check generated entries in Cryptex dictionary
   ```bash
   cat data/cryptex.json | jq '.entries[] | select(.symbol == "function_name")'
   ```

3. **Refine** - Update entries via MCP server or direct editing
   - Use `cryptex-annotate` tool
   - Or edit `data/cryptex.json` directly

4. **Validate** - Check for gaps
   ```bash
   # Use MCP gap-audit tool or:
   python -m mcp_server.server  # Then call gap-audit tool
   ```

5. **Document** - Update documentation with new mappings

### Automation

Create a script to run the full cycle:

```bash
#!/bin/bash
# audit_cycle.sh

echo "Step 1: Auditing codebase..."
python tools/audit_agent.py --directory libyara --extensions .c .h

echo "Step 2: Checking for gaps..."
# Run gap-audit via MCP

echo "Step 3: Review and refine entries in data/cryptex.json"
echo "Step 4: Commit changes"
```

## Phase 4: Coverage Validation

### Check Completeness

1. **Function Count**: Compare total functions in codebase vs Cryptex
2. **Module Coverage**: Ensure all modules are mapped
3. **Dependency Resolution**: Verify all dependencies have entries
4. **Line Reference Accuracy**: Validate line numbers are correct

### Gap Analysis

Run gap audit regularly:
```bash
python -m mcp_server.server  # Use gap-audit tool
```

## Phase 5: Quality Assurance

### Entry Quality Checklist

Each Cryptex entry should have:
- [ ] Accurate function signature
- [ ] Meaningful branded codename
- [ ] Clear summary (≤160 chars)
- [ ] Pseudocode that represents logic
- [ ] Correct line references
- [ ] Complete dependency list
- [ ] Appropriate risk level
- [ ] Owner/component assignment

### Review Process

1. **Automated Checks**: Validate JSON schema
2. **Peer Review**: Review codenames and pseudocode
3. **Functional Verification**: Test that pseudocode matches implementation

## Phase 6: Rust Migration Preparation

Once dictionary is complete:

1. **Export Mappings**: Generate Rust code from Cryptex entries
2. **Create Bindings**: Map C functions to Rust equivalents
3. **Implement Pseudocode**: Convert pseudocode to Rust implementations
4. **Test Compatibility**: Ensure Rust version matches C behavior

## Continuous Improvement

### Regular Updates

- Run audit after code changes
- Update entries when functions are modified
- Add new entries for new functions
- Deprecate entries for removed functions

### Metrics

Track:
- Total entries in dictionary
- Coverage percentage
- Last update timestamp
- Number of unmapped functions

## Tools Reference

- **audit_agent.py**: Analyzes source files and generates entries
- **MCP Server**: Exposes resources and provides tools
- **gap-audit tool**: Finds unmapped functions
- **cryptex-annotate tool**: Adds/updates entries
- **cryptex-lookup tool**: Queries dictionary

## Next Steps

1. Run initial audit on `libyara/` directory
2. Review and refine generated entries
3. Set up automated audit cycle
4. Achieve 100% function coverage
5. Begin Rust migration planning

