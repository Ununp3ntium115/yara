# Agent Integration Guide

## Overview

The Cryptex dictionary system is designed for agent-based refinement and analysis. This guide explains how agents can interact with the system.

## Available Agent Tools

### 1. cryptex-annotate
Add or update Cryptex dictionary entries.

```python
from tools.mcp_agent_tools import annotate_entry

result = await annotate_entry(
    symbol="yr_initialize",
    pyro_name="BlackFlag-Bootstrap-Initialize",
    kind="function",
    location="libyara/libyara.c",
    signature="YR_API int yr_initialize(void);",
    summary="Initializes libyara global state",
    pseudocode="function yr_initialize():\n    init_arenas()\n    init_modules()",
    line_references=[{"file": "libyara/libyara.c", "start": 100, "end": 200}],
    dependencies=[],
    owner="libyara/core",
    risk="critical"
)
```

### 2. function-discovery
Discover functions in source files.

```python
from tools.mcp_agent_tools import MCPAgentTools

tools = MCPAgentTools()
result = await tools.function_discovery("libyara/rules.c", "yr_rules_scan_file")
```

### 3. gap-audit
Find unmapped functions.

```python
result = await tools.gap_audit("libyara")
print(f"Unmapped: {result['unmapped_functions']}")
```

### 4. cryptex-lookup
Query dictionary entries.

```python
from tools.mcp_agent_tools import lookup_entry

# By symbol
entry = await lookup_entry(symbol="yr_initialize")

# By codename
entry = await lookup_entry(pyro_name="BlackFlag-Bootstrap-Initialize")
```

### 5. batch-refine
Batch refine entries.

```python
result = await tools.batch_refine(limit=50)
print(f"Refined: {result['refined']} entries")
```

### 6. get-statistics
Get dictionary statistics.

```python
from tools.mcp_agent_tools import get_stats

stats = await get_stats()
print(f"Total entries: {stats['total_entries']}")
```

## Agent Workflow

### Iterative Refinement Cycle

1. **Discover Gaps**
   ```python
   gaps = await tools.gap_audit("libyara")
   ```

2. **Analyze Functions**
   ```python
   functions = await tools.function_discovery("libyara/rules.c")
   ```

3. **Create/Update Entries**
   ```python
   for func in functions["functions"]:
       await annotate_entry(
           symbol=func["name"],
           pyro_name=generate_codename(func["name"]),
           # ... other fields
       )
   ```

4. **Refine Entries**
   ```python
   await tools.batch_refine(limit=100)
   ```

5. **Validate**
   ```python
   from tools.validate_cryptex import validate_cryptex
   report = validate_cryptex()
   ```

## MCP Server Integration

The MCP server exposes these tools for agent access:

- `cryptex-annotate` - Add/update entries
- `function-discovery` - Find functions
- `gap-audit` - Find gaps
- `cryptex-lookup` - Query entries

## Example Agent Script

```python
import asyncio
from tools.mcp_agent_tools import MCPAgentTools
from tools.validate_cryptex import validate_cryptex

async def agent_refinement_cycle():
    tools = MCPAgentTools()
    
    # 1. Check statistics
    stats = await tools.get_statistics()
    print(f"Current entries: {stats['total_entries']}")
    
    # 2. Find gaps
    gaps = await tools.gap_audit("libyara")
    if gaps['unmapped_functions'] > 0:
        print(f"Found {gaps['unmapped_functions']} unmapped functions")
    
    # 3. Refine entries
    refined = await tools.batch_refine(limit=50)
    print(f"Refined {refined['refined']} entries")
    
    # 4. Validate
    report = validate_cryptex()
    print(f"Validation: {report['status']}")

asyncio.run(agent_refinement_cycle())
```

## Best Practices

1. **Batch Operations**: Use batch_refine for efficiency
2. **Validation**: Always validate after updates
3. **Incremental**: Process in small batches
4. **Review**: Review agent-generated entries
5. **Iterate**: Use SDLC cycle for continuous improvement

## Integration Points

- **MCP Server**: Direct tool access
- **Python API**: Direct function calls
- **CLI Tools**: Command-line interface
- **Validation**: Quality assurance

The system is fully agent-ready!

