# YARA Audit Tools

Tools for agent-based auditing of the YARA codebase and Cryptex dictionary generation.

## audit_agent.py

Analyzes YARA source files and generates Cryptex dictionary entries with:
- Function names and signatures
- Branded anarchist codenames
- Pseudocode representations
- Line references
- Dependencies

### Usage

```bash
# Audit a single file
python tools/audit_agent.py --file libyara/rules.c

# Audit entire directory
python tools/audit_agent.py --directory libyara

# Audit with specific extensions
python tools/audit_agent.py --directory libyara --extensions .c .h

# Specify output file
python tools/audit_agent.py --directory libyara --output data/cryptex.json
```

## SDLC Workflow

1. **Discovery**: Run audit agent on codebase sections
2. **Review**: Check generated Cryptex entries
3. **Refinement**: Use MCP server tools to update entries
4. **Iteration**: Repeat until all functions mapped
5. **Validation**: Verify completeness with gap-audit tool

## Integration with MCP Server

The audit agent can work with the MCP server:
- Use `function-discovery` tool to find functions
- Use `cryptex-annotate` tool to add entries
- Use `gap-audit` tool to find unmapped functions

