# Cryptex Dictionary Specification

The Cryptex Dictionary is our canonical catalog that maps native YARA constructs to the internal “Pyro / Fire Marshal” vocabulary. It is designed to be produced automatically during MCP ingestion so downstream agents, Node-RED flows, and humans share the same mental model.

## Goals
- Provide a one-to-many mapping between upstream symbols (functions, structs, modules, CLI commands, rule files) and our branded terminology.
- Capture enough metadata (file path, signature, summary, dependencies) so LLM tooling can reconstruct context without rescanning the repository.
- Support incremental regeneration (only touched symbols are reprocessed).

## Naming Scheme
| Domain | Prefix | Example |
| --- | --- | --- |
| Core initialization / teardown | `Pyro-Sentinel-` | `Pyro-Sentinel-Boot` → `yr_initialize` |
| Configuration knobs | `Pyro-Governor-` | `Pyro-Governor-StackDepth` → `yr_set_configuration` (`YR_CONFIG_STACK_SIZE`) |
| Rule compiler / VM | `FireMarshal-Forge-` | `FireMarshal-Forge-Arena` → `yr_compiler_emit*` helpers |
| Scanning APIs | `FireMarshal-Patrol-` | `FireMarshal-Patrol-File` → `yr_rules_scan_file` |
| CLI entry points | `Pyro-Comm-` | `Pyro-Comm-YaraCLI` → `cli/yara.c:main` |
| Rule bundles | `Cryptex-Bundle-` | `Cryptex-Bundle-MalwareSafe` → `yara-rules/safe_malware_index.yar` |
| Helper scripts / automation | `Switchboard-` | `Switchboard-SafeIndex` → `create_safe_rules.py` |

Use kebab-cased suffixes for clarity (e.g., `Pyro-Sentinel-Teardown`).

## Data Model
Store entries as JSON objects (persisted in `data/cryptex.json` and surfaced via MCP `CryptexProvider`):
```json
{
  "symbol": "yr_initialize",
  "pyro_name": "Pyro-Sentinel-Boot",
  "kind": "function",
  "location": "libyara/include/yara/libyara.h",
  "signature": "YR_API int yr_initialize(void);",
  "summary": "Initializes libyara global state (allocators, modules).",
  "dependencies": ["memory_arena", "module_registry"],
  "owner": "libyara/core",
  "risk": "critical",
  "notes": ["Must be invoked before any compiler/scanner API."]
}
```

### Required Fields
- `symbol`: canonical upstream identifier.
- `pyro_name`: branded alias.
- `kind`: `function | struct | module | cli | rule | script`.
- `location`: relative path.
- `signature`: best-effort textual signature (first declaration line).
- `summary`: ≤160 characters.
- `dependencies`: list of other Cryptex `pyro_name` values or external resources.
- `owner`: team/component label (e.g., `libyara/modules`).
- `risk`: `critical | high | standard | informational`.
- `notes`: free-form list (optional).

### Optional Fields
- `examples`: array of file paths that demonstrate usage.
- `tags`: e.g., `["hash", "thread-safe"]`.
- `status`: `stable | experimental | deprecated`.

## Generation Pipeline
1. **Symbol Harvesting**
   - Use `clangd` JSON output or `ctags` to enumerate C declarations inside `libyara/` and `cli/`.
   - Parse Python/PowerShell helpers via `libcst` or `ast`.
   - For YARA rule indexes, parse `include` statements and treat each referenced `.yar` file as a symbol.
2. **Mapping & Enrichment**
   - Apply regex-based router to assign prefixes (e.g., functions containing `yr_rules_scan` ⇒ `FireMarshal-Patrol-*`).
   - Pull docstrings/comments when available; fallback to heuristics (function name + file).
   - Flag any symbols lacking comments for manual review (risk = `informational`).
3. **Validation**
   - Ensure uniqueness of `pyro_name`.
   - Validate dependencies resolve to known entries (allow placeholders for future modules).
4. **Output**
   - Emit deterministic JSON sorted by `pyro_name`.
   - Optionally generate markdown tables for human review (publish under `docs/cryptex/`).
5. **Integration**
   - MCP `CryptexProvider` reads the JSON and serves filtered views.
   - Node-RED flows can request a specific `pyro_name` to drive automations (e.g., show doc panel in Svelte UI).

## Initial Coverage Targets
1. **Bootstrapping APIs**: `yr_initialize`, `yr_finalize`, `yr_set_configuration*`, etc.
2. **Rule lifecycle**: Compiler, scanner, executor (`yr_compiler_create`, `yr_rules_scan_mem`, etc.).
3. **Modules**: `modules/pe`, `modules/elf`, `modules/dotnet`, `modules/math`, `modules/hash`.
4. **Helper automation**: `create_safe_rules.py`, `yara_scanner.py`, `scan.ps1`.
5. **Rule bundles**: Each category index under `yara-rules/`.

## Deliverables
- `data/cryptex.json` (committed artifact once generator exists).
- `docs/cryptex/README.md` summarizing conventions (future).
- Automated generator script (`tools/generate_cryptex.py`) invoked by CI and MCP ingestion.

