# Cryptex Dictionary Program (Anarchist Edition)

## Purpose
Rename every meaningful function, module, document, and helper in the YARA ecosystem using anarchist terminology, pair each entry with pseudocode, and serve it via the MCP server so downstream tooling (Pyro Fire Marshal, Node-RED, Svelte/Electron) can reason about the system using our branded vocabulary.

## Workflow
1. **Harvest Symbols**
   - Run symbol extraction (ctags/clangd) for C sources, AST parsing for Python/PowerShell, glob includes for `.yar` files, and headings for docs.
2. **Assign Codename**
   - Follow prefix taxonomy (e.g., `BlackFlag-*` for init/shutdown, `Molotov-*` for scanning, `IronCurtain-*` for PE module).
   - Keep naming anarchist, descriptive, and unique.
3. **Capture Metadata**
   - Upstream symbol name.
   - File path.
   - One-line summary.
   - Pseudocode sketch showing control flow.
   - Dependencies or linked Cryptex entries.
4. **Persist**
   - During early phase: append to `docs/CRYPTEX_DICTIONARY_SEED.md`.
   - Production phase: write to `redb` via `cryptex-store` crate (Rust) and expose through MCP `cryptex/*`.
5. **Distribute**
   - MCP `cryptex-lookup` tool.
   - Node-RED node for UI overlays.
   - Svelte/Electron dictionary panel (offline snapshots allowed).

## Naming Guidelines
| Domain | Prefix Examples |
| --- | --- |
| Init/Finalize | `BlackFlag-`, `Revolt-` |
| Configuration | `Cell-`, `Council-` |
| Compiler | `InkSlinger-`, `Forge-` |
| Scanner | `Molotov-`, `Patrol-` |
| Modules (PE/ELF/etc.) | `IronCurtain-`, `Ghostline-`, `Siren-` |
| Automation Scripts | `Switchblade-`, `Streetlight-` |
| Docs | `SignalFire-`, `Manifest-` |

Always include a hyphenated suffix describing the action (e.g., `BlackFlag-Bootstrap`, `Switchblade-SafeIndex`).

## Tooling
- `cryptex-cli` (Rust): add/list/export entries; syncs with `redb`.
- MCP tool `cryptex-annotate`: remote clients can append/edit entries.
- Node-RED node `cryptex-report`: fetch codename details for workflows.
- CI job verifying each entry has summary + pseudocode and references a real file.

## Integration Points
- **Gap Analyzer**: When a component lacks a Rust port, tag its Cryptex entry with `status = legacy` so dashboards highlight remaining work.
- **Training Pipelines**: LLM ingestion uses Cryptex metadata to prioritize context (alias + pseudocode + source snippet).
- **UI**: Svelte/Electron dictionary view offers search, filters (by prefix, status), and deep links to source via MCP resources.

## Next Steps
1. Continue expanding `docs/CRYPTEX_DICTIONARY_SEED.md` until coverage hits 100%.
2. Implement `cryptex-store` crate with Redb schema (`codename` → struct), plus migration scripts.
3. Wire Cryptex provider into MCP server and Node-RED node.
4. Create onboarding guide for contributors on how to propose new codenames.

