# In-House Audit (November 2025)

## Snapshot
- **Upstream baseline**: Classic C YARA 4.5.5 tree with GNU Autotools (`bootstrap.sh`, `build.sh`, `configure.ac`, `Makefile.am`).
- **Local additions**: Repository currently carries untracked automation and helper assets (`create_safe_rules.py`, `yara_scanner.py`, `scan.ps1`, `SESSION_NOTES.md`, `.claude/`, entire `yara-rules/` mirror). These need to be curated or promoted into tracked artifacts.
- **Rule corpus**: `yara-rules/` is checked in with the upstream indexes plus a generated `safe_malware_index.yar`, giving us a ready-to-serve dataset for training/export.
- **Current branch state**: Working tree diverges from `origin/master` with only untracked files, suggesting audit/cleanup can proceed without merge conflicts once files are formally added or ignored.

## Repo Anatomy (High-Level)
| Area | Purpose | Notes |
| --- | --- | --- |
| `libyara/` | Core compiler, scanner, VM, modules | Pure C; includes headers under `libyara/include/yara/` |
| `cli/` | `yara` and `yarac` command-line frontends | Linked against `libyara` |
| `docs/` | Sphinx documentation (`.rst`) plus tooling | Publish to Read the Docs |
| `tests/` | Module- and feature-level C tests run via `make check` | Uses `tests/util.c` harness |
| `extra/`, `sandbox/` | Sample integrations + experimental glue | Candidate areas for removal or documentation |
| `yara-rules/` | Embedded copy of community rules, including indexes | Treated as dataset source |
| `create_safe_rules.py`, `yara_scanner.py`, `scan.ps1` | Local automation for curating rules and scanning systems | Need formal home (likely `tools/`) |

## Build & Test Health
- Toolchain: `bootstrap.sh` ⇒ `configure` ⇒ `make`; optional convenience script `build.sh`.
- Works across Windows, Linux, macOS; Windows-specific scaffolding lives under `windows/` plus PowerShell scanner (`scan.ps1`).
- CI hooks exist upstream (`.github`, `appveyor.yml`), but no local GitHub Actions customization is present for our added tooling—worth adding once MCP/server pieces land.
- Tests rely on curated corpus in `tests/` and can be extended to cover the new automation (Python unit tests, integration scans).

## Rule Assets
- `yara-rules/index.yar` and topical indexes exist; safe subset generator writes to `yara-rules/safe_malware_index.yar` to avoid `cuckoo` dependencies.
- Scripts such as `create_safe_rules.py` expect the corpus to live at `yara-rules/` relative to repo root—good candidate for parametrization when exposing via MCP server.
- Recommend tracking checksum metadata (SBOM-style manifest) so the MCP export can advertise provenance.

## Custom Tooling Status
- `create_safe_rules.py` filters rule inclusions by inspecting each file for `cuckoo.` references, emitting a clean index for environments lacking that module.
- `yara_scanner.py` wraps `yara-python` to scan host directories, emits JSON, and is a natural backend for Node-RED/Svelte orchestrations.
- None of the helper scripts have automated tests or packaging; they should graduate into a `tools/` namespace with `pyproject.toml` or similar packaging for reuse in MCP plugins.

## Cleanup & Hardening Opportunities
1. **Source control hygiene**
   - Decide which of the untracked assets become first-class (recommended: scripts + safe index) and which belong in `.gitignore`.
   - Add CODEOWNERS / SECURITY updates reflecting the new automation scope.
2. **Documentation**
   - Surface helper tooling in `docs/gettingstarted.rst` and/or the yet-to-be-written Svelte UI spec so internal teams can discover it.
   - Capture rule-curation process (what makes a rule “safe”) as policy text for auditors.
3. **Testing**
   - Add Python unit tests for rule filtering + scanning logic.
   - Wire minimal CI job that runs `python -m compileall` or `pytest` on helper scripts alongside `make check`.
4. **Packaging & Distribution**
   - Provide a `tools/requirements.txt` (or `pyproject.toml`) locking `yara-python` and other deps.
   - Document how MCP/server components will vend both compiled and source rulesets without violating licensing.
5. **Security posture**
   - Enforce `YR_PARANOID_EXEC` (already default in `libyara/include/yara/libyara.h`) and document acceptable configuration overrides.
   - Plan for code-signing of rule bundles exported through the upcoming MCP server.

## Inputs for Re-engineering
- The existing CLI / library surface is stable; we can wrap it without patching C code.
- Python scanner + rule-curation scripts already offer a clean seam for Node-RED nodes and MCP tooling (they can be converted into services).
- Any Svelte interface should consume the MCP server APIs rather than touching the filesystem directly, to keep training exports + dashboards in sync.

Use this document as the baseline for the MCP server specification, cryptex dictionary plan, and the Node-RED/Svelte re-platforming roadmap.

