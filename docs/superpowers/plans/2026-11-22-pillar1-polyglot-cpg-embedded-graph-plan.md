# ALASTOR v5.0 Pillar 1 — Polyglot 18-Language CPG Compiler, Dual-Engine Embedded GraphStore & Leiden Communities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade ALASTOR's CPG compiler to support all 18 enterprise/systems/Web3/template language families with generalized domain-aware sanitizer tracking, hostile-repo scope walking, a dual-engine `Neo4j` + zero-Docker SQLite Embedded `GraphStore`, deterministic Leiden community clustering, 12 new polyglot deterministic rule packs (`RULE-22..RULE-33`), and Light-Only Daylight UI telemetry & `COMMUNITY_MAP` visualization.

**Architecture:** Introduce a declarative `LanguageSpec` registry (`backend/compiler/language_registry.py`) backed by `tree-sitter-language-pack` so all 4 CPG passes (`ASTNormalizer`, `CFGBuilder`, `DFGBuilder`, `CallGraphBuilder`) stay unified and language-agnostic. Wrap Neo4j and a new pure-Python SQLite WAL embedded CPG store behind `GraphStoreManager` (`backend/database/graph_store.py`) with automatic offline failover, wire deterministic modularity clustering (`backend/engine/community_detector.py`) and 12 new polyglot rules (`backend/engine/polyglot_rules.py`), expose confined FastAPI endpoints in `backend/main.py`, and render live engine status, polyglot telemetry, and the `COMMUNITY_MAP` graph view in the Next.js Daylight Studio UI.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, `tree-sitter` + `tree-sitter-language-pack`, SQLite 3 (WAL mode, stdlib `sqlite3`), Neo4j 5 + APOC, Next.js 15 / React 19, TypeScript, Zustand, `reactflow` (`11.11.4`) + `@dagrejs/dagre`, Tailwind CSS (Light-Only Daylight WCAG AA `>= 4.5:1`).

## Global Constraints

- **Work on `main` only** in `c:\Projects\Securecodereview\cpg-sast-platform`; preserve 100% of existing ALASTOR v4.0 capabilities (all 68 existing backend tests must remain passing).
- **Light-Only Daylight UI (`>= 4.5:1` WCAG AA):** Use `#f8fafc` / `#ffffff` surfaces, `slate-900`/`800`/`700` typography, and high-contrast `emerald`/`sky`/`indigo`/`amber`/`rose` badges; zero dark-only backgrounds.
- **Zero Self-Audit Findings:** ALASTOR self-audit across `c:\Projects\Securecodereview\cpg-sast-platform` must report `0` findings across CPG SAST, SCA, IaC, and working-tree + git-history Secret Scanner — **even after removing the hardcoded XSS variable allowlists from `ast_parser.py`**.
- **Security Invariants:** Strictly parameterized SQLite `?` queries; `.alastor_vault/cpg_embedded.db` permissions `0o600` (dir `0o700`); symlink confinement (`os.path.realpath` + `os.path.commonpath`) dropping escaping symlinks; pure-Python `.gitignore` parsing (never invoke target `git` hooks or read target `.env`); zero raw secret leakage; log sanitization via `_sanitize_log`.
- **Zero JVM Dependencies:** Never install `arcadedb-embedded` (avoids bundled JVM and `CVE-2026-91403`).

---

## File Map

| File | Action | Responsibility |
| :--- | :--- | :--- |
| `backend/requirements.txt` | Modify | Pin `tree-sitter` + `tree-sitter-language-pack` compatible with bundled wheels |
| `backend/models.py` | Modify | Add `GraphEngineMode`, `ScanScopeTelemetry`, `GraphCommunityItem`, `CommunityBridgeEdge`, `CommunityMapResponse`, `LanguageCapabilityItem`, `LanguageCapabilitiesResponse`; add optional `sanitizer_domains`, `sink_domain`, `language` on `CPGNode` and optional telemetry fields on `MetricsResponse` & `ScanResponse` |
| `backend/compiler/language_registry.py` | Create | Declarative 18-language `LanguageSpec` registry, extension map (55+ extensions), thread-safe lazy Tree-sitter parser loader, per-language sources/sinks/sanitizers/domains |
| `backend/compiler/scanner.py` | Modify | Hostile-repo-safe polyglot walker: symlink confinement, in-process `.gitignore`, contextual ecosystem build-dir exclusions, `scan_directory_with_telemetry` |
| `backend/compiler/ast_parser.py` | Modify | Consume `LanguageSpec`; remove hardcoded app-specific XSS allowlists (`detailsHtml`, `warnHtml`, `unverHtml`, `selfSearchLinks`, `HOT_TYPES.test(`, `breachCount`); attach domain-scoped `sanitizer_domains`/`sink_domain`/`language` |
| `backend/compiler/cfg_builder.py` | Modify | Consume `LanguageSpec` parsers & branch/loop/terminator node sets for all 18 languages |
| `backend/compiler/dfg_builder.py` | Modify | Consume `LanguageSpec`; implement generalized domain-aware `sanitized_vars` & helper-body sanitizer propagation |
| `backend/compiler/call_graph_builder.py` | Modify | Support cross-file polyglot call resolution & import-hint matching |
| `backend/engine/polyglot_rules.py` | Create | 12 deterministic polyglot rule packs (`RULE-22` through `RULE-33`) for C/C++/Rust, JVM/.NET/Go/PHP/Ruby/Swift/Dart, Solidity, and Web Templates |
| `backend/database/graph_store.py` | Create | `GraphStoreManager` facade (`auto|neo4j|embedded`), `Neo4jGraphStore`, and `EmbeddedGraphStore` (SQLite WAL + in-memory adjacency + native 21-rule parity + all 8 graph views) |
| `backend/engine/community_detector.py` | Create | Deterministic modularity/Leiden file clustering + cross-community & polyglot bridge detection |
| `backend/engine/rule_executor.py` | Modify | Domain-aware sanitizer check on `RULE-1-TAINT`, expose parity helpers, merge `polyglot_rules` execution |
| `backend/engine/enterprise_manager.py` | Modify | Enrich `RULE-22..RULE-33` findings with plain-English translations, RACI, STRIDE, and PASTA metadata |
| `backend/main.py` | Modify | Wire `graph_store_mgr`, zero-Docker startup/scan failover, `COMMUNITY_MAP` graph view, `/api/graph/communities`, `/api/languages/capabilities`, and telemetry in `/api/health`, `/api/metrics`, `/api/scan` |
| `backend/tests/test_polyglot_cpg_compiler.py` | Create | TDD suite covering 18 languages, hostile-repo walker, generalized domain-aware sanitizers, and `RULE-22..RULE-33` |
| `backend/tests/test_embedded_graph_store_and_communities.py` | Create | TDD suite covering offline zero-Docker failover, SQLite persistence, 21-rule parity, Leiden communities, and new FastAPI routes |
| `frontend/src/types/cpg.ts` | Modify | Add Pillar 1 TypeScript interfaces and `"COMMUNITY_MAP"` to `GraphViewMode` |
| `frontend/src/lib/api.ts` | Modify | Add `fetchCommunityMap()`, `fetchLanguageCapabilities()`, and typed `fetchBackendHealth()` |
| `frontend/src/store/useAuditStore.ts` | Modify | Add `graphEngineMode`, `scopeTelemetry`, `languagesDetected`, `communityMap`, `languageCapabilities` state & fetch actions |
| `frontend/src/components/StudioCommandHeader.tsx` | Modify | Add Light-Only Daylight Graph Engine pill (`Neo4j + APOC` vs `Embedded SQLite CPG • Zero-Docker`) |
| `frontend/src/components/TopMetricsBar.tsx` | Modify | Add Polyglot Language Coverage & Hostile-Walker Telemetry strip |
| `frontend/src/components/ReactFlowGraphPane.tsx` | Modify | Add `COMMUNITY_MAP` view mode button, cluster node rendering, polyglot bridge styling, and click-to-open representative file in Monaco |

---

### Task 1: Declarative 18-Language `LanguageSpec` Registry, Pillar 1 Models & Hostile-Repo Scope Walker

**Files:**
- Modify: `backend/requirements.txt`
- Modify: `backend/models.py`
- Create: `backend/compiler/language_registry.py`
- Modify: `backend/compiler/scanner.py`
- Create: `backend/tests/test_polyglot_cpg_compiler.py`

**Interfaces:**
- Consumes: `models.CPGNode`, `models.MetricsResponse`, `models.ScanResponse`, `tree_sitter_language_pack`.
- Produces:
  - `backend/models.py`: `GraphEngineMode`, `ScanScopeTelemetry`, `GraphCommunityItem`, `CommunityBridgeEdge`, `CommunityMapResponse`, `LanguageCapabilityItem`, `LanguageCapabilitiesResponse`; optional `CPGNode.sanitizer_domains: List[str]`, `CPGNode.sink_domain: Optional[str]`, `CPGNode.language: str`.
  - `backend/compiler/language_registry.py`: `LanguageSpec`, `LANGUAGE_SPECS: Dict[str, LanguageSpec]`, `EXTENSION_TO_LANGUAGE: Dict[str, str]`, `resolve_language_for_filename(filename: str) -> Optional[str]`, `get_language_spec(lang_key: str) -> LanguageSpec`, `get_parser_for_language(lang_key: str) -> Optional[tree_sitter.Parser]`, `list_language_capabilities() -> LanguageCapabilitiesResponse`.
  - `backend/compiler/scanner.py`: `CODE_EXTENSIONS` (55+ extensions), `ScannedFile`, `scan_directory(root_dir: str) -> List[ScannedFile]`, `scan_directory_with_telemetry(root_dir: str, exclude_tests: bool = False) -> Tuple[List[ScannedFile], ScanScopeTelemetry]`.

- [ ] **Step 1: Install `tree-sitter-language-pack` in `.venv` and pin in `backend/requirements.txt`**

Run in `c:\Projects\Securecodereview\cpg-sast-platform`:
```powershell
.\.venv\Scripts\python.exe -m pip install "tree-sitter>=0.23.2,<0.26" "tree-sitter-language-pack>=0.7.0"
.\.venv\Scripts\python.exe -c "import tree_sitter, tree_sitter_language_pack as tslp; print(tree_sitter.__version__, tslp.get_parser('go'), tslp.get_parser('java'), tslp.get_parser('rust'), tslp.get_parser('solidity'))"
```
Pin the installed compatible `tree-sitter` and `tree-sitter-language-pack` versions in `backend/requirements.txt` (preserving `tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-typescript` compatibility; verify existing 68 tests still import cleanly).

- [ ] **Step 2: Write failing TDD tests in `backend/tests/test_polyglot_cpg_compiler.py`**

```python
import os
from pathlib import Path
import pytest

from compiler.language_registry import (
    LANGUAGE_SPECS,
    get_language_spec,
    get_parser_for_language,
    list_language_capabilities,
    resolve_language_for_filename,
)
from compiler.scanner import scan_directory_with_telemetry


EXPECTED_18_LANGUAGES = {
    "python", "javascript", "typescript", "tsx", "go", "java", "kotlin",
    "csharp", "scala", "c", "cpp", "rust", "ruby", "php", "swift", "dart",
    "solidity", "web_template",
}


def test_language_registry_covers_all_18_families_and_parsers():
    assert EXPECTED_18_LANGUAGES.issubset(set(LANGUAGE_SPECS.keys()))
    assert resolve_language_for_filename("app.blade.php") == "web_template"
    assert resolve_language_for_filename("Vault.sol") == "solidity"
    assert resolve_language_for_filename("handler.go") == "go"
    assert resolve_language_for_filename("Main.kt") == "kotlin"
    assert resolve_language_for_filename("Program.cs") == "csharp"
    assert resolve_language_for_filename("index.jinja2") == "web_template"

    caps = list_language_capabilities()
    assert caps.total_languages >= 18
    for lang_key in ("python", "javascript", "typescript", "tsx", "go", "java", "c", "cpp", "rust", "php", "ruby", "csharp"):
        parser = get_parser_for_language(lang_key)
        assert parser is not None, f"Parser failed to load for {lang_key}"


def test_hostile_scope_walker_drops_escaping_symlinks_gitignore_and_contextual_build_dirs(tmp_path: Path):
    outside_dir = tmp_path / "outside_host"
    outside_dir.mkdir()
    secret_host_file = outside_dir / "host_secret.py"
    secret_host_file.write_text("SECRET = 'top_secret'\n", encoding="utf-8")

    repo = tmp_path / "target_repo"
    repo.mkdir()
    (repo / ".gitignore").write_text("ignored_dir/\n*.ignored.py\n", encoding="utf-8")
    (repo / "ignored_dir").mkdir()
    (repo / "ignored_dir" / "skip.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "temp.ignored.py").write_text("x = 2\n", encoding="utf-8")

    # Contextual build output: Cargo.toml + target/ must skip target/
    (repo / "Cargo.toml").write_text("[package]\nname = 'demo'\n", encoding="utf-8")
    (repo / "target").mkdir()
    (repo / "target" / "compiled.rs").write_text("fn gen() {}\n", encoding="utf-8")

    # Application folder named target/ WITHOUT a manifest in a subdir must stay in scope!
    (repo / "app" / "target").mkdir(parents=True)
    (repo / "app" / "target" / "service.go").write_text("package target\nfunc Run() {}\n", encoding="utf-8")

    # Generated stub must be excluded
    (repo / "api.pb.go").write_text("package pb\n", encoding="utf-8")
    # Valid source files
    (repo / "main.py").write_text("def hello():\n    return 1\n", encoding="utf-8")
    (repo / "Vault.sol").write_text("pragma solidity ^0.8.20;\ncontract Vault {}\n", encoding="utf-8")

    # Escaping symlink (skip creation if Windows lacks symlink privilege; test helper directly)
    escape_link = repo / "escape.py"
    symlink_created = False
    try:
        os.symlink(str(secret_host_file), str(escape_link))
        symlink_created = True
    except OSError:
        symlink_created = False

    files, telemetry = scan_directory_with_telemetry(str(repo))
    rel_paths = {f.filepath for f in files}
    assert "main.py" in rel_paths
    assert "Vault.sol" in rel_paths
    assert "app/target/service.go" in rel_paths
    assert "ignored_dir/skip.py" not in rel_paths
    assert "temp.ignored.py" not in rel_paths
    assert "target/compiled.rs" not in rel_paths
    assert "api.pb.go" not in rel_paths
    assert "escape.py" not in rel_paths
    assert telemetry.gitignore_excluded >= 2
    assert telemetry.build_dirs_excluded >= 1
    assert telemetry.generated_excluded >= 1
    if symlink_created:
        assert telemetry.symlinks_dropped >= 1
```

- [ ] **Step 3: Run focused test to verify RED failure**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_polyglot_cpg_compiler.py -v
```
Expected: FAIL (`ModuleNotFoundError: No module named 'compiler.language_registry'`).

- [ ] **Step 4: Implement Pillar 1 models in `backend/models.py`, create `backend/compiler/language_registry.py`, and upgrade `backend/compiler/scanner.py`**

1. In `backend/models.py`:
   - Add `sanitizer_domains: List[str] = Field(default_factory=list)`, `sink_domain: Optional[str] = None`, `language: str = "python"` to `CPGNode`.
   - Add Section 14 models: `GraphEngineMode`, `ScanScopeTelemetry`, `GraphCommunityItem`, `CommunityBridgeEdge`, `CommunityMapResponse`, `LanguageCapabilityItem`, `LanguageCapabilitiesResponse`.
   - Add optional backward-compatible fields `graph_engine_mode: Optional[GraphEngineMode] = None`, `languages_detected: Dict[str, int] = Field(default_factory=dict)`, `scope_telemetry: Optional[ScanScopeTelemetry] = None`, `communities_count: int = 0` to `MetricsResponse` and `ScanResponse`.
2. Create `backend/compiler/language_registry.py` with:
   - `LanguageSpec` dataclass declaring `key`, `display_name`, `grammar_name`, `extensions`, `suffix_patterns` (e.g., `.blade.php`), `function_types`, `class_types`, `call_types`, `assign_types`, `branch_types`, `loop_types`, `return_types`, `terminator_types`, `param_types`, `import_types`, `string_types`, `source_patterns`, `sink_catalog: Dict[str, str]` (`pattern -> sink_domain`), `sanitizer_catalog: Dict[str, List[str]]` (`pattern -> sanitizer_domains`), `route_markers`, and `rule_pack_ids`.
   - All 18 language families populated completely per Section 2.1 of the design spec.
   - Thread-safe lazy parser loader using `tree_sitter_language_pack.get_parser(...)` with fallback to `tree_sitter_python`/`javascript`/`typescript`.
3. Upgrade `backend/compiler/scanner.py`:
   - Derive `CODE_EXTENSIONS` from `EXTENSION_TO_LANGUAGE` (plus `.blade.php` suffix resolution via `resolve_language_for_filename`).
   - Implement pure-Python nested `.gitignore` matcher, `os.path.realpath` + `os.path.commonpath` symlink guard (`followlinks=False`), contextual build-output directory skipping (`target/`, `bin/`, `obj/`, `Pods/`, `out/`, `artifacts/`, `cache/`), generated-stub skipping (`*.pb.go`, `*_pb2.py`, `*.g.cs`, `*.Designer.cs`, `*.generated.*`), and `scan_directory_with_telemetry(...)` while keeping `scan_directory(root_dir)` returning `List[ScannedFile]`.

- [ ] **Step 5: Run tests and verify GREEN**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_polyglot_cpg_compiler.py -v
..\.venv\Scripts\python.exe -m pytest -q
```
Expected: All Task 1 tests + all 68 existing tests PASS.

- [ ] **Step 6: Commit Task 1**

```powershell
git add backend/requirements.txt backend/models.py backend/compiler/language_registry.py backend/compiler/scanner.py backend/tests/test_polyglot_cpg_compiler.py
git commit -m "feat(polyglot): add 18-language Tree-sitter registry, Pillar 1 models, and hostile-repo scope walker"
```

---

### Task 2: Unified 4-Pass Polyglot CPG Compiler, Generalized Domain-Aware Sanitizer Tracking & 12 New Polyglot Rule Packs (`RULE-22..RULE-33`)

**Files:**
- Modify: `backend/compiler/ast_parser.py`
- Modify: `backend/compiler/cfg_builder.py`
- Modify: `backend/compiler/dfg_builder.py`
- Modify: `backend/compiler/call_graph_builder.py`
- Create: `backend/engine/polyglot_rules.py`
- Modify: `backend/tests/test_polyglot_cpg_compiler.py`

**Interfaces:**
- Consumes: `compiler.language_registry` (`get_language_spec`, `get_parser_for_language`, `LANGUAGE_SPECS`), `compiler.scanner.ScannedFile`, `models.CPGNode`, `models.CPGEdge`, `models.Finding`.
- Produces:
  - `ASTNormalizer(scanned_file).parse() -> Tuple[List[CPGNode], List[CPGEdge]]` working across all 18 languages with domain-scoped `sanitizer_domains`/`sink_domain`/`language` and zero hardcoded app-specific variable names.
  - `CFGBuilder(...).build() -> List[CPGEdge]` working across all 18 languages.
  - `DFGBuilder(...).build() -> List[CPGEdge]` working across all 18 languages + propagating `sanitized_vars` and structurally verified helper-function sanitizer domains.
  - `CallGraphBuilder(all_nodes).resolve_calls() -> List[CPGEdge]` resolving local, imported, and cross-file polyglot calls.
  - `backend/engine/polyglot_rules.py`: `POLYGLOT_RULE_CATALOG: List[Dict[str, Any]]`, `run_polyglot_rules(scanned_files: List[ScannedFile], all_nodes: List[CPGNode], all_edges: List[CPGEdge], enabled_rule_ids: Optional[Set[str]] = None) -> List[Finding]`.

- [ ] **Step 1: Add failing TDD tests to `backend/tests/test_polyglot_cpg_compiler.py`**

Add tests covering:
1. `test_all_18_languages_compile_ast_cfg_dfg_and_calls`: Compiles representative code snippets for all 18 language families (`python`, `javascript`, `typescript`, `tsx`, `go`, `java`, `kotlin`, `csharp`, `scala`, `c`, `cpp`, `rust`, `ruby`, `php`, `swift`, `dart`, `solidity`, `web_template`) through `ASTNormalizer` -> `CFGBuilder` -> `DFGBuilder` -> `CallGraphBuilder`, asserting non-empty nodes and deterministic `AST_CHILD`, `CFG_NEXT`, `DFG_FLOWS_TO`, and `CALLS` edges.
2. `test_generalized_domain_aware_sanitizer_tracking_replaces_hardcoded_allowlists`:
   - Verifies that an arbitrary new variable name `const safeCard = \`<div>\${escapeHtml(user.name)}</div>\`; el.innerHTML = safeCard;` is marked HTML-sanitized (`is_sanitizer=True`, `"HTML" in sanitizer_domains`, `el.innerHTML` assignment not flagged as unsafe XSS).
   - Verifies that `el.innerHTML = \`<a href="\${escapeHtml(user.url)}">Link</a>\`;` IS STILL flagged (`sink_domain="URL"` not cleared by `"HTML"` sanitizer!).
   - Verifies that `html.escape(cmd)` does NOT neutralize `os.system(cmd)` (`sink_domain="SHELL"`), whereas `shlex.quote(cmd)` DOES.
   - Asserts legacy hardcoded identifiers (`detailsHtml`, `warnHtml`, `unverHtml`, `HOT_TYPES.test(`) no longer exist in `backend/compiler/ast_parser.py`.
3. `test_polyglot_rule_packs_22_through_33_detect_vulns_and_respect_safe_patterns`:
   - Tests positive (vulnerable) and negative (safe/remediated) fixtures for all 12 rules:
     - `RULE-22-CPP-BUFFER-OVERFLOW` (`strcpy(dst, user_in)` vs `strncpy`)
     - `RULE-23-CPP-FORMAT-STRING` (`printf(user_in)` vs `printf("%s", user_in)`)
     - `RULE-24-CPP-UAF-DOUBLE-FREE` (`free(ptr); use(ptr);` / `free(ptr); free(ptr);`)
     - `RULE-25-RUST-UNSAFE-FFI` (`unsafe { *raw_ptr }` / `std::mem::transmute`)
     - `RULE-26-POLYGLOT-SQLI` (Go `db.Query("SELECT ... " + id)`, Java `stmt.executeQuery("..." + id)`, PHP `mysqli_query($c, "... " . $_GET['id'])` vs parameterized queries)
     - `RULE-27-POLYGLOT-CMDI` (Go `exec.Command("sh", "-c", userCmd)`, Java `Runtime.getRuntime().exec(cmd)`, PHP `shell_exec($_GET['c'])`)
     - `RULE-28-POLYGLOT-DESER` (Java `ObjectInputStream.readObject`, C# `BinaryFormatter.Deserialize`, PHP `unserialize($_POST['d'])`, Ruby `Marshal.load(data)`)
     - `RULE-29-POLYGLOT-XXE` (Java `DocumentBuilderFactory.newInstance()` without `disallow-doctype-decl`, C# `XmlDocument.Load`)
     - `RULE-30-SOLIDITY-REENTRANCY` (`msg.sender.call{value: bal}("")` before `balances[msg.sender] = 0;` without `nonReentrant` vs `nonReentrant` modifier)
     - `RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE` (`require(tx.origin == owner)` and `target.delegatecall(data)`)
     - `RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI` (`{{ user_bio|safe }}`, `<%- rawHtml %>`, `{!! $body !!}`)
     - `RULE-33-TEMPLATE-MISSING-CSRF` (`<form method="POST" action="/transfer">` without CSRF token vs with `csrf_token`)

- [ ] **Step 2: Run new tests to verify RED**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_polyglot_cpg_compiler.py -v
```
Expected: FAIL (`ModuleNotFoundError: No module named 'engine.polyglot_rules'` and generalized sanitizer/18-lang assertions failing).

- [ ] **Step 3: Upgrade `ast_parser.py`, `cfg_builder.py`, `dfg_builder.py`, `call_graph_builder.py` and create `backend/engine/polyglot_rules.py`**

1. **`backend/compiler/ast_parser.py`**:
   - Keep `py_parser`, `js_parser`, `ts_parser`, `tsx_parser`, `compute_node_id`, `compute_edge_id`, `classify_taint` exported for backward compatibility.
   - Refactor `ASTNormalizer.parse()` to fetch `spec = get_language_spec(self.language)` and `parser = get_parser_for_language(self.language)`. Handle `web_template` via HTML Tree-sitter + lightweight template-block extraction so template nodes appear cleanly in the CPG.
   - Remove the app-specific hardcoded allowlists (`detailsHtml`, `warnHtml`, `unverHtml`, `selfSearchLinks`, `HOT_TYPES.test(`, `breachCount`, `done.has(`, `s.links.join`) from `_is_unsafe_html_assignment`. Instead use pure structural checks (pure literals, pure numeric/boolean expressions, sanitizer calls, and rejecting `href="${esc(...)}"` URI bypasses), while delegating variable-level sanitizer tracking to `DFGBuilder`!
   - Populate `CPGNode.language`, `CPGNode.sink_domain`, and `CPGNode.sanitizer_domains` from `LanguageSpec`.
2. **`backend/compiler/cfg_builder.py`**:
   - Use `get_parser_for_language(self.language)` and `LanguageSpec` node sets (`function_types`, `branch_types`, `loop_types`, `terminator_types`, `return_types`) so all 18 languages emit `CFG_NEXT`, `CFG_TRUE`, `CFG_FALSE`, `CFG_LOOP_BACK`, and `CFG_UNREACHABLE`.
3. **`backend/compiler/dfg_builder.py`**:
   - Use `get_parser_for_language(self.language)` and `LanguageSpec` node sets (`assign_types`, `call_types`, `function_types`, `param_types`, `return_types`).
   - Add `sanitized_vars: Dict[str, Dict[str, Set[str]]]` tracking per scope + structural helper-function sanitizer inference (`_analyze_sanitizer_helpers()`): when an assignment LHS builds a value exclusively from literals, numeric/boolean ops, or domain-compatible sanitizer calls/vars (and not an unsafe URI `href=`), tag the LHS `Variable` node with `is_sanitizer=True` and `sanitizer_domains`, and clear `is_sink=False` on `.innerHTML = safeVar` assignments when `"HTML"` is proven!
4. **`backend/compiler/call_graph_builder.py`**:
   - Enhance `_resolve_call_targets` to normalize receiver/namespace prefixes (`pkg.Func`, `obj->method`, `Class::method`, `self.method`) and prefer same-language / same-directory targets before repository-wide fallback.
5. **`backend/engine/polyglot_rules.py`**:
   - Implement `POLYGLOT_RULE_CATALOG` (metadata for `RULE-22` through `RULE-33`) and deterministic `run_polyglot_rules(...)` producing fully populated `Finding` objects (`id`, `rule_id`, `severity`, `title`, `description`, `cwe_id`, `owasp_category`, `cvss_score`, `remediation`, `scan_engine="SAST"`, `language`, `path_nodes`, `path_edges`, `best_fix_location`).

- [ ] **Step 4: Run full pytest suite & ALASTOR self-audit**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_polyglot_cpg_compiler.py -v
..\.venv\Scripts\python.exe -m pytest -q
```
Verify ALASTOR self-audit across `cpg-sast-platform` still produces `0` findings after removing the hardcoded XSS allowlists from `ast_parser.py`!

- [ ] **Step 5: Commit Task 2**

```powershell
git add backend/compiler/ast_parser.py backend/compiler/cfg_builder.py backend/compiler/dfg_builder.py backend/compiler/call_graph_builder.py backend/engine/polyglot_rules.py backend/tests/test_polyglot_cpg_compiler.py
git commit -m "feat(polyglot): unify 18-language CPG compiler with domain-aware sanitizers and 12 polyglot rule packs"
```

---

### Task 3: Dual-Engine `GraphStore` (`Neo4j` + Pure-Python SQLite WAL Embedded Fallback) & Deterministic Leiden Community Detector

**Files:**
- Create: `backend/database/graph_store.py`
- Create: `backend/engine/community_detector.py`
- Modify: `backend/engine/rule_executor.py`
- Create: `backend/tests/test_embedded_graph_store_and_communities.py`

**Interfaces:**
- Consumes: `database.neo4j_client.Neo4jClient`, `database.batch_ingestor.BatchIngestor`, `engine.rule_executor.RuleExecutor`, `engine.polyglot_rules.run_polyglot_rules`, `models.*`.
- Produces:
  - `backend/engine/community_detector.py`: `detect_code_communities(nodes: List[CPGNode], edges: List[CPGEdge], app_tree: Optional[AppTreeSummary], findings: List[Finding], graph_engine_mode: GraphEngineMode) -> CommunityMapResponse`, `build_community_graph_view(community_map: CommunityMapResponse) -> GraphDataResponse`.
  - `backend/database/graph_store.py`: `EmbeddedGraphStore`, `Neo4jGraphStore`, `GraphStoreManager` (`get_instance(vault_dir)`, `mode`, `ensure_backend()`, `ingest_scan(...)`, `run_all_rules(...)`, `query_graph_view(...)`, `get_metrics_counts()`, `save_communities(...)`, `get_communities()`).
  - `backend/engine/rule_executor.py`: domain-aware sanitizer filtering on `RULE-1-TAINT` (both Cypher and Embedded parity evaluator), `execute_polyglot_rules(...)`.

- [ ] **Step 1: Write failing TDD tests in `backend/tests/test_embedded_graph_store_and_communities.py`**

```python
from pathlib import Path
from compiler.scanner import scan_directory_with_telemetry
from compiler.ast_parser import ASTNormalizer
from compiler.cfg_builder import CFGBuilder
from compiler.dfg_builder import DFGBuilder
from compiler.call_graph_builder import CallGraphBuilder
from database.graph_store import EmbeddedGraphStore, GraphStoreManager
from engine.community_detector import build_community_graph_view, detect_code_communities


def test_embedded_graph_store_persists_sqlite_and_detects_taint_and_rules(tmp_path: Path):
    repo = tmp_path / "polyglot_app"
    (repo / "api").mkdir(parents=True)
    (repo / "services").mkdir(parents=True)
    (repo / "contracts").mkdir(parents=True)

    (repo / "api" / "routes.py").write_text(
        "import os\n"
        "from flask import request\n"
        "def run_cmd():\n"
        "    user_cmd = request.args.get('cmd')\n"
        "    os.system(user_cmd)\n",
        encoding="utf-8",
    )
    (repo / "services" / "worker.go").write_text(
        'package services\nimport "os/exec"\nfunc Run(u string) {\n    exec.Command("sh", "-c", u)\n}\n',
        encoding="utf-8",
    )
    (repo / "contracts" / "Bank.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Bank {\n"
        "  mapping(address => uint) public balances;\n"
        "  function withdraw() public {\n"
        "    uint b = balances[msg.sender];\n"
        "    (bool ok, ) = msg.sender.call{value: b}(\"\");\n"
        "    require(ok);\n"
        "    balances[msg.sender] = 0;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    scanned, telemetry = scan_directory_with_telemetry(str(repo))
    all_nodes, all_edges = [], []
    for sf in scanned:
        norm = ASTNormalizer(sf)
        n_list, e_list = norm.parse()
        node_map = {n.id: n for n in n_list}
        cfg_e = CFGBuilder(sf.filepath, sf.content_bytes, sf.language, n_list, node_map).build()
        dfg_e = DFGBuilder(sf.filepath, sf.content_bytes, sf.language, n_list, node_map, norm.function_params_map, norm.function_returns_map).build()
        all_nodes.extend(n_list)
        all_edges.extend(e_list + cfg_e + dfg_e)
    all_edges.extend(CallGraphBuilder(all_nodes).resolve_calls())

    db_path = tmp_path / "vault" / "cpg_embedded.db"
    store = EmbeddedGraphStore(str(db_path))
    store.init_schema()
    store.clear_database()
    store.ingest_cpg(all_nodes, all_edges)

    assert db_path.exists()
    counts = store.get_counts()
    assert counts["nodes"] == len(all_nodes)
    assert counts["edges"] == len(all_edges)

    # Re-open from SQLite to prove persistence across server restarts
    reloaded = EmbeddedGraphStore(str(db_path))
    assert reloaded.get_counts()["nodes"] == len(all_nodes)

    findings = reloaded.run_cpg_rules(scanned_files=scanned)
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-1-TAINT" in rule_ids
    assert "RULE-27-POLYGLOT-CMDI" in rule_ids
    assert "RULE-30-SOLIDITY-REENTRANCY" in rule_ids

    # Leiden community clustering + COMMUNITY_MAP view
    comm_map = detect_code_communities(all_nodes, all_edges, None, findings, "EMBEDDED_SQLITE")
    assert comm_map.total_communities >= 1
    graph_resp = build_community_graph_view(comm_map)
    assert len(graph_resp["nodes"]) == comm_map.total_communities


def test_graph_store_manager_auto_failover_when_neo4j_offline(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ALASTOR_GRAPH_ENGINE", "auto")

    class _OfflineNeo4j:
        def verify_connectivity_and_apoc(self):
            raise ConnectionRefusedError("Neo4j Docker stopped")

    mgr = GraphStoreManager(neo4j_client=_OfflineNeo4j(), vault_dir=str(tmp_path / "vault"))
    mode = mgr.ensure_backend()
    assert mode == "EMBEDDED_SQLITE"
    assert mgr.mode == "EMBEDDED_SQLITE"
```

- [ ] **Step 2: Run test to verify RED**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_embedded_graph_store_and_communities.py -v
```
Expected: FAIL (`ModuleNotFoundError: No module named 'database.graph_store'`).

- [ ] **Step 3: Implement `backend/engine/community_detector.py`, `backend/database/graph_store.py`, and update `backend/engine/rule_executor.py`**

1. **`backend/engine/community_detector.py`**:
   - Pure-Python deterministic modularity clustering (Louvain/Leiden local-move + connected-component refinement with fixed filepath sorting).
   - Computes `GraphCommunityItem` (including `primary_language`, `languages`, `filepaths`, `entrypoint_count`, `sink_count`, `finding_count`, `risk_tier`) and `CommunityBridgeEdge` (`is_polyglot_bridge` when source & target communities have distinct `primary_language`).
   - Provides `build_community_graph_view(community_map)` returning ReactFlow-ready `{"nodes": [...], "edges": [...], "view_mode": "COMMUNITY_MAP", "summary": ...}`.
2. **`backend/database/graph_store.py`**:
   - `EmbeddedGraphStore`:
     - SQLite WAL database under `.alastor_vault/cpg_embedded.db` (`0o700` dir, `0o600` file, `threading.RLock()`).
     - Parameterized `?` SQL exclusively for `cpg_nodes`, `cpg_edges`, `app_files`, `app_directories`, `communities_json`, and `meta_kv`.
     - In-memory adjacency maps hydrated on ingest and on cold reload from SQLite.
     - Native Python evaluators achieving 100% parity with `RuleExecutor`'s CPG rules (`RULE-1-TAINT` with BFS shortest-path & domain-aware sanitizer check, `RULE-2-ORPHAN`, `RULE-3-DEADSTORE`, `RULE-4-INFINITE-LOOP`, `RULE-5-UNREACHABLE`, `RULE-6..RULE-18` AST/sink/secret/XSS/SQLi/SSRF/PathTraversal/Deser/XXE/WeakPRNG/LogInjection rules) + merging `run_polyglot_rules(...)`.
     - Native `query_graph_view(view_mode, finding_id, filepath, findings, app_tree)` supporting all 8 modes (`FINDING_PATH`, `CALL_GRAPH`, `ENTRYPOINTS`, `DFG`, `CFG`, `SPIDER`, `FULL_CPG`, `COMMUNITY_MAP`).
   - `GraphStoreManager`:
     - Supports `ALASTOR_GRAPH_ENGINE=auto|neo4j|embedded` (default `auto`).
     - Transparently uses `Neo4jGraphStore` when Neo4j + APOC succeeds, and falls back to `EmbeddedGraphStore` when Neo4j is offline!
3. **`backend/engine/rule_executor.py`**:
   - Enforce domain-aware sanitizer checking on `RULE-1-TAINT` so `"HTML"` sanitizers never falsely suppress `"SHELL"`/`"SQL"`/`"URL"` sinks.
   - Add `execute_all_rules_with_polyglot(scanned_files, all_nodes, all_edges, ...)` helper merging Neo4j Cypher results with `run_polyglot_rules(...)` cleanly without duplicates.

- [ ] **Step 4: Run tests to verify GREEN**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_embedded_graph_store_and_communities.py -v
..\.venv\Scripts\python.exe -m pytest -q
```
Expected: All tests PASS.

- [ ] **Step 5: Commit Task 3**

```powershell
git add backend/database/graph_store.py backend/engine/community_detector.py backend/engine/rule_executor.py backend/tests/test_embedded_graph_store_and_communities.py
git commit -m "feat(graph-store): add dual Neo4j/SQLite embedded GraphStore and deterministic Leiden community detector"
```

---

### Task 4: FastAPI Route Wiring, Offline Zero-Docker Startup/Scan Support & Enterprise Rule Enrichment

**Files:**
- Modify: `backend/main.py`
- Modify: `backend/engine/enterprise_manager.py`
- Modify: `backend/tests/test_embedded_graph_store_and_communities.py`

**Interfaces:**
- Consumes: `database.graph_store.GraphStoreManager`, `engine.community_detector`, `compiler.language_registry.list_language_capabilities`, `compiler.scanner.scan_directory_with_telemetry`, `engine.polyglot_rules.run_polyglot_rules`.
- Produces:
  - `GET /api/health` -> `{"status": "HEALTHY", "neo4j": "CONNECTED" | "OFFLINE_EMBEDDED_FALLBACK", "graph_engine_mode": "NEO4J_APOC" | "EMBEDDED_SQLITE"}`
  - `GET /api/metrics` -> includes `graph_engine_mode`, `languages_detected`, `scope_telemetry`, `communities_count`
  - `POST /api/scan` -> works identically whether Neo4j is online OR offline (`EMBEDDED_SQLITE`), runs `scan_directory_with_telemetry`, polyglot compiler + `RULE-22..RULE-33`, Leiden community detection, and returns `graph_engine_mode`, `languages_detected`, `scope_telemetry`, `communities_count`
  - `GET /api/graph?view_mode=COMMUNITY_MAP` -> returns Leiden community & polyglot bridge graph (and all other 7 graph views work in both Neo4j and Embedded modes!)
  - `GET /api/graph/communities` -> `CommunityMapResponse`
  - `GET /api/languages/capabilities` -> `LanguageCapabilitiesResponse`

- [ ] **Step 1: Add failing FastAPI integration tests to `backend/tests/test_embedded_graph_store_and_communities.py`**

Add tests exercising `TestClient(main_mod.app)`:
1. `test_fastapi_languages_capabilities_and_health_engine_mode`: verifies `GET /api/languages/capabilities` returns `>= 18` languages and `GET /api/health` includes `graph_engine_mode`.
2. `test_fastapi_offline_embedded_scan_communities_and_graph_views`: forces `ALASTOR_GRAPH_ENGINE=embedded`, scans a temp polyglot workspace (`.py`, `.go`, `.sol`, `.jinja2`) via `POST /api/scan`, verifies HTTP `200`, `graph_engine_mode == "EMBEDDED_SQLITE"`, `languages_detected` contains all 4 languages, `GET /api/metrics` works with zero Neo4j calls, `GET /api/graph/communities` returns communities, and `GET /api/graph?view_mode=COMMUNITY_MAP` + `ENTRYPOINTS` + `DFG` + `CFG` all return HTTP `200` with nodes!

- [ ] **Step 2: Run new API tests to verify RED**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_embedded_graph_store_and_communities.py -k "fastapi" -v
```
Expected: FAIL (`404 Not Found` on `/api/languages/capabilities` and `/api/graph/communities`).

- [ ] **Step 3: Wire `graph_store_mgr`, community detection, polyglot rules, and new endpoints in `backend/main.py` and `backend/engine/enterprise_manager.py`**

1. **`backend/main.py`**:
   - Instantiate `graph_store_mgr = GraphStoreManager.get_instance(neo4j_client=neo4j_client, vault_dir=os.path.join(enterprise_mgr.platform_root, ".alastor_vault"))`.
   - Update `startup_event()`: call `graph_store_mgr.ensure_backend()` so if Neo4j is offline, ALASTOR starts cleanly in `EMBEDDED_SQLITE` mode instead of logging a fatal DB error and leaving metrics/graph endpoints broken!
   - Update `GET /api/health` to return `{"status": "HEALTHY", "neo4j": "CONNECTED" if graph_store_mgr.mode == "NEO4J_APOC" else "OFFLINE_EMBEDDED_FALLBACK", "graph_engine_mode": graph_store_mgr.mode}`.
   - Update `POST /api/scan` (and `_run_cpg_scan_pipeline` if shared):
     - Call `scan_directory_with_telemetry(target_dir)` -> store `_last_scope_telemetry` and `_last_languages_detected`.
     - Compile all 18 languages, ingest via `graph_store_mgr.ingest_cpg(...)` (which ingests into Neo4j when `NEO4J_APOC` AND mirrors/persists into `EmbeddedGraphStore` when `EMBEDDED_SQLITE`).
     - Run all 21+12 rules via `graph_store_mgr` + `run_polyglot_rules(...)`.
     - Compute `current_community_map = detect_code_communities(...)` and save via `graph_store_mgr.save_communities(...)`.
     - Populate `graph_engine_mode`, `languages_detected`, `scope_telemetry`, `communities_count` in `ScanResponse`.
   - Update `GET /api/metrics` and `GET /api/graph` so both use `graph_store_mgr` cleanly when `EMBEDDED_SQLITE` is active, and support `view_mode=COMMUNITY_MAP` in both modes!
   - Add `GET /api/graph/communities` (`response_model=CommunityMapResponse`) and `GET /api/languages/capabilities` (`response_model=LanguageCapabilitiesResponse`).
2. **`backend/engine/enterprise_manager.py`**:
   - Register `RULE-22` through `RULE-33` in `SecurityQueryRule` default catalog and plain-English / RACI / STRIDE / PASTA taxonomy helpers so every new polyglot rule gets full executive translations, Best Fix Locations, STRIDE mapping, and PASTA Stage IV–VII scoring automatically!

- [ ] **Step 4: Run full pytest suite to verify GREEN**

Run from `backend/`:
```powershell
..\.venv\Scripts\python.exe -m pytest -v
```
Expected: `100%` passing (all 68 existing + all new Pillar 1 tests).

- [ ] **Step 5: Commit Task 4**

```powershell
git add backend/main.py backend/engine/enterprise_manager.py backend/tests/test_embedded_graph_store_and_communities.py
git commit -m "feat(api): wire dual-engine failover, polyglot telemetry, and Leiden community map endpoints"
```

---

### Task 5: Light-Only Daylight Frontend UI (`StudioCommandHeader`, `TopMetricsBar`, `ReactFlowGraphPane`) & Full-Stack Verification

**Files:**
- Modify: `frontend/src/types/cpg.ts`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/store/useAuditStore.ts`
- Modify: `frontend/src/components/StudioCommandHeader.tsx`
- Modify: `frontend/src/components/TopMetricsBar.tsx`
- Modify: `frontend/src/components/ReactFlowGraphPane.tsx`

**Interfaces:**
- Consumes: `GET /api/health`, `GET /api/metrics`, `POST /api/scan`, `GET /api/graph?view_mode=COMMUNITY_MAP`, `GET /api/graph/communities`, `GET /api/languages/capabilities`.
- Produces:
  - TypeScript types (`GraphEngineMode`, `ScanScopeTelemetry`, `GraphCommunityItem`, `CommunityBridgeEdge`, `CommunityMapResponse`, `LanguageCapabilityItem`, `LanguageCapabilitiesResponse`, `GraphViewMode` with `"COMMUNITY_MAP"`).
  - Store state & actions (`graphEngineMode`, `scopeTelemetry`, `languagesDetected`, `communityMap`, `languageCapabilities`, `fetchCommunityMap`, `fetchLanguageCapabilities`, `fetchBackendHealth`).
  - Daylight UI: top-bar Graph Engine status pill, Polyglot language & scope telemetry bar, and interactive `COMMUNITY_MAP` view in `ReactFlowGraphPane.tsx`.

- [ ] **Step 1: Add TypeScript types in `frontend/src/types/cpg.ts` and API clients in `frontend/src/lib/api.ts`**

1. In `frontend/src/types/cpg.ts`:
   - Add `"COMMUNITY_MAP"` to `GraphViewMode`.
   - Add `GraphEngineMode = "NEO4J_APOC" | "EMBEDDED_SQLITE"`, `ScanScopeTelemetry`, `GraphCommunityItem`, `CommunityBridgeEdge`, `CommunityMapResponse`, `LanguageCapabilityItem`, `LanguageCapabilitiesResponse`.
   - Add optional `graph_engine_mode?`, `languages_detected?`, `scope_telemetry?`, `communities_count?` on `MetricsResponse` and `ScanResponse`.
2. In `frontend/src/lib/api.ts`:
   - Add `fetchBackendHealth()`, `fetchCommunityMap()`, `fetchLanguageCapabilities()`.

- [ ] **Step 2: Wire Zustand store in `frontend/src/store/useAuditStore.ts`**

- Add `graphEngineMode: GraphEngineMode | null`, `scopeTelemetry: ScanScopeTelemetry | null`, `languagesDetected: Record<string, number>`, `communityMap: CommunityMapResponse | null`, `languageCapabilities: LanguageCapabilitiesResponse | null`.
- Hydrate `graphEngineMode`, `languagesDetected`, `scopeTelemetry` inside `fetchMetrics()`, `triggerScan()`, and new `fetchBackendHealth()`, `fetchCommunityMap()`, `fetchLanguageCapabilities()` actions.

- [ ] **Step 3: Implement Daylight UI enhancements in `StudioCommandHeader.tsx`, `TopMetricsBar.tsx`, and `ReactFlowGraphPane.tsx`**

1. **`frontend/src/components/StudioCommandHeader.tsx`**:
   - Render a compact, accessible Light-Only Daylight Graph Engine pill next to the branding/status controls:
     - `NEO4J_APOC`: `bg-emerald-50 text-emerald-900 border border-emerald-300` (`Neo4j + APOC`)
     - `EMBEDDED_SQLITE`: `bg-sky-50 text-sky-950 border border-sky-300` (`Embedded SQLite CPG • Zero-Docker`)
   - Call `fetchBackendHealth()` and `fetchLanguageCapabilities()` on mount.
2. **`frontend/src/components/TopMetricsBar.tsx`**:
   - Render a clean Daylight **Polyglot Coverage & Scope Telemetry** row whenever `languagesDetected` or `scopeTelemetry` is populated: high-contrast language pills (`Python`, `TS`, `Go`, `Java`, `Rust`, `C++`, `Solidity`, `Templates`, etc. with file counts) plus hostile-walker badges (`symlinks dropped`, `.gitignore skipped`, `build dirs excluded`, `communities`).
3. **`frontend/src/components/ReactFlowGraphPane.tsx`**:
   - Add **`Community Map`** (`COMMUNITY_MAP`) to the Graph View selector tabs.
   - Support rendering `COMMUNITY_MAP` cluster nodes (risk-tiered Daylight cards showing community name, primary language, file count, finding count, sink count) and cross-community / polyglot bridge edges (highlighted in high-contrast indigo/amber when `is_polyglot_bridge === true`), with click-to-open the community's representative file in Monaco!

- [ ] **Step 4: Run TypeScript typecheck, full backend pytest, and ALASTOR self-audit**

```powershell
# Frontend strict typecheck
Set-Location 'c:\Projects\Securecodereview\cpg-sast-platform\frontend'
npx tsc --noEmit

# Full backend suite
Set-Location 'c:\Projects\Securecodereview\cpg-sast-platform\backend'
..\.venv\Scripts\python.exe -m pytest -v
```
Run ALASTOR self-audit across `c:\Projects\Securecodereview\cpg-sast-platform` and confirm `0` findings across CPG SAST, SCA, IaC, and working-tree + git-history Secret Scanner.

- [ ] **Step 5: Commit Task 5**

```powershell
git add frontend/src/types/cpg.ts frontend/src/lib/api.ts frontend/src/store/useAuditStore.ts frontend/src/components/StudioCommandHeader.tsx frontend/src/components/TopMetricsBar.tsx frontend/src/components/ReactFlowGraphPane.tsx
git commit -m "feat(ui): display live Graph Engine mode, polyglot telemetry, and Leiden Community Map view"
```
