# ALASTOR v5.0 Pillar 1 Design Specification — Polyglot 18-Language CPG Compiler, Dual-Engine Embedded GraphStore, Leiden Communities & Generalized Sanitizer Taint

**Date:** 2026-11-22  
**Status:** Approved in Brainstorming — Ready for Spec Review  
**Roadmap Context:** Pillar 1 of 5 in the ALASTOR v5.0 ("100% VVAH Parity + 300% Beyond") architecture evolution  
**Target Codebase:** `cpg-sast-platform` (`backend/` FastAPI + Neo4j/SQLite CPG Engine, `frontend/` Next.js + ReactFlow + Monaco + Zustand)

---

## 1. Executive Summary & Goals

Pillar 1 upgrades ALASTOR's foundational Code Property Graph (CPG) compiler, storage backend, and deterministic static analysis engine while preserving **100% of existing ALASTOR v4.0 functionality**, **Light-Only Daylight WCAG AA (`>= 4.5:1`) UI compliance**, and **zero self-audit findings** on `cpg-sast-platform`:

1. **Polyglot 18-Language CPG Compiler (`backend/compiler/language_registry.py` + upgraded `ast_parser.py`, `cfg_builder.py`, `dfg_builder.py`, `call_graph_builder.py`)**:
   - Expands deterministic Tree-sitter CPG parsing from 4 languages (`Python, JS, TS, TSX`) to **all 17 VVAH graph languages + Web Templates (18 language families across 55+ extensions)**: `python`, `javascript`, `typescript`, `tsx`, `go`, `java`, `kotlin`, `csharp`, `scala`, `c`, `cpp`, `rust`, `ruby`, `php`, `swift`, `dart`, `solidity`, and `web_template` (`.html`, `.htm`, `.jinja`, `.jinja2`, `.j2`, `.ejs`, `.hbs`, `.handlebars`, `.blade.php`, `.erb`, `.twig`, `.ftl`, `.jsp`, `.cshtml`).
   - Unlike VVAH (which lacks deterministic taint & sanitizer tracking), every one of ALASTOR's 18 language families generates full **`AST_CHILD` + `CFG_NEXT` + `DFG_FLOWS_TO` + `:CALLS`** graphs and runs deterministic security analysis at **\$0 token cost**.
2. **Generalized Domain-Aware Sanitizer Tracking**:
   - Removes the hardcoded app-specific variable allowlists (`detailsHtml`, `warnHtml`, `unverHtml`, `selfSearchLinks`, `HOT_TYPES.test(`, `breachCount`) from `backend/compiler/ast_parser.py`.
   - Replaces them with intra-file and inter-procedural **domain-scoped sanitizer propagation** (`HTML`, `URL`, `SQL`, `SHELL`, `PATH`, `XML`, `UNIVERSAL`) inside `DFGBuilder` and `ASTNormalizer`, preserving exact detection of `href="javascript:..."` HTML-entity bypasses while eliminating false positives on sanitized variables and helper functions across unseen repositories.
3. **Hostile-Repo-Safe Polyglot Scope Walker (`backend/compiler/scanner.py`)**:
   - Confines every walked directory and file via `os.path.realpath` + `os.path.commonpath`, silently dropping symlinks that escape the repository root and reporting exact counts in `ScanScopeTelemetry`.
   - Evaluates nested `.gitignore` rules in-process (pure Python globbing — never executes target git hooks or loads target `.env`/configs), filters generated stubs (`*.pb.go`, `*_pb2.py`, `*.g.cs`, `*.Designer.cs`, `*.generated.*`), and contextually skips ecosystem build outputs (`target/`, `bin/`, `obj/`, `Pods/`, `out/`, `artifacts/`, `cache/`) only when their corresponding build manifest is present.
4. **Dual-Engine `GraphStore` (`Neo4j` Primary + Pure-Python SQLite Embedded Fallback) (`backend/database/graph_store.py`)**:
   - Preserves Neo4j 5 + APOC as the primary engine when reachable (`NEO4J_APOC`), and automatically falls back to a pure-Python **SQLite WAL Embedded CPG Store** (`.alastor_vault/cpg_embedded.db`, `0o600` permissions, zero Docker, zero JVM — completely avoiding ArcadeDB's bundled-JVM `CVE-2026-91403`) whenever Docker/Neo4j is offline or `ALASTOR_GRAPH_ENGINE=embedded`.
   - Achieves **100% deterministic rule parity** across all existing 21 rules + 12 new polyglot rule families in both engines.
5. **Deterministic Leiden/Modularity Community Detection & 12 New Polyglot Rule Packs (`backend/engine/community_detector.py`, `backend/engine/polyglot_rules.py`)**:
   - Clusters repository files into logical architectural security communities using deterministic modularity optimization over `CALLS`, `IMPORTS`, and `DFG_FLOWS_TO` weights, identifying cross-community and cross-language trust crossings.
   - Adds 12 deterministic polyglot rule families (Rules 22–33) covering C/C++/Rust memory & unsafe FFI, Java/Kotlin/C#/Go/PHP/Ruby/Scala/Swift/Dart taint/deserialization/XXE/SSRF, Solidity smart-contract vulnerabilities, and Web Template XSS/SSTI/CSRF.
6. **Daylight Studio UI Upgrades (`GraphViewer.tsx`, `page.tsx`, `useAuditStore.ts`, `api.ts`, `cpg.ts`)**:
   - Live top-bar Graph Engine status pill (`Neo4j + APOC` vs. `Embedded SQLite CPG (Zero-Docker)`).
   - Polyglot Language Coverage & Hostile-Walker Telemetry strip in the workspace header/analytics view.
   - Interactive **`COMMUNITY_MAP`** view mode in `GraphViewer.tsx` visualizing Leiden architectural communities and cross-language bridges with click-to-jump into Monaco.

---

## 2. Architecture & Component Boundaries

### 2.1 Declarative `LanguageSpec` Registry (`backend/compiler/language_registry.py`)

A single, pure-Python declarative registry decouples grammar loading and per-language syntax tables from the 4 CPG compiler passes:

| Language Key | Extensions | Tree-sitter Grammar Name (`tree-sitter-language-pack`) | Key Taint Sources | Key Sinks & Domains | Key Sanitizers & Domains |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `python` | `.py` | `python` (fallback `tree_sitter_python`) | `request.args`, `request.form`, `request.json`, `sys.argv`, `input`, FastAPI/Flask route params | `cursor.execute` (`SQL`), `os.system`/`subprocess.*` (`SHELL`), `eval`/`exec` (`CODE`), `pickle.loads`/`yaml.load` (`DESER`), `open` (`PATH`) | `int`/`float`/`bool` (`UNIVERSAL`), `shlex.quote` (`SHELL`), `html.escape`/`bleach.clean` (`HTML`), `os.path.commonpath`/`os.path.basename` (`PATH`), `yaml.safe_load` (`DESER`) |
| `javascript` / `typescript` / `tsx` | `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx` | `javascript`, `typescript`, `tsx` (fallback bundled wheels) | `req.query`, `req.body`, `req.params`, `request.nextUrl.searchParams`, `window.location`, `document.location` | `eval`, `exec`, `child_process.exec`, `.innerHTML`/`.outerHTML`/`dangerouslySetInnerHTML` (`HTML`), `db.query` (`SQL`), `fetch`/`axios` (`URL`) | `DOMPurify.sanitize`/`escapeHtml`/`esc` (`HTML`), `encodeURIComponent` (`URL`), `path.basename` (`PATH`), `Number`/`parseInt` (`UNIVERSAL`) |
| `go` | `.go` | `go` | `r.URL.Query`, `r.FormValue`, `c.Query`, `c.Param`, `os.Args`, `http.Request` | `db.Query`/`db.Exec` (`SQL`), `exec.Command` (`SHELL`), `os.Open`/`os.ReadFile` (`PATH`), `http.Get`/`http.Post` (`URL`), `template.HTML` (`HTML`) | `strconv.Atoi`/`strconv.ParseInt` (`UNIVERSAL`), `filepath.Clean`/`filepath.Base` (`PATH`), `html.EscapeString` (`HTML`), `url.QueryEscape` (`URL`) |
| `java` | `.java` | `java` | `@RequestParam`, `@PathVariable`, `@RequestBody`, `request.getParameter`, `HttpServletRequest` | `Statement.executeQuery`/`executeUpdate` (`SQL`), `Runtime.getRuntime().exec`/`ProcessBuilder` (`SHELL`), `ObjectInputStream.readObject` (`DESER`), `DocumentBuilderFactory` (`XML`), `Files.readString`/`new File` (`PATH`) | `PreparedStatement` (`SQL`), `Integer.parseInt` (`UNIVERSAL`), `HtmlUtils.htmlEscape`/`ESAPI.encoder` (`HTML`), `Paths.get(...).normalize()` (`PATH`) |
| `kotlin` | `.kt`, `.kts` | `kotlin` | `@RequestParam`, `call.parameters`, `request.getParameter` | `executeQuery` (`SQL`), `Runtime.getRuntime().exec`/`ProcessBuilder` (`SHELL`), `ObjectInputStream.readObject` (`DESER`) | `PreparedStatement` (`SQL`), `toInt`/`toLong` (`UNIVERSAL`), `HtmlUtils.htmlEscape` (`HTML`) |
| `csharp` | `.cs` | `csharp` | `[FromQuery]`, `[FromBody]`, `[FromRoute]`, `Request.Query`, `Request.Form`, `HttpContext.Request` | `SqlCommand`/`ExecuteReader` (`SQL`), `Process.Start` (`SHELL`), `BinaryFormatter.Deserialize` (`DESER`), `XmlDocument.Load` (`XML`), `File.ReadAllText` (`PATH`) | `SqlParameter` (`SQL`), `int.TryParse`/`int.Parse` (`UNIVERSAL`), `HtmlEncoder.Default.Encode` (`HTML`), `Path.GetFileName` (`PATH`) |
| `scala` | `.scala`, `.sc` | `scala` | `request.queryString`, `request.body`, `parameter(` | `SQL(`/`executeQuery` (`SQL`), `Process(`/`Runtime.getRuntime.exec` (`SHELL`), `ObjectInputStream` (`DESER`) | `toInt` (`UNIVERSAL`), `PreparedStatement` (`SQL`) |
| `c` / `cpp` | `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh` | `c`, `cpp` | `argv`, `getenv`, `scanf`, `gets`, `fgets`, `recv`, `read`, `cin` | `strcpy`/`strcat`/`sprintf`/`gets`/`memcpy` (`MEMORY`), `printf`/`fprintf`/`syslog` (`FORMAT`), `system`/`popen`/`execv` (`SHELL`), `free`/`delete` (`LIFETIME`) | `strncpy`/`snprintf`/`strlcpy` (`MEMORY`), `strtol`/`atoi` (`UNIVERSAL`) |
| `rust` | `.rs` | `rust` | `web::Query`, `web::Json`, `web::Path`, `env::args`, `stdin` | `Command::new` (`SHELL`), `sqlx::raw_sql` (`SQL`), `unsafe` raw pointer deref / `transmute` (`MEMORY`), `fs::read` (`PATH`) | `parse::<i64>` (`UNIVERSAL`), `Path::file_name` (`PATH`) |
| `ruby` | `.rb`, `.rake` | `ruby` | `params[`, `request.params`, `ARGV`, `ENV[` | `find_by_sql`/`where(` (`SQL`), `system(`/`` `...` ``/`%x`/`Open3` (`SHELL`), `eval`/`send` (`CODE`), `Marshal.load`/`YAML.load` (`DESER`), `File.read` (`PATH`) | `to_i` (`UNIVERSAL`), `ERB::Util.html_escape`/`CGI.escapeHTML` (`HTML`), `Shellwords.escape` (`SHELL`), `YAML.safe_load` (`DESER`) |
| `php` | `.php`, `.phtml` | `php` | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$request->input` | `mysqli_query`/`PDO::query` (`SQL`), `exec`/`shell_exec`/`system`/`passthru`/`proc_open` (`SHELL`), `unserialize` (`DESER`), `eval`/`include`/`require` (`CODE`), `file_get_contents` (`PATH`/`URL`) | `intval` (`UNIVERSAL`), `htmlspecialchars`/`htmlentities` (`HTML`), `escapeshellarg` (`SHELL`), `basename` (`PATH`), `prepare` (`SQL`) |
| `swift` | `.swift` | `swift` | `req.query`, `req.parameters`, `CommandLine.arguments`, `URLComponents` | `Process()`/`system(` (`SHELL`), `sqlite3_exec` (`SQL`), `evaluateJavaScript` (`HTML`), `NSKeyedUnarchiver` (`DESER`) | `Int(` (`UNIVERSAL`), `URL.lastPathComponent` (`PATH`) |
| `dart` | `.dart` | `dart` | `request.uri.queryParameters`, `request.headers`, `args` | `Process.run`/`Process.start` (`SHELL`), `rawQuery`/`rawExecute` (`SQL`), `File(` (`PATH`), `http.get` (`URL`) | `int.parse`/`int.tryParse` (`UNIVERSAL`), `HtmlEscape().convert` (`HTML`), `path.basename` (`PATH`) |
| `solidity` | `.sol` | `solidity` | `msg.sender`, `msg.data`, `tx.origin`, external/public function params | `.call{value:`/`.call.value(` (`REENTRANCY`), `delegatecall` (`DELEGATECALL`), `selfdestruct`/`suicide` (`LIFECYCLE`), `tx.origin` (`AUTH`) | `nonReentrant`, `ReentrancyGuard`, `require(msg.sender ==` (`AUTH`) |
| `web_template` | `.html`, `.htm`, `.jinja`, `.jinja2`, `.j2`, `.ejs`, `.hbs`, `.handlebars`, `.blade.php`, `.erb`, `.twig`, `.ftl`, `.jsp`, `.cshtml` | `html` + template expression scanner | `{{`, `<%=`, `<%-`, `{{{`, `{!!`, `<%= raw`, `@Html.Raw`, `<form method="post">` | Unescaped template sink (`HTML`), `render_template_string`/dynamic template eval (`SSTI`), POST `<form>` without CSRF token (`CSRF`) | `csrf_token`, `csrf_field`, `@csrf`, `authenticity_token`, `|e`, `|escape`, `DOMPurify` |

**Parser Loading Contract:**
- `get_parser_for_language(lang_key: str) -> Optional[tree_sitter.Parser]` lazily caches one `Parser` per language inside a `threading.RLock()`.
- Loads via `tree_sitter_language_pack.get_parser(grammar_name)` first; for `python`, `javascript`, `typescript`, `tsx`, falls back to the pinned individual `tree_sitter_*` packages if needed.
- Any unsupported grammar returns `None` cleanly without throwing, allowing regex/line-level template or fallback extractors to run safely.

### 2.2 Generalized Domain-Aware Sanitizer Tracking (`backend/compiler/ast_parser.py` & `dfg_builder.py`)

1. **Remove Hardcoded App Allowlists:** Remove app-specific identifiers (`detailsHtml`, `warnHtml`, `unverHtml`, `selfSearchLinks`, `HOT_TYPES.test(`, `breachCount`, `s.links.join`, `done.has(`, `i === 0`) from `_is_unsafe_html_assignment` in `ast_parser.py`.
2. **Domain-Scoped Sanitizer Metadata on `CPGNode`:**
   - Extend `CPGNode` with optional backward-compatible fields:
     - `sanitizer_domains: List[str] = Field(default_factory=list)` (e.g., `["HTML"]`, `["SHELL"]`, `["UNIVERSAL"]`)
     - `sink_domain: Optional[str] = None` (e.g., `"HTML"`, `"URL"`, `"SQL"`, `"SHELL"`, `"PATH"`, `"XML"`, `"MEMORY"`, `"DESER"`, `"REENTRANCY"`)
     - `language: str = "python"`
3. **Data-Flow Sanitizer Propagation in `DFGBuilder`:**
   - Track `sanitized_vars: Dict[str, Dict[str, Set[str]]]` mapping `(scope_id, var_name) -> Set[sanitizer_domain]`.
   - When `lhs = rhs`:
     - If `rhs` is a pure literal / numeric / boolean expression -> `lhs` inherits `{"UNIVERSAL"}`.
     - If `rhs` is a sanitizer call (e.g., `escapeHtml(x)` -> `{"HTML"}`; `shlex.quote(x)` -> `{"SHELL"}`; `int(x)` -> `{"UNIVERSAL"}`) -> `lhs` inherits those domains and the `lhs` Variable node receives `is_sanitizer=True`, `sanitizer_domains=...`.
     - If `rhs` is a template literal, `.map().join()`, or string concatenation whose **every** interpolated identifier is either a literal, numeric/boolean expression (`.length`, `Number(...)`, `parseInt(...)`, comparison `===`/`>`), or in `sanitized_vars` for `"HTML"` (and **not** placed inside an `<a href="${...}">` / `src=` / `action=` URI attribute without a `"URL"` sanitizer) -> `lhs` inherits `{"HTML"}`!
     - If `rhs` is a call to a local/imported helper function whose return statements are structurally verified to return sanitized values for domain `D` -> call site inherits `{D}`!
   - **Sink Evaluation Rule:** A taint path `(source)-[:DFG_FLOWS_TO*1..15]->(sink)` is neutralized **only** when a node on the path has `is_sanitizer == True` AND (`"UNIVERSAL"` in `sanitizer_domains` OR `sink.sink_domain` is `None` OR `sink.sink_domain` in `sanitizer_domains`). Thus `html.escape()` neutralizes HTML body XSS (`sink_domain="HTML"`), never clears `href="javascript:..."` (`sink_domain="URL"`), and never clears SQL (`"SQL"`) or Shell (`"SHELL"`) sinks.

### 2.3 Hostile-Repo-Safe Polyglot Scope Walker (`backend/compiler/scanner.py`)

1. **Symlink Confinement:** Canonicalize `real_root = os.path.realpath(root_dir)`. For every directory and file encountered during `os.walk(..., followlinks=False)`, check `os.path.islink(full_path)` and `os.path.commonpath([real_root, os.path.realpath(full_path)]) == real_root`. Escaping symlinks are skipped and counted in `ScanScopeTelemetry.symlinks_dropped`.
2. **In-Process `.gitignore` Evaluation:** Load `.gitignore` patterns scoped to each walked directory (pure Python `fnmatch` / path-segment matching — never invokes `git` subprocesses on untrusted repos, never reads `.env` or target config files). Count excluded paths in `ScanScopeTelemetry.gitignore_excluded`.
3. **Contextual Ecosystem Build Exclusions:**
   - Always skip VCS/tool caches (`.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.next`, `.gradle`, `.dart_tool`, `.mypy_cache`, `.pytest_cache`, `.turbo`, `coverage`, `vendor`, `third_party`, `bower_components`).
   - Contextually skip build output folders **only** when their manifest sits in the same directory:
     - `target/` beside `pom.xml`, `Cargo.toml`, `build.gradle`, `build.gradle.kts`, `build.sbt`
     - `bin/` & `obj/` beside any `*.csproj`, `*.fsproj`, `*.sln`
     - `Pods/` beside `Podfile`
     - `out/` beside `foundry.toml`
     - `artifacts/` & `cache/` beside `hardhat.config.js` / `hardhat.config.ts`
   - Skip generated stubs (`*.pb.go`, `*_pb2.py`, `*.g.cs`, `*.Designer.cs`, `*.generated.*`, `*.min.js`, `*.bundle.js`).
4. **Backward-Compatible API:** `scan_directory(root_dir: str) -> List[ScannedFile]` retains its exact existing signature and return type, plus a new companion `scan_directory_with_telemetry(root_dir: str, exclude_tests: bool = False) -> Tuple[List[ScannedFile], ScanScopeTelemetry]` used by `main.py` and tests.

### 2.4 Dual-Engine `GraphStore` (`backend/database/graph_store.py`)

```
                       +-------------------------------+
                       |   GraphStoreManager (Facade)  |
                       | ALASTOR_GRAPH_ENGINE =        |
                       |   auto | neo4j | embedded     |
                       +---------------+---------------+
                                       |
               +-----------------------+-----------------------+
               | (Bolt + APOC healthy)                         | (Neo4j offline / embedded)
               v                                               v
    +-----------------------+                       +---------------------------+
    |   Neo4jGraphStore     |                       |   EmbeddedGraphStore      |
    | - Neo4jClient (Bolt)  |                       | - SQLite WAL              |
    | - BatchIngestor       |                       |   .alastor_vault/         |
    | - Cypher RuleExecutor |                       |   cpg_embedded.db (0o600) |
    +-----------------------+                       | - In-Memory Adjacency Map |
                                                    | - Native Python 21+12     |
                                                    |   Rule Evaluators         |
                                                    +---------------------------+
```

- **Shared `GraphStore` Operations:**
  - `mode` property: `"NEO4J_APOC"` or `"EMBEDDED_SQLITE"`
  - `is_ready() -> bool`, `init_schema()`, `clear_database()`
  - `ingest_cpg(nodes: List[CPGNode], edges: List[CPGEdge])`, `ingest_app_tree(summary: AppTreeSummary)`
  - `save_communities(community_map: CommunityMapResponse)`, `get_communities() -> CommunityMapResponse`
  - `run_rules(custom_sanitizers, enabled_rule_ids) -> List[Finding]`
  - `query_graph_view(view_mode, finding_id, filepath) -> GraphDataResponse` (supports `FINDING_PATH`, `CALL_GRAPH`, `ENTRYPOINTS`, `DFG`, `CFG`, `SPIDER`, `FULL_CPG`, and new `COMMUNITY_MAP`)
  - `get_metrics() -> MetricsResponse` (returns node/edge counts, language breakdown, `graph_engine_mode`, `communities_count`)
- **SQLite Persistence & Security:**
  - Stored at `<platform_root>/.alastor_vault/cpg_embedded.db` (directory `0o700`, file `0o600`), using `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` and exclusively parameterized `?` queries.
  - Thread-safe via `threading.RLock()`.
  - On backend startup, if Neo4j fails to connect (e.g., Docker Desktop stopped), `startup_event()` activates `EmbeddedGraphStore` cleanly and reloads any persisted SQLite CPG state instead of failing!

### 2.5 Deterministic Leiden/Modularity Community Detector (`backend/engine/community_detector.py`)

- Pure-Python deterministic modularity optimization (Louvain/Leiden local-move + refinement phase, fixed iteration order sorted by filepath for 100% deterministic cluster IDs across runs):
  - **Nodes:** Source files in the scanned repository.
  - **Weighted Undirected Edges:** `CALLS` (`+3.0`), inter-file `DFG_FLOWS_TO` (`+2.5`), `IMPORTS` (`+1.5`), same-directory locality (`+0.5`).
  - **Outputs (`CommunityMapResponse`):**
    - `communities: List[GraphCommunityItem]` (`id`, `label`, `primary_language`, `languages`, `filepaths`, `file_count`, `entrypoint_count`, `sink_count`, `finding_count`, `risk_tier`)
    - `cross_community_edges: List[CommunityBridgeEdge]` (`source_community_id`, `target_community_id`, `edge_count`, `edge_types`, `is_polyglot_bridge`, `sample_files`)
    - `polyglot_bridges_count: int`
  - Automatically labels each community deterministically from its top directory segments & security symbols (e.g., `Auth & Session (Go)`, `Checkout Ledger (Python)`, `Smart Contracts (Solidity)`, `Web Templates (HTML/Jinja)`).

### 2.6 Deep Polyglot Security Rule Packs (`backend/engine/polyglot_rules.py`)

All 21 existing deterministic rules remain untouched in Neo4j Cypher and receive 100%-parity Python evaluators inside `EmbeddedGraphStore`. In addition, **12 deterministic polyglot rule packs (Rules 22–33)** execute over parsed `ScannedFile` + CPG nodes/edges in **both** Neo4j and Embedded modes:

| Rule ID | Languages | Vulnerability Class | CWE | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `RULE-22-CPP-BUFFER-OVERFLOW` | `c`, `cpp` | Unbounded memory/string copy (`strcpy`, `strcat`, `gets`, `sprintf`, `vsprintf`, tainted `memcpy`) | `CWE-120` / `CWE-787` | `CRITICAL` |
| `RULE-23-CPP-FORMAT-STRING` | `c`, `cpp` | Non-literal format string passed to `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog` | `CWE-134` | `HIGH` |
| `RULE-24-CPP-UAF-DOUBLE-FREE` | `c`, `cpp` | Use-after-free or double-free detected along intra-procedural CFG after `free()` / `delete` | `CWE-416` | `CRITICAL` |
| `RULE-25-RUST-UNSAFE-FFI` | `rust` | `unsafe { ... }` block performing raw pointer dereference, `mem::transmute`, or unchecked C FFI | `CWE-242` | `HIGH` |
| `RULE-26-POLYGLOT-SQLI` | `go`, `java`, `kotlin`, `csharp`, `scala`, `php`, `ruby`, `swift`, `dart`, `rust` | Dynamic string concatenation/interpolation into SQL query execution (`executeQuery`, `db.Query`, `SqlCommand`, `mysqli_query`, `find_by_sql`, `rawQuery`) | `CWE-89` | `CRITICAL` |
| `RULE-27-POLYGLOT-CMDI` | `go`, `java`, `kotlin`, `csharp`, `scala`, `php`, `ruby`, `swift`, `dart`, `rust` | Dynamic/tainted argument passed to OS process execution (`exec.Command`, `Runtime.exec`, `Process.Start`, `shell_exec`, `system`, `Command::new`) | `CWE-78` | `CRITICAL` |
| `RULE-28-POLYGLOT-DESER` | `java`, `kotlin`, `csharp`, `scala`, `php`, `ruby`, `swift` | Unsafe native deserialization (`ObjectInputStream.readObject`, `BinaryFormatter.Deserialize`, `unserialize`, `Marshal.load`, `YAML.load`, `NSKeyedUnarchiver`) | `CWE-502` | `CRITICAL` |
| `RULE-29-POLYGLOT-XXE` | `java`, `kotlin`, `csharp`, `php`, `ruby`, `go` | XML parser enabled without disabling external entities / DTDs (`DocumentBuilderFactory`, `SAXParserFactory`, `XmlDocument`, `simplexml_load_string(..., LIBXML_NOENT)`) | `CWE-611` | `HIGH` |
| `RULE-30-SOLIDITY-REENTRANCY` | `solidity` | External `.call{value:...}` / `.send` / `.transfer` invoked before storage state mutation (Checks-Effects-Interactions violation) without `nonReentrant` | `CWE-841` | `CRITICAL` |
| `RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE` | `solidity` | `tx.origin` used for authorization or unguarded `delegatecall` / `selfdestruct` | `CWE-284` | `CRITICAL` |
| `RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI` | `web_template` | Unescaped template rendering (`\|safe`, `{% autoescape false %}`, `<%-`, `{{{`, `{!!`, `@Html.Raw`, `v-html`) or dynamic SSTI expression | `CWE-79` / `CWE-1336` | `HIGH` |
| `RULE-33-TEMPLATE-MISSING-CSRF` | `web_template` | State-changing `<form method="post">` lacking a CSRF token input/directive (`csrf_token`, `@csrf`, `csrf_field`, `authenticity_token`) | `CWE-352` | `MEDIUM` |

---

## 3. Data Models, API Contracts & Frontend UI Design

### 3.1 Backend Models (`backend/models.py`)
- `GraphEngineMode = Literal["NEO4J_APOC", "EMBEDDED_SQLITE"]`
- `ScanScopeTelemetry(BaseModel)`: `total_discovered`, `symlinks_dropped`, `gitignore_excluded`, `build_dirs_excluded`, `generated_excluded`, `languages_breakdown: Dict[str, int]`
- `GraphCommunityItem(BaseModel)`: `id`, `label`, `primary_language`, `languages: List[str]`, `filepaths: List[str]`, `file_count`, `entrypoint_count`, `sink_count`, `finding_count`, `risk_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]`
- `CommunityBridgeEdge(BaseModel)`: `id`, `source_community_id`, `target_community_id`, `edge_count`, `edge_types: List[str]`, `is_polyglot_bridge: bool`, `sample_files: List[str]`
- `CommunityMapResponse(BaseModel)`: `graph_engine_mode`, `total_communities`, `polyglot_bridges_count`, `communities`, `cross_community_edges`
- `LanguageCapabilityItem(BaseModel)` & `LanguageCapabilitiesResponse(BaseModel)`
- Backward-compatible optional fields added to `MetricsResponse` and `ScanResponse`: `graph_engine_mode`, `languages_detected`, `scope_telemetry`, `communities_count`.

### 3.2 REST Endpoints (`backend/main.py`)
- `GET /api/health` -> includes `"graph_engine_mode": "NEO4J_APOC" | "EMBEDDED_SQLITE"`, `"neo4j": "CONNECTED" | "OFFLINE_EMBEDDED_FALLBACK"`.
- `GET /api/graph/communities` -> returns `CommunityMapResponse` for the active scan.
- `GET /api/graph?view_mode=COMMUNITY_MAP` -> returns ReactFlow-ready `GraphDataResponse` with community cluster nodes and cross-community/polyglot bridge edges.
- `GET /api/languages/capabilities` -> returns all 18 supported language families, loaded Tree-sitter status, extensions, and deterministic rule pack counts.
- All existing endpoints (`/api/scan`, `/api/findings`, `/api/graph`, `/api/metrics`, `/api/aspm/*`, `/api/export/*`) seamlessly read from `graph_store_mgr` so the entire platform operates identically in Neo4j **and** Zero-Docker Embedded mode.

### 3.3 Light-Only Daylight Frontend UI (`frontend/src/`)
- **`frontend/src/types/cpg.ts`**: Add `GraphEngineMode`, `ScanScopeTelemetry`, `GraphCommunityItem`, `CommunityBridgeEdge`, `CommunityMapResponse`, `LanguageCapabilitiesResponse`, and extend `GraphViewMode` with `"COMMUNITY_MAP"`.
- **`frontend/src/lib/api.ts` & `frontend/src/store/useAuditStore.ts`**: Add `fetchCommunityMap()`, `fetchLanguageCapabilities()`, and store `graphEngineMode`, `scopeTelemetry`, `languagesDetected`, `communityMap`, and `languageCapabilities` hydrated from `/api/health`, `/api/metrics`, `/api/scan`, and `/api/graph/communities`.
- **`frontend/src/app/page.tsx`**:
  - Top-bar **Graph Engine Pill** (Light-Only Daylight, WCAG AA `>= 4.5:1`):
    - `NEO4J_APOC`: `bg-emerald-50 text-emerald-900 border-emerald-300` (`Neo4j + APOC`)
    - `EMBEDDED_SQLITE`: `bg-sky-50 text-sky-950 border-sky-300` (`Embedded SQLite CPG • Zero-Docker`)
  - **Polyglot Language & Scope Telemetry Strip** inside the Scan/Overview header displaying detected language counts (`Python`, `TS`, `Go`, `Java`, `Rust`, `C++`, `Solidity`, `Templates`, etc.) and hostile-walker stats (`symlinks dropped`, `.gitignore skipped`, `build dirs excluded`).
- **`frontend/src/components/GraphViewer.tsx`**:
  - Add **`Community Map`** tab (`COMMUNITY_MAP`) to the existing Graph View selector alongside Finding Path, Call Graph, Entrypoints, DFG, CFG, 360° Spider, and Full CPG, rendering Leiden cluster nodes color-coded by risk tier and polyglot trust-crossing edges with click-to-open representative files in Monaco.

---

## 4. Error Handling, Security & Testing Strategy

1. **Dependencies (`backend/requirements.txt`)**:
   - Pin `tree-sitter-language-pack` compatible with Python 3.12 on Windows/Linux/macOS (upgrading `tree-sitter` if required by the pack while preserving full compatibility with `tree-sitter-python`/`javascript`/`typescript`).
2. **Error Handling**:
   - Per-file parse errors or malformed binary/UTF-8 bytes never crash a scan; they log via `_sanitize_log` and continue.
   - Neo4j connection errors during `startup_event()` or `/api/scan` automatically failover to `EmbeddedGraphStore` in `auto` mode instead of throwing HTTP `500`.
3. **Security Invariants**:
   - All SQLite operations use strictly parameterized `?` statements; `.alastor_vault/cpg_embedded.db` enforces `0o600` permissions.
   - Scope walker refuses escaping symlinks and never executes target git hooks or loads target `.env` files.
   - Zero raw secrets stored in community labels or graph responses.
   - Zero ALASTOR self-audit findings across `cpg-sast-platform` (verified after removing hardcoded allowlists from `ast_parser.py`!).
4. **Automated TDD Suites**:
   - `backend/tests/test_polyglot_cpg_compiler.py`: Verifies all 18 language families compile into `AST_CHILD`/`CFG_NEXT`/`DFG_FLOWS_TO`/`CALLS`, verifies hostile-symlink drop & `.gitignore` + contextual `target/`/`bin/`/`obj/` exclusions, verifies generalized domain-aware sanitizer propagation (including `href="javascript:..."` bypass detection), and tests all 12 new polyglot rules (`RULE-22` through `RULE-33`) with positive (vulnerable) and negative (safe/sanitized) cases.
   - `backend/tests/test_embedded_graph_store_and_communities.py`: Verifies automatic zero-Docker failover when Neo4j is offline, SQLite persistence across store reload, 100% rule parity between `EmbeddedGraphStore` and Neo4j mode, deterministic Leiden community clustering + polyglot bridge detection, and FastAPI endpoints (`/api/health`, `/api/graph/communities`, `/api/graph?view_mode=COMMUNITY_MAP`, `/api/languages/capabilities`).
   - Full regression: `pytest -v` (`100%` pass), `npx tsc --noEmit` (`0` errors), ALASTOR self-audit (`0` findings), and live `:8000`/`:3000` smoke verification.
