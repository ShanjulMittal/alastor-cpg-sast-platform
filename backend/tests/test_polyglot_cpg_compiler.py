"""
TDD Suite for ALASTOR v5.0 Pillar 1 Task 1:
- Pillar 1 Pydantic Data Contracts (models.py)
- Declarative 18-Language Tree-sitter Registry (compiler/language_registry.py)
- Hostile-Repo-Safe Polyglot Scope Walker (compiler/scanner.py)
"""
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from models import (
    CPGNode,
    MetricsResponse,
    ScanResponse,
    GraphEngineMode,
    ScanScopeTelemetry,
    GraphCommunityItem,
    CommunityBridgeEdge,
    CommunityMapResponse,
    LanguageCapabilityItem,
    LanguageCapabilitiesResponse,
)
from compiler.language_registry import (
    LanguageSpec,
    LANGUAGE_SPECS,
    EXTENSION_TO_LANGUAGE,
    resolve_language_for_filename,
    get_language_spec,
    get_parser_for_language,
    list_language_capabilities,
    _load_fallback_bundled_parser,
)
from compiler.scanner import (
    CODE_EXTENSIONS,
    IGNORE_DIRS,
    ScannedFile,
    scan_directory,
    scan_directory_with_telemetry,
    _is_confined,
)


EXPECTED_18_LANGUAGES = {
    "python",
    "javascript",
    "typescript",
    "tsx",
    "go",
    "java",
    "kotlin",
    "csharp",
    "scala",
    "c",
    "cpp",
    "rust",
    "ruby",
    "php",
    "swift",
    "dart",
    "solidity",
    "web_template",
}

LANGUAGE_SNIPPETS = {
    "python": b"def greet(name):\n    return name\n",
    "javascript": b"function greet(name) { return name; }\n",
    "typescript": b"function greet(name: string): string { return name; }\n",
    "tsx": b"export const App = () => <div>Hello</div>;\n",
    "go": b"package main\nfunc main() { println(1) }\n",
    "java": b"class App { public static void main(String[] args) {} }\n",
    "kotlin": b"fun greet(name: String): String = name\n",
    "csharp": b"class App { static void Main() {} }\n",
    "scala": b"object App { def main(args: Array[String]): Unit = {} }\n",
    "c": b"int main(void) { return 0; }\n",
    "cpp": b"int main() { return 0; }\n",
    "rust": b"fn main() { let x = 1; }\n",
    "ruby": b"def greet(name)\n  name\nend\n",
    "php": b"<?php function greet($name) { return $name; } ?>\n",
    "swift": b"func greet(name: String) -> String { return name }\n",
    "dart": b"void main() { var x = 1; }\n",
    "solidity": b"pragma solidity ^0.8.0;\ncontract Vault { uint256 public bal; }\n",
    "web_template": b"<html><body><form method=\"post\"><input name=\"q\"></form></body></html>\n",
}


class TestPillar1Models:
    def test_cpg_node_backward_compatible_defaults(self):
        node = CPGNode(
            id="abc123",
            label="Call",
            ast_type="call",
            name="cursor.execute",
            code="cursor.execute(q)",
            filepath="app.py",
            start_line=10,
            end_line=10,
            start_col=4,
            end_col=21,
            scope_id="scope1",
        )
        assert node.sanitizer_domains == []
        assert node.sink_domain is None
        assert node.language == "python"

        enriched = CPGNode(
            id="def456",
            label="Call",
            ast_type="call_expression",
            name="html.EscapeString",
            code="html.EscapeString(x)",
            filepath="main.go",
            start_line=5,
            end_line=5,
            start_col=0,
            end_col=20,
            scope_id="scope2",
            is_sanitizer=True,
            sanitizer_domains=["HTML"],
            sink_domain="HTML",
            language="go",
        )
        assert enriched.sanitizer_domains == ["HTML"]
        assert enriched.sink_domain == "HTML"
        assert enriched.language == "go"

    def test_telemetry_communities_and_capabilities_models(self):
        telemetry = ScanScopeTelemetry(
            total_discovered=12,
            symlinks_dropped=2,
            gitignore_excluded=4,
            build_dirs_excluded=3,
            generated_excluded=1,
            tests_excluded=2,
            languages_breakdown={"python": 5, "go": 7},
        )
        assert telemetry.total_discovered == 12
        assert telemetry.languages_breakdown["go"] == 7

        comm = GraphCommunityItem(
            id="comm-1",
            label="Auth Service (Go)",
            primary_language="go",
            languages=["go", "python"],
            filepaths=["auth/handler.go"],
            file_count=1,
            entrypoint_count=1,
            sink_count=1,
            finding_count=1,
            risk_tier="HIGH",
        )
        bridge = CommunityBridgeEdge(
            id="bridge-1",
            source_community_id="comm-1",
            target_community_id="comm-2",
            edge_count=3,
            edge_types=["CALLS", "DFG_FLOWS_TO"],
            is_polyglot_bridge=True,
            sample_files=["auth/handler.go", "web/index.ts"],
        )
        cmap = CommunityMapResponse(
            graph_engine_mode="EMBEDDED_SQLITE",
            total_communities=1,
            polyglot_bridges_count=1,
            communities=[comm],
            cross_community_edges=[bridge],
        )
        assert cmap.graph_engine_mode == "EMBEDDED_SQLITE"
        assert cmap.communities[0].risk_tier == "HIGH"
        assert cmap.cross_community_edges[0].is_polyglot_bridge is True

        cap = LanguageCapabilityItem(
            language="rust",
            display_name="Rust",
            extensions=[".rs"],
            parser_available=True,
            rule_pack_count=3,
            supports_taint=True,
        )
        caps = LanguageCapabilitiesResponse(
            total_languages=1,
            ready_parsers=1,
            languages=[cap],
        )
        assert caps.ready_parsers == 1

    def test_metrics_and_scan_response_backward_compatible(self):
        metrics = MetricsResponse(
            total_nodes=10,
            total_edges=20,
            total_findings=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
        )
        assert metrics.graph_engine_mode is None
        assert metrics.languages_detected == {}
        assert metrics.scope_telemetry is None
        assert metrics.communities_count == 0

        scan_resp = ScanResponse(
            project_path="/tmp/demo",
            files_scanned=3,
            nodes_created=50,
            edges_created=60,
            status="SUCCESS",
            graph_engine_mode="NEO4J_APOC",
            languages_detected={"python": 2, "go": 1},
            scope_telemetry=ScanScopeTelemetry(total_discovered=3),
            communities_count=2,
        )
        assert scan_resp.graph_engine_mode == "NEO4J_APOC"
        assert scan_resp.communities_count == 2
        assert scan_resp.scope_telemetry is not None


class TestLanguageRegistry:
    def test_all_18_language_families_registered(self):
        assert set(LANGUAGE_SPECS.keys()) == EXPECTED_18_LANGUAGES
        assert len(EXTENSION_TO_LANGUAGE) >= 55
        for lang_key in EXPECTED_18_LANGUAGES:
            spec = get_language_spec(lang_key)
            assert isinstance(spec, LanguageSpec)
            assert spec.key == lang_key
            assert spec.display_name
            assert spec.grammar_name
            assert len(spec.extensions) >= 1
            assert len(spec.source_patterns) >= 1
            assert len(spec.sink_patterns) >= 1
            assert len(spec.sanitizer_patterns) >= 1

    def test_compound_suffix_and_case_insensitive_resolution(self):
        assert resolve_language_for_filename("resources/views/home.blade.php") == "web_template"
        assert resolve_language_for_filename("views/ADMIN.BLADE.PHP") == "web_template"
        assert resolve_language_for_filename("app/Http/Controllers/UserController.php") == "php"
        assert resolve_language_for_filename("src/Main.JAVA") == "java"
        assert resolve_language_for_filename("contracts/Vault.sol") == "solidity"
        assert resolve_language_for_filename("templates/dashboard.jinja2") == "web_template"
        assert resolve_language_for_filename("templates/page.cshtml") == "web_template"
        assert resolve_language_for_filename("lib/main.dart") == "dart"
        assert resolve_language_for_filename("Sources/App.swift") == "swift"
        assert resolve_language_for_filename("README.md") is None

    def test_get_language_spec_unknown_raises(self):
        with pytest.raises(KeyError):
            get_language_spec("cobol_unknown")

    @pytest.mark.parametrize("lang_key", sorted(EXPECTED_18_LANGUAGES))
    def test_parser_loads_and_parses_each_of_18_languages(self, lang_key: str):
        parser = get_parser_for_language(lang_key)
        assert parser is not None, f"Parser unavailable for {lang_key}"
        tree = parser.parse(LANGUAGE_SNIPPETS[lang_key])
        assert tree is not None
        assert tree.root_node is not None
        assert tree.root_node.end_byte > 0

    def test_parser_unknown_language_returns_none_cleanly(self):
        assert get_parser_for_language("nonexistent_lang") is None

    def test_list_language_capabilities(self):
        caps = list_language_capabilities()
        assert isinstance(caps, LanguageCapabilitiesResponse)
        assert caps.total_languages == 18
        assert caps.ready_parsers == 18
        assert len(caps.languages) == 18
        by_lang = {item.language: item for item in caps.languages}
        assert by_lang["web_template"].parser_available is True
        assert ".blade.php" in by_lang["web_template"].extensions
        assert by_lang["solidity"].parser_available is True

    def test_ast_node_type_categories_are_mutually_disjoint_across_all_18_specs(self):
        category_fields = (
            "module_node_types",
            "class_node_types",
            "function_node_types",
            "parameter_node_types",
            "assignment_node_types",
            "call_node_types",
            "control_node_types",
            "loop_node_types",
            "return_node_types",
            "identifier_node_types",
            "literal_node_types",
            "import_node_types",
            "skip_node_types",
        )
        for lang_key, spec in LANGUAGE_SPECS.items():
            seen: dict[str, str] = {}
            for field_name in category_fields:
                for node_type in getattr(spec, field_name):
                    assert node_type not in seen, (
                        f"LanguageSpec[{lang_key!r}] repeats AST node type {node_type!r} "
                        f"in both {seen[node_type]} and {field_name}"
                    )
                    seen[node_type] = field_name

    def test_get_parser_for_language_returns_distinct_instances_across_threads(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        barrier = threading.Barrier(4)

        def fetch_and_parse(lang_key: str):
            p = get_parser_for_language(lang_key)
            assert p is not None
            tree = p.parse(LANGUAGE_SNIPPETS[lang_key])
            assert tree.root_node.end_byte > 0
            barrier.wait(timeout=5)
            return id(p)

        main_py_id = id(get_parser_for_language("python"))
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(fetch_and_parse, "python") for _ in range(4)]
            worker_ids = [f.result() for f in futs]

        assert len(set(worker_ids) | {main_py_id}) == 5

    def test_fallback_bundled_parser_loader(self):
        for lang_key in ("python", "javascript", "typescript", "tsx"):
            parser = _load_fallback_bundled_parser(lang_key)
            assert parser is not None
            tree = parser.parse(LANGUAGE_SNIPPETS[lang_key])
            assert tree.root_node.end_byte > 0

        assert _load_fallback_bundled_parser("go") is None
        assert _load_fallback_bundled_parser("unknown_lang") is None


class TestHostileRepoScopeWalker:
    def test_code_extensions_aligned_with_registry(self):
        assert CODE_EXTENSIONS == EXTENSION_TO_LANGUAGE
        assert ".git" in IGNORE_DIRS

    def test_polyglot_discovery_and_telemetry(self, tmp_path: Path):
        files_to_create = {
            "backend/app.py": "def f(): return 1\n",
            "cmd/server/main.go": "package main\nfunc main() {}\n",
            "contracts/Vault.sol": "pragma solidity ^0.8.0;\ncontract Vault {}\n",
            "views/index.blade.php": "<div>{{ $user }}</div>\n",
            "controllers/user.php": "<?php echo 1; ?>\n",
            "src/lib.rs": "fn main() {}\n",
            "native/util.cpp": "int f() { return 0; }\n",
        }
        for rel, content in files_to_create.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

        scanned_legacy = scan_directory(str(tmp_path))
        scanned, telemetry = scan_directory_with_telemetry(str(tmp_path))

        assert [s.filepath for s in scanned_legacy] == [s.filepath for s in scanned]
        by_path = {s.filepath: s for s in scanned}
        assert set(by_path.keys()) == set(files_to_create.keys())
        assert by_path["views/index.blade.php"].language == "web_template"
        assert by_path["controllers/user.php"].language == "php"
        assert by_path["contracts/Vault.sol"].language == "solidity"
        assert telemetry.total_discovered == len(files_to_create)
        assert telemetry.languages_breakdown["web_template"] == 1
        assert telemetry.languages_breakdown["php"] == 1
        assert telemetry.languages_breakdown["go"] == 1

    def test_escaping_symlinks_are_dropped_and_counted(self, tmp_path: Path):
        repo = tmp_path / "repo"
        outside = tmp_path / "outside_secret"
        repo.mkdir()
        outside.mkdir()

        (repo / "safe.py").write_text("x = 1\n", encoding="utf-8")
        secret_file = outside / "leaked.py"
        secret_file.write_text("OUTSIDE_MARKER = 'external_payload'\n", encoding="utf-8")
        outside_dir = outside / "ext_pkg"
        outside_dir.mkdir()
        (outside_dir / "escape.py").write_text("y = 2\n", encoding="utf-8")

        link_file = repo / "link_secret.py"
        link_dir = repo / "link_ext"

        symlink_created = False
        try:
            os.symlink(str(secret_file), str(link_file))
            os.symlink(str(outside_dir), str(link_dir), target_is_directory=True)
            symlink_created = True
        except (OSError, NotImplementedError):
            symlink_created = False

        if symlink_created:
            scanned, telemetry = scan_directory_with_telemetry(str(repo))
            paths = {s.filepath for s in scanned}
            assert paths == {"safe.py"}
            assert telemetry.symlinks_dropped >= 2
        else:
            # Fallback for restricted Windows accounts lacking SeCreateSymbolicLinkPrivilege:
            # simulate escaping symlink via realpath/islink confinement check.
            fake_link = repo / "fake_escape.py"
            fake_link.write_text("OUTSIDE_MARKER = 'escaped_payload'\n", encoding="utf-8")
            real_islink = os.path.islink
            real_realpath = os.path.realpath

            def mock_islink(p):
                if os.path.abspath(p) == os.path.abspath(str(fake_link)):
                    return True
                return real_islink(p)

            def mock_realpath(p):
                if os.path.abspath(p) == os.path.abspath(str(fake_link)):
                    return str(secret_file)
                return real_realpath(p)

            with mock.patch("compiler.scanner.os.path.islink", side_effect=mock_islink), \
                 mock.patch("compiler.scanner.os.path.realpath", side_effect=mock_realpath):
                scanned, telemetry = scan_directory_with_telemetry(str(repo))
            paths = {s.filepath for s in scanned}
            assert paths == {"safe.py"}
            assert telemetry.symlinks_dropped == 1

    def test_nested_gitignore_with_negation_and_dir_only(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text(
            "# comment\n"
            "ignored_dir/\n"
            "*.tmp.py\n"
            "!keep.tmp.py\n",
            encoding="utf-8",
        )
        (tmp_path / "main.py").write_text("a = 1\n", encoding="utf-8")
        (tmp_path / "drop.tmp.py").write_text("b = 2\n", encoding="utf-8")
        (tmp_path / "keep.tmp.py").write_text("c = 3\n", encoding="utf-8")
        (tmp_path / "local_only.go").write_text("package main\n", encoding="utf-8")

        (tmp_path / "ignored_dir").mkdir()
        (tmp_path / "ignored_dir" / "hidden.py").write_text("d = 4\n", encoding="utf-8")

        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / ".gitignore").write_text("local_only.go\n", encoding="utf-8")
        (sub / "local_only.go").write_text("package sub\n", encoding="utf-8")
        (sub / "kept.go").write_text("package sub\n", encoding="utf-8")

        scanned, telemetry = scan_directory_with_telemetry(str(tmp_path))
        paths = {s.filepath for s in scanned}
        assert "main.py" in paths
        assert "keep.tmp.py" in paths
        assert "local_only.go" in paths
        assert "sub/kept.go" in paths
        assert "drop.tmp.py" not in paths
        assert "ignored_dir/hidden.py" not in paths
        assert "sub/local_only.go" not in paths
        assert telemetry.gitignore_excluded >= 3

    def test_contextual_ecosystem_build_output_exclusions(self, tmp_path: Path):
        # 1. Rust target/ beside Cargo.toml -> EXCLUDED
        rust_dir = tmp_path / "rust_svc"
        (rust_dir / "target" / "debug").mkdir(parents=True)
        (rust_dir / "Cargo.toml").write_text("[package]\nname='svc'\n", encoding="utf-8")
        (rust_dir / "src").mkdir()
        (rust_dir / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (rust_dir / "target" / "debug" / "gen.rs").write_text("fn gen() {}\n", encoding="utf-8")

        # 2. Go app/target/service.go WITHOUT manifest -> INCLUDED
        (tmp_path / "app" / "target").mkdir(parents=True)
        (tmp_path / "app" / "target" / "service.go").write_text("package target\n", encoding="utf-8")

        # 3. C# bin/ & obj/ beside App.csproj -> EXCLUDED; plain/bin/tool.py -> INCLUDED
        cs_dir = tmp_path / "dotnet_svc"
        (cs_dir / "bin" / "Debug").mkdir(parents=True)
        (cs_dir / "obj" / "Debug").mkdir(parents=True)
        (cs_dir / "App.csproj").write_text("<Project />\n", encoding="utf-8")
        (cs_dir / "Program.cs").write_text("class Program {}\n", encoding="utf-8")
        (cs_dir / "bin" / "Debug" / "Built.cs").write_text("class Built {}\n", encoding="utf-8")
        (cs_dir / "obj" / "Debug" / "Temp.cs").write_text("class Temp {}\n", encoding="utf-8")

        (tmp_path / "plain" / "bin").mkdir(parents=True)
        (tmp_path / "plain" / "bin" / "tool.py").write_text("x = 1\n", encoding="utf-8")

        # 4. iOS Pods/ beside Podfile -> EXCLUDED
        ios_dir = tmp_path / "ios_app"
        (ios_dir / "Pods").mkdir(parents=True)
        (ios_dir / "Podfile").write_text("platform :ios, '15.0'\n", encoding="utf-8")
        (ios_dir / "App.swift").write_text("let a = 1\n", encoding="utf-8")
        (ios_dir / "Pods" / "Dep.swift").write_text("let b = 2\n", encoding="utf-8")

        # 5. Foundry out/ beside foundry.toml -> EXCLUDED
        eth_dir = tmp_path / "foundry_app"
        (eth_dir / "out").mkdir(parents=True)
        (eth_dir / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        (eth_dir / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
        (eth_dir / "out" / "Vault.sol").write_text("contract Out {}\n", encoding="utf-8")

        # 6. Hardhat artifacts/ & cache/ beside hardhat.config.ts -> EXCLUDED
        hh_dir = tmp_path / "hardhat_app"
        (hh_dir / "artifacts").mkdir(parents=True)
        (hh_dir / "cache").mkdir(parents=True)
        (hh_dir / "hardhat.config.ts").write_text("export default {};\n", encoding="utf-8")
        (hh_dir / "Token.sol").write_text("contract Token {}\n", encoding="utf-8")
        (hh_dir / "artifacts" / "Token.sol").write_text("contract Art {}\n", encoding="utf-8")
        (hh_dir / "cache" / "Cache.sol").write_text("contract Cache {}\n", encoding="utf-8")

        scanned, telemetry = scan_directory_with_telemetry(str(tmp_path))
        paths = {s.filepath for s in scanned}

        assert "rust_svc/src/main.rs" in paths
        assert "rust_svc/target/debug/gen.rs" not in paths
        assert "app/target/service.go" in paths
        assert "dotnet_svc/Program.cs" in paths
        assert "dotnet_svc/bin/Debug/Built.cs" not in paths
        assert "dotnet_svc/obj/Debug/Temp.cs" not in paths
        assert "plain/bin/tool.py" in paths
        assert "ios_app/App.swift" in paths
        assert "ios_app/Pods/Dep.swift" not in paths
        assert "foundry_app/Vault.sol" in paths
        assert "foundry_app/out/Vault.sol" not in paths
        assert "hardhat_app/Token.sol" in paths
        assert "hardhat_app/artifacts/Token.sol" not in paths
        assert "hardhat_app/cache/Cache.sol" not in paths
        assert telemetry.build_dirs_excluded >= 7

    def test_generated_stubs_skipped_and_counted(self, tmp_path: Path):
        generated = [
            "api.pb.go",
            "user_pb2.py",
            "Model.g.cs",
            "MainForm.Designer.cs",
            "schema.generated.ts",
            "lib.min.js",
            "app.bundle.js",
            "old.pack.js",
            "mod.min.mjs",
        ]
        for name in generated:
            (tmp_path / name).write_text("// generated\n", encoding="utf-8")
        (tmp_path / "real_handler.go").write_text("package main\n", encoding="utf-8")

        scanned, telemetry = scan_directory_with_telemetry(str(tmp_path))
        paths = {s.filepath for s in scanned}
        assert paths == {"real_handler.go"}
        assert telemetry.generated_excluded == len(generated)

    def test_exclude_tests_optional_flag(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "src" / "service.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "tests" / "test_service.py").write_text("def test_x(): pass\n", encoding="utf-8")
        (tmp_path / "src" / "service.spec.ts").write_text("const t = 1;\n", encoding="utf-8")

        default_scanned, default_tel = scan_directory_with_telemetry(str(tmp_path))
        assert len(default_scanned) == 3
        assert default_tel.tests_excluded == 0

        filtered_scanned, filtered_tel = scan_directory_with_telemetry(str(tmp_path), exclude_tests=True)
        assert {s.filepath for s in filtered_scanned} == {"src/service.py"}
        assert filtered_tel.tests_excluded >= 2

    def test_synthetic_test_target_exclusion_behavior(self, tmp_path: Path):
        syn = tmp_path / "synthetic_test_target"
        syn.mkdir()
        (syn / "vuln.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "platform.py").write_text("y = 2\n", encoding="utf-8")

        parent_scanned = scan_directory(str(tmp_path))
        assert {s.filepath for s in parent_scanned} == {"platform.py"}

        direct_scanned = scan_directory(str(syn))
        assert {s.filepath for s in direct_scanned} == {"vuln.py"}

    def test_single_file_compound_suffix_and_never_reads_env_or_runs_git(self, tmp_path: Path):
        blade = tmp_path / "dashboard.blade.php"
        blade.write_text("<h1>{{ $title }}</h1>\n", encoding="utf-8")
        env_file = tmp_path / ".env"
        env_file.write_text("SAMPLE_CONFIG_ENTRY=placeholder_only\n", encoding="utf-8")
        (tmp_path / ".gitignore").write_text("**/ignored_sub/*.py\n", encoding="utf-8")
        (tmp_path / "a" / "b" / "ignored_sub").mkdir(parents=True)
        (tmp_path / "a" / "b" / "ignored_sub" / "drop.py").write_text("x = 1\n", encoding="utf-8")

        single_files = scan_directory(str(blade))
        assert len(single_files) == 1
        assert single_files[0].language == "web_template"

        with mock.patch("subprocess.run", side_effect=AssertionError("Must never invoke git subprocess")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("Must never invoke git subprocess")):
            scanned, telemetry = scan_directory_with_telemetry(str(tmp_path))

        paths = {s.filepath for s in scanned}
        assert paths == {"dashboard.blade.php"}
        assert ".env" not in paths
        assert "a/b/ignored_sub/drop.py" not in paths
        assert telemetry.gitignore_excluded >= 1

    def test_gitignore_wildcards_do_not_cross_slash_boundaries(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text(
            "/*.py\n"
            "src/*.py\n"
            "foo*bar.py\n",
            encoding="utf-8",
        )
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "foo_mid_bar.py").write_text("x = 2\n", encoding="utf-8")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.py").write_text("x = 3\n", encoding="utf-8")
        (tmp_path / "src" / "deep").mkdir()
        (tmp_path / "src" / "deep" / "app.py").write_text("x = 4\n", encoding="utf-8")
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "app.py").write_text("x = 5\n", encoding="utf-8")
        (tmp_path / "foo" / "sub").mkdir(parents=True)
        (tmp_path / "foo" / "sub" / "bar.py").write_text("x = 6\n", encoding="utf-8")

        scanned, telemetry = scan_directory_with_telemetry(str(tmp_path))
        paths = {s.filepath for s in scanned}

        assert "a.py" not in paths
        assert "foo_mid_bar.py" not in paths
        assert "src/a.py" not in paths
        assert "pkg/app.py" in paths
        assert "src/deep/app.py" in paths
        assert "foo/sub/bar.py" in paths
        assert telemetry.gitignore_excluded == 3

    def test_is_confined_fails_closed_on_oserror_and_drops_escaping_dir_and_file_links(self, tmp_path: Path):
        repo = tmp_path / "repo"
        outside = tmp_path / "outside"
        repo.mkdir()
        outside.mkdir()
        (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
        fake_file_link = repo / "esc_file.py"
        fake_file_link.write_text("OUTSIDE_MARKER = 'f'\n", encoding="utf-8")
        fake_dir_link = repo / "esc_dir"
        fake_dir_link.mkdir()
        (fake_dir_link / "nested.py").write_text("OUTSIDE_MARKER = 'd'\n", encoding="utf-8")

        real_islink = os.path.islink
        real_realpath = os.path.realpath

        def mock_islink(p):
            ap = os.path.abspath(p)
            if ap in (os.path.abspath(str(fake_file_link)), os.path.abspath(str(fake_dir_link))):
                return True
            return real_islink(p)

        def mock_realpath(p):
            ap = os.path.abspath(p)
            if ap == os.path.abspath(str(fake_file_link)):
                return str(outside / "secret_file.py")
            if ap == os.path.abspath(str(fake_dir_link)):
                return str(outside / "secret_dir")
            return real_realpath(p)

        with mock.patch("compiler.scanner.os.path.islink", side_effect=mock_islink), \
             mock.patch("compiler.scanner.os.path.realpath", side_effect=mock_realpath):
            scanned, telemetry = scan_directory_with_telemetry(str(repo))

        assert {s.filepath for s in scanned} == {"ok.py"}
        assert telemetry.symlinks_dropped == 2

        with mock.patch("compiler.scanner.os.path.realpath", side_effect=OSError("bad reparse point")):
            assert _is_confined(str(repo), str(fake_file_link)) is False
