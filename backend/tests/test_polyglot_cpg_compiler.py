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


# ---------------------------------------------------------------------------
# Task 2 TDD Suite: Unified 18-Language 4-Pass CPG Compiler,
# Domain-Aware Sanitizer Tracking & 12 Polyglot Rule Packs (RULE-22..RULE-33)
# ---------------------------------------------------------------------------

POLYGLOT_FULL_SAMPLES = {
    "python": (
        "app.py",
        b"def helper(x):\n    y = x\n    if y:\n        return y\n    for i in range(3):\n        print(y)\n    return ''\n\ndef main():\n    helper('a')\n",
    ),
    "javascript": (
        "app.js",
        b"function helper(x) {\n  const y = x;\n  if (y) { return y; }\n  for (let i = 0; i < 3; i++) { console.log(y); }\n  return '';\n}\nfunction main() { helper('a'); }\n",
    ),
    "typescript": (
        "app.ts",
        b"function helper(x: string): string {\n  const y: string = x;\n  if (y) { return y; }\n  for (let i = 0; i < 3; i++) { console.log(y); }\n  return '';\n}\nfunction main() { helper('a'); }\n",
    ),
    "tsx": (
        "App.tsx",
        b"function helper(x: string): string {\n  const y = x;\n  if (y) { return y; }\n  return '';\n}\nexport function App() { const v = helper('a'); return <div>{v}</div>; }\n",
    ),
    "go": (
        "main.go",
        b'package main\nfunc helper(x string) string {\n\ty := x\n\tif y != "" {\n\t\treturn y\n\t}\n\tfor i := 0; i < 3; i++ {\n\t\tprintln(y)\n\t}\n\treturn ""\n}\nfunc main() {\n\thelper("a")\n}\n',
    ),
    "java": (
        "App.java",
        b'class App {\n  String helper(String x) {\n    String y = x;\n    if (y != null) { return y; }\n    for (int i = 0; i < 3; i++) { System.out.println(y); }\n    return "";\n  }\n  void main() { helper("a"); }\n}\n',
    ),
    "kotlin": (
        "App.kt",
        b'fun helper(x: String): String {\n  val y = x\n  if (y.isNotEmpty()) { return y }\n  for (i in 1..3) { println(y) }\n  return ""\n}\nfun main() { helper("a") }\n',
    ),
    "csharp": (
        "App.cs",
        b'class App {\n  string Helper(string x) {\n    var y = x;\n    if (y != null) { return y; }\n    for (int i = 0; i < 3; i++) { Console.WriteLine(y); }\n    return "";\n  }\n  void Main() { Helper("a"); }\n}\n',
    ),
    "scala": (
        "App.scala",
        b'object App {\n  def helper(x: String): String = {\n    val y = x\n    if (y != null) return y\n    while (false) { println(y) }\n    y\n  }\n  def main(): Unit = { helper("a") }\n}\n',
    ),
    "c": (
        "util.c",
        b'int helper(char *x) {\n  char *y = x;\n  if (y) { return 1; }\n  for (int i = 0; i < 3; i++) { puts(y); }\n  return 0;\n}\nint main(void) { return helper("a"); }\n',
    ),
    "cpp": (
        "util.cpp",
        b'int helper(const char *x) {\n  const char *y = x;\n  if (y) { return 1; }\n  while (0) { puts(y); }\n  return 0;\n}\nint main() { return helper("a"); }\n',
    ),
    "rust": (
        "lib.rs",
        b'fn helper(x: &str) -> &str {\n  let y = x;\n  if !y.is_empty() { return y; }\n  while false { println!("{}", y); }\n  y\n}\nfn main() { helper("a"); }\n',
    ),
    "ruby": (
        "app.rb",
        b'def helper(x)\n  y = x\n  if y\n    return y\n  end\n  while false\n    puts(y)\n  end\n  y\nend\nhelper("a")\n',
    ),
    "php": (
        "app.php",
        b'<?php\nfunction helper($x) {\n  $y = $x;\n  if ($y) { return $y; }\n  for ($i = 0; $i < 3; $i++) { echo $y; }\n  return "";\n}\nhelper("a");\n?>\n',
    ),
    "swift": (
        "App.swift",
        b'func helper(x: String) -> String {\n  let y = x\n  if !y.isEmpty { return y }\n  while false { print(y) }\n  return ""\n}\nfunc main() { helper(x: "a") }\n',
    ),
    "dart": (
        "main.dart",
        b'String helper(String x) {\n  var y = x;\n  if (y.isNotEmpty) { return y; }\n  for (var i = 0; i < 3; i++) { print(y); }\n  return "";\n}\nvoid main() { helper("a"); }\n',
    ),
    "solidity": (
        "Vault.sol",
        b"pragma solidity ^0.8.0;\ncontract Vault {\n  function helper(uint x) public returns (uint) {\n    uint y = x;\n    if (y > 0) { return y; }\n    for (uint i = 0; i < 3; i++) { y += i; }\n    return y;\n  }\n  function run() public { helper(1); }\n}\n",
    ),
    "web_template": (
        "page.html",
        b'<html><body><form method="post"><input name="u" value="{{ user }}"></form><div><%- rawHtml %></div></body></html>\n',
    ),
}


def _make_scanned_file(filepath: str, content_bytes: bytes, language: str) -> ScannedFile:
    import hashlib
    return ScannedFile(
        filepath=filepath,
        full_path=f"/virtual/{filepath}",
        sha256=hashlib.sha256(content_bytes).hexdigest(),
        language=language,
        content_bytes=content_bytes,
    )


def _compile_four_passes(scanned_files):
    from compiler.ast_parser import ASTNormalizer
    from compiler.cfg_builder import CFGBuilder
    from compiler.dfg_builder import DFGBuilder
    from compiler.call_graph_builder import CallGraphBuilder

    all_nodes = []
    all_edges = []
    node_map = {}
    file_nodes = {}

    for sf in scanned_files:
        norm = ASTNormalizer(sf)
        nodes, edges = norm.parse()
        all_nodes.extend(nodes)
        all_edges.extend(edges)
        node_map.update(norm.node_map)
        file_nodes[sf.filepath] = nodes

    fn_params = {}
    fn_returns = {}
    func_by_id = {n.id: n for n in all_nodes if n.label == "Function"}
    for n in all_nodes:
        if n.label == "Parameter" and n.scope_id in func_by_id:
            fn_params.setdefault(func_by_id[n.scope_id].name, []).append(n)
        elif n.label == "Return" and n.scope_id in func_by_id:
            fn_returns.setdefault(func_by_id[n.scope_id].name, []).append(n)

    for sf in scanned_files:
        f_nodes = file_nodes[sf.filepath]
        cfg = CFGBuilder(sf.filepath, sf.content_bytes, sf.language, f_nodes, node_map)
        all_edges.extend(cfg.build())

    for sf in scanned_files:
        f_nodes = file_nodes[sf.filepath]
        dfg = DFGBuilder(sf.filepath, sf.content_bytes, sf.language, f_nodes, node_map, fn_params, fn_returns)
        all_edges.extend(dfg.build())

    cg = CallGraphBuilder(all_nodes)
    all_edges.extend(cg.resolve_calls())
    return all_nodes, all_edges


class TestUnifiedPolyglotCPGCompiler:
    def test_backward_compatible_exports_preserved(self):
        from compiler.ast_parser import (
            py_parser,
            js_parser,
            ts_parser,
            tsx_parser,
            compute_node_id,
            compute_edge_id,
            classify_taint,
            ASTNormalizer,
        )
        assert py_parser is not None
        assert js_parser is not None
        assert ts_parser is not None
        assert tsx_parser is not None
        assert len(compute_node_id("a.py", "call", 0, 5)) == 24
        assert len(compute_edge_id("a", "b", "CFG_NEXT")) == 24
        is_src, is_sink, is_san = classify_taint("os.system(cmd)", "call", "os.system(cmd)")
        assert is_sink is True and is_src is False and is_san is False
        sf = _make_scanned_file("a.py", b"def f(): return 1\n", "python")
        n1, e1 = ASTNormalizer(sf).normalize()
        n2, e2 = ASTNormalizer(sf).parse()
        assert [n.id for n in n1] == [n.id for n in n2]
        assert [e.id for e in e1] == [e.id for e in e2]

    @pytest.mark.parametrize("lang_key", sorted(EXPECTED_18_LANGUAGES))
    def test_four_pass_cpg_compilation_for_each_of_18_languages(self, lang_key: str):
        filepath, content = POLYGLOT_FULL_SAMPLES[lang_key]
        sf = _make_scanned_file(filepath, content, lang_key)
        nodes, edges = _compile_four_passes([sf])

        assert len(nodes) >= 3
        assert all(n.language == lang_key for n in nodes), f"Expected all nodes to carry language={lang_key}"
        edge_types = {e.edge_type for e in edges}
        assert "AST_CHILD" in edge_types

        if lang_key == "web_template":
            assert any("{{" in n.code or "<%-" in n.code for n in nodes)
            assert any(e.edge_type in ("CFG_NEXT", "DFG_FLOWS_TO") for e in edges)
        else:
            func_nodes = [n for n in nodes if n.label == "Function"]
            assert len(func_nodes) >= 1, f"No Function node for {lang_key}"
            assert "CFG_NEXT" in edge_types, f"No CFG_NEXT edges for {lang_key}"
            assert "DFG_FLOWS_TO" in edge_types, f"No DFG_FLOWS_TO edges for {lang_key}"
            assert "CALLS" in edge_types, f"No CALLS edges for {lang_key}"

    def test_polyglot_call_graph_separators_and_resolution_priority(self):
        from compiler.call_graph_builder import CallGraphBuilder

        f_local = CPGNode(
            id="fn_local", label="Function", ast_type="function_declaration", name="Run",
            code="func Run()", filepath="pkg/a.go", start_line=1, end_line=2,
            start_col=0, end_col=10, scope_id="g", language="go",
        )
        f_samedir_go = CPGNode(
            id="fn_samedir_go", label="Function", ast_type="function_declaration", name="Clean",
            code="func Clean()", filepath="pkg/util.go", start_line=1, end_line=2,
            start_col=0, end_col=10, scope_id="g", language="go",
        )
        f_otherdir_go = CPGNode(
            id="fn_otherdir_go", label="Function", ast_type="function_declaration", name="Clean",
            code="func Clean()", filepath="other/util.go", start_line=1, end_line=2,
            start_col=0, end_col=10, scope_id="g", language="go",
        )
        f_cpp = CPGNode(
            id="fn_cpp", label="Function", ast_type="function_definition", name="exec",
            code="void exec()", filepath="native/svc.cpp", start_line=1, end_line=2,
            start_col=0, end_col=10, scope_id="g", language="cpp",
        )
        f_rust = CPGNode(
            id="fn_rust", label="Function", ast_type="function_item", name="sanitize",
            code="fn sanitize()", filepath="crates/lib.rs", start_line=1, end_line=2,
            start_col=0, end_col=10, scope_id="g", language="rust",
        )

        c_go_local = CPGNode(
            id="c1", label="Call", ast_type="call_expression", name="pkg.Run",
            code="pkg.Run()", filepath="pkg/a.go", start_line=5, end_line=5,
            start_col=0, end_col=9, scope_id="g", language="go",
        )
        c_go_samedir = CPGNode(
            id="c2", label="Call", ast_type="call_expression", name="util.Clean",
            code="util.Clean()", filepath="pkg/a.go", start_line=6, end_line=6,
            start_col=0, end_col=12, scope_id="g", language="go",
        )
        c_cpp_arrow = CPGNode(
            id="c3", label="Call", ast_type="call_expression", name="svc->exec",
            code="svc->exec()", filepath="native/main.cpp", start_line=4, end_line=4,
            start_col=0, end_col=11, scope_id="g", language="cpp",
        )
        c_rust_scope = CPGNode(
            id="c4", label="Call", ast_type="call_expression", name="Utils::sanitize",
            code="Utils::sanitize()", filepath="crates/main.rs", start_line=4, end_line=4,
            start_col=0, end_col=17, scope_id="g", language="rust",
        )

        edges = CallGraphBuilder([
            f_local, f_samedir_go, f_otherdir_go, f_cpp, f_rust,
            c_go_local, c_go_samedir, c_cpp_arrow, c_rust_scope,
        ]).resolve_calls()
        by_src = {e.source_id: e.target_id for e in edges}
        assert by_src["c1"] == "fn_local"
        assert by_src["c2"] == "fn_samedir_go"
        assert by_src["c3"] == "fn_cpp"
        assert by_src["c4"] == "fn_rust"

    def test_graceful_degradation_on_malformed_bytes_and_unknown_language(self):
        from compiler.ast_parser import ASTNormalizer
        from compiler.cfg_builder import CFGBuilder
        from compiler.dfg_builder import DFGBuilder

        bad_sf = _make_scanned_file("broken.xyz", b"\xff\xfe\x00\x01{{{{", "unknown_lang")
        norm = ASTNormalizer(bad_sf)
        nodes, edges = norm.parse()
        assert len(nodes) >= 1
        assert CFGBuilder(bad_sf.filepath, bad_sf.content_bytes, bad_sf.language, nodes, norm.node_map).build() == []
        assert DFGBuilder(bad_sf.filepath, bad_sf.content_bytes, bad_sf.language, nodes, norm.node_map, {}, {}).build() == []


class TestDomainAwareSanitizerPropagation:
    def test_no_hardcoded_app_specific_xss_allowlists_in_ast_parser(self):
        ast_parser_src = (BACKEND_DIR / "compiler" / "ast_parser.py").read_text(encoding="utf-8")
        forbidden_tokens = [
            "detailsHtml",
            "warnHtml",
            "unverHtml",
            "selfSearchLinks",
            "HOT_TYPES.test(",
            "breachCount",
            "done.has(",
            "s.links.join",
            "i === 0",
        ]
        for tok in forbidden_tokens:
            assert tok not in ast_parser_src, f"Hardcoded app-specific allowlist token {tok!r} must be removed"

    def test_sanitized_variable_and_helper_clear_html_sink_in_dfg_pass(self):
        js_code = b"""
function buildSafeCard(user) {
  const title = esc(user.name);
  return `<div class="card"><h3>${title}</h3><span>${user.items.length}</span></div>`;
}
function buildUnsafeCard(user) {
  return `<div class="card">${user.bio}</div>`;
}
function render(el1, el2, el3, el4, user) {
  const safeFragment = `<p>${escapeHtml(user.name)}</p>`;
  el1.innerHTML = safeFragment;

  let accum = "";
  accum += `<li>${esc(user.role)}</li>`;
  el2.innerHTML = accum;

  el3.innerHTML = buildSafeCard(user);
  el4.innerHTML = buildUnsafeCard(user);
}
"""
        sf = _make_scanned_file("ui/render.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])

        inner_sinks = {
            n.name: n for n in nodes
            if n.label == "Assignment" and n.name.endswith(".innerHTML")
        }
        assert inner_sinks["el1.innerHTML"].is_sink is False
        assert inner_sinks["el2.innerHTML"].is_sink is False
        assert inner_sinks["el3.innerHTML"].is_sink is False
        assert inner_sinks["el4.innerHTML"].is_sink is True
        assert inner_sinks["el4.innerHTML"].sink_domain == "HTML"

    def test_href_esc_url_scheme_bypass_remains_sink_with_url_domain(self):
        js_code = b"""
function renderLinks(elDirect, elIndirect, elSafeUrl, item) {
  elDirect.innerHTML = `<a href="${esc(item.url)}">${esc(item.title)}</a>`;
  const linkMarkup = `<a href="${escapeHtml(item.url)}">Go</a>`;
  elIndirect.innerHTML = linkMarkup;
  elSafeUrl.innerHTML = `<a href="https://example.com/?q=${encodeURIComponent(item.q)}">${esc(item.title)}</a>`;
}
"""
        sf = _make_scanned_file("ui/links.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        inner_sinks = {
            n.name: n for n in nodes
            if n.label == "Assignment" and n.name.endswith(".innerHTML")
        }
        assert inner_sinks["elDirect.innerHTML"].is_sink is True
        assert inner_sinks["elDirect.innerHTML"].sink_domain == "URL"
        assert inner_sinks["elIndirect.innerHTML"].is_sink is True
        assert inner_sinks["elSafeUrl.innerHTML"].is_sink is False

    def test_cross_domain_sanitizer_isolation_html_vs_shell_and_universal(self):
        py_code = b"""
import html, os, shlex

def handle(request):
    raw = request.args["q"]
    html_only = html.escape(raw)
    shell_safe = shlex.quote(raw)
    num_safe = int(raw)
    os.system(html_only)
    os.system(shell_safe)
    return num_safe
"""
        sf = _make_scanned_file("api/handler.py", py_code, "python")
        nodes, _ = _compile_four_passes([sf])

        by_var = {n.name: n for n in nodes if n.label == "Variable" and n.is_sanitizer}
        assert "HTML" in by_var["html_only"].sanitizer_domains
        assert "SHELL" not in by_var["html_only"].sanitizer_domains
        assert "SHELL" in by_var["shell_safe"].sanitizer_domains
        assert "UNIVERSAL" in by_var["num_safe"].sanitizer_domains

        os_calls = [n for n in nodes if n.label == "Call" and n.name == "os.system"]
        assert len(os_calls) == 2
        assert all(c.is_sink and c.sink_domain == "SHELL" for c in os_calls)


class TestPolyglotRulePacks:
    def _run_rules_on_source(self, filepath: str, language: str, code: str, enabled_rule_ids=None):
        from engine.polyglot_rules import run_polyglot_rules

        sf = _make_scanned_file(filepath, code.encode("utf-8"), language)
        nodes, edges = _compile_four_passes([sf])
        return run_polyglot_rules([sf], nodes, edges, enabled_rule_ids=enabled_rule_ids)

    def test_catalog_contains_all_12_rules(self):
        from engine.polyglot_rules import POLYGLOT_RULE_CATALOG

        ids = [r["id"] for r in POLYGLOT_RULE_CATALOG]
        assert ids == [
            "RULE-22-CPP-BUFFER-OVERFLOW",
            "RULE-23-CPP-FORMAT-STRING",
            "RULE-24-CPP-UAF-DOUBLE-FREE",
            "RULE-25-RUST-UNSAFE-FFI",
            "RULE-26-POLYGLOT-SQLI",
            "RULE-27-POLYGLOT-CMDI",
            "RULE-28-POLYGLOT-DESER",
            "RULE-29-POLYGLOT-XXE",
            "RULE-30-SOLIDITY-REENTRANCY",
            "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE",
            "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI",
            "RULE-33-TEMPLATE-MISSING-CSRF",
        ]

    def test_rule_22_cpp_buffer_overflow(self):
        vuln = """
#include <string.h>
void copy_bad(const char *input, size_t len) {
    char buf[64];
    strcpy(buf, input);
    memcpy(buf, input, len);
}
"""
        safe = """
#include <stdio.h>
#include <string.h>
void copy_good(const char *input) {
    char buf[64];
    strncpy(buf, input, sizeof(buf) - 1);
    snprintf(buf, sizeof(buf), "%s", input);
}
"""
        f_vuln = self._run_rules_on_source("src/buf.c", "c", vuln)
        assert any(f.rule_id == "RULE-22-CPP-BUFFER-OVERFLOW" and f.cwe_id == "CWE-120" and f.severity == "CRITICAL" for f in f_vuln)
        f_safe = self._run_rules_on_source("src/safe_buf.c", "c", safe)
        assert not any(f.rule_id == "RULE-22-CPP-BUFFER-OVERFLOW" for f in f_safe)

    def test_rule_23_cpp_format_string(self):
        vuln = """
#include <stdio.h>
void log_bad(const char *msg) {
    printf(msg);
    fprintf(stderr, msg);
}
"""
        safe = """
#include <stdio.h>
void log_good(const char *msg) {
    printf("%s\\n", msg);
    fprintf(stderr, "err: %s\\n", msg);
}
"""
        f_vuln = self._run_rules_on_source("src/fmt.cpp", "cpp", vuln)
        assert any(f.rule_id == "RULE-23-CPP-FORMAT-STRING" and f.cwe_id == "CWE-134" and f.severity == "HIGH" for f in f_vuln)
        f_safe = self._run_rules_on_source("src/fmt_ok.cpp", "cpp", safe)
        assert not any(f.rule_id == "RULE-23-CPP-FORMAT-STRING" for f in f_safe)

    def test_rule_24_cpp_uaf_double_free(self):
        vuln = """
#include <stdlib.h>
#include <stdio.h>
void bad_uaf(void) {
    char *ptr = (char *)malloc(32);
    free(ptr);
    printf("%s", ptr);
}
void bad_df(void) {
    char *buf = (char *)malloc(16);
    free(buf);
    free(buf);
}
"""
        safe = """
#include <stdlib.h>
void good_mem(void) {
    char *ptr = (char *)malloc(32);
    free(ptr);
    ptr = NULL;
    char *buf = (char *)malloc(16);
    free(buf);
    buf = (char *)malloc(32);
    free(buf);
}
"""
        f_vuln = self._run_rules_on_source("src/mem.c", "c", vuln)
        uaf_hits = [f for f in f_vuln if f.rule_id == "RULE-24-CPP-UAF-DOUBLE-FREE"]
        assert len(uaf_hits) >= 2
        assert all(f.cwe_id == "CWE-416" and f.severity == "CRITICAL" for f in uaf_hits)
        f_safe = self._run_rules_on_source("src/mem_ok.c", "c", safe)
        assert not any(f.rule_id == "RULE-24-CPP-UAF-DOUBLE-FREE" for f in f_safe)

    def test_rule_25_rust_unsafe_ffi(self):
        vuln = """
extern "C" { fn c_parse(ptr: *const u8); }
pub fn dangerous(ptr: *const u8) -> u8 {
    unsafe {
        c_parse(ptr);
        *ptr
    }
}
"""
        safe = """
pub fn safe_add(a: i32, b: i32) -> i32 {
    a.saturating_add(b)
}
"""
        f_vuln = self._run_rules_on_source("src/ffi.rs", "rust", vuln)
        assert any(f.rule_id == "RULE-25-RUST-UNSAFE-FFI" and f.cwe_id == "CWE-242" and f.severity == "HIGH" for f in f_vuln)
        f_safe = self._run_rules_on_source("src/safe.rs", "rust", safe)
        assert not any(f.rule_id == "RULE-25-RUST-UNSAFE-FFI" for f in f_safe)

    def test_rule_26_polyglot_sqli(self):
        go_vuln = 'package main\nfunc q(db *DB, id string) { db.Query("SELECT * FROM users WHERE id = " + id) }\n'
        go_safe = 'package main\nfunc q(db *DB, id string) { db.Query("SELECT * FROM users WHERE id = $1", id) }\n'
        java_vuln = 'class Repo { void q(Statement s, String id) { s.executeQuery("SELECT * FROM u WHERE id=" + id); } }\n'
        java_safe = 'class Repo { void q(Connection c, String id) { PreparedStatement ps = c.prepareStatement("SELECT * FROM u WHERE id=?"); ps.setString(1, id); ps.executeQuery(); } }\n'
        php_vuln = '<?php function q($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id=" . $id); } ?>\n'

        assert any(f.rule_id == "RULE-26-POLYGLOT-SQLI" for f in self._run_rules_on_source("repo.go", "go", go_vuln))
        assert not any(f.rule_id == "RULE-26-POLYGLOT-SQLI" for f in self._run_rules_on_source("repo_ok.go", "go", go_safe))
        assert any(f.rule_id == "RULE-26-POLYGLOT-SQLI" for f in self._run_rules_on_source("Repo.java", "java", java_vuln))
        assert not any(f.rule_id == "RULE-26-POLYGLOT-SQLI" for f in self._run_rules_on_source("RepoOk.java", "java", java_safe))
        assert any(f.rule_id == "RULE-26-POLYGLOT-SQLI" for f in self._run_rules_on_source("repo.php", "php", php_vuln))

    def test_rule_27_polyglot_cmdi(self):
        go_vuln = 'package main\nfunc run(userArg string) { exec.Command("sh", "-c", userArg) }\n'
        go_safe = 'package main\nfunc run() { exec.Command("ls", "-la") }\n'
        php_vuln = '<?php function run($cmd) { shell_exec($cmd); } ?>\n'
        php_safe = '<?php function run($arg) { shell_exec("ls " . escapeshellarg($arg)); } ?>\n'

        assert any(f.rule_id == "RULE-27-POLYGLOT-CMDI" for f in self._run_rules_on_source("cmd.go", "go", go_vuln))
        assert not any(f.rule_id == "RULE-27-POLYGLOT-CMDI" for f in self._run_rules_on_source("cmd_ok.go", "go", go_safe))
        assert any(f.rule_id == "RULE-27-POLYGLOT-CMDI" for f in self._run_rules_on_source("cmd.php", "php", php_vuln))
        assert not any(f.rule_id == "RULE-27-POLYGLOT-CMDI" for f in self._run_rules_on_source("cmd_ok.php", "php", php_safe))

    def test_rule_28_polyglot_deser(self):
        java_vuln = "class D { Object load(ObjectInputStream ois) throws Exception { return ois.readObject(); } }\n"
        cs_vuln = "class D { object Load(Stream s) { var bf = new BinaryFormatter(); return bf.Deserialize(s); } }\n"
        rb_vuln = "def load(raw)\n  YAML.load(raw)\nend\n"
        rb_safe = "def load(raw)\n  YAML.safe_load(raw)\nend\n"

        assert any(f.rule_id == "RULE-28-POLYGLOT-DESER" for f in self._run_rules_on_source("D.java", "java", java_vuln))
        assert any(f.rule_id == "RULE-28-POLYGLOT-DESER" for f in self._run_rules_on_source("D.cs", "csharp", cs_vuln))
        assert any(f.rule_id == "RULE-28-POLYGLOT-DESER" for f in self._run_rules_on_source("d.rb", "ruby", rb_vuln))
        assert not any(f.rule_id == "RULE-28-POLYGLOT-DESER" for f in self._run_rules_on_source("d_ok.rb", "ruby", rb_safe))

    def test_rule_29_polyglot_xxe(self):
        java_vuln = "class X { void p() throws Exception { DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.newDocumentBuilder(); } }\n"
        java_safe = 'class X { void p() throws Exception { DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); } }\n'
        php_vuln = '<?php $doc = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NOENT); ?>\n'
        php_safe = '<?php $doc = simplexml_load_string($xml); ?>\n'

        assert any(f.rule_id == "RULE-29-POLYGLOT-XXE" for f in self._run_rules_on_source("X.java", "java", java_vuln))
        assert not any(f.rule_id == "RULE-29-POLYGLOT-XXE" for f in self._run_rules_on_source("XOk.java", "java", java_safe))
        assert any(f.rule_id == "RULE-29-POLYGLOT-XXE" for f in self._run_rules_on_source("x.php", "php", php_vuln))
        assert not any(f.rule_id == "RULE-29-POLYGLOT-XXE" for f in self._run_rules_on_source("x_ok.php", "php", php_safe))

    def test_rule_30_solidity_reentrancy(self):
        vuln = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""
        safe_cei = """
pragma solidity ^0.8.0;
contract SafeVault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
    }
}
"""
        safe_guard = """
pragma solidity ^0.8.0;
contract GuardedVault {
    mapping(address => uint256) public balances;
    function withdraw() external nonReentrant {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""
        assert any(f.rule_id == "RULE-30-SOLIDITY-REENTRANCY" for f in self._run_rules_on_source("Vault.sol", "solidity", vuln))
        assert not any(f.rule_id == "RULE-30-SOLIDITY-REENTRANCY" for f in self._run_rules_on_source("SafeVault.sol", "solidity", safe_cei))
        assert not any(f.rule_id == "RULE-30-SOLIDITY-REENTRANCY" for f in self._run_rules_on_source("GuardedVault.sol", "solidity", safe_guard))

    def test_rule_31_solidity_tx_origin_delegate(self):
        vuln = """
pragma solidity ^0.8.0;
contract Auth {
    address owner;
    function admin(address target, bytes calldata data) external {
        require(tx.origin == owner);
        target.delegatecall(data);
    }
}
"""
        safe = """
pragma solidity ^0.8.0;
contract SafeAuth {
    address owner;
    function admin() external view returns (bool) {
        require(msg.sender == owner);
        return true;
    }
}
"""
        hits = [f for f in self._run_rules_on_source("Auth.sol", "solidity", vuln) if f.rule_id == "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE"]
        assert len(hits) >= 2
        assert not any(f.rule_id == "RULE-31-SOLIDITY-TX-ORIGIN-DELEGATE" for f in self._run_rules_on_source("SafeAuth.sol", "solidity", safe))

    def test_rule_32_template_unescaped_xss_ssti(self):
        jinja_vuln = "<div>{{ user_bio|safe }}</div>\n"
        blade_vuln = "<div>{!! $comment !!}</div>\n"
        ejs_vuln = "<div><%- payload %></div>\n"
        safe_tpl = "<div>{{ user_bio|e }}</div>\n"

        assert any(f.rule_id == "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI" for f in self._run_rules_on_source("p.jinja2", "web_template", jinja_vuln))
        assert any(f.rule_id == "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI" for f in self._run_rules_on_source("p.blade.php", "web_template", blade_vuln))
        assert any(f.rule_id == "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI" for f in self._run_rules_on_source("p.ejs", "web_template", ejs_vuln))
        assert not any(f.rule_id == "RULE-32-TEMPLATE-UNESCAPED-XSS-SSTI" for f in self._run_rules_on_source("ok.jinja2", "web_template", safe_tpl))

    def test_rule_33_template_missing_csrf(self):
        vuln = '<form action="/transfer" method="POST"><input name="amount"><button>Send</button></form>\n'
        safe_jinja = '<form action="/transfer" method="POST">{{ csrf_token() }}<input name="amount"></form>\n'
        safe_blade = '<form action="/transfer" method="post">@csrf<input name="amount"></form>\n'
        safe_get = '<form action="/search" method="GET"><input name="q"></form>\n'

        assert any(f.rule_id == "RULE-33-TEMPLATE-MISSING-CSRF" and f.severity == "MEDIUM" for f in self._run_rules_on_source("pay.html", "web_template", vuln))
        assert not any(f.rule_id == "RULE-33-TEMPLATE-MISSING-CSRF" for f in self._run_rules_on_source("pay_ok.jinja2", "web_template", safe_jinja))
        assert not any(f.rule_id == "RULE-33-TEMPLATE-MISSING-CSRF" for f in self._run_rules_on_source("pay_ok.blade.php", "web_template", safe_blade))
        assert not any(f.rule_id == "RULE-33-TEMPLATE-MISSING-CSRF" for f in self._run_rules_on_source("search.html", "web_template", safe_get))

    def test_finding_contract_enabled_filter_and_enterprise_enrichment(self):
        from engine.enterprise_manager import EnterpriseManager
        from engine.polyglot_rules import POLYGLOT_RULE_CATALOG
        from models import SecurityQueryRule

        vuln = 'package main\nfunc q(db *DB, id string) { db.Query("SELECT * FROM users WHERE id = " + id) }\n'
        findings_1 = self._run_rules_on_source("svc/repo.go", "go", vuln)
        findings_2 = self._run_rules_on_source("svc/repo.go", "go", vuln)
        assert len(findings_1) == 1
        f = findings_1[0]
        assert f.id == findings_2[0].id
        assert len(f.id) >= 16
        assert f.best_fix_location is not None
        assert f.best_fix_location.filepath == "svc/repo.go"
        assert f.best_fix_location.line >= 1
        assert len(f.path_nodes) >= 1
        assert f.language == "Go"

        filtered = self._run_rules_on_source("svc/repo.go", "go", vuln, enabled_rule_ids={"RULE-30-SOLIDITY-REENTRANCY"})
        assert filtered == []

        em = EnterpriseManager()
        for rmeta in POLYGLOT_RULE_CATALOG:
            if not any(q.id == rmeta["id"] for q in em.queries):
                em.queries.append(
                    SecurityQueryRule(
                        id=rmeta["id"],
                        name=rmeta["name"],
                        engine="SAST",
                        language=", ".join(rmeta["languages"]),
                        severity=rmeta["severity"],
                        cwe_id=rmeta["cwe_id"],
                        owasp_category=rmeta["owasp_category"],
                        cvss_score=rmeta["cvss_score"],
                        description=rmeta["description"],
                        remediation=rmeta["remediation"],
                        enabled=True,
                    )
                )
        enriched = em.enrich_findings(findings_1)
        assert len(enriched) == 1
        assert enriched[0].plain_english_summary
        assert enriched[0].best_fix_location is not None


class TestTask2ReviewHardening:
    """Regression suite for all Task 2 Review Critical, Important, and Minor soundness fixes."""

    def test_arrow_function_and_html_angle_brackets_do_not_bypass_xss(self):
        js_code = b"""
function render(elArrow, elTagConcat, elMapPlusRaw, elMapSafe, items, userInput, userBio) {
  elArrow.innerHTML = items.map(x => x.bio).join("");
  elTagConcat.innerHTML = renderTag("<b>" + userInput);
  elMapPlusRaw.innerHTML = items.map(x => `<li>${esc(x)}</li>`).join("") + userBio;
  elMapSafe.innerHTML = items.map(x => `<li>${esc(x)}</li>`).join("");
}
"""
        sf = _make_scanned_file("ui/bypass1.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        sinks = {
            n.name: n for n in nodes
            if n.label == "Assignment" and n.name.endswith(".innerHTML")
        }
        assert sinks["elArrow.innerHTML"].is_sink is True
        assert sinks["elTagConcat.innerHTML"].is_sink is True
        assert sinks["elMapPlusRaw.innerHTML"].is_sink is True
        assert sinks["elMapSafe.innerHTML"].is_sink is False

    def test_partial_escaping_concat_assignment_does_not_clear_html_sink(self):
        js_code = b"""
function renderPartial(el, a, raw_b) {
  const x = escapeHtml(a) + raw_b;
  el.innerHTML = x;
}
"""
        sf = _make_scanned_file("ui/partial.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        sinks = [n for n in nodes if n.label == "Assignment" and n.name == "el.innerHTML"]
        assert len(sinks) == 1
        assert sinks[0].is_sink is True

    def test_cross_domain_inline_sanitizer_arg_never_clears_outer_sink(self):
        py_code = b"""
import html, os

def run(request):
    raw = request.args["q"]
    os.system(html.escape(raw))
"""
        sf = _make_scanned_file("api/cross_domain.py", py_code, "python")
        nodes, _ = _compile_four_passes([sf])
        os_calls = [n for n in nodes if n.label == "Call" and n.name == "os.system"]
        assert len(os_calls) == 1
        assert os_calls[0].is_sink is True
        assert os_calls[0].sink_domain == "SHELL"
        assert os_calls[0].is_sanitizer is False

        esc_calls = [n for n in nodes if n.label == "Call" and n.name == "html.escape"]
        assert len(esc_calls) == 1
        assert esc_calls[0].is_sanitizer is True
        assert esc_calls[0].sanitizer_domains == ["HTML"]

    def test_logical_and_with_unsanitized_rhs_remains_sink(self):
        js_code = b"""
function renderCond(elBad, elGood, isAdmin, user) {
  const bad = isAdmin && user.bio;
  elBad.innerHTML = bad;
  const good = isAdmin && esc(user.name);
  elGood.innerHTML = good;
}
"""
        sf = _make_scanned_file("ui/logical_and.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        sinks = {
            n.name: n for n in nodes
            if n.label == "Assignment" and n.name.endswith(".innerHTML")
        }
        assert sinks["elBad.innerHTML"].is_sink is True
        assert sinks["elGood.innerHTML"].is_sink is False

    def test_flow_sensitive_helper_early_return_unsanitized_not_registered(self):
        js_code = b"""
function h(u, c) {
  let out = u.bio;
  if (c) return out;
  out = esc(u.name);
  return out;
}
function render(el, u, c) {
  el.innerHTML = h(u, c);
}
"""
        sf = _make_scanned_file("ui/helper_flow.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        sinks = [n for n in nodes if n.label == "Assignment" and n.name == "el.innerHTML"]
        assert len(sinks) == 1
        assert sinks[0].is_sink is True

    def test_multiline_rust_command_new_cmdi_detected_and_safe_ignored(self):
        from engine.polyglot_rules import run_polyglot_rules

        vuln = """
use std::process::Command;
fn run_bad(user_cmd: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(user_cmd)
        .status()
        .unwrap();
}
"""
        safe = """
use std::process::Command;
fn run_good() {
    Command::new("echo")
        .arg("hello")
        .status()
        .unwrap();
}
"""
        sf_v = _make_scanned_file("src/cmd_bad.rs", vuln.encode("utf-8"), "rust")
        nv, ev = _compile_four_passes([sf_v])
        f_v = run_polyglot_rules([sf_v], nv, ev)
        assert any(f.rule_id == "RULE-27-POLYGLOT-CMDI" for f in f_v)

        sf_s = _make_scanned_file("src/cmd_good.rs", safe.encode("utf-8"), "rust")
        ns, es = _compile_four_passes([sf_s])
        f_s = run_polyglot_rules([sf_s], ns, es)
        assert not any(f.rule_id == "RULE-27-POLYGLOT-CMDI" for f in f_s)

    def test_multiline_csharp_binaryformatter_emits_single_finding(self):
        from engine.polyglot_rules import run_polyglot_rules

        cs_code = """
class Deser {
    object Load(Stream stream) {
        BinaryFormatter bf = new BinaryFormatter();
        return bf.Deserialize(stream);
    }
}
"""
        sf = _make_scanned_file("Deser.cs", cs_code.encode("utf-8"), "csharp")
        nodes, edges = _compile_four_passes([sf])
        hits = [
            f for f in run_polyglot_rules([sf], nodes, edges)
            if f.rule_id == "RULE-28-POLYGLOT-DESER"
        ]
        assert len(hits) == 1
        assert hits[0].best_fix_location is not None
        assert hits[0].best_fix_location.line == 5

    def test_rust_lifetimes_do_not_break_comment_stripping(self):
        from engine.polyglot_rules import run_polyglot_rules

        safe_with_odd_lifetime = """
const LABEL: &'static str = "safe";
fn clean() {
    // unsafe { *raw_ptr }
    /* unsafe { std::mem::transmute::<u32, f32>(1) } */
    println!("{}", LABEL);
}
"""
        vuln_after_odd_lifetime = """
const LABEL: &'static str = "demo";
pub fn bad(p: *const u8) -> u8 {
    unsafe { *p }
}
"""
        sf_s = _make_scanned_file("src/lt_ok.rs", safe_with_odd_lifetime.encode("utf-8"), "rust")
        ns, es = _compile_four_passes([sf_s])
        assert not any(
            f.rule_id == "RULE-25-RUST-UNSAFE-FFI"
            for f in run_polyglot_rules([sf_s], ns, es)
        )

        sf_v = _make_scanned_file("src/lt_bad.rs", vuln_after_odd_lifetime.encode("utf-8"), "rust")
        nv, ev = _compile_four_passes([sf_v])
        assert any(
            f.rule_id == "RULE-25-RUST-UNSAFE-FFI"
            for f in run_polyglot_rules([sf_v], nv, ev)
        )

    def test_minor_fixes_zero_width_space_and_c_early_return_free(self):
        from engine.polyglot_rules import POLYGLOT_RULE_CATALOG, run_polyglot_rules

        for r in POLYGLOT_RULE_CATALOG:
            assert "\u200b" not in r["description"]
            assert "\u200b" not in r["remediation"]

        c_safe_branch = """
#include <stdlib.h>
#include <stdio.h>
int process(int err) {
    char *ptr = (char *)malloc(64);
    if (err) {
        free(ptr);
        return -1;
    }
    printf("%s", ptr);
    free(ptr);
    return 0;
}
"""
        sf = _make_scanned_file("src/branch_ok.c", c_safe_branch.encode("utf-8"), "c")
        nodes, edges = _compile_four_passes([sf])
        assert not any(
            f.rule_id == "RULE-24-CPP-UAF-DOUBLE-FREE"
            for f in run_polyglot_rules([sf], nodes, edges)
        )


class TestTask2FixRound2:
    """Regression suite for Fix Round 2 scoped re-review findings."""

    def test_python_if_elif_else_and_fallthrough_helper_not_sanitizer(self):
        from compiler.ast_parser import ASTNormalizer
        from compiler.dfg_builder import DFGBuilder

        py_code = b"""
import html

def h_raw_else(u, a, b):
    if a:
        return html.escape(u)
    elif b:
        return html.escape(u)
    else:
        return u

def h_fallthrough(u, a, b):
    out = u
    if a:
        out = html.escape(u)
    elif b:
        out = html.escape(u)
    return out

def h_all_safe(u, a, b):
    if a:
        return html.escape(u)
    elif b:
        return html.escape(u)
    else:
        return html.escape(u)
"""
        sf = _make_scanned_file("api/branch_helpers.py", py_code, "python")
        norm = ASTNormalizer(sf)
        nodes, _ = norm.parse()
        dfg = DFGBuilder(sf.filepath, sf.content_bytes, sf.language, nodes, norm.node_map, {}, {})
        dfg.build()
        assert "h_raw_else" not in dfg.sanitizer_helpers
        assert "h_fallthrough" not in dfg.sanitizer_helpers
        assert "HTML" in dfg.sanitizer_helpers.get("h_all_safe", set())

    def test_php_single_quoted_strings_not_corrupted_by_comment_stripper(self):
        from engine.polyglot_rules import run_polyglot_rules

        php_vuln = "<?php\n$p = '/*';\nshell_exec($u);\n?>\n"
        php_safe = "<?php\nshell_exec('curl https://example.com');\n?>\n"

        sf_v = _make_scanned_file("cmd_vuln.php", php_vuln.encode("utf-8"), "php")
        nv, ev = _compile_four_passes([sf_v])
        assert any(
            f.rule_id == "RULE-27-POLYGLOT-CMDI"
            for f in run_polyglot_rules([sf_v], nv, ev)
        )

        sf_s = _make_scanned_file("cmd_safe.php", php_safe.encode("utf-8"), "php")
        ns, es = _compile_four_passes([sf_s])
        assert not any(
            f.rule_id == "RULE-27-POLYGLOT-CMDI"
            for f in run_polyglot_rules([sf_s], ns, es)
        )

    def test_comparison_chained_with_logical_and_remains_xss_sink(self):
        js_code = b"""
function render(el, count, user) {
  el.innerHTML = count > 0 && user.bio;
}
"""
        sf = _make_scanned_file("ui/cmp_and.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        sinks = [n for n in nodes if n.label == "Assignment" and n.name == "el.innerHTML"]
        assert len(sinks) == 1
        assert sinks[0].is_sink is True

    def test_augmented_assign_never_upgrades_unsanitized_variable(self):
        js_code = b"""
function renderAccum(elBad, elGood, user, a) {
  let s = user.bio;
  s += esc(a);
  elBad.innerHTML = s;

  let ok = "";
  ok += esc(a);
  elGood.innerHTML = ok;
}
"""
        sf = _make_scanned_file("ui/aug_assign.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        sinks = {
            n.name: n for n in nodes
            if n.label == "Assignment" and n.name.endswith(".innerHTML")
        }
        assert sinks["elBad.innerHTML"].is_sink is True
        assert sinks["elGood.innerHTML"].is_sink is False

    def test_secondary_sink_retains_sink_domain_with_replace_arg(self):
        from compiler.ast_parser import classify_taint_with_domains

        _, is_sink, is_san, sink_domain, _ = classify_taint_with_domains(
            'open(path.replace("\\r", ""))',
            "call",
            'open(path.replace("\\r", ""))',
            language="python",
        )
        assert is_san is False
        assert sink_domain == "PATH"

    def test_swift_and_solidity_if_else_branch_isolation_in_helpers(self):
        from compiler.ast_parser import ASTNormalizer
        from compiler.dfg_builder import DFGBuilder

        swift_code = b"""
func h1(u: String, a: Bool) -> String {
    var out = u
    if a {
        out = escapeHtml(u)
        return out
    } else {
        return out
    }
}

func h2(u: String, a: Bool) -> String {
    if a {
        return u
    } else {
        let x = 1
    }
    return escapeHtml(u)
}
"""
        sf_sw = _make_scanned_file("App/Helper.swift", swift_code, "swift")
        norm_sw = ASTNormalizer(sf_sw)
        ns_sw, _ = norm_sw.parse()
        dfg_sw = DFGBuilder(sf_sw.filepath, sf_sw.content_bytes, "swift", ns_sw, norm_sw.node_map, {}, {})
        dfg_sw.build()
        assert "h1" not in dfg_sw.sanitizer_helpers
        assert "h2" not in dfg_sw.sanitizer_helpers

        sol_code = b"""
pragma solidity ^0.8.0;
contract Helper {
    function clean(string memory x) public pure returns (string memory) {
        return "ok";
    }
    function h(string memory u, bool a) public pure returns (string memory) {
        string memory out = u;
        if (a) {
            out = clean(u);
        } else {
            out = u;
        }
        return out;
    }
}
"""
        sf_sol = _make_scanned_file("contracts/Helper.sol", sol_code, "solidity")
        norm_sol = ASTNormalizer(sf_sol)
        ns_sol, _ = norm_sol.parse()
        dfg_sol = DFGBuilder(sf_sol.filepath, sf_sol.content_bytes, "solidity", ns_sol, norm_sol.node_map, {}, {})
        dfg_sol.build()
        assert "h" not in dfg_sol.sanitizer_helpers

    def test_augmented_assign_does_not_mark_lhs_node_as_sanitizer_when_unsanitized(self):
        js_code = b"""
function f(user, a) {
  let s = user.bio;
  s += esc(a);
  return s;
}
"""
        sf = _make_scanned_file("ui/aug_node.js", js_code, "javascript")
        nodes, _ = _compile_four_passes([sf])
        s_nodes = [n for n in nodes if n.label == "Variable" and n.name == "s" and n.start_line == 4]
        assert len(s_nodes) >= 1
        assert all(n.is_sanitizer is False for n in s_nodes)




