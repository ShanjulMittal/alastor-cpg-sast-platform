"""
Application Tree & Architecture Purpose Analyzer.
Recursively inspects the entire codebase, classifies the purpose and role of every file,
and extracts structural elements (classes, functions, endpoints, dependencies, configs, services).
"""
import ast
import os
import posixpath
import re
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from pydantic import BaseModel, Field

# Directory names to ignore during scanning to prevent bloat
IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".next", "dist", "build", ".pytest_cache", ".idea", ".vscode",
    ".mypy_cache", ".tox", "coverage", ".turbo", "scratch"
}


class DiscoveredElement(BaseModel):
    name: str
    element_type: str       # 'FUNCTION', 'CLASS', 'INTERFACE', 'ROUTE', 'SERVICE', 'DEPENDENCY', 'CONFIG_KEY'
    signature: str = ""     # e.g., 'def scan_project(req: ScanRequest)'
    line_number: int = 1
    details: str = ""


class CrossFileEdge(BaseModel):
    source_filepath: str
    target_filepath: str
    edge_type: str = "IMPORTS"
    symbols: List[str] = Field(default_factory=list)
    flow_label: str = "IMPORTS"


class FilePurposeInfo(BaseModel):
    filepath: str           # Relative path from project root (forward slashes)
    filename: str
    extension: str
    category: str           # e.g., 'API_ROUTER', 'BUSINESS_LOGIC', 'FRONTEND_VIEW', 'INFRASTRUCTURE', etc.
    purpose: str            # Detailed human-readable explanation of role in architecture
    language: str           # 'python', 'typescript', 'javascript', 'yaml', 'json', 'docker', 'css', etc.
    line_count: int
    size_bytes: int
    sha256: str
    elements: List[DiscoveredElement] = Field(default_factory=list)
    is_cpg_supported: bool = False
    security_tags: List[str] = Field(default_factory=list)
    imports_files: List[str] = Field(default_factory=list)


class DirectoryTreeNode(BaseModel):
    name: str
    path: str               # Relative path
    purpose: str = ""
    files: List[FilePurposeInfo] = Field(default_factory=list)
    subdirectories: List["DirectoryTreeNode"] = Field(default_factory=list)


class AppTreeSummary(BaseModel):
    root_path: str
    total_files: int
    total_directories: int
    total_lines: int
    category_counts: Dict[str, int]
    detected_tech_stack: List[str]
    tree: DirectoryTreeNode
    flat_files: List[FilePurposeInfo]
    cross_file_edges: List[CrossFileEdge] = Field(default_factory=list)


class AppTreeAnalyzer:
    """
    Analyzes an entire application directory tree, determining the architectural purpose
    and extracting declared elements from every file.
    """

    def __init__(self, root_dir: str):
        self.raw_target = os.path.abspath(root_dir)
        self.is_single_file = os.path.isfile(self.raw_target)
        self.root_dir = os.path.dirname(self.raw_target) if self.is_single_file else self.raw_target
        self.flat_files: List[FilePurposeInfo] = []
        self.tech_stack: Set[str] = set()
        self.category_counts: Dict[str, int] = {}
        self._file_contents: Dict[str, str] = {}

    def analyze(self) -> AppTreeSummary:
        """Executes full architectural analysis and returns tree summary."""
        if self.is_single_file:
            filename = os.path.basename(self.raw_target)
            parent_name = os.path.basename(self.root_dir) or "SingleFileTarget"
            tree = DirectoryTreeNode(
                name=parent_name,
                path="",
                purpose=f"Single File Target ({filename})"
            )
            file_info = self._analyze_file(self.raw_target, filename.replace("\\", "/"))
            if file_info:
                tree.files.append(file_info)
                self.flat_files.append(file_info)
                cat = file_info.category
                self.category_counts[cat] = self.category_counts.get(cat, 0) + 1
        else:
            tree = self._build_directory_node(self.root_dir, "")
        
        # Sort flat files deterministically
        self.flat_files.sort(key=lambda f: f.filepath)

        # Resolve 360-degree intra-repo cross-file IMPORTS edges
        cross_file_edges = self._resolve_cross_file_imports()

        # Detect high-level tech stack
        detected = sorted(list(self.tech_stack))

        return AppTreeSummary(
            root_path=self.raw_target,
            total_files=len(self.flat_files),
            total_directories=self._count_dirs(tree),
            total_lines=sum(f.line_count for f in self.flat_files),
            category_counts=self.category_counts,
            detected_tech_stack=detected,
            tree=tree,
            flat_files=self.flat_files,
            cross_file_edges=cross_file_edges,
        )

    def _count_dirs(self, node: DirectoryTreeNode) -> int:
        count = 1 if node.path else 0
        for sub in node.subdirectories:
            count += self._count_dirs(sub)
        return count

    def _build_directory_node(self, current_abs: str, current_rel: str) -> DirectoryTreeNode:
        dir_name = os.path.basename(current_abs) if current_rel else os.path.basename(self.root_dir) or "root"
        node = DirectoryTreeNode(
            name=dir_name,
            path=current_rel.replace("\\", "/"),
            purpose=self._classify_directory_purpose(current_rel, dir_name)
        )

        try:
            entries = sorted(os.scandir(current_abs), key=lambda e: (not e.is_dir(), e.name.lower()))
        except Exception:
            return node

        for entry in entries:
            rel_path = os.path.relpath(entry.path, self.root_dir).replace("\\", "/")

            if entry.is_dir():
                is_synth_root = os.path.basename(self.root_dir).lower() == "synthetic_test_target"
                if (
                    entry.name in IGNORE_DIRS
                    or entry.name == "uploaded_scans"
                    or entry.name.startswith(".")
                    or (not is_synth_root and entry.name == "synthetic_test_target")
                ):
                    continue
                sub_node = self._build_directory_node(entry.path, rel_path)
                node.subdirectories.append(sub_node)
            elif entry.is_file():
                if entry.name.startswith("._") or entry.name.lower() in {".ds_store", "thumbs.db", "desktop.ini"}:
                    continue
                file_info = self._analyze_file(entry.path, rel_path)
                if file_info:
                    node.files.append(file_info)
                    self.flat_files.append(file_info)
                    cat = file_info.category
                    self.category_counts[cat] = self.category_counts.get(cat, 0) + 1

        return node

    def _classify_directory_purpose(self, rel_path: str, dir_name: str) -> str:
        p_lower = rel_path.lower()
        if not rel_path:
            return "Application Workspace Root"
        if "backend" in p_lower:
            if "compiler" in p_lower:
                return "CPG Compiler Engine: AST normalization, CFG state machine, DFG builder & call graphs"
            if "database" in p_lower:
                return "Graph Database Persistence Layer: Neo4j client, schema init & Cypher rule hunters"
            return "Backend Server: FastAPI controllers, REST endpoints & data models"
        if "frontend" in p_lower:
            if "components" in p_lower:
                return "Frontend UI Components: Monaco code editor, ReactFlow graph canvas & flaw sidebars"
            if "store" in p_lower:
                return "Client State Management: Zustand stores & bi-directional IDE synchronization"
            if "types" in p_lower:
                return "TypeScript Type Definitions: CPG node/edge contracts & finding schemas"
            return "Next.js Web Application: App Router pages, layout & styling"
        if "synthetic_test_target" in p_lower or "test" in p_lower:
            return "Synthetic Test & Verification Suite: Baseline vulnerable code targets & test scripts"
        if "api" in p_lower or "routes" in p_lower:
            return "REST API Routing & Endpoint Controllers"
        if "docker" in p_lower or "deploy" in p_lower or "k8s" in p_lower:
            return "DevOps & Infrastructure Configurations"
        return f"Directory: {dir_name}"

    def _analyze_file(self, abs_path: str, rel_path: str) -> Optional[FilePurposeInfo]:
        filename = os.path.basename(abs_path)
        ext = os.path.splitext(filename)[1].lower()

        # Skip binary / minified / lock files if desired, or index them as assets
        size = 0
        sha256_hash = ""
        content = ""
        lines: List[str] = []

        try:
            size = os.path.getsize(abs_path)
            # Read first 512KB for textual classification
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(512 * 1024)
            lines = content.splitlines()
            
            # Content SHA-256
            import hashlib
            sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        except Exception:
            return None

        line_count = len(lines) if lines else 1

        # Classify Category and Language
        category, language, is_cpg = self._classify_category_and_language(rel_path, filename, ext, content)
        
        # Identify Purpose
        purpose = self._determine_purpose(rel_path, filename, ext, category, content)

        # Extract Elements
        elements = self._extract_elements(rel_path, filename, ext, category, lines, content)

        # Detect Security Signals / Tags
        security_tags = self._detect_security_tags(filename, ext, content)

        # Update tech stack detection
        self._update_tech_stack(filename, ext, content)

        if ext in (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
            self._file_contents[rel_path] = content

        return FilePurposeInfo(
            filepath=rel_path,
            filename=filename,
            extension=ext,
            category=category,
            purpose=purpose,
            language=language,
            line_count=line_count,
            size_bytes=size,
            sha256=sha256_hash,
            elements=elements,
            is_cpg_supported=is_cpg,
            security_tags=security_tags
        )

    def _classify_category_and_language(self, rel_path: str, filename: str, ext: str, content: str) -> Tuple[str, str, bool]:
        p_lower = rel_path.lower()
        f_lower = filename.lower()

        # Infrastructure / Containers
        if f_lower in ("dockerfile", "docker-compose.yml", "docker-compose.yaml") or f_lower.startswith("dockerfile"):
            return "INFRASTRUCTURE", "docker", False
        if ext in (".tf", ".hcl") or ".github" in p_lower or f_lower.endswith(".k8s.yaml"):
            return "INFRASTRUCTURE", "yaml" if ext in (".yaml", ".yml") else "hcl", False

        # Package Manifests
        if f_lower in ("package.json", "package-lock.json"):
            return "DEPENDENCY_MANIFEST", "json", False
        if f_lower in ("requirements.txt", "pipfile", "pipfile.lock", "pyproject.toml", "setup.py"):
            return "DEPENDENCY_MANIFEST", "python" if ext == ".py" else "text", False
        if f_lower in ("cargo.toml", "go.mod", "pom.xml", "build.gradle"):
            return "DEPENDENCY_MANIFEST", ext[1:], False

        # Configuration & Environment
        if f_lower.startswith(".env") or ext in (".env", ".ini", ".conf", ".cfg"):
            return "CONFIGURATION", "env", False
        if ext in (".toml", ".properties"):
            return "CONFIGURATION", ext[1:], False
        if f_lower in ("tsconfig.json", "next.config.mjs", "next.config.js", "postcss.config.js", "tailwind.config.ts", "tailwind.config.js"):
            return "BUILD_TOOLING", "typescript" if ext == ".ts" else "javascript" if ext in (".js", ".mjs") else "json", False

        # Documentation
        if ext in (".md", ".rst", ".txt", ".adoc") or f_lower.startswith("license"):
            return "DOCUMENTATION", "markdown" if ext == ".md" else "text", False

        # Styling & Design
        if ext in (".css", ".scss", ".sass", ".less"):
            return "STYLING_THEME", "css", False

        # Database Schemas & Migrations
        if ext in (".sql", ".prisma") or "migration" in p_lower:
            return "DATABASE_SCHEMA", "sql", False

        # Test Suites
        if (f_lower.startswith("test_") or f_lower.endswith("_test.py") or f_lower.endswith(".spec.ts")
                or f_lower.endswith(".test.tsx") or "verify_harness" in f_lower):
            lang = "python" if ext == ".py" else "typescript" if ext in (".ts", ".tsx") else "javascript"
            return "TEST_SUITE", lang, ext in (".py", ".js", ".ts", ".tsx")

        # Python Code
        if ext == ".py":
            if "@app." in content or "@router." in content or "fastapi" in content or "blueprint" in content:
                return "API_ROUTER", "python", True
            return "BUSINESS_LOGIC", "python", True

        # TypeScript / JavaScript Code
        if ext in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            c_low = content.lower()
            is_frontend_view = (
                ext in (".tsx", ".jsx")
                or '"use client"' in c_low
                or "'use client'" in c_low
                or 'from "react"' in c_low
                or "from 'react'" in c_low
                or "components" in p_lower
                or f_lower in ("page.tsx", "layout.tsx")
            )
            if is_frontend_view:
                return "FRONTEND_VIEW", "typescript" if "ts" in ext else "javascript", True
            if "router" in p_lower or "api" in p_lower or "export async function get" in c_low:
                return "API_ROUTER", "typescript" if "ts" in ext else "javascript", True
            return "BUSINESS_LOGIC", "typescript" if "ts" in ext else "javascript", True

        # Structured JSON / YAML
        if ext in (".json",):
            return "CONFIGURATION", "json", False
        if ext in (".yaml", ".yml"):
            return "CONFIGURATION", "yaml", False

        return "GENERAL_ASSET", ext[1:] if ext else "text", False

    def _determine_purpose(self, rel_path: str, filename: str, ext: str, category: str, content: str) -> str:
        f_lower = filename.lower()
        p_lower = rel_path.lower()

        # Exact Known High-Impact Files
        if f_lower == "docker-compose.yml":
            return "Multi-container Docker orchestration service defining Neo4j graph database, APOC plugins, network ports, and volumes."
        if f_lower == "package.json":
            return "Node.js application manifest declaring npm dependencies, build scripts (dev, build, lint), and project metadata."
        if f_lower == "requirements.txt":
            return "Python package manifest specifying required dependencies (FastAPI, Neo4j, Tree-sitter, Uvicorn)."
        if f_lower == "verify_harness.py":
            return "Autonomous self-verification test harness asserting end-to-end correctness of compiler, graph database, and Cypher rule hunters."
        if f_lower == "app.py" and "synthetic_test_target" in p_lower:
            return "Synthetic vulnerable target application containing inter-procedural taint flows, dead stores, infinite loops, and dead code."
        if f_lower == "hidden_gadgets.py":
            return "Orphan function gadget repository containing dormant zero-day code blocks disconnected from standard execution paths."
        if f_lower == "main.py":
            return "FastAPI REST API controller providing endpoints for CPG code scanning, graph visualization, finding queries, and health status."
        if f_lower == "models.py":
            return "Strict Pydantic v2 data contracts defining CPGNode, CPGEdge, Finding, and Scan metrics schemas."
        if f_lower == "ast_parser.py":
            return "Tree-sitter AST compiler frontend normalizing syntax trees into deterministic CPGNodes and classifying security taint sources and sinks."
        if f_lower == "cfg_builder.py":
            return "Control Flow Graph (CFG) engine tracking statement sequences, conditional branches (CFG_TRUE/FALSE), and loop back-edges."
        if f_lower == "dfg_builder.py":
            return "Data Flow Graph (DFG) engine computing reaching definitions, symbol tables, and inter-procedural def-use chains."
        if f_lower == "call_graph_builder.py":
            return "Inter-procedural Call Graph resolver linking function invocations across project files and modules."
        if f_lower == "scanner.py":
            return "Recursive filesystem discovery walker computing deterministic SHA-256 hashes and file metadata."
        if f_lower == "neo4j_client.py":
            return "Neo4j Bolt driver singleton managing database connections, APOC verification, schema indexes, and constraints."
        if f_lower == "batch_ingestor.py":
            return "High-throughput graph batch ingestion engine utilizing UNWIND and APOC procedures for fast node and relationship creation."
        if f_lower == "cypher_rules.py":
            return "Deterministic Cypher graph rule hunters identifying taint vulnerabilities, dead stores, infinite loops, and orphan gadgets."
        if f_lower == "page.tsx":
            return "Primary Next.js audit workbench view integrating TopMetricsBar, FlawExplorerSidebar, MonacoCodePane, and ReactFlowGraphPane."
        if f_lower == "layout.tsx":
            return "Root application layout configuring HTML metadata, fonts, and global UI container styling."
        if f_lower == "globals.css":
            return "Global stylesheet defining Tailwind CSS utility directives, dark theme tokens, and custom graph styles."
        if f_lower == "useauditstore.ts":
            return "Zustand reactive state management store coordinating active findings, Monaco editor line highlights, and ReactFlow graph views."
        if f_lower == "monacocodepane.tsx":
            return "Monaco Code Editor pane rendering source files with live vulnerability line decorations and bi-directional graph sync."
        if f_lower == "reactflowgraphpane.tsx":
            return "Interactive ReactFlow CPG graph canvas rendering AST, CFG, DFG, Call Graph, and Application Tree topologies with Dagre auto-layout."
        if f_lower == "flawexplorersidebar.tsx":
            return "Flaw and Application Architecture Explorer sidebar providing interactive navigation through discovered vulnerabilities and codebase files."
        if f_lower == "topmetricsbar.tsx":
            return "Executive metrics and scan controller header displaying graph statistics, vulnerability counters, and scan trigger controls."
        if f_lower == "customgraphnode.tsx":
            return "Custom ReactFlow graph node component rendering CPG node badges, AST labels, and code snippets."
        if f_lower == "tsconfig.json":
            return "TypeScript compiler configuration specifying strict type-checking, module resolution, and path aliases."
        if f_lower == "next.config.mjs":
            return "Next.js framework build configuration tuning bundle compilation and asset optimization."
        if f_lower == "tailwind.config.ts":
            return "Tailwind CSS theme configuration defining color palettes, spacing tokens, and component extensions."

        # Dynamic Generic Purpose Heuristics
        if category == "API_ROUTER":
            return f"API Controller ({filename}): Handles incoming HTTP endpoints, request parameters, and service routing."
        if category == "FRONTEND_VIEW":
            return f"UI View Component ({filename}): Renders user interface elements, layouts, and interactive visual widgets."
        if category == "BUSINESS_LOGIC":
            return f"Core Business Logic ({filename}): Implements processing algorithms, domain models, and application utilities."
        if category == "INFRASTRUCTURE":
            return f"Infrastructure Configuration ({filename}): Configures deployment environments, containers, or CI/CD pipelines."
        if category == "DEPENDENCY_MANIFEST":
            return f"Dependency Manifest ({filename}): Declares required external libraries and runtime package constraints."
        if category == "CONFIGURATION":
            return f"Configuration File ({filename}): Controls runtime application settings, parameters, and environment flags."
        if category == "TEST_SUITE":
            return f"Test Suite ({filename}): Implements automated verification assertions, test targets, or mocks."
        if category == "STYLING_THEME":
            return f"Stylesheet ({filename}): Defines visual styling, typography, and layout formatting."
        if category == "DOCUMENTATION":
            return f"Documentation ({filename}): Provides technical instructions, architectural specifications, or project references."

        return f"Application File: {filename}"

    def _extract_elements(self, rel_path: str, filename: str, ext: str, category: str, lines: List[str], content: str) -> List[DiscoveredElement]:
        elements: List[DiscoveredElement] = []

        # Python element extraction
        if ext == ".py":
            for i, line in enumerate(lines):
                line_str = line.strip()
                # Functions
                if line_str.startswith("def "):
                    match = re.match(r"def\s+([a-zA-Z0-9_]+)\s*\((.*?)\)", line_str)
                    if match:
                        elements.append(DiscoveredElement(
                            name=match.group(1),
                            element_type="FUNCTION",
                            signature=line_str.split(":")[0],
                            line_number=i + 1,
                            details="Function definition"
                        ))
                # Classes
                elif line_str.startswith("class "):
                    match = re.match(r"class\s+([a-zA-Z0-9_]+)", line_str)
                    if match:
                        elements.append(DiscoveredElement(
                            name=match.group(1),
                            element_type="CLASS",
                            signature=line_str.split(":")[0],
                            line_number=i + 1,
                            details="Class definition"
                        ))
                # FastAPI / Flask Routes
                elif line_str.startswith("@app.") or line_str.startswith("@router."):
                    elements.append(DiscoveredElement(
                        name=line_str,
                        element_type="ROUTE",
                        signature=line_str,
                        line_number=i + 1,
                        details="HTTP API Route decorator"
                    ))

        # TypeScript / JavaScript element extraction
        elif ext in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            seen_elem_names: Set[str] = set()
            for i, line in enumerate(lines):
                line_str = line.strip()
                # Functions / Components (including inline function declarations in bundled/minified JS)
                for fn_match in re.finditer(r"(?:export\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]{0,60})\)", line_str):
                    fn_name = fn_match.group(1)
                    fn_args = fn_match.group(2)
                    if fn_name not in seen_elem_names and len(elements) < 50:
                        seen_elem_names.add(fn_name)
                        elements.append(DiscoveredElement(
                            name=fn_name,
                            element_type="FUNCTION",
                            signature=f"function {fn_name}({fn_args})",
                            line_number=i + 1,
                            details="Function or Component"
                        ))
                # Arrow function components
                if re.match(r"^(?:export\s+)?const\s+([A-Z][a-zA-Z0-9_]*)\s*[:=]", line_str):
                    match = re.match(r"^(?:export\s+)?const\s+([A-Z][a-zA-Z0-9_]*)", line_str)
                    if match and match.group(1) not in seen_elem_names:
                        seen_elem_names.add(match.group(1))
                        elements.append(DiscoveredElement(
                            name=match.group(1),
                            element_type="COMPONENT",
                            signature=line_str.split("=")[0].strip()[:80],
                            line_number=i + 1,
                            details="React Functional Component"
                        ))
                # Interfaces / Types
                elif line_str.startswith("export interface ") or line_str.startswith("interface "):
                    match = re.match(r"(?:export\s+)?interface\s+([a-zA-Z0-9_]+)", line_str)
                    if match:
                        elements.append(DiscoveredElement(
                            name=match.group(1),
                            element_type="INTERFACE",
                            signature=line_str.split("{")[0].strip()[:80],
                            line_number=i + 1,
                            details="TypeScript Interface Contract"
                        ))

        # package.json dependencies and scripts extraction
        elif filename == "package.json":
            try:
                pkg = json.loads(content)
                scripts = pkg.get("scripts", {})
                for s_name, cmd in scripts.items():
                    elements.append(DiscoveredElement(
                        name=s_name,
                        element_type="SCRIPT",
                        signature=f"npm run {s_name}: {cmd}",
                        details="NPM Lifecycle Script"
                    ))
                deps = pkg.get("dependencies", {})
                for dep, ver in deps.items():
                    elements.append(DiscoveredElement(
                        name=dep,
                        element_type="DEPENDENCY",
                        signature=f"{dep}@{ver}",
                        details="Runtime Production Dependency"
                    ))
            except Exception:
                pass

        # requirements.txt dependencies extraction
        elif filename == "requirements.txt":
            for i, line in enumerate(lines):
                line_str = line.strip()
                if line_str and not line_str.startswith("#"):
                    elements.append(DiscoveredElement(
                        name=line_str.split("=")[0].split(">")[0].split("<")[0].strip(),
                        element_type="DEPENDENCY",
                        signature=line_str,
                        line_number=i + 1,
                        details="Python PIP Package Dependency"
                    ))

        # docker-compose.yml services extraction
        elif "docker-compose" in filename:
            for i, line in enumerate(lines):
                if re.match(r"^\s{2}[a-zA-Z0-9_\-]+:\s*$", line):
                    svc_name = line.strip().rstrip(":")
                    if svc_name not in ("services", "networks", "volumes", "version"):
                        elements.append(DiscoveredElement(
                            name=svc_name,
                            element_type="SERVICE",
                            signature=f"Service: {svc_name}",
                            line_number=i + 1,
                            details="Containerized Microservice / Daemon"
                        ))

        return elements[:50]  # Cap to first 50 elements per file to prevent UI bloat

    def _detect_security_tags(self, filename: str, ext: str, content: str) -> List[str]:
        tags = []
        c_lower = content.lower()
        if "password" in c_lower and ("cpgsast-password" in content or "admin" in c_lower):
            tags.append("DEFAULT_CREDENTIAL")
        if "os.system" in content or "subprocess." in content:
            tags.append("PROCESS_EXECUTION")
        if re.search(r"(?<![.\w$])(?:eval|exec)\s*\(", content) or re.search(r"\bnew\s+Function\s*\(", content):
            tags.append("DYNAMIC_CODE_EXECUTION")
        if "document.write(" in content or ".innerHTML=" in content or ".innerHTML =" in content:
            tags.append("DOM_XSS_SINK")
        if "while true:" in c_lower or "while(true)" in c_lower:
            tags.append("POTENTIAL_INFINITE_LOOP")
        if filename.startswith(".env"):
            tags.append("ENVIRONMENT_SECRETS")
        return tags

    def _update_tech_stack(self, filename: str, ext: str, content: str):
        c_lower = content.lower()
        if "fastapi" in c_lower:
            self.tech_stack.add("FastAPI")
        if "next.config" in filename or "from 'next" in c_lower or 'from "next' in c_lower:
            self.tech_stack.add("Next.js")
        if ext in (".tsx", ".jsx") or "from 'react'" in c_lower or 'from "react"' in c_lower:
            self.tech_stack.add("React")
        if "neo4j" in c_lower or "bolt://" in c_lower:
            self.tech_stack.add("Neo4j Graph Database")
        if "tree_sitter" in c_lower or "tree-sitter" in c_lower:
            self.tech_stack.add("Tree-sitter Compiler")
        if "docker" in filename.lower() or "dockerfile" in filename.lower():
            self.tech_stack.add("Docker Containerization")
        if "tailwind.config" in filename or "@tailwind" in c_lower:
            self.tech_stack.add("Tailwind CSS")
        if "zustand" in c_lower:
            self.tech_stack.add("Zustand State Store")
        if "monaco" in c_lower:
            self.tech_stack.add("Monaco Code Editor")
        if "reactflow" in c_lower:
            self.tech_stack.add("ReactFlow Visual Graph")
        if "document.cookie" in content or "XMLHttpRequest" in content:
            self.tech_stack.add("Browser DOM / Web API")
        if ext == ".py":
            self.tech_stack.add("Python")
        if ext in (".ts", ".tsx"):
            self.tech_stack.add("TypeScript")
        if ext in (".js", ".jsx", ".mjs"):
            self.tech_stack.add("JavaScript")

    @staticmethod
    def _parse_js_import_symbols(clause: str) -> List[str]:
        """Extracts imported symbol identifiers from a JS/TS import/export/require binding clause."""
        syms: List[str] = []
        for brace_m in re.finditer(r"\{([^}]*)\}", clause):
            for tok in brace_m.group(1).split(","):
                cleaned = re.sub(r"^\s*type\s+", "", tok.strip())
                orig_sym = re.split(r"\s+(?:as|:)\s+", cleaned)[0].strip()
                if orig_sym and re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", orig_sym):
                    syms.append(orig_sym)

        rem = re.sub(r"\{[^}]*\}", " ", clause)
        for ns_m in re.finditer(r"\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)", rem):
            syms.append(ns_m.group(1))

        rem_plain = re.sub(r"\*\s+as\s+[A-Za-z_$][A-Za-z0-9_$]*", " ", rem)
        for part in rem_plain.split(","):
            p_clean = re.sub(r"^\s*type\s+", "", part.strip())
            if p_clean and p_clean != "*" and re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", p_clean):
                syms.append(p_clean)
        return syms

    def _resolve_cross_file_imports(self) -> List[CrossFileEdge]:
        """
        Resolves intra-repository imports across Python and JS/TS files against `self.flat_files`,
        populating `FilePurposeInfo.imports_files` and deduplicated `CrossFileEdge` records.
        """
        if not self.flat_files:
            return []

        exact_map: Dict[str, str] = {f.filepath: f.filepath for f in self.flat_files}
        lower_map: Dict[str, str] = {f.filepath.lower(): f.filepath for f in self.flat_files}

        def _match_known(cand: str) -> Optional[str]:
            if not cand:
                return None
            norm = posixpath.normpath(cand.replace("\\", "/")).lstrip("/")
            if not norm or norm == "." or norm.startswith(".."):
                return None
            if norm in exact_map:
                return exact_map[norm]
            return lower_map.get(norm.lower())

        def _probe_js_target(base_cand: str) -> Optional[str]:
            direct = _match_known(base_cand)
            if direct:
                return direct
            for ext_cand in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json"):
                hit = _match_known(f"{base_cand}{ext_cand}")
                if hit:
                    return hit
            if base_cand.endswith(".js"):
                for ts_ext in (".ts", ".tsx"):
                    hit = _match_known(base_cand[:-3] + ts_ext)
                    if hit:
                        return hit
            for idx_sfx in ("/index.ts", "/index.tsx", "/index.js", "/index.jsx", "/index.mjs"):
                hit = _match_known(f"{base_cand}{idx_sfx}")
                if hit:
                    return hit
            return None

        def _resolve_js_specifier(source_fp: str, raw_spec: str) -> Optional[str]:
            spec = raw_spec.strip().split("?", 1)[0].split("#", 1)[0]
            if not spec or spec.startswith(("http://", "https://", "data:", "node:")):
                return None
            src_dir = posixpath.dirname(source_fp)
            candidates: List[str] = []
            if spec.startswith(("./", "../")) or spec in (".", ".."):
                joined = posixpath.normpath(posixpath.join(src_dir, spec)) if src_dir else posixpath.normpath(spec)
                if not joined.startswith(".."):
                    candidates.append(joined)
            elif spec.startswith(("@/", "~/")):
                tail = spec[2:].lstrip("/")
                parts = source_fp.split("/")
                if "src" in parts[:-1]:
                    src_idx = parts.index("src")
                    enclosing_src = "/".join(parts[: src_idx + 1])
                    candidates.append(f"{enclosing_src}/{tail}")
                candidates.extend([f"src/{tail}", f"frontend/src/{tail}", tail, f"frontend/{tail}"])
            elif not spec.startswith("@"):
                candidates.extend([spec, f"src/{spec}", f"frontend/src/{spec}"])
                if src_dir:
                    candidates.append(f"{src_dir}/{spec}")

            for cand in candidates:
                resolved = _probe_js_target(cand)
                if resolved and resolved != source_fp:
                    return resolved
            return None

        def _probe_py_module(source_fp: str, base_dir: str, mod_rel: str) -> Optional[str]:
            prefix = f"{base_dir}/{mod_rel}" if base_dir else mod_rel
            for py_cand in (f"{prefix}.py", f"{prefix}/__init__.py"):
                hit = _match_known(py_cand)
                if hit and hit != source_fp:
                    return hit
            return None

        def _extract_py_file_imports(source_fp: str, src_text: str) -> List[Tuple[str, List[str]]]:
            found: List[Tuple[str, List[str]]] = []
            src_dir = posixpath.dirname(source_fp)
            abs_bases: List[str] = []
            cur_dir = src_dir
            while cur_dir:
                abs_bases.append(cur_dir)
                cur_dir = posixpath.dirname(cur_dir)
            abs_bases.append("")
            for extra_root in ("src", "backend"):
                if extra_root not in abs_bases:
                    abs_bases.append(extra_root)

            try:
                tree = ast.parse(src_text)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            mod_rel = alias.name.replace(".", "/")
                            for b_dir in abs_bases:
                                hit = _probe_py_module(source_fp, b_dir, mod_rel)
                                if hit:
                                    sym_lbl = alias.asname or alias.name.split(".")[-1]
                                    found.append((hit, [sym_lbl] if sym_lbl else []))
                                    break
                    elif isinstance(node, ast.ImportFrom):
                        alias_names = [a.name for a in node.names if a.name and a.name != "*"]
                        if node.level and node.level > 0:
                            src_parts = [p for p in src_dir.split("/") if p]
                            up_levels = node.level - 1
                            if up_levels <= len(src_parts):
                                rel_base = "/".join(src_parts[: len(src_parts) - up_levels])
                                mod_rel = (node.module or "").replace(".", "/")
                                unmatched: List[str] = []
                                for sym_name in alias_names:
                                    sub_mod = f"{mod_rel}/{sym_name}" if mod_rel else sym_name
                                    sub_hit = _probe_py_module(source_fp, rel_base, sub_mod)
                                    if sub_hit:
                                        found.append((sub_hit, [sym_name]))
                                    else:
                                        unmatched.append(sym_name)
                                if mod_rel and (unmatched or not alias_names):
                                    mod_hit = _probe_py_module(source_fp, rel_base, mod_rel)
                                    if mod_hit:
                                        found.append((mod_hit, unmatched))
                        else:
                            mod_rel = (node.module or "").replace(".", "/")
                            if mod_rel:
                                resolved_sub = False
                                unmatched = []
                                for sym_name in alias_names:
                                    sub_hit_any: Optional[str] = None
                                    for b_dir in abs_bases:
                                        sub_hit_any = _probe_py_module(source_fp, b_dir, f"{mod_rel}/{sym_name}")
                                        if sub_hit_any:
                                            break
                                    if sub_hit_any:
                                        resolved_sub = True
                                        found.append((sub_hit_any, [sym_name]))
                                    else:
                                        unmatched.append(sym_name)
                                if unmatched or not resolved_sub:
                                    for b_dir in abs_bases:
                                        mod_hit = _probe_py_module(source_fp, b_dir, mod_rel)
                                        if mod_hit:
                                            found.append((mod_hit, unmatched))
                                            break
            except SyntaxError:
                for line in src_text.splitlines():
                    s_line = line.strip()
                    from_m = re.match(r"^from\s+(\.*[A-Za-z0-9_.]+)\s+import\s+(.+)$", s_line)
                    if from_m:
                        raw_mod, raw_syms = from_m.group(1), from_m.group(2)
                        syms = [t.strip().split(" as ")[0].strip() for t in raw_syms.split(",") if t.strip()]
                        clean_mod = raw_mod.lstrip(".").replace(".", "/")
                        if clean_mod:
                            for b_dir in abs_bases:
                                hit = _probe_py_module(source_fp, b_dir, clean_mod)
                                if hit:
                                    found.append((hit, syms))
                                    break
                        continue
                    imp_m = re.match(r"^import\s+([A-Za-z0-9_.,\s]+)$", s_line)
                    if imp_m:
                        for part in imp_m.group(1).split(","):
                            mod_tok = part.strip().split(" as ")[0].strip()
                            if mod_tok:
                                for b_dir in abs_bases:
                                    hit = _probe_py_module(source_fp, b_dir, mod_tok.replace(".", "/"))
                                    if hit:
                                        found.append((hit, [mod_tok.split(".")[-1]]))
                                        break
            return found

        edge_accum: Dict[Tuple[str, str], Set[str]] = {}

        for file_info in self.flat_files:
            src_fp = file_info.filepath
            content = self._file_contents.get(src_fp, "")
            if not content:
                continue

            file_targets: Set[str] = set()
            if file_info.extension == ".py":
                for tgt_fp, syms in _extract_py_file_imports(src_fp, content):
                    file_targets.add(tgt_fp)
                    bucket = edge_accum.setdefault((src_fp, tgt_fp), set())
                    bucket.update(s for s in syms if s)
            elif file_info.extension in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
                for m_from in re.finditer(
                    r"""\b(?:import|export)\s+(?:type\s+)?([^;'"`]+?)\s+from\s*['"]([^'"]+)['"]""",
                    content,
                ):
                    clause, spec = m_from.group(1), m_from.group(2)
                    tgt_fp = _resolve_js_specifier(src_fp, spec)
                    if tgt_fp:
                        file_targets.add(tgt_fp)
                        bucket = edge_accum.setdefault((src_fp, tgt_fp), set())
                        bucket.update(self._parse_js_import_symbols(clause))

                for m_side in re.finditer(r"""\bimport\s*['"]([^'"]+)['"]""", content):
                    tgt_fp = _resolve_js_specifier(src_fp, m_side.group(1))
                    if tgt_fp:
                        file_targets.add(tgt_fp)
                        edge_accum.setdefault((src_fp, tgt_fp), set())

                for m_req_bind in re.finditer(
                    r"""(?:const|let|var)\s+(\{[^}]+\}|[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
                    content,
                ):
                    lhs_clause, spec = m_req_bind.group(1), m_req_bind.group(2)
                    tgt_fp = _resolve_js_specifier(src_fp, spec)
                    if tgt_fp:
                        file_targets.add(tgt_fp)
                        bucket = edge_accum.setdefault((src_fp, tgt_fp), set())
                        bucket.update(self._parse_js_import_symbols(lhs_clause))

                for m_req_bare in re.finditer(
                    r"""\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)""",
                    content,
                ):
                    tgt_fp = _resolve_js_specifier(src_fp, m_req_bare.group(1))
                    if tgt_fp:
                        file_targets.add(tgt_fp)
                        edge_accum.setdefault((src_fp, tgt_fp), set())

            file_info.imports_files = sorted(file_targets)

        edges: List[CrossFileEdge] = []
        for (src_fp, tgt_fp), sym_set in sorted(edge_accum.items()):
            sorted_syms = sorted(sym_set)
            lbl = f"IMPORTS ({', '.join(sorted_syms[:3])}) ▶" if sorted_syms else "IMPORTS ▶"
            edges.append(
                CrossFileEdge(
                    source_filepath=src_fp,
                    target_filepath=tgt_fp,
                    edge_type="IMPORTS",
                    symbols=sorted_syms,
                    flow_label=lbl,
                )
            )
        return edges
