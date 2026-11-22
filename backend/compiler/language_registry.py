"""
Declarative 18-Language Tree-sitter Registry for ALASTOR v5.0 Polyglot CPG Compiler.

Decouples grammar loading, extension/compound-suffix resolution, AST syntax categories,
and domain-scoped taint metadata (sources, sinks, sanitizers) from compiler passes.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import tree_sitter

from models import LanguageCapabilitiesResponse, LanguageCapabilityItem


@dataclass(frozen=True)
class LanguageSpec:
    """Immutable declarative specification for a single language family."""

    key: str
    display_name: str
    grammar_name: str
    extensions: Tuple[str, ...]
    module_node_types: Tuple[str, ...]
    class_node_types: Tuple[str, ...]
    function_node_types: Tuple[str, ...]
    parameter_node_types: Tuple[str, ...]
    assignment_node_types: Tuple[str, ...]
    call_node_types: Tuple[str, ...]
    control_node_types: Tuple[str, ...]
    loop_node_types: Tuple[str, ...]
    return_node_types: Tuple[str, ...]
    identifier_node_types: Tuple[str, ...]
    literal_node_types: Tuple[str, ...]
    import_node_types: Tuple[str, ...]
    skip_node_types: Tuple[str, ...]
    source_patterns: Tuple[str, ...]
    sink_patterns: Tuple[Tuple[str, str], ...]
    sanitizer_patterns: Tuple[Tuple[str, Tuple[str, ...]], ...]
    rule_pack_count: int = 1
    supports_taint: bool = True

    @property
    def sink_domain_map(self) -> Dict[str, str]:
        return dict(self.sink_patterns)

    @property
    def sanitizer_domain_map(self) -> Dict[str, Tuple[str, ...]]:
        return dict(self.sanitizer_patterns)


_JS_SHARED_CLASS_TYPES = ("class_declaration", "class", "abstract_class_declaration")
_JS_SHARED_FUNC_TYPES = (
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
)
_JS_SHARED_PARAM_TYPES = (
    "formal_parameters",
    "required_parameter",
    "optional_parameter",
    "rest_pattern",
    "assignment_pattern",
)
_JS_SHARED_ASSIGN_TYPES = (
    "assignment_expression",
    "augmented_assignment_expression",
    "variable_declarator",
)
_JS_SHARED_CONTROL_TYPES = (
    "if_statement",
    "else_clause",
    "switch_statement",
    "switch_case",
    "try_statement",
    "catch_clause",
)
_JS_SHARED_LOOP_TYPES = (
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
)
_JS_SHARED_LITERAL_TYPES = (
    "string",
    "template_string",
    "number",
    "true",
    "false",
    "null",
    "undefined",
)
_JS_SHARED_SKIP_TYPES = (
    "comment",
    "interface_declaration",
    "type_alias_declaration",
    "type_annotation",
    "type_arguments",
    "type_parameters",
    "jsx_text",
    "jsx_closing_element",
    "string_fragment",
    "escape_sequence",
)
_JS_SHARED_SOURCES = (
    "req.query",
    "req.body",
    "req.params",
    "req.cookies",
    "req.headers",
    "request.nextUrl.searchParams",
    "window.location",
    "document.location",
    "process.argv",
)
_JS_SHARED_SINKS: Tuple[Tuple[str, str], ...] = (
    ("eval", "CODE"),
    ("Function", "CODE"),
    ("child_process.exec", "SHELL"),
    ("child_process.execSync", "SHELL"),
    ("child_process.spawn", "SHELL"),
    (".innerHTML", "HTML"),
    (".outerHTML", "HTML"),
    ("dangerouslySetInnerHTML", "HTML"),
    ("document.write", "HTML"),
    ("document.writeln", "HTML"),
    ("db.query", "SQL"),
    ("pool.query", "SQL"),
    ("sequelize.query", "SQL"),
    ("fetch", "URL"),
    ("axios.get", "URL"),
    ("axios.post", "URL"),
    ("fs.readFile", "PATH"),
    ("fs.readFileSync", "PATH"),
)
_JS_SHARED_SANITIZERS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("DOMPurify.sanitize", ("HTML",)),
    ("escapeHtml", ("HTML",)),
    ("esc", ("HTML",)),
    ("encodeURIComponent", ("URL",)),
    ("encodeURI", ("URL",)),
    ("path.basename", ("PATH",)),
    ("Number", ("UNIVERSAL",)),
    ("parseInt", ("UNIVERSAL",)),
    ("parseFloat", ("UNIVERSAL",)),
    ("Boolean", ("UNIVERSAL",)),
)


LANGUAGE_SPECS: Dict[str, LanguageSpec] = {
    "python": LanguageSpec(
        key="python",
        display_name="Python",
        grammar_name="python",
        extensions=(".py", ".pyw", ".pyi"),
        module_node_types=("module",),
        class_node_types=("class_definition",),
        function_node_types=("function_definition", "lambda"),
        parameter_node_types=(
            "parameters",
            "typed_parameter",
            "default_parameter",
            "typed_default_parameter",
            "list_splat_pattern",
            "dictionary_splat_pattern",
        ),
        assignment_node_types=("assignment", "augmented_assignment", "named_expression"),
        call_node_types=("call",),
        control_node_types=("if_statement", "elif_clause", "else_clause", "match_statement", "try_statement"),
        loop_node_types=("for_statement", "while_statement"),
        return_node_types=("return_statement", "yield"),
        identifier_node_types=("identifier",),
        literal_node_types=("string", "integer", "float", "true", "false", "none"),
        import_node_types=("import_statement", "import_from_statement"),
        skip_node_types=("comment", "string_content", "string_start", "string_end", "escape_sequence"),
        source_patterns=(
            "request.args",
            "request.form",
            "request.json",
            "request.values",
            "request.cookies",
            "request.GET",
            "request.POST",
            "sys.argv",
            "input",
            "fastapi.Query",
            "fastapi.Body",
        ),
        sink_patterns=(
            ("cursor.execute", "SQL"),
            ("session.execute", "SQL"),
            ("os.system", "SHELL"),
            ("os.popen", "SHELL"),
            ("subprocess.Popen", "SHELL"),
            ("subprocess.run", "SHELL"),
            ("subprocess.call", "SHELL"),
            ("subprocess.check_output", "SHELL"),
            ("eval", "CODE"),
            ("exec", "CODE"),
            ("pickle.loads", "DESER"),
            ("yaml.load", "DESER"),
            ("render_template_string", "HTML"),
            ("open", "PATH"),
            ("requests.get", "URL"),
            ("urllib.request.urlopen", "URL"),
        ),
        sanitizer_patterns=(
            ("int", ("UNIVERSAL",)),
            ("float", ("UNIVERSAL",)),
            ("bool", ("UNIVERSAL",)),
            ("shlex.quote", ("SHELL",)),
            ("html.escape", ("HTML",)),
            ("bleach.clean", ("HTML",)),
            ("urllib.parse.quote", ("URL",)),
            ("os.path.commonpath", ("PATH",)),
            ("os.path.basename", ("PATH",)),
            ("secure_filename", ("PATH",)),
            ("yaml.safe_load", ("DESER",)),
            ("ast.literal_eval", ("CODE",)),
            ("defusedxml.ElementTree.fromstring", ("XML",)),
        ),
        rule_pack_count=21,
        supports_taint=True,
    ),
    "javascript": LanguageSpec(
        key="javascript",
        display_name="JavaScript",
        grammar_name="javascript",
        extensions=(".js", ".jsx", ".mjs", ".cjs"),
        module_node_types=("program",),
        class_node_types=_JS_SHARED_CLASS_TYPES,
        function_node_types=_JS_SHARED_FUNC_TYPES,
        parameter_node_types=_JS_SHARED_PARAM_TYPES,
        assignment_node_types=_JS_SHARED_ASSIGN_TYPES,
        call_node_types=("call_expression", "new_expression"),
        control_node_types=_JS_SHARED_CONTROL_TYPES,
        loop_node_types=_JS_SHARED_LOOP_TYPES,
        return_node_types=("return_statement",),
        identifier_node_types=("identifier", "property_identifier", "shorthand_property_identifier"),
        literal_node_types=_JS_SHARED_LITERAL_TYPES,
        import_node_types=("import_statement",),
        skip_node_types=_JS_SHARED_SKIP_TYPES,
        source_patterns=_JS_SHARED_SOURCES,
        sink_patterns=_JS_SHARED_SINKS,
        sanitizer_patterns=_JS_SHARED_SANITIZERS,
        rule_pack_count=16,
        supports_taint=True,
    ),
    "typescript": LanguageSpec(
        key="typescript",
        display_name="TypeScript",
        grammar_name="typescript",
        extensions=(".ts", ".mts", ".cts"),
        module_node_types=("program",),
        class_node_types=_JS_SHARED_CLASS_TYPES,
        function_node_types=_JS_SHARED_FUNC_TYPES,
        parameter_node_types=_JS_SHARED_PARAM_TYPES,
        assignment_node_types=_JS_SHARED_ASSIGN_TYPES,
        call_node_types=("call_expression", "new_expression"),
        control_node_types=_JS_SHARED_CONTROL_TYPES,
        loop_node_types=_JS_SHARED_LOOP_TYPES,
        return_node_types=("return_statement",),
        identifier_node_types=("identifier", "property_identifier", "shorthand_property_identifier"),
        literal_node_types=_JS_SHARED_LITERAL_TYPES,
        import_node_types=("import_statement",),
        skip_node_types=_JS_SHARED_SKIP_TYPES,
        source_patterns=_JS_SHARED_SOURCES,
        sink_patterns=_JS_SHARED_SINKS,
        sanitizer_patterns=_JS_SHARED_SANITIZERS,
        rule_pack_count=16,
        supports_taint=True,
    ),
    "tsx": LanguageSpec(
        key="tsx",
        display_name="TypeScript JSX (TSX)",
        grammar_name="tsx",
        extensions=(".tsx",),
        module_node_types=("program",),
        class_node_types=_JS_SHARED_CLASS_TYPES,
        function_node_types=_JS_SHARED_FUNC_TYPES,
        parameter_node_types=_JS_SHARED_PARAM_TYPES,
        assignment_node_types=_JS_SHARED_ASSIGN_TYPES,
        call_node_types=("call_expression", "new_expression"),
        control_node_types=_JS_SHARED_CONTROL_TYPES,
        loop_node_types=_JS_SHARED_LOOP_TYPES,
        return_node_types=("return_statement",),
        identifier_node_types=("identifier", "property_identifier", "shorthand_property_identifier"),
        literal_node_types=_JS_SHARED_LITERAL_TYPES,
        import_node_types=("import_statement",),
        skip_node_types=_JS_SHARED_SKIP_TYPES,
        source_patterns=_JS_SHARED_SOURCES,
        sink_patterns=_JS_SHARED_SINKS,
        sanitizer_patterns=_JS_SHARED_SANITIZERS,
        rule_pack_count=16,
        supports_taint=True,
    ),
    "go": LanguageSpec(
        key="go",
        display_name="Go",
        grammar_name="go",
        extensions=(".go",),
        module_node_types=("source_file",),
        class_node_types=("type_declaration", "struct_type", "interface_type"),
        function_node_types=("function_declaration", "method_declaration", "func_literal"),
        parameter_node_types=("parameter_list", "parameter_declaration", "variadic_parameter_declaration"),
        assignment_node_types=("assignment_statement", "short_var_declaration", "var_spec"),
        call_node_types=("call_expression",),
        control_node_types=("if_statement", "expression_switch_statement", "type_switch_statement", "select_statement"),
        loop_node_types=("for_statement",),
        return_node_types=("return_statement",),
        identifier_node_types=("identifier", "field_identifier"),
        literal_node_types=(
            "interpreted_string_literal",
            "raw_string_literal",
            "int_literal",
            "float_literal",
            "true",
            "false",
            "nil",
        ),
        import_node_types=("import_declaration", "import_spec"),
        skip_node_types=("comment", "package_clause"),
        source_patterns=(
            "r.URL.Query",
            "r.FormValue",
            "r.PostFormValue",
            "c.Query",
            "c.Param",
            "os.Args",
            "http.Request",
        ),
        sink_patterns=(
            ("db.Query", "SQL"),
            ("db.Exec", "SQL"),
            ("db.QueryRow", "SQL"),
            ("exec.Command", "SHELL"),
            ("exec.CommandContext", "SHELL"),
            ("os.Open", "PATH"),
            ("os.ReadFile", "PATH"),
            ("http.Get", "URL"),
            ("http.Post", "URL"),
            ("template.HTML", "HTML"),
        ),
        sanitizer_patterns=(
            ("strconv.Atoi", ("UNIVERSAL",)),
            ("strconv.ParseInt", ("UNIVERSAL",)),
            ("strconv.ParseUint", ("UNIVERSAL",)),
            ("filepath.Clean", ("PATH",)),
            ("filepath.Base", ("PATH",)),
            ("html.EscapeString", ("HTML",)),
            ("url.QueryEscape", ("URL",)),
        ),
        rule_pack_count=4,
        supports_taint=True,
    ),
    "java": LanguageSpec(
        key="java",
        display_name="Java",
        grammar_name="java",
        extensions=(".java",),
        module_node_types=("program",),
        class_node_types=("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"),
        function_node_types=("method_declaration", "constructor_declaration", "lambda_expression"),
        parameter_node_types=("formal_parameters", "formal_parameter", "spread_parameter"),
        assignment_node_types=("assignment_expression", "variable_declarator"),
        call_node_types=("method_invocation", "object_creation_expression"),
        control_node_types=("if_statement", "switch_expression", "try_statement", "catch_clause"),
        loop_node_types=("for_statement", "enhanced_for_statement", "while_statement", "do_statement"),
        return_node_types=("return_statement",),
        identifier_node_types=("identifier",),
        literal_node_types=(
            "string_literal",
            "decimal_integer_literal",
            "decimal_floating_point_literal",
            "true",
            "false",
            "null_literal",
        ),
        import_node_types=("import_declaration",),
        skip_node_types=("line_comment", "block_comment", "package_declaration"),
        source_patterns=(
            "@RequestParam",
            "@PathVariable",
            "@RequestBody",
            "request.getParameter",
            "HttpServletRequest",
        ),
        sink_patterns=(
            ("executeQuery", "SQL"),
            ("executeUpdate", "SQL"),
            ("Runtime.getRuntime().exec", "SHELL"),
            ("ProcessBuilder", "SHELL"),
            ("ObjectInputStream.readObject", "DESER"),
            ("readObject", "DESER"),
            ("DocumentBuilderFactory", "XML"),
            ("SAXParserFactory", "XML"),
            ("Files.readString", "PATH"),
            ("new File", "PATH"),
        ),
        sanitizer_patterns=(
            ("PreparedStatement", ("SQL",)),
            ("Integer.parseInt", ("UNIVERSAL",)),
            ("Long.parseLong", ("UNIVERSAL",)),
            ("HtmlUtils.htmlEscape", ("HTML",)),
            ("ESAPI.encoder", ("HTML",)),
            ("normalize", ("PATH",)),
        ),
        rule_pack_count=5,
        supports_taint=True,
    ),
    "kotlin": LanguageSpec(
        key="kotlin",
        display_name="Kotlin",
        grammar_name="kotlin",
        extensions=(".kt", ".kts"),
        module_node_types=("source_file",),
        class_node_types=("class_declaration", "object_declaration"),
        function_node_types=("function_declaration", "lambda_literal", "anonymous_function"),
        parameter_node_types=("function_value_parameters", "parameter"),
        assignment_node_types=("assignment", "property_declaration", "variable_declaration"),
        call_node_types=("call_expression",),
        control_node_types=("if_expression", "when_expression", "try_expression"),
        loop_node_types=("for_statement", "while_statement", "do_while_statement"),
        return_node_types=("jump_expression",),
        identifier_node_types=("simple_identifier", "identifier"),
        literal_node_types=("line_string_literal", "integer_literal", "boolean_literal", "null_literal"),
        import_node_types=("import_header",),
        skip_node_types=("line_comment", "multiline_comment", "package_header"),
        source_patterns=(
            "@RequestParam",
            "@PathVariable",
            "@RequestBody",
            "call.parameters",
            "request.getParameter",
        ),
        sink_patterns=(
            ("executeQuery", "SQL"),
            ("executeUpdate", "SQL"),
            ("Runtime.getRuntime().exec", "SHELL"),
            ("ProcessBuilder", "SHELL"),
            ("ObjectInputStream.readObject", "DESER"),
            ("DocumentBuilderFactory", "XML"),
        ),
        sanitizer_patterns=(
            ("PreparedStatement", ("SQL",)),
            ("toInt", ("UNIVERSAL",)),
            ("toLong", ("UNIVERSAL",)),
            ("HtmlUtils.htmlEscape", ("HTML",)),
        ),
        rule_pack_count=5,
        supports_taint=True,
    ),
    "csharp": LanguageSpec(
        key="csharp",
        display_name="C#",
        grammar_name="csharp",
        extensions=(".cs", ".csx"),
        module_node_types=("compilation_unit",),
        class_node_types=("class_declaration", "struct_declaration", "record_declaration", "interface_declaration"),
        function_node_types=("method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression"),
        parameter_node_types=("parameter_list", "parameter"),
        assignment_node_types=("assignment_expression", "variable_declarator"),
        call_node_types=("invocation_expression", "object_creation_expression"),
        control_node_types=("if_statement", "switch_statement", "try_statement", "catch_clause"),
        loop_node_types=("for_statement", "foreach_statement", "while_statement", "do_statement"),
        return_node_types=("return_statement",),
        identifier_node_types=("identifier",),
        literal_node_types=("string_literal", "interpolated_string_expression", "integer_literal", "boolean_literal", "null_literal"),
        import_node_types=("using_directive",),
        skip_node_types=("comment",),
        source_patterns=(
            "[FromQuery]",
            "[FromBody]",
            "[FromRoute]",
            "Request.Query",
            "Request.Form",
            "HttpContext.Request",
        ),
        sink_patterns=(
            ("SqlCommand", "SQL"),
            ("ExecuteReader", "SQL"),
            ("ExecuteNonQuery", "SQL"),
            ("Process.Start", "SHELL"),
            ("BinaryFormatter.Deserialize", "DESER"),
            ("XmlDocument.Load", "XML"),
            ("File.ReadAllText", "PATH"),
        ),
        sanitizer_patterns=(
            ("SqlParameter", ("SQL",)),
            ("int.TryParse", ("UNIVERSAL",)),
            ("int.Parse", ("UNIVERSAL",)),
            ("HtmlEncoder.Default.Encode", ("HTML",)),
            ("Path.GetFileName", ("PATH",)),
        ),
        rule_pack_count=5,
        supports_taint=True,
    ),
    "scala": LanguageSpec(
        key="scala",
        display_name="Scala",
        grammar_name="scala",
        extensions=(".scala", ".sc", ".sbt"),
        module_node_types=("compilation_unit",),
        class_node_types=("class_definition", "object_definition", "trait_definition"),
        function_node_types=("function_definition", "lambda_expression"),
        parameter_node_types=("parameters", "parameter"),
        assignment_node_types=("val_definition", "var_definition", "assignment_expression"),
        call_node_types=("call_expression",),
        control_node_types=("if_expression", "match_expression", "try_expression"),
        loop_node_types=("for_expression", "while_expression"),
        return_node_types=("return_expression",),
        identifier_node_types=("identifier",),
        literal_node_types=("string", "interpolated_string_expression", "integer_literal", "boolean_literal", "null_literal"),
        import_node_types=("import_declaration",),
        skip_node_types=("comment", "block_comment", "package_clause"),
        source_patterns=(
            "request.queryString",
            "request.body",
            "parameter(",
            "params(",
        ),
        sink_patterns=(
            ("SQL(", "SQL"),
            ("executeQuery", "SQL"),
            ("Process(", "SHELL"),
            ("Runtime.getRuntime.exec", "SHELL"),
            ("ObjectInputStream", "DESER"),
        ),
        sanitizer_patterns=(
            ("toInt", ("UNIVERSAL",)),
            ("toLong", ("UNIVERSAL",)),
            ("PreparedStatement", ("SQL",)),
        ),
        rule_pack_count=4,
        supports_taint=True,
    ),
    "c": LanguageSpec(
        key="c",
        display_name="C",
        grammar_name="c",
        extensions=(".c", ".h"),
        module_node_types=("translation_unit",),
        class_node_types=("struct_specifier", "union_specifier", "enum_specifier"),
        function_node_types=("function_definition",),
        parameter_node_types=("parameter_list", "parameter_declaration"),
        assignment_node_types=("assignment_expression", "init_declarator"),
        call_node_types=("call_expression",),
        control_node_types=("if_statement", "switch_statement", "case_statement"),
        loop_node_types=("for_statement", "while_statement", "do_statement"),
        return_node_types=("return_statement",),
        identifier_node_types=("identifier", "field_identifier"),
        literal_node_types=("string_literal", "number_literal", "char_literal", "true", "false", "null"),
        import_node_types=("preproc_include",),
        skip_node_types=("comment",),
        source_patterns=(
            "argv",
            "getenv",
            "scanf",
            "gets",
            "fgets",
            "recv",
            "read",
        ),
        sink_patterns=(
            ("strcpy", "MEMORY"),
            ("strcat", "MEMORY"),
            ("sprintf", "MEMORY"),
            ("vsprintf", "MEMORY"),
            ("gets", "MEMORY"),
            ("memcpy", "MEMORY"),
            ("printf", "FORMAT"),
            ("fprintf", "FORMAT"),
            ("syslog", "FORMAT"),
            ("system", "SHELL"),
            ("popen", "SHELL"),
            ("execv", "SHELL"),
            ("free", "LIFETIME"),
        ),
        sanitizer_patterns=(
            ("strncpy", ("MEMORY",)),
            ("snprintf", ("MEMORY", "FORMAT")),
            ("strlcpy", ("MEMORY",)),
            ("strtol", ("UNIVERSAL",)),
            ("atoi", ("UNIVERSAL",)),
        ),
        rule_pack_count=4,
        supports_taint=True,
    ),
    "cpp": LanguageSpec(
        key="cpp",
        display_name="C++",
        grammar_name="cpp",
        extensions=(".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".inl", ".ipp", ".tpp"),
        module_node_types=("translation_unit",),
        class_node_types=("class_specifier", "struct_specifier", "union_specifier", "namespace_definition"),
        function_node_types=("function_definition", "lambda_expression"),
        parameter_node_types=("parameter_list", "parameter_declaration"),
        assignment_node_types=("assignment_expression", "init_declarator"),
        call_node_types=("call_expression",),
        control_node_types=("if_statement", "switch_statement", "try_statement", "catch_clause"),
        loop_node_types=("for_statement", "for_range_loop", "while_statement", "do_statement"),
        return_node_types=("return_statement",),
        identifier_node_types=("identifier", "field_identifier"),
        literal_node_types=("string_literal", "raw_string_literal", "number_literal", "true", "false", "nullptr"),
        import_node_types=("preproc_include",),
        skip_node_types=("comment",),
        source_patterns=(
            "argv",
            "getenv",
            "scanf",
            "gets",
            "fgets",
            "recv",
            "read",
            "std::cin",
            "cin",
        ),
        sink_patterns=(
            ("strcpy", "MEMORY"),
            ("strcat", "MEMORY"),
            ("sprintf", "MEMORY"),
            ("vsprintf", "MEMORY"),
            ("gets", "MEMORY"),
            ("memcpy", "MEMORY"),
            ("printf", "FORMAT"),
            ("fprintf", "FORMAT"),
            ("syslog", "FORMAT"),
            ("system", "SHELL"),
            ("popen", "SHELL"),
            ("execv", "SHELL"),
            ("free", "LIFETIME"),
            ("delete", "LIFETIME"),
        ),
        sanitizer_patterns=(
            ("strncpy", ("MEMORY",)),
            ("snprintf", ("MEMORY", "FORMAT")),
            ("strlcpy", ("MEMORY",)),
            ("strtol", ("UNIVERSAL",)),
            ("std::stoi", ("UNIVERSAL",)),
            ("atoi", ("UNIVERSAL",)),
        ),
        rule_pack_count=4,
        supports_taint=True,
    ),
    "rust": LanguageSpec(
        key="rust",
        display_name="Rust",
        grammar_name="rust",
        extensions=(".rs",),
        module_node_types=("source_file",),
        class_node_types=("struct_item", "enum_item", "trait_item", "impl_item"),
        function_node_types=("function_item", "closure_expression"),
        parameter_node_types=("parameters", "parameter"),
        assignment_node_types=("let_declaration", "assignment_expression", "compound_assignment_expr"),
        call_node_types=("call_expression", "macro_invocation"),
        control_node_types=("if_expression", "match_expression"),
        loop_node_types=("for_expression", "while_expression", "loop_expression"),
        return_node_types=("return_expression",),
        identifier_node_types=("identifier", "field_identifier"),
        literal_node_types=("string_literal", "raw_string_literal", "integer_literal", "float_literal", "boolean_literal"),
        import_node_types=("use_declaration",),
        skip_node_types=("line_comment", "block_comment"),
        source_patterns=(
            "web::Query",
            "web::Json",
            "web::Path",
            "env::args",
            "stdin",
        ),
        sink_patterns=(
            ("Command::new", "SHELL"),
            ("sqlx::raw_sql", "SQL"),
            ("mem::transmute", "MEMORY"),
            ("unsafe", "MEMORY"),
            ("fs::read", "PATH"),
            ("fs::read_to_string", "PATH"),
        ),
        sanitizer_patterns=(
            ("parse::<i64>", ("UNIVERSAL",)),
            ("parse::<u64>", ("UNIVERSAL",)),
            ("parse::<usize>", ("UNIVERSAL",)),
            ("Path::file_name", ("PATH",)),
        ),
        rule_pack_count=4,
        supports_taint=True,
    ),
    "ruby": LanguageSpec(
        key="ruby",
        display_name="Ruby",
        grammar_name="ruby",
        extensions=(".rb", ".rake", ".ru", ".gemspec"),
        module_node_types=("program",),
        class_node_types=("class", "module"),
        function_node_types=("method", "singleton_method", "lambda", "block"),
        parameter_node_types=("method_parameters", "block_parameters", "optional_parameter", "keyword_parameter"),
        assignment_node_types=("assignment", "operator_assignment"),
        call_node_types=("call",),
        control_node_types=("if", "elsif", "unless", "case", "begin", "rescue"),
        loop_node_types=("while", "until", "for"),
        return_node_types=("return",),
        identifier_node_types=("identifier", "instance_variable", "constant"),
        literal_node_types=("string", "integer", "float", "true", "false", "nil"),
        import_node_types=(),
        skip_node_types=("comment",),
        source_patterns=(
            "params[",
            "request.params",
            "ARGV",
            "ENV[",
        ),
        sink_patterns=(
            ("find_by_sql", "SQL"),
            ("where(", "SQL"),
            ("system(", "SHELL"),
            ("Open3", "SHELL"),
            ("eval", "CODE"),
            ("send", "CODE"),
            ("Marshal.load", "DESER"),
            ("YAML.load", "DESER"),
            ("File.read", "PATH"),
        ),
        sanitizer_patterns=(
            ("to_i", ("UNIVERSAL",)),
            ("to_f", ("UNIVERSAL",)),
            ("ERB::Util.html_escape", ("HTML",)),
            ("CGI.escapeHTML", ("HTML",)),
            ("Shellwords.escape", ("SHELL",)),
            ("YAML.safe_load", ("DESER",)),
        ),
        rule_pack_count=5,
        supports_taint=True,
    ),
    "php": LanguageSpec(
        key="php",
        display_name="PHP",
        grammar_name="php",
        extensions=(".php", ".phtml", ".php5", ".php7", ".inc"),
        module_node_types=("program",),
        class_node_types=("class_declaration", "interface_declaration", "trait_declaration"),
        function_node_types=("function_definition", "method_declaration", "anonymous_function", "arrow_function"),
        parameter_node_types=("formal_parameters", "simple_parameter", "variadic_parameter"),
        assignment_node_types=("assignment_expression", "augmented_assignment_expression"),
        call_node_types=("function_call_expression", "member_call_expression", "scoped_call_expression"),
        control_node_types=("if_statement", "switch_statement", "try_statement", "catch_clause"),
        loop_node_types=("for_statement", "foreach_statement", "while_statement", "do_statement"),
        return_node_types=("return_statement",),
        identifier_node_types=("variable_name", "name"),
        literal_node_types=("string", "encapsed_string", "integer", "float", "boolean", "null"),
        import_node_types=("namespace_use_declaration", "include_expression", "require_expression"),
        skip_node_types=("comment",),
        source_patterns=(
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_COOKIE",
            "$_SERVER",
            "$request->input",
        ),
        sink_patterns=(
            ("mysqli_query", "SQL"),
            ("PDO::query", "SQL"),
            ("->query", "SQL"),
            ("exec", "SHELL"),
            ("shell_exec", "SHELL"),
            ("system", "SHELL"),
            ("passthru", "SHELL"),
            ("proc_open", "SHELL"),
            ("unserialize", "DESER"),
            ("eval", "CODE"),
            ("include", "CODE"),
            ("require", "CODE"),
            ("file_get_contents", "PATH"),
            ("simplexml_load_string", "XML"),
        ),
        sanitizer_patterns=(
            ("intval", ("UNIVERSAL",)),
            ("floatval", ("UNIVERSAL",)),
            ("htmlspecialchars", ("HTML",)),
            ("htmlentities", ("HTML",)),
            ("escapeshellarg", ("SHELL",)),
            ("basename", ("PATH",)),
            ("prepare", ("SQL",)),
        ),
        rule_pack_count=5,
        supports_taint=True,
    ),
    "swift": LanguageSpec(
        key="swift",
        display_name="Swift",
        grammar_name="swift",
        extensions=(".swift",),
        module_node_types=("source_file",),
        class_node_types=("class_declaration", "protocol_declaration"),
        function_node_types=("function_declaration", "init_declaration", "lambda_literal"),
        parameter_node_types=("parameter",),
        assignment_node_types=("property_declaration", "assignment"),
        call_node_types=("call_expression",),
        control_node_types=("if_statement", "guard_statement", "switch_statement", "do_statement"),
        loop_node_types=("for_statement", "while_statement", "repeat_while_statement"),
        return_node_types=("control_transfer_statement",),
        identifier_node_types=("simple_identifier",),
        literal_node_types=("line_string_literal", "integer_literal", "real_literal", "boolean_literal"),
        import_node_types=("import_declaration",),
        skip_node_types=("comment", "multiline_comment"),
        source_patterns=(
            "req.query",
            "req.parameters",
            "CommandLine.arguments",
            "URLComponents",
        ),
        sink_patterns=(
            ("Process()", "SHELL"),
            ("system(", "SHELL"),
            ("sqlite3_exec", "SQL"),
            ("evaluateJavaScript", "HTML"),
            ("NSKeyedUnarchiver", "DESER"),
        ),
        sanitizer_patterns=(
            ("Int(", ("UNIVERSAL",)),
            ("Double(", ("UNIVERSAL",)),
            ("URL.lastPathComponent", ("PATH",)),
        ),
        rule_pack_count=4,
        supports_taint=True,
    ),
    "dart": LanguageSpec(
        key="dart",
        display_name="Dart",
        grammar_name="dart",
        extensions=(".dart",),
        module_node_types=("program",),
        class_node_types=("class_definition", "mixin_declaration", "enum_declaration"),
        function_node_types=("function_signature", "method_signature", "function_expression"),
        parameter_node_types=("formal_parameter_list", "normal_formal_parameter"),
        assignment_node_types=("assignment_expression", "initialized_variable_definition"),
        call_node_types=("selector",),
        control_node_types=("if_statement", "switch_statement", "try_statement"),
        loop_node_types=("for_statement", "while_statement", "do_statement"),
        return_node_types=("return_statement",),
        identifier_node_types=("identifier",),
        literal_node_types=("string_literal", "decimal_integer_literal", "true", "false", "null_literal"),
        import_node_types=("import_or_export",),
        skip_node_types=("comment", "documentation_comment"),
        source_patterns=(
            "request.uri.queryParameters",
            "request.headers",
            "args",
        ),
        sink_patterns=(
            ("Process.run", "SHELL"),
            ("Process.start", "SHELL"),
            ("rawQuery", "SQL"),
            ("rawExecute", "SQL"),
            ("File(", "PATH"),
            ("http.get", "URL"),
        ),
        sanitizer_patterns=(
            ("int.parse", ("UNIVERSAL",)),
            ("int.tryParse", ("UNIVERSAL",)),
            ("HtmlEscape().convert", ("HTML",)),
            ("path.basename", ("PATH",)),
        ),
        rule_pack_count=3,
        supports_taint=True,
    ),
    "solidity": LanguageSpec(
        key="solidity",
        display_name="Solidity",
        grammar_name="solidity",
        extensions=(".sol",),
        module_node_types=("source_file",),
        class_node_types=("contract_declaration", "interface_declaration", "library_declaration"),
        function_node_types=("function_definition", "constructor_definition", "fallback_receive_definition", "modifier_definition"),
        parameter_node_types=("parameter",),
        assignment_node_types=("assignment_expression", "augmented_assignment_expression", "variable_declaration_statement", "state_variable_declaration"),
        call_node_types=("call_expression",),
        control_node_types=("if_statement", "try_statement"),
        loop_node_types=("for_statement", "while_statement", "do_while_statement"),
        return_node_types=("return_statement",),
        identifier_node_types=("identifier",),
        literal_node_types=("string_literal", "number_literal", "boolean_literal", "hex_string_literal"),
        import_node_types=("import_directive",),
        skip_node_types=("comment", "pragma_directive"),
        source_patterns=(
            "msg.sender",
            "msg.data",
            "msg.value",
            "tx.origin",
        ),
        sink_patterns=(
            (".call{value:", "REENTRANCY"),
            (".call.value(", "REENTRANCY"),
            ("delegatecall", "DELEGATECALL"),
            ("selfdestruct", "LIFECYCLE"),
            ("suicide", "LIFECYCLE"),
            ("tx.origin", "AUTH"),
        ),
        sanitizer_patterns=(
            ("nonReentrant", ("REENTRANCY",)),
            ("ReentrancyGuard", ("REENTRANCY",)),
            ("require(msg.sender ==", ("AUTH",)),
        ),
        rule_pack_count=3,
        supports_taint=True,
    ),
    "web_template": LanguageSpec(
        key="web_template",
        display_name="Web Templates (HTML/Jinja/Blade/EJS/ERB/Razor)",
        grammar_name="html",
        extensions=(
            ".html",
            ".htm",
            ".xhtml",
            ".jinja",
            ".jinja2",
            ".j2",
            ".ejs",
            ".hbs",
            ".handlebars",
            ".blade.php",
            ".erb",
            ".rhtml",
            ".twig",
            ".ftl",
            ".jsp",
            ".jspx",
            ".cshtml",
            ".vbhtml",
            ".njk",
            ".mustache",
            ".liquid",
            ".pug",
            ".vue",
            ".svelte",
        ),
        module_node_types=("document", "fragment"),
        class_node_types=(),
        function_node_types=("script_element",),
        parameter_node_types=(),
        assignment_node_types=("attribute",),
        call_node_types=("element",),
        control_node_types=(),
        loop_node_types=(),
        return_node_types=(),
        identifier_node_types=("tag_name", "attribute_name"),
        literal_node_types=("quoted_attribute_value", "attribute_value", "text"),
        import_node_types=(),
        skip_node_types=("comment", "doctype"),
        source_patterns=(
            "{{",
            "<%=",
            "<%-",
            "{{{",
            "{!!",
            "<%= raw",
            "@Html.Raw",
            '<form method="post"',
        ),
        sink_patterns=(
            ("|safe", "HTML"),
            ("autoescape false", "HTML"),
            ("<%-", "HTML"),
            ("{{{", "HTML"),
            ("{!!", "HTML"),
            ("@Html.Raw", "HTML"),
            ("v-html", "HTML"),
            ("render_template_string", "SSTI"),
            ('<form method="post"', "CSRF"),
        ),
        sanitizer_patterns=(
            ("csrf_token", ("CSRF",)),
            ("csrf_field", ("CSRF",)),
            ("@csrf", ("CSRF",)),
            ("authenticity_token", ("CSRF",)),
            ("|e", ("HTML",)),
            ("|escape", ("HTML",)),
            ("DOMPurify", ("HTML",)),
        ),
        rule_pack_count=3,
        supports_taint=True,
    ),
}


EXTENSION_TO_LANGUAGE: Dict[str, str] = {}
for _lang_key, _spec in LANGUAGE_SPECS.items():
    for _ext in _spec.extensions:
        EXTENSION_TO_LANGUAGE[_ext.lower()] = _lang_key

# Compound extensions (containing more than one '.') ordered longest-first
# so '.blade.php' always matches 'web_template' before '.php' matches 'php'.
_COMPOUND_SUFFIXES: Tuple[Tuple[str, str], ...] = tuple(
    sorted(
        ((ext, lang) for ext, lang in EXTENSION_TO_LANGUAGE.items() if ext.count(".") > 1),
        key=lambda item: len(item[0]),
        reverse=True,
    )
)

_LANGUAGE_LOCK = threading.RLock()
_LANGUAGE_CACHE: Dict[str, Optional[tree_sitter.Language]] = {}
_THREAD_LOCAL_PARSERS = threading.local()


def resolve_language_for_filename(filename: str) -> Optional[str]:
    """
    Resolves a filename or path to one of the 18 canonical language family keys.
    Evaluates compound suffixes (e.g. '.blade.php') prior to single extensions ('.php').
    """
    if not filename:
        return None
    base = os.path.basename(filename.replace("\\", "/")).lower()
    if not base:
        return None

    for suffix, lang_key in _COMPOUND_SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix):
            return lang_key

    _, ext = os.path.splitext(base)
    if not ext:
        return None
    return EXTENSION_TO_LANGUAGE.get(ext.lower())


def get_language_spec(lang_key: str) -> LanguageSpec:
    """Returns the immutable LanguageSpec for a canonical language key."""
    normalized = (lang_key or "").strip().lower()
    if normalized not in LANGUAGE_SPECS:
        raise KeyError(f"Unsupported language key: {lang_key!r}")
    return LANGUAGE_SPECS[normalized]


def _load_fallback_bundled_language(lang_key: str) -> Optional[tree_sitter.Language]:
    """Fallback loader using pinned individual tree-sitter wheels for core languages."""
    try:
        if lang_key == "python":
            import tree_sitter_python

            return tree_sitter.Language(tree_sitter_python.language())
        if lang_key == "javascript":
            import tree_sitter_javascript

            return tree_sitter.Language(tree_sitter_javascript.language())
        if lang_key == "typescript":
            import tree_sitter_typescript

            return tree_sitter.Language(tree_sitter_typescript.language_typescript())
        if lang_key == "tsx":
            import tree_sitter_typescript

            return tree_sitter.Language(tree_sitter_typescript.language_tsx())
    except Exception:
        return None
    return None


def _load_fallback_bundled_parser(lang_key: str) -> Optional[tree_sitter.Parser]:
    """Constructs a fresh Parser from pinned individual tree-sitter wheels."""
    language = _load_fallback_bundled_language(lang_key)
    if language is None:
        return None
    return tree_sitter.Parser(language)


def _get_cached_language(normalized: str, spec: LanguageSpec) -> Optional[tree_sitter.Language]:
    """Thread-safe lazy cache of immutable tree_sitter.Language grammar objects."""
    with _LANGUAGE_LOCK:
        if normalized in _LANGUAGE_CACHE:
            return _LANGUAGE_CACHE[normalized]

        language: Optional[tree_sitter.Language] = None
        try:
            import tree_sitter_language_pack

            language = tree_sitter_language_pack.get_language(spec.grammar_name)
        except Exception:
            language = None

        if language is None:
            language = _load_fallback_bundled_language(normalized)

        _LANGUAGE_CACHE[normalized] = language
        return language


def get_parser_for_language(lang_key: str) -> Optional[tree_sitter.Parser]:
    """
    Thread-safe lazy Tree-sitter parser provider.
    Caches immutable tree_sitter.Language grammars globally and stores mutable
    tree_sitter.Parser instances per thread in threading.local() so concurrent
    threads never share a C TSParser*. Returns None cleanly for unsupported languages.
    """
    normalized = (lang_key or "").strip().lower()
    spec = LANGUAGE_SPECS.get(normalized)
    if spec is None:
        return None

    thread_cache: Optional[Dict[str, Optional[tree_sitter.Parser]]] = getattr(
        _THREAD_LOCAL_PARSERS, "parsers", None
    )
    if thread_cache is None:
        thread_cache = {}
        _THREAD_LOCAL_PARSERS.parsers = thread_cache

    if normalized in thread_cache:
        return thread_cache[normalized]

    language = _get_cached_language(normalized, spec)
    parser: Optional[tree_sitter.Parser] = None
    if language is not None:
        parser = tree_sitter.Parser(language)
    else:
        try:
            import tree_sitter_language_pack

            parser = tree_sitter_language_pack.get_parser(spec.grammar_name)
        except Exception:
            parser = None
        if parser is None:
            parser = _load_fallback_bundled_parser(normalized)

    thread_cache[normalized] = parser
    return parser


def list_language_capabilities() -> LanguageCapabilitiesResponse:
    """Returns capability and parser-readiness telemetry across all 18 language families."""
    items: List[LanguageCapabilityItem] = []
    ready_count = 0

    for lang_key, spec in LANGUAGE_SPECS.items():
        available = get_parser_for_language(lang_key) is not None
        if available:
            ready_count += 1
        items.append(
            LanguageCapabilityItem(
                language=spec.key,
                display_name=spec.display_name,
                extensions=list(spec.extensions),
                parser_available=available,
                rule_pack_count=spec.rule_pack_count,
                supports_taint=spec.supports_taint,
            )
        )

    return LanguageCapabilitiesResponse(
        total_languages=len(items),
        ready_parsers=ready_count,
        languages=items,
    )
