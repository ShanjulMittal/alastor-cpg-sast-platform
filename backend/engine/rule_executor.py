"""
Deterministic Vulnerability and Logic Flaw Hunting Engine.
Executes pure Cypher graph algorithms over CPG to find taint flows, orphan gadgets,
dead stores, infinite loops, and unreachable logic.
"""
import hashlib
import logging
from typing import List, Dict, Any
from models import Finding
from database.neo4j_client import Neo4jClient

logger = logging.getLogger("cpg-sast.engine")


RULES = [
    {
        "id": "RULE-1-TAINT",
        "name": "End-to-End Taint Analysis",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 9.8,
        "remediation": "Validate or sanitize untrusted input using strict type conversion (e.g., int()), allowlists, or shlex.quote() before passing to execution sinks.",
        "description": "Untrusted input source flows into sensitive execution sink without required sanitizer.",
        "cypher": """
        MATCH (source:CPGNode {is_source: true})
        MATCH (sink:CPGNode {is_sink: true})
        MATCH path = shortestPath((source)-[:DFG_FLOWS_TO*1..25]->(sink))
        WHERE NONE(n IN nodes(path) WHERE n.is_sanitizer = true)
        RETURN 
          'CRITICAL' AS severity,
          'Taint Vulnerability: Untrusted Input Flows to Sensitive Sink' AS title,
          [n IN nodes(path) | properties(n)] AS path_nodes,
          [r IN relationships(path) | {id: r.id, source: startNode(r).id, target: endNode(r).id, type: type(r)}] AS path_edges
        """
    },
    {
        "id": "RULE-2-ORPHAN",
        "name": "Orphaned Functions, Bypassed Auth Guards & Dormant Gadgets",
        "cwe_id": "CWE-561",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 7.5,
        "remediation": "Wire bypassed authentication/session verification guards (e.g., getSession(), sendCode()) into route handlers, or remove uncalled debug/gadget routines from production code.",
        "description": "Uncalled non-entrypoint functions representing either bypassed security/authentication guards (e.g., getSession, sendCode) or dormant execution gadgets.",
        "cypher": """
        MATCH (f:Function)
        WHERE NOT ()-[:CALLS]->(f)
          AND NOT f.name IN ['main', '__init__', '__call__', 'anonymous_func']
          AND NOT f.name STARTS WITH 'test_'
          AND NOT f.filepath STARTS WITH 'scratch/'
          AND NOT f.filepath ENDS WITH '.tsx'
          AND NOT f.code STARTS WITH 'export '
          AND NOT f.code CONTAINS '@app.'
          AND NOT f.code CONTAINS '@router.'
          AND (
            (f)-[:AST_CHILD*1..8]->(:CPGNode {is_sink: true})
            OR f.name IN ['getSession', 'sendCode', 'verifySession', 'verifyToken', 'authenticate']
            OR toLower(f.name) CONTAINS 'debug'
            OR toLower(f.name) CONTAINS 'shell'
            OR toLower(f.name) CONTAINS 'gadget'
            OR toLower(f.name) CONTAINS 'backdoor'
            OR f.code CONTAINS 'subprocess'
            OR f.code CONTAINS 'os.system'
            OR f.code CONTAINS 'shell=True'
          )
        RETURN 
          'HIGH' AS severity,
          CASE
            WHEN f.name IN ['getSession', 'sendCode', 'verifySession', 'verifyToken', 'authenticate']
              THEN 'Bypassed / Orphaned Security Control (Uncalled Auth Guard): ' + f.name + '()'
            ELSE 'Dormant Zero-Day Gadget / Uncalled Open Function: ' + f.name
          END AS title,
          [properties(f)] AS path_nodes,
          [] AS path_edges
        """
    },
    {
        "id": "RULE-3-DEADSTORE",
        "name": "Dead Stores & Unread Data Feeds",
        "cwe_id": "CWE-563",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 5.3,
        "remediation": "Remove unused variable assignments or verify whether a security check/audit result was accidentally ignored.",
        "description": "Variables assigned the result of a computation or call whose values are never read anywhere in scope.",
        "cypher": """
        MATCH (source:Call)-[r:DFG_FLOWS_TO]->(target:Variable)
        WHERE NOT (target)-[:DFG_FLOWS_TO]->()
          AND NOT target.name STARTS WITH '_'
          AND NOT target.name CONTAINS '.'
          AND NOT target.name CONTAINS '['
          AND NOT target.name CONTAINS ','
          AND NOT target.name CONTAINS '{'
          AND NOT target.ast_type IN ['pattern_list', 'tuple_pattern', 'object_pattern', 'array_pattern']
          AND NOT source.name IN ['Field', 'create']
          AND size(target.name) > 2
          AND NOT EXISTS {
            MATCH (other:Variable {filepath: target.filepath, name: target.name})
            WHERE other.id <> target.id AND other.start_line >= target.start_line
          }
        RETURN 
          'MEDIUM' AS severity,
          'Dead Store / Unused Data Element: ' + target.name AS title,
          [properties(source), properties(target)] AS path_nodes,
          [{id: r.id, source: source.id, target: target.id, type: type(r)}] AS path_edges
        """
    },
    {
        "id": "RULE-4-INFINITE-LOOP",
        "name": "Deterministic Infinite Loops",
        "cwe_id": "CWE-835",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 7.5,
        "remediation": "Add a bounded loop condition, explicit break statement, or cancellation check to prevent CPU exhaustion (DoS).",
        "description": "Loop headers with cyclic control back-edges lacking condition exit or termination jumps.",
        "cypher": """
        MATCH cycle = (loop:LoopBlock)-[:CFG_TRUE|CFG_NEXT*1..15]->(tail:CPGNode)-[:CFG_LOOP_BACK]->(loop)
        WHERE NOT (loop)-[:CFG_FALSE]->()
          AND NOT (loop)-[:CFG_TRUE|CFG_NEXT*1..15]->(:CPGNode)-[:CFG_BREAK]->()
          AND NOT (loop)-[:CFG_TRUE|CFG_NEXT*1..15]->(:Return)
          AND (
            loop.code STARTS WITH 'while True'
            OR loop.code STARTS WITH 'while(true)'
            OR loop.code STARTS WITH 'while (true)'
            OR loop.code STARTS WITH 'while 1'
            OR loop.code CONTAINS 'for(;;)'
            OR loop.code CONTAINS 'for (;;)'
          )
        RETURN 
          'HIGH' AS severity,
          'Logical Flaw: Non-Terminating Infinite Loop' AS title,
          [n IN nodes(cycle) | properties(n)] AS path_nodes,
          [r IN relationships(cycle) | {id: r.id, source: startNode(r).id, target: endNode(r).id, type: type(r)}] AS path_edges
        """
    },
    {
        "id": "RULE-5-UNREACHABLE",
        "name": "Unreachable Dead Logic",
        "cwe_id": "CWE-561",
        "owasp_category": "A04:2021 - Insecure Design",
        "cvss_score": 5.3,
        "remediation": "Refactor control flow so cleanup or post-action logic executes before return/raise or inside a finally block.",
        "description": "Executable statements inside a function block placed after a return/throw terminator with no reachable CFG path.",
        "cypher": """
        MATCH (fn:Function)-[:AST_CHILD*1..3]->(block:CPGNode)-[:AST_CHILD]->(ret:Return)
        MATCH (block)-[:AST_CHILD*1..2]->(stmt:CPGNode)
        WHERE block.ast_type IN ['block', 'statement_block']
          AND ret.scope_id = fn.id
          AND stmt.scope_id = fn.id
          AND stmt.id <> ret.id
          AND stmt.label IN ['Assignment', 'Call', 'ControlBlock', 'LoopBlock', 'Return']
          AND (stmt.start_line > ret.end_line OR (stmt.start_line = ret.end_line AND stmt.start_col > ret.end_col))
          AND NOT ()-[:CFG_NEXT|CFG_TRUE|CFG_FALSE|CFG_LOOP_BACK|CFG_BREAK]->(stmt)
          AND NOT (ret)-[:AST_CHILD*1..5]->(stmt)
        RETURN 
          'MEDIUM' AS severity,
          'Logical Flaw: Unreachable Dead Code Block' AS title,
          [properties(stmt), properties(fn)] AS path_nodes,
          [] AS path_edges
        """
    },
    {
        "id": "RULE-6-SHELL-INJECTION",
        "name": "Unsafe Subprocess / Shell Execution",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 9.8,
        "remediation": "Avoid spawning a command shell (subprocess with shell=True in Python or child_process.exec() in Node.js). Use argument arrays via subprocess.run([...], shell=False) or child_process.execFile().",
        "description": "Process execution explicitly spawns an OS command shell (shell=True or child_process.exec), exposing the application to command injection.",
        "cypher": """
        MATCH (c:Call)
        WHERE (
            c.code CONTAINS 'shell=True'
            AND (c.name CONTAINS 'subprocess' OR c.name IN ['Popen', 'run', 'call', 'check_output'])
          )
          OR (
            c.name IN ['cp.exec', 'child_process.exec']
          )
        RETURN
          CASE WHEN c.name IN ['cp.exec', 'child_process.exec'] THEN 'MEDIUM' ELSE 'CRITICAL' END AS severity,
          'Unsafe Shell Execution: ' + c.name AS title,
          [properties(c)] AS path_nodes,
          [] AS path_edges
        """
    },
    {
        "id": "RULE-7-SQLI-FORMAT",
        "name": "SQL Query Constructed via String Interpolation",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 8.1,
        "remediation": "Replace f-string SQL query construction with parameterized placeholders (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (safe_id,))).",
        "description": "Database execute() call constructs SQL query dynamically using string interpolation instead of bound parameters.",
        "cypher": """
        MATCH (c:Call)
        WHERE (c.name ENDS WITH '.execute' OR c.code CONTAINS 'cursor.execute')
          AND (c.code CONTAINS 'f\"SELECT' OR c.code CONTAINS \"f'SELECT\" OR c.code CONTAINS 'SELECT * FROM')
        RETURN
          'HIGH' AS severity,
          'Unparameterized SQL String Interpolation in ' + c.name AS title,
          [properties(c)] AS path_nodes,
          [] AS path_edges
        """
    },
    {
        "id": "RULE-8-HARDCODED-SECRET",
        "name": "Hardcoded Credential or Secret Assignment",
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "cvss_score": 7.5,
        "remediation": "Load secrets and database credentials exclusively from a secret manager or required environment variables without hardcoded fallback passwords.",
        "description": "Source code contains hardcoded password, secret, or API token strings.",
        "cypher": """
        MATCH (a:Assignment)
        WHERE (toLower(a.name) CONTAINS 'password' OR toLower(a.name) CONTAINS 'secret' OR toLower(a.name) CONTAINS 'api_key')
          AND (a.code CONTAINS '\"' OR a.code CONTAINS \"'\")
          AND NOT a.code CONTAINS '==='
          AND NOT a.code CONTAINS '!=='
          AND NOT a.code CONTAINS '=='
          AND NOT a.code ENDS WITH '\"\"'
          AND NOT a.code ENDS WITH \"''\"
        RETURN
          'HIGH' AS severity,
          'Hardcoded Secret / Fallback Credential in ' + a.name AS title,
          [properties(a)] AS path_nodes,
          [] AS path_edges
        """
    },
    {
        "id": "RULE-9-DOM-XSS",
        "name": "Client-Side DOM XSS & Unvalidated URL Scheme Injection",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 - Injection",
        "cvss_score": 7.5,
        "remediation": "Validate URL protocols (allowlisting only https: and http: via new URL(u).protocol) before interpolating URLs into <a href=\"...\">, because HTML-entity escaping (esc) only replaces [&<>\"'] and does not block javascript: URI execution. Prefer textContent or DOMPurify.sanitize() over raw innerHTML.",
        "description": "Dynamic client-side or external data flows into a DOM HTML/Script execution sink (document.write, unescaped innerHTML, <a href=\"${esc(url)}\"> without protocol validation, or dynamic script src).",
        "cypher": """
        MATCH (sink:CPGNode)
        WHERE (
            (sink.label = 'Call' AND sink.name IN ['document.write', 'document.writeln'])
            OR (sink.label = 'Assignment' AND sink.is_sink = true AND (sink.name ENDS WITH '.innerHTML' OR sink.name ENDS WITH '.outerHTML' OR sink.name = 'dangerouslySetInnerHTML'))
            OR (sink.label = 'Call' AND sink.name ENDS WITH '.setAttribute' AND (sink.code CONTAINS '(\"src\",' OR sink.code CONTAINS \"('src',\") AND NOT sink.code CONTAINS '(\"src\",\"' AND NOT sink.code CONTAINS \"('src','\")
          )
        OPTIONAL MATCH (use_node:CPGNode)-[r2:DFG_FLOWS_TO]->(sink)
        OPTIONAL MATCH (def_node:CPGNode)-[r1:DFG_FLOWS_TO]->(use_node)
        WHERE def_node IS NULL OR (def_node.id <> use_node.id AND def_node.id <> sink.id)
        WITH sink,
             head(collect(def_node)) AS def_node,
             head(collect(use_node)) AS use_node,
             head(collect(r1)) AS r1,
             head(collect(r2)) AS r2
        RETURN
          'HIGH' AS severity,
          CASE
            WHEN sink.name IN ['document.write', 'document.writeln'] THEN 'DOM-Based XSS / Dynamic Script Sink: ' + sink.name + '()'
            WHEN sink.name ENDS WITH '.setAttribute' THEN 'Dynamic Script Source Injection via ' + sink.name + '(\"src\", ...)'
            WHEN sink.code CONTAINS 'href=\"${esc(' THEN 'DOM XSS via Unvalidated URL Scheme in <a href> (esc() Bypass): ' + sink.name
            ELSE 'Unsanitized DOM HTML Sink: ' + sink.name
          END AS title,
          CASE
            WHEN def_node IS NOT NULL AND use_node IS NOT NULL THEN [properties(def_node), properties(use_node), properties(sink)]
            WHEN use_node IS NOT NULL THEN [properties(use_node), properties(sink)]
            ELSE [properties(sink)]
          END AS path_nodes,
          CASE
            WHEN r1 IS NOT NULL AND r2 IS NOT NULL THEN [
              {id: r1.id, source: def_node.id, target: use_node.id, type: type(r1)},
              {id: r2.id, source: use_node.id, target: sink.id, type: type(r2)}
            ]
            WHEN r2 IS NOT NULL THEN [
              {id: r2.id, source: use_node.id, target: sink.id, type: type(r2)}
            ]
            ELSE []
          END AS path_edges
        """
    }
]


class RuleExecutor:
    def __init__(self, client: Neo4jClient):
        self.client = client

    def run_all_rules(self) -> List[Finding]:
        """Executes all deterministic rules against Neo4j and returns structured findings."""
        findings: List[Finding] = []
        seen_finding_keys = set()

        with self.client.driver.session() as session:
            for rule in RULES:
                try:
                    result = session.run(rule["cypher"])
                    for record in result:
                        severity = record["severity"]
                        title = record["title"]
                        raw_nodes = record["path_nodes"] or []
                        raw_edges = record["path_edges"] or []

                        # Filter and clean path_nodes
                        path_nodes: List[Dict[str, Any]] = []
                        seen_node_ids = set()
                        for n in raw_nodes:
                            if isinstance(n, list):
                                for item in n:
                                    if isinstance(item, dict) and "id" in item and item["id"] not in seen_node_ids:
                                        if item.get("filepath") and int(item.get("start_line", 0)) >= 1:
                                            seen_node_ids.add(item["id"])
                                            path_nodes.append(item)
                            elif isinstance(n, dict) and "id" in n and n["id"] not in seen_node_ids:
                                if n.get("filepath") and int(n.get("start_line", 0)) >= 1:
                                    seen_node_ids.add(n["id"])
                                    path_nodes.append(n)

                        if not path_nodes:
                            continue

                        # Clean path_edges
                        path_edges: List[Dict[str, Any]] = []
                        seen_edge_ids = set()
                        for e in raw_edges:
                            if isinstance(e, dict) and "id" in e and e["id"] not in seen_edge_ids:
                                seen_edge_ids.add(e["id"])
                                path_edges.append(e)

                        # Generate deterministic finding ID based on rule, title, and sorted node IDs
                        sorted_ids_str = ",".join(sorted(n["id"] for n in path_nodes))
                        finding_id = hashlib.sha256(f"{rule['id']}:{title}:{sorted_ids_str}".encode()).hexdigest()[:16]

                        # Deduplicate findings with identical rule and nodes
                        dedup_key = (rule["id"], sorted_ids_str)
                        if dedup_key in seen_finding_keys:
                            continue
                        seen_finding_keys.add(dedup_key)

                        cwe_id = rule.get("cwe_id")
                        cwe_num = cwe_id.split("-")[1] if cwe_id and "-" in cwe_id else None

                        first_n = path_nodes[0]
                        sink_n = path_nodes[-1]
                        sink_fp = str(sink_n.get("filepath") or first_n.get("filepath") or "unknown")
                        sink_ln = int(sink_n.get("start_line") or 1)
                        sink_code = str(sink_n.get("code") or sink_n.get("name") or "").strip().replace("\x00", "")
                        sink_sym = str(sink_n.get("name") or sink_n.get("ast_type") or "statement").strip()

                        if len(path_nodes) > 1:
                            src_fp = str(first_n.get("filepath") or sink_fp)
                            src_ln = int(first_n.get("start_line") or 1)
                            src_code = str(first_n.get("code") or first_n.get("name") or "").strip().replace("\x00", "")
                            trace_steps = " → ".join(
                                f"`{n.get('filepath', sink_fp)}`:L{n.get('start_line', 1)} (`{str(n.get('code') or n.get('name') or '').strip()[:70]}`)"
                                for n in path_nodes
                            )
                            detailed_desc = (
                                f"{rule['description']} "
                                f"[Written Evidence: Untrusted input enters at `{src_fp}` (Line {src_ln}: `{src_code[:90]}`) "
                                f"and reaches vulnerable sink `{sink_sym}` at `{sink_fp}` (Line {sink_ln}: `{sink_code[:100]}`). "
                                f"Full CPG Trace: {trace_steps}]"
                            )
                        else:
                            detailed_desc = (
                                f"{rule['description']} "
                                f"[Written Evidence: Flagged symbol/statement `{sink_sym}` in `{sink_fp}` at Line {sink_ln}: "
                                f"`{sink_code[:120]}`]"
                            )

                        base_rem = rule.get("remediation") or "Apply defensive input validation and safe API parameterization."
                        detailed_rem = (
                            f"{base_rem} (Target Location: `{sink_fp}` at Line {sink_ln} — replace or harden `{sink_code[:90]}`)."
                        )

                        findings.append(
                            Finding(
                                id=finding_id,
                                rule_id=rule["id"],
                                severity=severity,
                                title=title,
                                description=detailed_desc,
                                cwe_id=cwe_id,
                                owasp_category=rule.get("owasp_category"),
                                cvss_score=rule.get("cvss_score"),
                                remediation=detailed_rem,
                                source_site="ALASTOR CPG Engine",
                                reference_url=f"https://cwe.mitre.org/data/definitions/{cwe_num}.html" if cwe_num else None,
                                path_nodes=path_nodes,
                                path_edges=path_edges
                            )
                        )
                except Exception as e:
                    logger.error(f"Error executing rule {rule['id']}: {e}", exc_info=True)

        return findings

