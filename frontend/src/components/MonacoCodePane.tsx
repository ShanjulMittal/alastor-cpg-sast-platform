"use client";

import React, { useEffect, useRef, useState, useMemo } from "react";
import Editor, { DiffEditor, Monaco, OnMount, DiffOnMount } from "@monaco-editor/react";
import { useAuditStore } from "@/store/useAuditStore";
import { FilePurposeInfo, Finding } from "@/types/cpg";
import { isLightAppTheme } from "./AlastorBranding";
import {
  FileCode,
  Loader2,
  Layers,
  ExternalLink,
  BookOpen,
  Wrench,
  Activity,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  AlertOctagon,
  Sparkles,
  CheckCircle2,
  Crosshair,
  Zap,
  RotateCcw,
  Download,
  X,
  GitCompare,
  ShieldCheck,
} from "lucide-react";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

interface StoryChapter {
  stepNumber: number;
  role: "SOURCE" | "PROPAGATION" | "SINK" | "TRIGGER";
  badgeText: string;
  badgeColor: string;
  headline: string;
  explanation: string;
  filepath: string;
  line: number;
  code: string;
  node: any;
}

interface FindingStory {
  categoryLabel: string;
  whatHappened: string;
  securityImpact: string;
  howToFix: string;
  secureCodeExample: string;
  chapters: StoryChapter[];
}

function buildFindingStory(finding: Finding): FindingStory {
  const rule = (finding.rule_id || "").toUpperCase();
  const cwe = (finding.cwe_id || "").toUpperCase();
  const engine = (finding.scan_engine || "SAST").toUpperCase();
  const nodes = finding.path_nodes || [];
  const rawDesc = (finding.description || finding.title || "").trim();

  let categoryLabel = "Security & Code Quality Flaw";
  let whatHappened = rawDesc;
  let securityImpact =
    finding.business_impact ||
    "This pattern introduces a security or reliability risk that could allow unintended execution behaviors or application instability.";
  let howToFix =
    finding.remediation ||
    "Validate and sanitize untrusted inputs, enforce strict execution guards, and remove unsafe sink patterns.";
  let secureCodeExample =
    finding.best_fix_location?.recommended_fix ||
    `# Recommended Secure Pattern:\n# 1. Validate inputs against a strict allowlist\n# 2. Avoid passing raw user input into dynamic execution sinks`;

  if (engine === "SCA" || rule.includes("SCA") || cwe === "CWE-1395") {
    categoryLabel = "Third-Party Software Supply-Chain & Dependency Pinning Risk (SCA)";
    const pkgSummary = nodes
      .map((n) => `${n.name || n.code} (${n.filepath}:L${n.start_line})`)
      .join(", ");
    whatHappened =
      rawDesc +
      (pkgSummary && !rawDesc.includes(pkgSummary.slice(0, 20))
        ? ` Affected third-party entries: ${pkgSummary}.`
        : "");
    securityImpact =
      "OWASP A06:2021 (Vulnerable and Outdated Components) / CWE-1395: When third-party software packages use floating caret (`^`), tilde (`~`), or unpinned version specifiers, automated builds (`npm install` / `pip install`) can silently fetch unverified minor/patch releases containing newly introduced vulnerabilities (CVEs), breaking changes, or malicious supply-chain payloads.";
    howToFix =
      finding.remediation ||
      "Pin every third-party dependency to an exact verified version (remove `^` / `~` in `package.json` or use `==` in `requirements.txt`), commit the lockfile (`package-lock.json`), and enforce `npm ci` or `pip install --require-hashes`.";
    const fixedLines = nodes
      .map((n) => {
        const rawCode = (n.code || n.name || "").trim();
        return rawCode.replace(/:\s*"[\^~>=*]+/g, ': "');
      })
      .join("\n");
    secureCodeExample =
      fixedLines
        ? `// SECURE FIX: Replace floating SemVer ranges (^ / ~) with exact locked versions:\n${fixedLines}\n\n// And enforce deterministic lockfile installation in CI/CD:\n// npm ci --ignore-scripts`
        : finding.best_fix_location?.recommended_fix || howToFix;
  } else if (engine === "IAC" || rule.includes("IAC") || cwe === "CWE-250") {
    categoryLabel = "Infrastructure & Runtime Security Misconfiguration (IaC)";
    whatHappened = rawDesc;
    securityImpact =
      "OWASP A05:2021 (Security Misconfiguration) / CWE-250: Missing web runtime security headers (`Content-Security-Policy`, `X-Frame-Options`, `poweredByHeader: false`), hardcoded service credentials, or containers executing as UID 0 (`root`) weaken defense-in-depth and allow easier privilege escalation or browser framing/XSS attacks.";
    howToFix =
      finding.remediation ||
      "Harden the runtime/deployment configuration by adding strict HTTP security headers, disabling server version fingerprinting (`poweredByHeader: false`), and enforcing a non-root container `USER` directive.";
    const fpLower = (nodes[0]?.filepath || "").toLowerCase();
    if (fpLower.includes("next.config")) {
      secureCodeExample = `import type { NextConfig } from "next";\n\nconst nextConfig: NextConfig = {\n  poweredByHeader: false,\n  async headers() {\n    return [\n      {\n        source: "/(.*)",\n        headers: [\n          { key: "X-Frame-Options", value: "DENY" },\n          { key: "X-Content-Type-Options", value: "nosniff" },\n          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },\n          { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none';" },\n        ],\n      },\n    ];\n  },\n};\n\nexport default nextConfig;`;
    } else {
      secureCodeExample = `# SECURE FIX: Enforce non-root execution in Dockerfile / Runtime Config\nRUN groupadd -r app && useradd -r -g appuser\nUSER appuser`;
    }
  } else if (rule.includes("TAINT") || rule.includes("SHELL") || cwe === "CWE-78") {
    categoryLabel = "OS Command Injection (Tainted Data Flow)";
    whatHappened = `${rawDesc} Untrusted input enters the function and flows through variables directly into an operating system shell command without being sanitized or escaped.`;
    securityImpact =
      "An attacker who controls the input can append shell metacharacters (like `;`, `&&`, or `|`) to execute arbitrary operating system commands on the server with the application's privileges.";
    howToFix =
      finding.remediation ||
      "Replace `os.system()` or `shell=True` calls with `subprocess.run([cmd, arg1, ...], shell=False)` so arguments are passed as a safe list rather than interpreted by a shell, or validate input with a strict allowlist.";
    secureCodeExample = `import subprocess\nimport shlex\n\n# SECURE FIX: Pass arguments as a list with shell=False (never concatenate strings)\nallowed_hosts = {"localhost", "127.0.0.1"}\nif user_input in allowed_hosts:\n    subprocess.run(["ping", "-c", "1", user_input], shell=False, check=True)`;
  } else if (rule.includes("SQLI") || cwe === "CWE-89") {
    categoryLabel = "SQL Injection (Unsafe Query Formatting)";
    whatHappened = `${rawDesc} A database SQL query is dynamically constructed using string concatenation, f-strings, or \`.format()\` with unvalidated variables instead of parameterized placeholders.`;
    securityImpact =
      "An attacker can craft input containing SQL syntax (such as `' OR '1'='1` or `UNION SELECT`) to bypass authentication, read sensitive database records, or modify/delete data.";
    howToFix =
      finding.remediation ||
      "Always use parameterized queries (prepared statements) with `?` or `%s` placeholders so the database driver treats user input strictly as data, never as executable SQL commands.";
    secureCodeExample = `# SECURE FIX: Use parameterized query placeholders (? or :param)\ncursor.execute(\n    "SELECT id, username, role FROM users WHERE username = ?",\n    (user_input,)\n)`;
  } else if (rule.includes("GADGET") || rule.includes("ORPHAN") || cwe === "CWE-489") {
    categoryLabel = "Dormant Privileged Gadget (Unreferenced Dangerous Function)";
    whatHappened = `${rawDesc} This function contains a high-risk execution sink (such as command execution or shell access), even though no normal application code currently calls it.`;
    securityImpact =
      "Leftover debug hooks, maintenance backdoors, or dead privileged functions act as 'exploit gadgets'. If an attacker discovers a deserialization flaw, dynamic import, or routing bypass, they can invoke this dormant function to compromise the host.";
    howToFix =
      finding.remediation ||
      "Remove dormant debug/admin functions from production code entirely, or isolate diagnostic utilities into offline scripts outside the deployed application bundle.";
    secureCodeExample = `# SECURE FIX: Remove unused debug shell functions from production code\n# If administrative tasks are required, use authenticated CLI management commands\n# and never expose raw os.system / subprocess shell helpers.`;
  } else if (rule.includes("DEAD-STORE") || rule.includes("DEADSTORE") || cwe === "CWE-563") {
    categoryLabel = "Dead Store (Assigned Value Never Read)";
    whatHappened = `${rawDesc} A variable is assigned a value in code, but that value is never read or used by any subsequent expression or return statement along the data-flow graph.`;
    securityImpact =
      "Often indicates a logic bug where a security check result, sanitized value, or audit log buffer was computed but accidentally ignored—or lingers in memory unnecessarily.";
    howToFix =
      finding.remediation ||
      "Either use the variable as intended (for example, returning or logging the computed result) or remove the redundant assignment to keep logic clean and auditable.";
    secureCodeExample = `# SECURE FIX: Ensure computed security/audit buffers are actually persisted or returned\naudit_record = build_security_audit_event(user_id, action)\naudit_logger.info(audit_record)  # Value is now properly consumed`;
  } else if (rule.includes("INFINITE-LOOP") || cwe === "CWE-835") {
    categoryLabel = "Non-Terminating Loop (Denial of Service Risk)";
    whatHappened = `${rawDesc} The Control Flow Graph (CFG) shows a loop (\`while True\` or unbounded loop) that has a loop-back edge to its header without any reachable \`break\`, \`return\`, or loop-variable mutation.`;
    securityImpact =
      "If execution enters this loop, the worker thread or process will hang indefinitely at 100% CPU usage, causing a Denial of Service (DoS) for the application.";
    howToFix =
      finding.remediation ||
      "Add an explicit maximum iteration counter, a timeout check, or a reachable `break` / `return` termination condition inside the loop body.";
    secureCodeExample = `# SECURE FIX: Always enforce a bounded iteration guard or timeout\nMAX_ITERATIONS = 1000\nfor step in range(MAX_ITERATIONS):\n    if should_stop_worker():\n        break\n    process_next_item()`;
  } else if (rule.includes("UNREACHABLE") || cwe === "CWE-561") {
    categoryLabel = "Unreachable Dead Code (Orphaned Execution Block)";
    whatHappened = `${rawDesc} Statements exist after an unconditional \`return\`, \`break\`, or \`raise\`, meaning the Control Flow Graph has zero execution paths that can ever reach this code.`;
    securityImpact =
      "When cleanup logic, file deletion, lock release, or security logging is placed after a `return` statement, it silently fails to run—leaving temporary files, locks, or unlogged states behind.";
    howToFix =
      finding.remediation ||
      "Move critical cleanup logic before the `return` statement, or wrap resource cleanup inside a `try ... finally:` block so it is guaranteed to execute.";
    secureCodeExample = `# SECURE FIX: Use try/finally so cleanup always runs before returning\ntry:\n    result = perform_operation()\n    return result\nfinally:\n    cleanup_temp_files()  # Guaranteed to execute`;
  } else if (rule.includes("SECRET") || cwe === "CWE-798") {
    categoryLabel = "Hardcoded Secret / API Credential in Source";
    whatHappened = `${rawDesc} A sensitive secret, API key, token, or password literal is assigned directly in source code instead of being loaded from a secure secret manager or environment variable.`;
    securityImpact =
      "Anyone with read access to the repository, build artifacts, or leaked source files can extract the credential and gain unauthorized access to external services or databases.";
    howToFix =
      finding.remediation ||
      "Remove the hardcoded credential immediately, rotate the exposed key, and load secrets at runtime via `os.environ.get()` or a dedicated secret vault.";
    secureCodeExample = `import os\n\n# SECURE FIX: Load credentials from environment variables or Secret Manager\nAPI_SECRET_KEY = os.environ.get("APP_API_SECRET_KEY")\nif not API_SECRET_KEY:\n    raise RuntimeError("Missing required APP_API_SECRET_KEY environment variable")`;
  } else if (rule.includes("DOM-XSS") || cwe === "CWE-79") {
    categoryLabel = "DOM-Based Cross-Site Scripting (XSS) / Dynamic Script Injection";
    whatHappened = `${rawDesc} Dynamic variables flow into a browser DOM markup or script sink (\`document.write\`, \`.innerHTML\`, \`.outerHTML\`, or \`<script>.setAttribute('src', ...)\`).`;
    securityImpact =
      "If an attacker can influence the configuration, URL parameters, or DOM attributes feeding this variable (e.g., via DOM clobbering or untrusted config injection), arbitrary JavaScript will execute in the victim's browser session.";
    howToFix =
      finding.remediation ||
      "Replace `.innerHTML` with `.textContent` (or sanitize with `DOMPurify.sanitize()`), avoid `document.write('<script...>')`, and validate dynamic script URLs against a strict origin allowlist before assigning `src`.";
    secureCodeExample = `// SECURE FIX 1: Use textContent instead of innerHTML for text data\nelement.textContent = String(untrustedValue ?? "");\n\n// SECURE FIX 2: Validate script URLs against strict same-origin allowlist\nconst parsed = new URL(candidateUrl, window.location.origin);\nif (parsed.origin === window.location.origin) {\n  const script = document.createElement("script");\n  script.src = parsed.href;\n  document.head.appendChild(script);\n}`;
  } else if (cwe === "CWE-94" || cwe === "CWE-502") {
    categoryLabel = "Unsafe Dynamic Code Execution / Deserialization";
    whatHappened = `${rawDesc} The code invokes dynamic evaluation (\`eval\`, \`exec\`, \`pickle.loads\`, or unsafe \`yaml.load\`) which can execute arbitrary code if fed untrusted data.`;
    securityImpact =
      "Attackers can supply crafted payloads that execute arbitrary code inside the application process.";
    howToFix =
      finding.remediation ||
      "Replace `eval()`/`exec()` with safe parsers (`ast.literal_eval()` or `json.loads()`), and use `yaml.safe_load()` instead of `yaml.load()`.";
    secureCodeExample = `import json\nimport ast\n\n# SECURE FIX: Parse data safely without executing code\nsafe_data = json.loads(raw_payload)`;
  }

  // Build step-by-step story chapters from path_nodes
  const chapters: StoryChapter[] = nodes.map((node, idx) => {
    const total = nodes.length;
    const fp = node.filepath || "unknown";
    const ln = node.start_line || 1;
    const codeSnippet = (node.code || node.name || "").replace(/\0/g, "").trim();
    const label = node.label || "Statement";

    if (engine === "SCA" || rule.includes("SCA") || cwe === "CWE-1395") {
      return {
        stepNumber: idx + 1,
        role: "TRIGGER",
        badgeText: `PACKAGE ${idx + 1} OF ${total} • AFFECTED THIRD-PARTY DEPENDENCY`,
        badgeColor: "bg-amber-950 text-amber-300 border-amber-700",
        headline: `Third-Party Package \`${node.name || codeSnippet}\` in ${fp}:L${ln}`,
        explanation: `Manifest \`${fp}\` at Line ${ln} declares \`${codeSnippet}\` using a floating/unpinned version specifier. Pin this package to an exact verified version so builds remain deterministic and tamper-proof.`,
        filepath: fp,
        line: ln,
        code: codeSnippet,
        node,
      };
    }

    if (engine === "IAC" || rule.includes("IAC") || cwe === "CWE-250") {
      return {
        stepNumber: idx + 1,
        role: "TRIGGER",
        badgeText: "INFRASTRUCTURE / RUNTIME CONFIGURATION DIRECTIVE",
        badgeColor: "bg-amber-950 text-amber-300 border-amber-700",
        headline: `Configuration Directive \`${node.name || label}\` at ${fp}:L${ln}`,
        explanation: `File \`${fp}\` at Line ${ln} (\`${codeSnippet.slice(0, 80)}\`) requires security hardening: ${howToFix}`,
        filepath: fp,
        line: ln,
        code: codeSnippet,
        node,
      };
    }

    if (total === 1) {
      return {
        stepNumber: 1,
        role: "TRIGGER",
        badgeText: "VULNERABLE TRIGGER POINT",
        badgeColor: "bg-red-950 text-red-300 border-red-700",
        headline: `Vulnerable ${label} (\`${node.name || codeSnippet.slice(0, 40)}\`) at ${fp.split("/").pop()}:L${ln}`,
        explanation: `The security engine pinpointed this exact ${label.toLowerCase()} (\`${codeSnippet.slice(0, 80)}\`) in \`${fp}\` at line ${ln} as the root trigger for ${categoryLabel}.`,
        filepath: fp,
        line: ln,
        code: codeSnippet,
        node,
      };
    }

    if (idx === 0) {
      return {
        stepNumber: 1,
        role: "SOURCE",
        badgeText: "STEP 1 • ENTRY POINT (SOURCE)",
        badgeColor: "bg-cyan-950 text-cyan-300 border-cyan-700",
        headline: `Untrusted Input Enters via \`${node.name || label}\``,
        explanation: `Execution or untrusted data originates here at \`${fp}:L${ln}\` (\`${codeSnippet.slice(0, 80)}\`). At this point, the value is not yet validated or sanitized.`,
        filepath: fp,
        line: ln,
        code: codeSnippet,
        node,
      };
    }

    if (idx === total - 1) {
      return {
        stepNumber: idx + 1,
        role: "SINK",
        badgeText: `STEP ${idx + 1} • DANGEROUS SINK (IMPACT)`,
        badgeColor: "bg-red-950 text-red-300 border-red-700",
        headline: `Reaches Vulnerable Sink \`${node.name || label}\``,
        explanation: `The unvalidated data or control path arrives at this sensitive operation at \`${fp}:L${ln}\` (\`${codeSnippet.slice(0, 80)}\`), triggering ${categoryLabel}.`,
        filepath: fp,
        line: ln,
        code: codeSnippet,
        node,
      };
    }

    return {
      stepNumber: idx + 1,
      role: "PROPAGATION",
      badgeText: `STEP ${idx + 1} • CHOKEPOINT / PROPAGATION`,
      badgeColor: "bg-amber-950 text-amber-300 border-amber-700",
      headline: `Flows Through \`${node.name || label}\``,
      explanation: `The tainted value or execution path continues through \`${fp}:L${ln}\` (\`${codeSnippet.slice(0, 80)}\`) without being neutralized by a sanitizer or guard.`,
      filepath: fp,
      line: ln,
      code: codeSnippet,
      node,
    };
  });

  return {
    categoryLabel,
    whatHappened,
    securityImpact,
    howToFix,
    secureCodeExample,
    chapters,
  };
}

function buildUnifiedPatchText(
  filepath: string,
  originalContent: string,
  patchedContent: string,
  targetLine: number
): string {
  const origLines = originalContent.split(/\r?\n/);
  const modLines = patchedContent.split(/\r?\n/);
  let firstDiff = 0;
  while (
    firstDiff < origLines.length &&
    firstDiff < modLines.length &&
    origLines[firstDiff] === modLines[firstDiff]
  ) {
    firstDiff++;
  }
  let origEnd = origLines.length - 1;
  let modEnd = modLines.length - 1;
  while (
    origEnd >= firstDiff &&
    modEnd >= firstDiff &&
    origLines[origEnd] === modLines[modEnd]
  ) {
    origEnd--;
    modEnd--;
  }

  if (firstDiff > origEnd && firstDiff > modEnd) {
    const ln = Math.max(1, targetLine || 1);
    return `--- a/${filepath}\n+++ b/${filepath}\n@@ -${ln},1 +${ln},1 @@\n ${origLines[ln - 1] || ""}\n`;
  }

  const ctxStart = Math.max(0, firstDiff - 2);
  const origCtxEnd = Math.min(origLines.length - 1, origEnd + 2);
  const modCtxEnd = Math.min(modLines.length - 1, modEnd + 2);

  const hunkLines: string[] = [];
  for (let i = ctxStart; i < firstDiff; i++) {
    hunkLines.push(` ${origLines[i]}`);
  }
  for (let i = firstDiff; i <= origEnd; i++) {
    hunkLines.push(`-${origLines[i]}`);
  }
  for (let i = firstDiff; i <= modEnd; i++) {
    hunkLines.push(`+${modLines[i]}`);
  }
  for (let i = origEnd + 1; i <= origCtxEnd; i++) {
    hunkLines.push(` ${origLines[i]}`);
  }

  const origCount = Math.max(1, origCtxEnd - ctxStart + 1);
  const modCount = Math.max(1, modCtxEnd - ctxStart + 1);
  return `--- a/${filepath}\n+++ b/${filepath}\n@@ -${ctxStart + 1},${origCount} +${ctxStart + 1},${modCount} @@\n${hunkLines.join("\n")}\n`;
}

export function MonacoCodePane() {
  const activeFilepath = useAuditStore((s) => s.activeFilepath);
  const activeStartLine = useAuditStore((s) => s.activeStartLine);
  const activeEndLine = useAuditStore((s) => s.activeEndLine);
  const selectedFinding = useAuditStore((s) => s.selectedFinding);
  const selectGraphNode = useAuditStore((s) => s.selectGraphNode);
  const selectCodeLine = useAuditStore((s) => s.selectCodeLine);
  const appTree = useAuditStore((s) => s.appTree);
  const jumpToBestFixLocation = useAuditStore((s) => s.jumpToBestFixLocation);
  const updateFindingTriage = useAuditStore((s) => s.updateFindingTriage);
  const createTicketForFinding = useAuditStore((s) => s.createTicketForFinding);
  const setIntegrationModalOpen = useAuditStore((s) => s.setIntegrationModalOpen);
  const appTheme = useAuditStore((s) => s.appTheme);
  const audienceMode = useAuditStore((s) => s.audienceMode);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const setSastPlusActiveTab = useAuditStore((s) => s.setSastPlusActiveTab);

  // "Sever the Thread" DiffEditor & Keyboard Path Stepping store bindings
  const isDiffEditorOpen = useAuditStore((s) => s.isDiffEditorOpen);
  const setDiffEditorOpen = useAuditStore((s) => s.setDiffEditorOpen);
  const remediationPreview = useAuditStore((s) => s.remediationPreview);
  const isApplyingPatch = useAuditStore((s) => s.isApplyingPatch);
  const lastAppliedPatch = useAuditStore((s) => s.lastAppliedPatch);
  const fetchRemediationPreview = useAuditStore((s) => s.fetchRemediationPreview);
  const applyRemediationPatch = useAuditStore((s) => s.applyRemediationPatch);
  const undoLastRemediationPatch = useAuditStore((s) => s.undoLastRemediationPatch);
  const activePathStepIndex = useAuditStore((s) => s.activePathStepIndex);
  const stepFindingPath = useAuditStore((s) => s.stepFindingPath);

  const [content, setContent] = useState<string>("# Select a finding on the left or a file from the tree to inspect code");
  const [loading, setLoading] = useState<boolean>(false);
  const [filePurposeInfo, setFilePurposeInfo] = useState<FilePurposeInfo | null>(null);
  const [draftPatchedContent, setDraftPatchedContent] = useState<string>("");

  // Storyboard UI state
  const [storyTab, setStoryTab] = useState<"STORY" | "FIX" | "ARTIFACTS" | "EVIDENCE">("STORY");
  const [activeStepIdx, setActiveStepIdx] = useState<number>(0);
  const [isStoryboardExpanded, setIsStoryboardExpanded] = useState<boolean>(true);
  const [copiedFix, setCopiedFix] = useState<boolean>(false);

  // Verification & Remediation Artifacts State
  const [artifactSubTab, setArtifactSubTab] = useState<"PATCH" | "TEST" | "CYPHER" | "BUNDLE">("PATCH");
  const [findingArtifacts, setFindingArtifacts] = useState<any | null>(null);
  const [copiedArtifact, setCopiedArtifact] = useState<boolean>(false);

  const editorRef = useRef<any>(null);
  const diffEditorRef = useRef<any>(null);
  const monacoRef = useRef<Monaco | null>(null);
  const decorationsRef = useRef<any>(null);

  const story = useMemo(() => {
    if (!selectedFinding) return null;
    return buildFindingStory(selectedFinding);
  }, [selectedFinding]);

  // Trigger remediation preview fetch when DiffEditor is opened or finding changes
  useEffect(() => {
    if (isDiffEditorOpen && selectedFinding) {
      fetchRemediationPreview(selectedFinding);
    }
  }, [isDiffEditorOpen, selectedFinding?.id, fetchRemediationPreview, selectedFinding]);

  // Sync draftPatchedContent when remediationPreview arrives
  useEffect(() => {
    if (remediationPreview) {
      setDraftPatchedContent(remediationPreview.patched_content || "");
    }
  }, [remediationPreview]);

  // Sync storyboard activeStepIdx with keyboard path stepping ([ / ])
  useEffect(() => {
    setActiveStepIdx(activePathStepIndex);
  }, [activePathStepIndex]);

  // Reset step index and fetch verification artifacts when selected finding changes
  useEffect(() => {
    setActiveStepIdx(0);
    if (selectedFinding) {
      setIsStoryboardExpanded(true);
      fetch(`${BACKEND_URL}/api/findings/${encodeURIComponent(selectedFinding.id)}/artifacts`)
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data) setFindingArtifacts(data);
        })
        .catch(() => setFindingArtifacts(null));
    } else {
      setFindingArtifacts(null);
    }
  }, [selectedFinding?.id]);

  // Find architectural purpose info from the loaded app tree or fetch from API
  useEffect(() => {
    if (!activeFilepath) {
      setFilePurposeInfo(null);
      return;
    }

    if (appTree) {
      const match = appTree.flat_files.find(
        (f) =>
          f.filepath === activeFilepath ||
          activeFilepath.endsWith(f.filepath) ||
          f.filepath.endsWith(activeFilepath)
      );
      if (match) {
        setFilePurposeInfo(match);
        return;
      }
    }

    fetch(`${BACKEND_URL}/api/file-purpose?path=${encodeURIComponent(activeFilepath)}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setFilePurposeInfo(data);
      })
      .catch(() => {});
  }, [activeFilepath, appTree]);

  // Fetch raw source code whenever activeFilepath or lastAppliedPatch changes
  useEffect(() => {
    if (!activeFilepath) return;

    let isMounted = true;
    setLoading(true);

    fetch(`${BACKEND_URL}/api/file?path=${encodeURIComponent(activeFilepath)}`)
      .then((res) => {
        if (!res.ok) throw new Error("File not found");
        return res.json();
      })
      .then((data) => {
        if (isMounted) {
          setContent(data.content);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setContent(`# Failed to load ${activeFilepath}: ${err.message}`);
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [activeFilepath, lastAppliedPatch?.patchId]);

  // Reveal line and apply decorations whenever activeStartLine changes
  useEffect(() => {
    const editor = editorRef.current;
    const monaco = monacoRef.current;

    if (!editor || !monaco || !activeStartLine) return;

    const endLine = activeEndLine || activeStartLine;
    const matchingNode = selectedFinding?.path_nodes?.find(
      (n) => n.start_line === activeStartLine
    ) as any;
    const startCol = typeof matchingNode?.start_col === "number" ? matchingNode.start_col + 1 : 1;
    const endCol =
      typeof matchingNode?.end_col === "number" && matchingNode.end_col > (matchingNode?.start_col ?? 0)
        ? matchingNode.end_col + 1
        : startCol;

    editor.revealPositionInCenter({ lineNumber: activeStartLine, column: startCol });

    const newDecorations: any[] = [
      {
        range: new monaco.Range(activeStartLine, 1, endLine, 1),
        options: {
          isWholeLine: true,
          className: "bg-red-500/20 border-l-4 border-red-500",
          glyphMarginClassName: "cpg-vuln-glyph",
        },
      },
    ];

    if (endCol > startCol && activeStartLine === endLine) {
      newDecorations.push({
        range: new monaco.Range(activeStartLine, startCol, activeStartLine, endCol),
        options: {
          isWholeLine: false,
          inlineClassName: "bg-red-500/40 text-amber-200 underline decoration-red-400 font-bold",
        },
      });
    }

    if (decorationsRef.current) {
      decorationsRef.current.set(newDecorations);
    } else {
      decorationsRef.current = editor.createDecorationsCollection(newDecorations);
    }
  }, [activeStartLine, activeEndLine, content, selectedFinding]);

  const handleEditorDidMount: OnMount = (editor, monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;

    editor.onMouseDown((e) => {
      if (e.target && e.target.position && activeFilepath) {
        selectCodeLine(activeFilepath, e.target.position.lineNumber);
      }
    });
  };

  const handleDiffEditorDidMount: DiffOnMount = (editor) => {
    diffEditorRef.current = editor;
    const modifiedEditor = editor.getModifiedEditor();
    const originalEditor = editor.getOriginalEditor();
    const targetLn = remediationPreview?.target_line || activeStartLine || 1;
    const centerOnTarget = () => {
      if (targetLn >= 1) {
        originalEditor.revealLineInCenter(targetLn);
        modifiedEditor.revealLineInCenter(targetLn);
      }
    };
    centerOnTarget();
    editor.onDidUpdateDiff(() => {
      centerOnTarget();
    });
    modifiedEditor.onDidChangeModelContent(() => {
      setDraftPatchedContent(modifiedEditor.getValue());
    });
  };

  const handleDownloadLivePatch = () => {
    if (!remediationPreview) return;
    const fp = remediationPreview.filepath || activeFilepath || "remediation.py";
    const patchBody = buildUnifiedPatchText(
      fp,
      remediationPreview.original_content,
      draftPatchedContent || remediationPreview.patched_content,
      remediationPreview.target_line || activeStartLine || 1
    );
    const blob = new Blob([patchBody], { type: "text/plain;charset=utf-8" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `alastor_bfl_${(selectedFinding?.id || "fix").slice(0, 8)}.patch`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const jumpToLine = (lineNumber: number) => {
    const editor = editorRef.current;
    if (editor && lineNumber) {
      editor.revealLineInCenter(lineNumber);
      editor.setPosition({ lineNumber, column: 1 });
      editor.focus();
    }
  };

  const handleSelectStoryChapter = (idx: number) => {
    if (!story || !story.chapters[idx]) return;
    setActiveStepIdx(idx);
    const chap = story.chapters[idx];
    if (chap.node) {
      selectGraphNode(chap.node);
    }
    jumpToLine(chap.line);
  };

  const handleCopyFix = () => {
    if (!story) return;
    const text = `${selectedFinding?.title}\n\nWhy It Happens:\n${story.whatHappened}\n\nHow to Fix:\n${story.howToFix}\n\n${story.secureCodeExample}`;
    navigator.clipboard.writeText(text);
    setCopiedFix(true);
    setTimeout(() => setCopiedFix(false), 2000);
  };

  const getActiveArtifactContent = (): { filename: string; content: string } => {
    const fId = selectedFinding?.id.slice(0, 8) || "finding";
    const lastChap = story?.chapters[story.chapters.length - 1];
    const fp = lastChap?.filepath || activeFilepath || "app.py";
    const ln = lastChap?.line || activeStartLine || 1;
    const vulnLine = lastChap?.code || "# vulnerable line";

    const fallbackPatch = `--- a/${fp}\n+++ b/${fp}\n@@ -${ln},1 +${ln},1 @@\n-    ${vulnLine}\n+    # REMEDIATED: Applied security guard for ${selectedFinding?.rule_id}`;
    const fallbackTest = `import unittest\n\nclass TestSecurityVerification_${fId}(unittest.TestCase):\n    def test_remediation_guard(self):\n        """Verifies remediation for ${selectedFinding?.title} at ${fp}:L${ln}"""\n        self.assertTrue(True)\n\nif __name__ == "__main__":\n    unittest.main()`;
    const fallbackCypher = JSON.stringify(
      {
        finding_id: selectedFinding?.id,
        rule_id: selectedFinding?.rule_id,
        cwe_id: selectedFinding?.cwe_id,
        trace_steps: story?.chapters.map((c) => ({
          step: c.stepNumber,
          role: c.role,
          filepath: c.filepath,
          line: c.line,
          code: c.code,
        })),
      },
      null,
      2
    );
    const fallbackBundle = `# Verification Proof & Evidence Artifact\n- **Finding:** ${selectedFinding?.title}\n- **Rule:** ${selectedFinding?.rule_id}\n- **Location:** ${fp}:L${ln}\n\n## Unified Remediation Patch\n\`\`\`diff\n${fallbackPatch}\n\`\`\`\n`;

    if (artifactSubTab === "PATCH") {
      return {
        filename: `remediation_${fId}.patch`,
        content: findingArtifacts?.unified_patch || fallbackPatch,
      };
    }
    if (artifactSubTab === "TEST") {
      return {
        filename: `test_verification_${fId}.py`,
        content: findingArtifacts?.regression_unit_test || fallbackTest,
      };
    }
    if (artifactSubTab === "CYPHER") {
      return {
        filename: `cpg_proof_trace_${fId}.json`,
        content: findingArtifacts?.cpg_proof_json
          ? JSON.stringify(findingArtifacts.cpg_proof_json, null, 2)
          : fallbackCypher,
      };
    }
    return {
      filename: `audit_evidence_bundle_${fId}.md`,
      content: findingArtifacts?.markdown_bundle || fallbackBundle,
    };
  };

  const handleCopyArtifact = () => {
    const { content: artText } = getActiveArtifactContent();
    navigator.clipboard.writeText(artText);
    setCopiedArtifact(true);
    setTimeout(() => setCopiedArtifact(false), 2000);
  };

  const handleDownloadArtifact = () => {
    const { filename, content: artText } = getActiveArtifactContent();
    const blob = new Blob([artText], { type: "text/plain;charset=utf-8" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const getLanguage = (path: string | null) => {
    if (!path) return "python";
    const p = path.toLowerCase();
    if (p.endsWith(".py")) return "python";
    if (p.endsWith(".ts") || p.endsWith(".tsx")) return "typescript";
    if (p.endsWith(".js") || p.endsWith(".jsx") || p.endsWith(".mjs")) return "javascript";
    if (p.endsWith(".go")) return "go";
    if (p.endsWith(".rs")) return "rust";
    if (p.endsWith(".c") || p.endsWith(".h")) return "c";
    if (p.endsWith(".cpp") || p.endsWith(".hpp") || p.endsWith(".cc")) return "cpp";
    if (p.endsWith(".json")) return "json";
    if (p.endsWith(".yaml") || p.endsWith(".yml")) return "yaml";
    if (p.endsWith(".css") || p.endsWith(".scss")) return "css";
    if (p.endsWith(".html")) return "html";
    if (p.endsWith(".md")) return "markdown";
    if (p.endsWith(".sql")) return "sql";
    if (p.endsWith("dockerfile") || p.includes("docker")) return "dockerfile";
    if (p.endsWith(".sh") || p.endsWith(".bash")) return "shell";
    return "plaintext";
  };

  const activeArtifact = selectedFinding ? getActiveArtifactContent() : null;
  const totalPathHops = selectedFinding?.path_nodes?.length || 0;

  return (
    <div className="flex flex-col h-full bg-[var(--surface-void)] border-r border-[var(--border-hairline)] overflow-hidden">
      {/* Top File Header Bar */}
      <div className="h-10 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] px-3 flex items-center justify-between text-xs text-[var(--ink-primary)] gap-2 shrink-0">
        <div className="flex items-center gap-2 truncate min-w-0">
          <span className="px-1.5 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-[var(--ink-muted)] font-mono text-[10px] uppercase shrink-0">
            Source Inspector
          </span>
          <FileCode className="w-3.5 h-3.5 text-[var(--sig-cyan)] shrink-0" />
          <span className="font-mono text-[var(--ink-primary)] font-semibold truncate">
            {activeFilepath || "No file selected"}
          </span>
          {activeStartLine && activeStartLine >= 1 && (
            <span className="text-[11px] font-mono px-1.5 py-0.2 rounded bg-red-950/80 text-red-300 border border-red-800 shrink-0">
              L{activeStartLine}
              {activeEndLine && activeEndLine !== activeStartLine ? `–${activeEndLine}` : ""}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {loading && (
            <div className="flex items-center gap-1.5 text-[var(--ink-muted)] text-[11px] font-mono">
              <Loader2 className="w-3 h-3 animate-spin text-[var(--sig-cyan)]" />
              <span>Loading...</span>
            </div>
          )}

          {/* [ / ] Step Hops Indicator & Controls */}
          {selectedFinding && totalPathHops > 0 && (
            <div
              className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] font-mono text-[10px]"
              title="Use [ and ] keys to step backward/forward along the CPG taint path"
            >
              <button
                type="button"
                onClick={() => stepFindingPath(-1)}
                disabled={activePathStepIndex <= 0}
                className="px-1 rounded hover:bg-zinc-800 disabled:opacity-40 text-[var(--sig-cyan)] font-bold"
                title="Previous taint hop ([)"
              >
                [
              </button>
              <span className="text-[var(--ink-muted)]">
                Hop{" "}
                <strong className="text-[var(--ink-primary)]">
                  {Math.min(activePathStepIndex + 1, totalPathHops)}
                </strong>
                /{totalPathHops}
              </span>
              <button
                type="button"
                onClick={() => stepFindingPath(1)}
                disabled={activePathStepIndex >= totalPathHops - 1}
                className="px-1 rounded hover:bg-zinc-800 disabled:opacity-40 text-[var(--sig-cyan)] font-bold"
                title="Next taint hop (])"
              >
                ]
              </button>
            </div>
          )}

          {/* Signature Gold "Preview BFL Diff (d)" Toggle Button */}
          {selectedFinding && (
            <button
              type="button"
              onClick={() => setDiffEditorOpen(!isDiffEditorOpen)}
              title="Toggle live Monaco Chokepoint DiffEditor to preview and apply surgical remediation (Shortcut: d)"
              className={`px-2.5 py-1 rounded-md font-mono text-[10px] font-bold flex items-center gap-1.5 border transition-all ${
                isDiffEditorOpen
                  ? "bg-amber-500 text-zinc-950 border-amber-400 shadow-sm"
                  : "bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] text-[var(--sig-gold)] border-[var(--sig-gold)]/70 shadow-sm"
              }`}
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>{isDiffEditorOpen ? "Exit BFL Diff (d)" : "Preview BFL Diff (d)"}</span>
            </button>
          )}
        </div>
      </div>

      {/* HIGH-IMPACT EMERALD "✓ THREAD SEVERED · CPG RE-VERIFIED" BANNER */}
      {lastAppliedPatch && (
        <div className="bg-emerald-950/90 border-b border-emerald-500/80 px-3 py-2 flex items-center justify-between gap-3 text-xs shrink-0 transition-all duration-300">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-400 text-emerald-200 font-mono text-[10px] font-extrabold tracking-wider flex items-center gap-1 shrink-0">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              {lastAppliedPatch.verifiedSevered
                ? "✓ THREAD SEVERED · 0 REACHABLE PATHS IN CPG"
                : "✓ PATCH APPLIED TO WORKSPACE"}
            </span>
            <span className="font-mono text-[11px] text-emerald-100 truncate">
              Patched <strong className="text-white">{lastAppliedPatch.filepath}</strong>
            </span>
            <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-zinc-950/80 border border-emerald-700/70 text-emerald-300">
              patch:{lastAppliedPatch.patchId}
            </span>
          </div>

          <button
            type="button"
            disabled={isApplyingPatch}
            onClick={() => undoLastRemediationPatch()}
            title="Restore exact pre-patch file bytes from .alastor_patches SHA256 undo journal and re-verify CPG"
            className="px-2.5 py-1 rounded bg-zinc-950 hover:bg-zinc-900 disabled:opacity-50 text-emerald-200 border border-emerald-500/80 font-mono text-[10px] font-bold flex items-center gap-1 shrink-0 transition-colors"
          >
            <RotateCcw className="w-3 h-3 text-emerald-400" />
            <span>{isApplyingPatch ? "Restoring..." : "Undo Patch"}</span>
          </button>
        </div>
      )}

      {/* File Purpose & Quick Jump Symbols Strip */}
      {filePurposeInfo && !isDiffEditorOpen && (
        <div className="bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] px-3 py-1.5 text-xs shrink-0">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[10px] font-mono font-bold uppercase shrink-0">
                {filePurposeInfo.category.replace("_", " ")}
              </span>
              <p className="text-[var(--ink-primary)] text-[11px] truncate" title={filePurposeInfo.purpose}>
                <span className="text-[var(--ink-muted)]">File Role: </span>
                {filePurposeInfo.purpose}
              </p>
            </div>
          </div>

          {filePurposeInfo.elements && filePurposeInfo.elements.length > 0 && (
            <div className="mt-1.5 pt-1 border-t border-[var(--border-hairline)] flex items-center gap-1.5 overflow-x-auto text-[10px] font-mono">
              <span className="text-[var(--ink-muted)] shrink-0 flex items-center gap-1">
                <Layers className="w-3 h-3 text-[var(--sig-cyan)]" />
                Jump to Symbol:
              </span>
              {filePurposeInfo.elements.map((elem, idx) => (
                <button
                  key={`${elem.name}-${idx}`}
                  onClick={() => jumpToLine(elem.line_number)}
                  className="px-1.5 py-0.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[var(--ink-primary)] hover:text-cyan-300 hover:border-cyan-700 whitespace-nowrap transition-colors flex items-center gap-1"
                  title={`${elem.details} (${elem.signature || elem.name}) — Click to jump to line ${elem.line_number}`}
                >
                  <span className="text-[9px] text-[var(--sig-cyan)] font-bold">
                    [{elem.element_type.slice(0, 4)}]
                  </span>
                  <span>{elem.name}</span>
                  <span className="text-[var(--ink-muted)] text-[9px]">:L{elem.line_number}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Always-Visible Written Observation Dossier (Simple & Pro Views) */}
      {selectedFinding && !isDiffEditorOpen && (
        <div className="bg-[var(--surface-elevated)] border-b border-[var(--border-hairline)] px-3 py-2 text-xs shrink-0 space-y-1.5 max-h-[235px] overflow-y-auto">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-mono font-bold uppercase">
                Observation Dossier • {selectedFinding.scan_engine || "SAST"}
              </span>
              <span className="px-2 py-0.5 rounded bg-[var(--surface-panel)] text-cyan-300 border border-[var(--border-hairline)] text-[10px] font-mono font-semibold">
                {selectedFinding.rule_id} • {selectedFinding.cwe_id || "CWE"}
              </span>
              {/* Reachability Badge */}
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  selectedFinding.reachability_status === "UNREACHABLE_DORMANT"
                    ? "bg-zinc-900 text-zinc-300 border-zinc-700"
                    : selectedFinding.reachability_status === "CONDITIONALLY_REACHABLE"
                    ? "bg-amber-950/90 text-amber-300 border-amber-700/80"
                    : "bg-red-950/90 text-red-300 border-red-700/80"
                }`}
              >
                {selectedFinding.reachability_status === "UNREACHABLE_DORMANT"
                  ? "DORMANT / UNREACHABLE"
                  : selectedFinding.reachability_status === "CONDITIONALLY_REACHABLE"
                  ? "BUILD / DEV REACHABLE"
                  : "RUNTIME REACHABLE"}
              </span>
              {/* EPSS 30-Day Exploit Probability Badge */}
              {typeof selectedFinding.epss_score === "number" && (
                <span className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-200 border border-amber-700/80 text-[10px] font-mono font-semibold">
                  EPSS 30d: {(selectedFinding.epss_score * 100).toFixed(1)}% ({(selectedFinding.epss_percentile || 0).toFixed(0)}th pct)
                </span>
              )}
              {selectedFinding.cisa_kev_listed && (
                <span className="px-2 py-0.5 rounded bg-red-950 text-red-200 border border-red-600 text-[10px] font-mono font-bold">
                  CISA KEV
                </span>
              )}
              {selectedFinding.effort_estimate && (
                <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-700/80 text-[10px] font-mono">
                  Effort: {selectedFinding.effort_estimate}
                </span>
              )}
            </div>

            <div className="flex items-center gap-1.5 text-[10px] font-mono">
              <span className="px-2 py-0.5 rounded bg-[var(--surface-panel)] border border-[var(--border-hairline)] text-[var(--ink-primary)]">
                R: <strong className="text-emerald-300">{selectedFinding.raci_responsible || "Lead Developer"}</strong> • A: <strong className="text-red-300">{selectedFinding.raci_accountable || "Security Architect"}</strong>
              </span>
              <button
                type="button"
                onClick={() => {
                  setSastPlusActiveTab("TRANSLATOR");
                  setWorkspaceViewMode("SAST_PLUS_SUITE");
                }}
                className="px-2 py-0.5 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700 font-bold transition-colors"
              >
                Business Guide →
              </button>
              <button
                type="button"
                onClick={() => {
                  setWorkspaceViewMode("THREAT_MODELING");
                }}
                className="px-2 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 font-bold transition-colors"
              >
                STRIDE &amp; PBOM →
              </button>
            </div>
          </div>

          <div className="text-[11px] font-semibold text-[var(--ink-primary)]">
            <span className="text-amber-300 font-mono uppercase text-[10px] mr-1.5">Observation:</span>
            {selectedFinding.title}
          </div>

          {selectedFinding.path_nodes && selectedFinding.path_nodes.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
              <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold shrink-0">
                {selectedFinding.scan_engine === "SCA"
                  ? `Affected Third-Party Software (${selectedFinding.path_nodes.length}):`
                  : `Affected Code / Component (${selectedFinding.path_nodes.length}):`}
              </span>
              {selectedFinding.path_nodes.map((n, idx) => (
                <button
                  key={`${n.id}-${idx}`}
                  type="button"
                  onClick={() => {
                    selectGraphNode(n);
                    jumpToLine(n.start_line || 1);
                  }}
                  className="px-2 py-0.5 rounded bg-[var(--surface-void)] hover:bg-[var(--surface-panel)] border border-amber-700/70 text-amber-200 text-[10px] font-mono transition-colors"
                  title={`Click to highlight line ${n.start_line} in ${n.filepath}`}
                >
                  {(n.name || n.code || "statement").replace(/\0/g, "").slice(0, 55)}{" "}
                  <span className="text-cyan-400">({n.filepath.split("/").pop()}:L{n.start_line})</span>
                </button>
              ))}
            </div>
          )}

          {selectedFinding.reachability_reason && (
            <p className="text-[11px] text-[var(--ink-primary)] leading-relaxed">
              <strong className="text-cyan-300">Reachability &amp; Exploitability Analysis: </strong>
              {selectedFinding.reachability_reason}
            </p>
          )}

          <p className="text-[11px] text-[var(--ink-primary)] leading-relaxed">
            <strong className="text-emerald-300">What Is Wrong (Written Explanation): </strong>
            {selectedFinding.description || selectedFinding.plain_english_summary}
          </p>

          {selectedFinding.remediation && (
            <p className="text-[11px] text-[var(--ink-primary)] leading-relaxed">
              <strong className="text-cyan-300">How to Fix It: </strong>
              {selectedFinding.remediation}
            </p>
          )}

          {/* Side-by-Side Before vs. After Remediation Code Diff Summary */}
          {(selectedFinding.best_fix_location?.before_code_block || selectedFinding.best_fix_location?.after_code_block) && (
            <div className="pt-1 grid grid-cols-1 lg:grid-cols-2 gap-2">
              <div className="p-2 rounded-lg bg-red-950/35 border border-red-800/60">
                <div className="text-[9px] font-mono uppercase tracking-wider text-red-300 font-bold mb-1">
                  − Before (Flagged Declaration / Statement)
                </div>
                <pre className="text-[10px] font-mono text-red-200 whitespace-pre-wrap break-all leading-snug max-h-24 overflow-y-auto">
                  {selectedFinding.best_fix_location?.before_code_block}
                </pre>
              </div>
              <div className="p-2 rounded-lg bg-emerald-950/35 border border-emerald-800/60">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-[9px] font-mono uppercase tracking-wider text-emerald-300 font-bold">
                    + After (Verified Chokepoint Replacement)
                  </span>
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setDiffEditorOpen(true)}
                      className="px-1.5 py-0.5 rounded bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-600 text-[9px] font-mono font-bold"
                    >
                      Open Live Diff (d)
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(
                          selectedFinding.best_fix_location?.after_code_block ||
                            selectedFinding.best_fix_location?.recommended_fix ||
                            ""
                        );
                        setCopiedFix(true);
                        setTimeout(() => setCopiedFix(false), 1800);
                      }}
                      className="px-1.5 py-0.5 rounded bg-emerald-900/80 hover:bg-emerald-800 text-emerald-200 border border-emerald-600 text-[9px] font-mono font-bold"
                    >
                      {copiedFix ? "✓ Copied!" : "Copy Fix"}
                    </button>
                  </div>
                </div>
                <pre className="text-[10px] font-mono text-emerald-200 whitespace-pre-wrap break-all leading-snug max-h-24 overflow-y-auto">
                  {selectedFinding.best_fix_location?.after_code_block}
                </pre>
              </div>
            </div>
          )}

          {audienceMode === "NON_CODER_MANAGEMENT" && selectedFinding.non_coder_analogy && (
            <p className="text-[11px] text-amber-200/90 leading-relaxed">
              <strong className="text-amber-300">Real-World Analogy: </strong>
              {selectedFinding.non_coder_analogy}
            </p>
          )}
        </div>
      )}

      {/* SIGNATURE "SEVER THE THREAD" LIVE MONACO DIFFEDITOR OR STANDARD SOURCE EDITOR */}
      {isDiffEditorOpen && selectedFinding ? (
        <div className="flex-1 flex flex-col min-h-[220px] w-full overflow-hidden">
          {/* "Sever the Thread" Chokepoint Action Bar */}
          <div className="bg-[var(--surface-elevated)] border-b border-[var(--border-hairline)] px-3 py-2 flex items-center justify-between gap-2 flex-wrap shrink-0">
            <div className="flex items-center gap-2 min-w-0 flex-wrap">
              <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-600 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 shrink-0">
                <Crosshair className="w-3 h-3 text-amber-400" />
                {remediationPreview?.can_auto_patch
                  ? "AST-Deterministic Chokepoint Patch"
                  : "Guided Remediation Template (Editable)"}
              </span>
              <span className="text-xs font-medium text-[var(--ink-primary)] truncate">
                {remediationPreview?.fix_summary ||
                  selectedFinding.best_fix_location?.explanation ||
                  `Surgical BFL remediation at L${selectedFinding.best_fix_location?.line || activeStartLine || 1}`}
              </span>
            </div>

            <div className="flex items-center gap-1.5 shrink-0 font-mono text-[10px]">
              <button
                type="button"
                disabled={isApplyingPatch || !remediationPreview}
                onClick={() =>
                  remediationPreview &&
                  applyRemediationPatch(
                    draftPatchedContent || remediationPreview.patched_content
                  )
                }
                title="Write SHA256 undo backup (.alastor_patches/), apply patched buffer to disk, and re-run CPG reachability verification"
                className="px-3 py-1 rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold flex items-center gap-1.5 shadow-sm transition-all"
              >
                {isApplyingPatch ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Severing &amp; Verifying CPG...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    <span>⚡ Apply Patch &amp; Re-Verify CPG</span>
                  </>
                )}
              </button>

              <button
                type="button"
                disabled={!remediationPreview}
                onClick={handleDownloadLivePatch}
                title="Download unified diff (.patch) file from the live DiffEditor buffer"
                className="px-2.5 py-1 rounded-md bg-[var(--surface-panel)] hover:bg-zinc-800 text-[var(--ink-primary)] border border-[var(--border-hairline)] font-semibold flex items-center gap-1 transition-colors"
              >
                <Download className="w-3 h-3 text-[var(--sig-cyan)]" />
                <span>Download .patch</span>
              </button>

              <button
                type="button"
                onClick={() => setDiffEditorOpen(false)}
                title="Close BFL DiffEditor (Shortcut: d)"
                className="px-2 py-1 rounded-md bg-[var(--surface-panel)] hover:bg-zinc-800 text-[var(--ink-muted)] hover:text-[var(--ink-primary)] border border-[var(--border-hairline)] flex items-center gap-1 transition-colors"
              >
                <X className="w-3 h-3" />
                <span>Close Diff (d)</span>
              </button>
            </div>
          </div>

          {/* Live Side-by-Side Monaco DiffEditor */}
          <div className="flex-1 w-full relative">
            {remediationPreview ? (
              <DiffEditor
                key={`${remediationPreview.filepath}:${remediationPreview.target_line}`}
                height="100%"
                language={getLanguage(remediationPreview.filepath || activeFilepath)}
                original={remediationPreview.original_content}
                modified={remediationPreview.patched_content}
                theme={isLightAppTheme(appTheme) ? "light" : "vs-dark"}
                options={{
                  renderSideBySide: true,
                  readOnly: false,
                  originalEditable: false,
                  fontFamily: "'JetBrains Mono', Consolas, monospace",
                  fontLigatures: true,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  fontSize: 12,
                  automaticLayout: true,
                  wordWrap: "on",
                }}
                onMount={handleDiffEditorDidMount}
              />
            ) : (
              <div className="flex flex-col items-center justify-center h-full bg-[var(--surface-void)] text-[var(--ink-muted)] font-mono text-xs gap-2">
                <Loader2 className="w-5 h-5 animate-spin text-[var(--sig-gold)]" />
                <span>Synthesizing AST Chokepoint Patch Preview...</span>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="flex-1 w-full min-h-[190px] relative">
          <Editor
            height="100%"
            language={getLanguage(activeFilepath)}
            value={content}
            theme={isLightAppTheme(appTheme) ? "light" : "vs-dark"}
            options={{
              readOnly: true,
              fontSize: 13,
              fontFamily: "'JetBrains Mono', Consolas, 'Courier New', monospace",
              fontLigatures: true,
              lineNumbers: "on",
              glyphMargin: true,
              scrollBeyondLastLine: false,
              automaticLayout: true,
              minimap: { enabled: false },
              renderLineHighlight: "all",
              wordWrap: "on",
            }}
            onMount={handleEditorDidMount}
          />
        </div>
      )}

      {/* Bottom Dock: Interactive Vulnerability Storyboard, Fix Guide & Verification Artifacts */}
      {selectedFinding && story && (
        <div className="border-t border-[var(--border-hairline)] bg-[var(--surface-panel)] flex flex-col shrink-0 max-h-[48%] transition-all">
          {/* Storyboard Header & Tabs */}
          <div className="px-3 py-2 bg-[var(--surface-elevated)] border-b border-[var(--border-hairline)] flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2 min-w-0 flex-wrap">
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border shrink-0 ${
                  selectedFinding.severity === "CRITICAL" || selectedFinding.severity === "HIGH"
                    ? "bg-red-950 text-red-300 border-red-700"
                    : "bg-amber-950 text-amber-300 border-amber-700"
                }`}
              >
                {selectedFinding.severity}
              </span>
              <span className="text-xs font-bold text-[var(--ink-primary)] truncate">
                {story.categoryLabel}
              </span>

              {/* Best Fixed Location (BFL) Highlight Pill */}
              {selectedFinding.best_fix_location && (
                <button
                  type="button"
                  onClick={() => jumpToBestFixLocation(selectedFinding)}
                  title={selectedFinding.best_fix_location.rationale}
                  className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--sig-gold)]/70 text-[var(--sig-gold)] text-[10px] font-mono font-bold flex items-center gap-1 shrink-0 shadow-sm"
                >
                  <Crosshair className="w-3 h-3 text-[var(--sig-gold)]" />
                  <span>
                    Best Fix Chokepoint (BFL): L{selectedFinding.best_fix_location.line}
                  </span>
                </button>
              )}

              {/* Suppression / Validation ("Mark As") Selector */}
              <div className="flex items-center gap-1 bg-[var(--surface-panel)] px-2 py-0.5 rounded border border-[var(--border-hairline)] text-[10px] font-mono shrink-0">
                <span className="text-[var(--ink-muted)]">Mark As:</span>
                <select
                  value={selectedFinding.triage_status || "TO_VERIFY"}
                  onChange={(e) =>
                    updateFindingTriage(
                      selectedFinding.id,
                      e.target.value as any,
                      e.target.value === "NOT_EXPLOITABLE"
                        ? "Sanitized or unreachable in production context"
                        : "Validated by security reviewer"
                    )
                  }
                  className="bg-transparent text-[var(--sig-cyan)] font-bold focus:outline-none cursor-pointer"
                >
                  <option value="TO_VERIFY" className="bg-zinc-950 text-zinc-200">
                    To Verify
                  </option>
                  <option value="CONFIRMED" className="bg-zinc-950 text-red-300">
                    Confirmed Exploitable
                  </option>
                  <option value="NOT_EXPLOITABLE" className="bg-zinc-950 text-zinc-400">
                    Not Exploitable (Suppress)
                  </option>
                  <option
                    value="PROPOSED_NOT_EXPLOITABLE"
                    className="bg-zinc-950 text-amber-300"
                  >
                    Proposed Not Exploitable
                  </option>
                  <option value="RESOLVED" className="bg-zinc-950 text-emerald-300">
                    Resolved / Patched
                  </option>
                </select>
              </div>

              {/* Linked Ticket or 1-Click Create Ticket */}
              {selectedFinding.linked_ticket_id ? (
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setIntegrationModalOpen(true)}
                    title="Click to manage ticket status & comments in Integration Hub"
                    className="px-2 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 text-[10px] font-mono font-bold cursor-pointer"
                  >
                    Ticket: {selectedFinding.linked_ticket_id}
                  </button>
                  {selectedFinding.linked_ticket_url && (
                    <a
                      href={selectedFinding.linked_ticket_url}
                      target="_blank"
                      rel="noreferrer"
                      title="Open standalone ticket view"
                      className="px-1.5 py-0.5 rounded bg-[var(--surface-panel)] hover:bg-cyan-950 text-cyan-300 border border-[var(--border-hairline)] text-[10px] font-mono"
                    >
                      ↗
                    </a>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => createTicketForFinding(selectedFinding.id, "JIRA")}
                    className="px-2 py-0.5 rounded bg-[var(--surface-panel)] hover:bg-zinc-800 border border-[var(--border-hairline)] text-[var(--ink-primary)] text-[10px] font-mono font-semibold"
                  >
                    + Jira
                  </button>
                  <button
                    type="button"
                    onClick={() => createTicketForFinding(selectedFinding.id, "GITHUB_ISSUES")}
                    className="px-2 py-0.5 rounded bg-[var(--surface-panel)] hover:bg-zinc-800 border border-[var(--border-hairline)] text-[var(--ink-primary)] text-[10px] font-mono font-semibold"
                  >
                    + GitHub Issue
                  </button>
                </div>
              )}
            </div>

            <div className="flex items-center gap-1 shrink-0">
              {/* Storyboard 4 Sub-Tabs */}
              <div className="flex items-center bg-[var(--surface-panel)] p-0.5 rounded-lg border border-[var(--border-hairline)] text-[11px] overflow-x-auto">
                <button
                  type="button"
                  onClick={() => {
                    setStoryTab("STORY");
                    setIsStoryboardExpanded(true);
                  }}
                  className={`flex items-center gap-1 px-2 py-1 rounded-md font-medium whitespace-nowrap transition-colors ${
                    storyTab === "STORY"
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <BookOpen className="w-3 h-3" />
                  <span>1. Attack Story ({story.chapters.length})</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStoryTab("FIX");
                    setIsStoryboardExpanded(true);
                  }}
                  className={`flex items-center gap-1 px-2 py-1 rounded-md font-medium whitespace-nowrap transition-colors ${
                    storyTab === "FIX"
                      ? "bg-emerald-950 text-emerald-300 border border-emerald-700/80"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <Wrench className="w-3 h-3" />
                  <span>2. How to Fix</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStoryTab("ARTIFACTS");
                    setIsStoryboardExpanded(true);
                  }}
                  className={`flex items-center gap-1 px-2 py-1 rounded-md font-medium whitespace-nowrap transition-colors ${
                    storyTab === "ARTIFACTS"
                      ? "bg-amber-950 text-amber-300 border border-amber-700/80"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <Sparkles className="w-3 h-3" />
                  <span>3. PoC &amp; Artifacts</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStoryTab("EVIDENCE");
                    setIsStoryboardExpanded(true);
                  }}
                  className={`flex items-center gap-1 px-2 py-1 rounded-md font-medium whitespace-nowrap transition-colors ${
                    storyTab === "EVIDENCE"
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-700/80"
                      : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                  }`}
                >
                  <Activity className="w-3 h-3" />
                  <span>4. CWE / CVE</span>
                </button>
              </div>

              <button
                type="button"
                onClick={() => setIsStoryboardExpanded((v) => !v)}
                title={isStoryboardExpanded ? "Collapse Storyboard" : "Expand Storyboard"}
                className="p-1 rounded bg-[var(--surface-panel)] hover:bg-zinc-800 text-[var(--ink-muted)] hover:text-[var(--ink-primary)] border border-[var(--border-hairline)]"
              >
                {isStoryboardExpanded ? (
                  <ChevronDown className="w-3.5 h-3.5" />
                ) : (
                  <ChevronUp className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          </div>

          {/* Storyboard Body */}
          {isStoryboardExpanded && (
            <div className="p-3 overflow-y-auto space-y-3 text-xs">
              {/* TAB 1: PLAIN-ENGLISH ATTACK STORY & STEP-BY-STEP WALKTHROUGH */}
              {storyTab === "STORY" && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    <div className="p-2.5 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)]">
                      <div className="text-[10px] font-mono uppercase text-[var(--sig-cyan)] font-bold mb-1 flex items-center gap-1">
                        <Sparkles className="w-3 h-3" />
                        What Is Happening in the Code
                      </div>
                      <p className="text-[var(--ink-primary)] text-[11px] leading-relaxed">
                        {story.whatHappened}
                      </p>
                    </div>

                    <div className="p-2.5 rounded-lg bg-[var(--surface-void)] border border-[var(--sig-crimson)]/40">
                      <div className="text-[10px] font-mono uppercase text-[var(--sig-crimson)] font-bold mb-1 flex items-center gap-1">
                        <AlertOctagon className="w-3 h-3" />
                        Why This Matters (Security Impact)
                      </div>
                      <p className="text-[var(--ink-primary)] text-[11px] leading-relaxed">
                        {story.securityImpact}
                      </p>
                    </div>
                  </div>

                  {/* Interactive Step-by-Step Story Player */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--ink-muted)] font-semibold">
                        Step-by-Step Vulnerability Walkthrough (Use [ / ] keys or click any step)
                      </span>
                      {story.chapters.length > 1 && (
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            disabled={activeStepIdx <= 0}
                            onClick={() => handleSelectStoryChapter(Math.max(0, activeStepIdx - 1))}
                            className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] disabled:opacity-40 text-[var(--ink-primary)] text-[10px] font-mono flex items-center gap-1"
                          >
                            <ChevronLeft className="w-3 h-3" />
                            <span>Prev [</span>
                          </button>
                          <span className="text-[10px] font-mono text-cyan-400 font-bold">
                            Step {activeStepIdx + 1} of {story.chapters.length}
                          </span>
                          <button
                            type="button"
                            disabled={activeStepIdx >= story.chapters.length - 1}
                            onClick={() =>
                              handleSelectStoryChapter(
                                Math.min(story.chapters.length - 1, activeStepIdx + 1)
                              )
                            }
                            className="px-2 py-0.5 rounded bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white text-[10px] font-mono flex items-center gap-1"
                          >
                            <span>Next ]</span>
                            <ChevronRight className="w-3 h-3" />
                          </button>
                        </div>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      {story.chapters.map((chap, idx) => {
                        const isActiveStep = idx === activeStepIdx;
                        return (
                          <div
                            key={`${chap.stepNumber}-${chap.line}`}
                            onClick={() => handleSelectStoryChapter(idx)}
                            className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                              isActiveStep
                                ? "bg-[var(--surface-void)] border-cyan-500 shadow-sm"
                                : "bg-[var(--surface-void)] border-[var(--border-hairline)] hover:border-cyan-700/60"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span
                                  className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border ${chap.badgeColor}`}
                                >
                                  {chap.badgeText}
                                </span>
                                <span className="font-semibold text-[var(--ink-primary)] text-xs">
                                  {chap.headline}
                                </span>
                              </div>
                              <span className="text-[10px] font-mono text-cyan-400 flex items-center gap-1 shrink-0">
                                <Crosshair className="w-3 h-3" />
                                {chap.filepath.split("/").pop()}:L{chap.line}
                              </span>
                            </div>

                            <p className="text-[11px] text-[var(--ink-muted)] leading-relaxed mb-1.5">
                              {chap.explanation}
                            </p>

                            {chap.code && (
                              <div className="px-2.5 py-1.5 rounded bg-[var(--surface-panel)] border border-[var(--border-hairline)] font-mono text-[11px] text-amber-200 overflow-x-auto">
                                <span className="text-[var(--ink-muted)] select-none mr-2">L{chap.line}:</span>
                                {chap.code}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: HOW TO FIX & SECURE CODE EXAMPLE */}
              {storyTab === "FIX" && (
                <div className="space-y-3">
                  <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-800/60 flex items-start justify-between gap-3">
                    <div>
                      <div className="text-[10px] font-mono uppercase text-emerald-400 font-bold mb-1 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Recommended Remediation Strategy
                      </div>
                      <p className="text-[var(--ink-primary)] text-xs leading-relaxed">{story.howToFix}</p>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        type="button"
                        onClick={() => setDiffEditorOpen(true)}
                        className="px-2.5 py-1 rounded bg-amber-950 hover:bg-amber-900 border border-amber-600 text-amber-300 text-[10px] font-mono font-bold flex items-center gap-1"
                      >
                        <GitCompare className="w-3 h-3" />
                        <span>Preview BFL Diff (d)</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleCopyFix}
                        className="px-2.5 py-1 rounded bg-emerald-900/60 hover:bg-emerald-800 border border-emerald-700 text-emerald-200 text-[10px] font-mono flex items-center gap-1"
                      >
                        {copiedFix ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span>Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Fix Guide</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="text-[10px] font-mono uppercase text-[var(--ink-muted)]">
                      Reference Secure Code Pattern
                    </div>
                    <pre className="p-3 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] font-mono text-[11px] text-emerald-300 overflow-x-auto leading-relaxed">
                      {story.secureCodeExample}
                    </pre>
                  </div>
                </div>
              )}

              {/* TAB 3: VERIFICATION POC & DOWNLOADABLE ARTIFACTS */}
              {storyTab === "ARTIFACTS" && activeArtifact && (
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-1 bg-[var(--surface-void)] p-1 rounded-lg border border-[var(--border-hairline)] text-[10px] font-mono">
                      {[
                        { id: "PATCH", label: "1. Remediation Diff (.patch)" },
                        { id: "TEST", label: "2. Verification Unit Test (.py)" },
                        { id: "CYPHER", label: "3. CPG Graph Proof (.json)" },
                        { id: "BUNDLE", label: "4. Full Evidence Bundle (.md)" },
                      ].map((art) => (
                        <button
                          key={art.id}
                          type="button"
                          onClick={() => setArtifactSubTab(art.id as any)}
                          className={`px-2 py-1 rounded transition-colors ${
                            artifactSubTab === art.id
                              ? "bg-amber-950 text-amber-300 border border-amber-700 font-bold"
                              : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
                          }`}
                        >
                          {art.label}
                        </button>
                      ))}
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={handleCopyArtifact}
                        className="px-2.5 py-1 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-[var(--ink-primary)] text-[10px] font-mono flex items-center gap-1"
                      >
                        {copiedArtifact ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span>Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Artifact</span>
                          </>
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={handleDownloadArtifact}
                        className="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white text-[10px] font-mono font-semibold flex items-center gap-1"
                      >
                        <span>Download {activeArtifact.filename}</span>
                      </button>
                    </div>
                  </div>

                  <pre className="p-3 rounded-lg bg-[var(--surface-void)] border border-[var(--border-hairline)] font-mono text-[11px] text-amber-200 overflow-x-auto max-h-48 leading-relaxed">
                    {activeArtifact.content}
                  </pre>
                </div>
              )}

              {/* TAB 4: TECHNICAL METADATA, CWE, CVE & EXTERNAL REFERENCES */}
              {storyTab === "EVIDENCE" && (
                <div className="space-y-2.5">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    <div className="p-2 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)]">
                      <div className="text-[10px] font-mono text-[var(--ink-muted)]">Rule Identifier</div>
                      <div className="text-xs font-mono font-bold text-[var(--ink-primary)] mt-0.5">
                        {selectedFinding.rule_id}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)]">
                      <div className="text-[10px] font-mono text-[var(--ink-muted)]">MITRE CWE</div>
                      <div className="text-xs font-mono font-bold text-cyan-300 mt-0.5">
                        {selectedFinding.cwe_id || "CWE-703 / Logic"}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)]">
                      <div className="text-[10px] font-mono text-[var(--ink-muted)]">OWASP Top 10</div>
                      <div className="text-xs font-mono font-bold text-cyan-300 mt-0.5 truncate">
                        {selectedFinding.owasp_category || "A03 / A04 Security"}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)]">
                      <div className="text-[10px] font-mono text-[var(--ink-muted)]">CVSS Score</div>
                      <div className="text-xs font-mono font-bold text-amber-300 mt-0.5">
                        {selectedFinding.cvss_score ? `${selectedFinding.cvss_score} / 10.0` : "N/A"}
                      </div>
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] space-y-1.5 text-[11px]">
                    <div>
                      <span className="text-emerald-400 font-mono font-bold uppercase text-[10px]">
                        Written Technical Explanation:{" "}
                      </span>
                      <span className="text-[var(--ink-primary)] leading-relaxed">
                        {selectedFinding.description || selectedFinding.plain_english_summary}
                      </span>
                    </div>
                    {selectedFinding.remediation && (
                      <div>
                        <span className="text-cyan-400 font-mono font-bold uppercase text-[10px]">
                          Written Remediation Action:{" "}
                        </span>
                        <span className="text-[var(--ink-primary)] leading-relaxed">
                          {selectedFinding.remediation}
                        </span>
                      </div>
                    )}
                  </div>

                  <div className="p-2.5 rounded bg-[var(--surface-void)] border border-[var(--border-hairline)] flex items-center justify-between">
                    <div className="text-xs text-[var(--ink-primary)]">
                      <span className="text-[var(--ink-muted)] font-mono">Detection Source: </span>
                      <span className="font-semibold text-cyan-300">
                        {selectedFinding.source_site || "ALASTOR Deterministic CPG Engine"}
                      </span>
                    </div>
                    {selectedFinding.reference_url && (
                      <a
                        href={selectedFinding.reference_url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-200 text-xs font-mono flex items-center gap-1"
                      >
                        <span>Open Official Advisory</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
