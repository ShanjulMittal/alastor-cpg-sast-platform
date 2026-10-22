"use client";

import React, { useEffect, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Sparkles,
  GraduationCap,
  Package,
  Compass,
  Layers,
  BookOpen,
  Download,
  Crosshair,
  Ticket,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Users,
  Clock,
  Lightbulb,
  Briefcase,
  Search,
  FileCode2,
} from "lucide-react";

const ACADEMY_GLOSSARY = [
  {
    term: "SAST (Static Application Security Testing)",
    category: "Core Engine",
    analogy:
      "Like an architectural blueprint inspector who checks a building's wiring and fire exits on paper before anyone moves in.",
    plainMeaning:
      "Analyzes source code files directly without needing to run the program, finding security flaws early during development.",
    managementWhy:
      "Fixing a bug during coding costs 10x–30x less than fixing it after a production launch or data breach.",
  },
  {
    term: "SCA (Software Composition Analysis) & SBOM",
    category: "Supply Chain",
    analogy:
      "Like an FDA nutrition & ingredient label (SBOM) that checks whether any third-party ingredient in your kitchen has been recalled.",
    plainMeaning:
      "Audits open-source libraries and third-party packages (in requirements.txt or package.json) for known vulnerabilities and unpinned versions.",
    managementWhy:
      "Over 80% of modern application code comes from third-party libraries; U.S. Executive Order 14028 & enterprise buyers require a CycloneDX SBOM.",
  },
  {
    term: "IaC (Infrastructure as Code) Scanning",
    category: "Cloud & Containers",
    analogy:
      "Like checking the digital lock and alarm settings on the shipping container that holds your product.",
    plainMeaning:
      "Inspects Dockerfiles, docker-compose.yml, and deployment configs for hardcoded passwords or overly permissive 'root' administrator settings.",
    managementWhy:
      "Even secure code can be breached if the cloud container hosting it leaves default passwords or root access open.",
  },
  {
    term: "CPG (Code Property Graph: AST + CFG + DFG)",
    category: "ALASTOR Core Tech",
    analogy:
      "Like a 3D GPS subway map of the entire software application showing every station (AST), train track switch (CFG), and passenger journey (DFG).",
    plainMeaning:
      "Combines Syntax (AST), Control Flow (CFG), and Data Flow (DFG) into a single Neo4j mathematical graph to prove whether an attack is actually reachable.",
    managementWhy:
      "Eliminates false alarms (false positives) so engineers don't waste sprint hours chasing fake warnings.",
  },
  {
    term: "Source → Propagation → Sink (Taint Analysis)",
    category: "Attack Mechanics",
    analogy:
      "Tracing a drop of dye from a water intake pipe (Source) through building pipes (Propagation) to see if it reaches a drinking faucet (Sink) without passing through a water filter (Sanitizer).",
    plainMeaning:
      "Tracks untrusted user input from where it enters the app (Source) to where it executes a sensitive command or database query (Sink).",
    managementWhy:
      "Proves the exact end-to-end story of how a hacker could exploit the system.",
  },
  {
    term: "Best Fixed Location (BFL Chokepoint)",
    category: "Remediation Efficiency",
    analogy:
      "Putting one water filter on the main building pipe instead of installing 20 separate filters on every individual sink.",
    plainMeaning:
      "The single optimal line of code where adding validation or sanitization neutralizes the vulnerability across all downstream paths.",
    managementWhy:
      "Cuts engineering fix time from hours to minutes and minimizes regression risk.",
  },
  {
    term: "RACI Governance Matrix (R / A / C / I)",
    category: "Management & GRC",
    analogy:
      "A flight crew checklist where everyone knows who flies the plane (R), who is the Captain in command (A), who advises from air traffic control (C), and who receives arrival updates (I).",
    plainMeaning:
      "Maps Responsible, Accountable, Consulted, and Informed roles across security tasks and findings.",
    managementWhy:
      "Prevents 'dropped balls' and SLA breaches by ensuring every security activity has exactly one Accountable owner.",
  },
  {
    term: "CWE, CVE & CVSS Severity Score",
    category: "Risk Standards",
    analogy:
      "CWE is the category of illness (e.g., 'Flu'), CVE is a specific outbreak strain ('2026-Flu-Variant'), and CVSS (0.0–10.0) is the fever thermometer reading.",
    plainMeaning:
      "Standardized global identifiers from MITRE and NIST used to classify weakness types (CWE), public package advisories (CVE), and numerical severity (CVSS).",
    managementWhy:
      "Allows executives and auditors to prioritize fixes objektivly (e.g., CVSS >= 9.0 Critical must be fixed within 7 days).",
  },
];

export function SastPlusSuiteView() {
  const sastPlusSuite = useAuditStore((s) => s.sastPlusSuite);
  const fetchSastPlusSuite = useAuditStore((s) => s.fetchSastPlusSuite);
  const sastPlusActiveTab = useAuditStore((s) => s.sastPlusActiveTab);
  const setSastPlusActiveTab = useAuditStore((s) => s.setSastPlusActiveTab);
  const findings = useAuditStore((s) => s.findings);
  const appTree = useAuditStore((s) => s.appTree);
  const projectPath = useAuditStore((s) => s.projectPath);
  const jumpToBestFixLocation = useAuditStore((s) => s.jumpToBestFixLocation);
  const openCodeLocationInIde = useAuditStore((s) => s.openCodeLocationInIde);
  const createTicketForFinding = useAuditStore((s) => s.createTicketForFinding);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);

  const activeAppPath = appTree?.root_path || projectPath || "cpg-sast-platform";
  const activeAppName =
    activeAppPath.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ||
    "cpg-sast-platform";

  const [searchFilter, setSearchFilter] = useState("");
  const [showRawCdx, setShowRawCdx] = useState(false);

  useEffect(() => {
    fetchSastPlusSuite();
  }, [fetchSastPlusSuite]);

  const handleDownloadSbom = () => {
    const cdx = sastPlusSuite?.cyclonedx_json || {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [],
    };
    const blob = new Blob([JSON.stringify(cdx, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alastor-sbom-cyclonedx.cdx.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const sbomComponents = sastPlusSuite?.sbom_components || [];
  const endpoints = sastPlusSuite?.endpoints || [];
  const roadmapItems = sastPlusSuite?.roadmap_items || [];
  const strideThreats = sastPlusSuite?.stride_threats || [];
  const pipelineChecks = sastPlusSuite?.pipeline_checks || [];

  const filteredFindings = findings.filter((f) => {
    if (!searchFilter.trim()) return true;
    const q = searchFilter.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      (f.plain_english_summary || "").toLowerCase().includes(q) ||
      (f.non_coder_analogy || "").toLowerCase().includes(q) ||
      (f.cwe_id || "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="flex-1 h-full overflow-y-auto bg-zinc-950/90 p-5 text-zinc-100 space-y-5">
      {/* Top Hero Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-rose-950/45 via-zinc-900/90 to-indigo-950/45 border border-rose-700/50 p-5 shadow-xl">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="space-y-1.5 max-w-3xl">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2.5 py-0.5 rounded-full bg-rose-950 text-rose-300 border border-rose-700 text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1">
                <Sparkles className="w-3.5 h-3.5 text-rose-400" />
                Ultimate SAST ++++++ ASPM &amp; Non-Coder Command Center
              </span>
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-200 border border-cyan-600 text-[10px] font-mono font-bold">
                Application: {activeAppName}
              </span>
              <span className="px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-mono font-bold">
                {activeAppPath}
              </span>
            </div>
            <h1 className="text-xl font-bold text-white">
              Plain-English Business Risk, Live CycloneDX SBOM, STRIDE Threat Model &amp; Attack Surface —{" "}
              <span className="text-cyan-300">{activeAppName}</span>
            </h1>
            <p className="text-xs text-zinc-300 leading-relaxed">
              {sastPlusSuite?.executive_plain_summary ||
                "Translating compiler-grade Code Property Graph (CPG) discoveries into plain-English analogies, business impact, live supply-chain SBOM inventories, STRIDE threat models, and phased management roadmaps."}
            </p>
          </div>

          {/* Maturity Scorecard */}
          <div className="flex items-center gap-4 bg-zinc-950/90 border border-zinc-800 rounded-xl p-3.5 shrink-0">
            <div>
              <div className="text-[10px] font-mono uppercase text-zinc-400">
                Security Maturity Grade
              </div>
              <div className="text-lg font-mono font-extrabold text-emerald-400">
                {sastPlusSuite?.overall_maturity_grade || "B (Managed)"}
              </div>
              <div className="text-[10px] font-mono text-zinc-500">
                Score: {sastPlusSuite?.maturity_score ?? 82}/100
              </div>
            </div>
            <div className="border-l border-zinc-800 pl-4 space-y-1 text-[11px] font-mono">
              <div className="text-cyan-300">
                SBOM Components:{" "}
                <strong>{sastPlusSuite?.total_sbom_components ?? 0}</strong>
              </div>
              <div className="text-amber-300">
                Discovered Entrypoints:{" "}
                <strong>{sastPlusSuite?.discovered_endpoints_count ?? 0}</strong>
              </div>
              <div className="text-indigo-300">
                Reachable / Dormant:{" "}
                <strong>
                  {sastPlusSuite?.reachable_findings_count ?? findings.length} /{" "}
                  {sastPlusSuite?.dormant_findings_count ?? 0}
                </strong>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 6-Pillar Navigation Bar */}
      <div className="flex items-center justify-between gap-2 flex-wrap border-b border-zinc-800 pb-2.5">
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            type="button"
            onClick={() => setSastPlusActiveTab("TRANSLATOR")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all ${
              sastPlusActiveTab === "TRANSLATOR"
                ? "bg-emerald-950 text-emerald-300 border border-emerald-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <GraduationCap className="w-4 h-4 text-emerald-400" />
            <span>
              1. Plain-English Impact Translator ({findings.length})
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSastPlusActiveTab("SBOM")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all ${
              sastPlusActiveTab === "SBOM"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <Package className="w-4 h-4 text-cyan-400" />
            <span>
              2. Live SBOM &amp; Supply Chain ({sbomComponents.length})
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSastPlusActiveTab("ATTACK_SURFACE")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all ${
              sastPlusActiveTab === "ATTACK_SURFACE"
                ? "bg-amber-950 text-amber-300 border border-amber-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <Compass className="w-4 h-4 text-amber-400" />
            <span>
              3. API &amp; Entrypoint Attack Surface ({endpoints.length})
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSastPlusActiveTab("ROADMAP")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all ${
              sastPlusActiveTab === "ROADMAP"
                ? "bg-indigo-950 text-indigo-300 border border-indigo-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <Layers className="w-4 h-4 text-indigo-400" />
            <span>
              4. Management Remediation Roadmap ({roadmapItems.length})
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSastPlusActiveTab("THREAT_MODEL")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all ${
              sastPlusActiveTab === "THREAT_MODEL"
                ? "bg-purple-950 text-purple-200 border border-purple-600 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <ShieldAlert className="w-4 h-4 text-purple-400" />
            <span>
              5. STRIDE Threat Model &amp; CI/CD PBOM ({strideThreats.length + pipelineChecks.length})
            </span>
          </button>

          <button
            type="button"
            onClick={() => setSastPlusActiveTab("ACADEMY")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all ${
              sastPlusActiveTab === "ACADEMY"
                ? "bg-rose-950 text-rose-300 border border-rose-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <BookOpen className="w-4 h-4 text-rose-400" />
            <span>6. Non-Coder Security Academy &amp; Glossary</span>
          </button>
        </div>
      </div>

      {/* PILLAR 1: PLAIN-ENGLISH BUSINESS IMPACT TRANSLATOR FOR NON-CODERS */}
      {sastPlusActiveTab === "TRANSLATOR" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3 flex-wrap bg-zinc-900/70 border border-zinc-800 p-3.5 rounded-xl">
            <div className="text-xs text-zinc-300 flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-amber-400 shrink-0" />
              <span>
                <strong>No Coding Required:</strong> Every technical finding is
                translated below into a{" "}
                <strong className="text-emerald-300">
                  Plain-English Explanation
                </strong>
                , a{" "}
                <strong className="text-amber-300">Real-World Analogy</strong>,{" "}
                <strong className="text-rose-300">Business Impact</strong>, and
                a{" "}
                <strong className="text-cyan-300">
                  3-Step Management Action Plan
                </strong>
                .
              </span>
            </div>
            <div className="relative w-64">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Filter by keyword or CWE..."
                className="w-full bg-zinc-950 border border-zinc-700 rounded-lg pl-8 pr-3 py-1 text-xs text-zinc-200"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {filteredFindings.map((f) => {
              const fp =
                f.best_fix_location?.filepath ||
                (f.path_nodes && f.path_nodes.length > 0
                  ? f.path_nodes[f.path_nodes.length - 1].filepath
                  : "app.py");
              const ln =
                f.best_fix_location?.line ||
                (f.path_nodes && f.path_nodes.length > 0
                  ? f.path_nodes[f.path_nodes.length - 1].start_line
                  : 1);

              return (
                <div
                  key={f.id}
                  className="rounded-2xl bg-zinc-900/75 border border-zinc-800 p-4 flex flex-col justify-between space-y-3.5 shadow-lg hover:border-zinc-700 transition-all"
                >
                  <div className="space-y-2.5">
                    {/* Header Badges */}
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            f.severity === "CRITICAL"
                              ? "bg-red-950 text-red-300 border-red-700"
                              : f.severity === "HIGH"
                              ? "bg-amber-950 text-amber-300 border-amber-700"
                              : "bg-cyan-950 text-cyan-300 border-cyan-800"
                          }`}
                        >
                          {f.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-[10px] font-mono text-zinc-300">
                          {f.scan_engine || "SAST"} • {f.cwe_id || "CWE"}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/70 text-[10px] font-mono text-rose-200">
                          {f.financial_risk_tier || "Enterprise Risk"}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            f.reachability_status === "UNREACHABLE_DORMANT"
                              ? "bg-zinc-950 text-zinc-400 border-zinc-700"
                              : f.reachability_status === "CONDITIONALLY_REACHABLE"
                              ? "bg-amber-950 text-amber-300 border-amber-700"
                              : "bg-emerald-950 text-emerald-300 border-emerald-700"
                          }`}
                        >
                          {f.reachability_status === "UNREACHABLE_DORMANT"
                            ? "💤 Dormant Path"
                            : f.reachability_status === "CONDITIONALLY_REACHABLE"
                            ? "⚙️ Build/Dev Reachable"
                            : "🎯 Runtime Reachable"}
                        </span>
                        {typeof f.epss_score === "number" && (
                          <span className="px-2 py-0.5 rounded bg-indigo-950/90 border border-indigo-700 text-[10px] font-mono text-indigo-200 font-semibold">
                            EPSS 30d: {(f.epss_score * 100).toFixed(1)}%
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] font-mono text-emerald-400 font-semibold">
                        {fp}:L{ln}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-white">{f.title}</h3>

                    {/* Affected Third-Party Software / Flagged Code Statement */}
                    <div className="p-2.5 rounded-xl bg-zinc-950 border border-cyan-900/50 space-y-1">
                      <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold">
                        {f.scan_engine === "SCA"
                          ? `Affected Third-Party Software (${f.path_nodes?.length || 1} package${(f.path_nodes?.length || 1) === 1 ? "" : "s"}):`
                          : `Affected Component / Code Statement (${fp}:L${ln}):`}
                      </div>
                      {f.scan_engine === "SCA" && f.path_nodes && f.path_nodes.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {f.path_nodes.map((pn, pIdx) => (
                            <span
                              key={pn.id || pIdx}
                              className="px-2 py-0.5 rounded bg-amber-950/50 border border-amber-700/60 text-amber-200 font-mono text-[10px]"
                            >
                              {pn.name} ({pn.filepath}:L{pn.start_line})
                            </span>
                          ))}
                        </div>
                      ) : (
                        <div className="text-[11px] font-mono text-amber-200 break-all">
                          {f.best_fix_location?.code_snippet ||
                            (f.path_nodes && f.path_nodes.length > 0
                              ? f.path_nodes[f.path_nodes.length - 1].code ||
                                f.path_nodes[f.path_nodes.length - 1].name
                              : fp)}
                        </div>
                      )}
                    </div>

                    {/* Written Technical Explanation & Remediation */}
                    <div className="p-3 rounded-xl bg-amber-950/20 border border-amber-800/50 space-y-1.5">
                      <div className="text-[10px] font-mono uppercase tracking-wider text-amber-300 font-bold">
                        Written Observation Details (What Is Wrong &amp; Why)
                      </div>
                      <p className="text-xs text-zinc-200 leading-relaxed">
                        {f.description}
                      </p>
                      {f.remediation && (
                        <div className="pt-1.5 border-t border-amber-900/40 text-xs text-emerald-200 leading-relaxed">
                          <strong className="text-emerald-400">How to Fix: </strong>
                          {f.remediation}
                        </div>
                      )}
                    </div>

                    {/* Plain English Box */}
                    <div className="p-3 rounded-xl bg-zinc-950/90 border border-emerald-800/50 space-y-1">
                      <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-1">
                        <GraduationCap className="w-3.5 h-3.5" />
                        In Plain English (For Non-Coders)
                      </div>
                      <p className="text-xs text-zinc-200 leading-relaxed">
                        {f.plain_english_summary || f.description}
                      </p>
                    </div>

                    {/* Real-World Analogy Box */}
                    {f.non_coder_analogy && (
                      <div className="p-3 rounded-xl bg-amber-950/25 border border-amber-800/50 space-y-1">
                        <div className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1">
                          <Lightbulb className="w-3.5 h-3.5" />
                          Real-World Analogy
                        </div>
                        <p className="text-xs text-amber-100/90 italic leading-relaxed">
                          &ldquo;{f.non_coder_analogy}&rdquo;
                        </p>
                      </div>
                    )}

                    {/* Business & Regulatory Impact */}
                    {f.business_impact && (
                      <div className="p-3 rounded-xl bg-rose-950/25 border border-rose-800/50 space-y-1">
                        <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400 font-bold flex items-center gap-1">
                          <Briefcase className="w-3.5 h-3.5" />
                          Business, Financial &amp; Compliance Impact
                        </div>
                        <p className="text-xs text-zinc-200 leading-relaxed">
                          {f.business_impact}
                        </p>
                      </div>
                    )}

                    {/* Step-by-Step Management Action Plan */}
                    {f.management_action_steps &&
                      f.management_action_steps.length > 0 && (
                        <div className="p-3 rounded-xl bg-zinc-950 border border-zinc-800 space-y-1">
                          <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold">
                            Management Action Checklist
                          </div>
                          <ul className="space-y-1 text-[11px] text-zinc-300">
                            {f.management_action_steps.map((step, idx) => (
                              <li key={idx} className="leading-relaxed">
                                {step}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                  </div>

                  {/* Footer: RACI Roles, Effort & Quick Buttons */}
                  <div className="pt-3 border-t border-zinc-800 flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap text-[10px] font-mono">
                      <span className="px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-700/70 text-emerald-300">
                        R: {f.raci_responsible || "Lead Dev"}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-rose-950/70 border border-rose-700/70 text-rose-300">
                        A: {f.raci_accountable || "Security Lead"}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-300 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-cyan-400" />
                        {f.effort_estimate || "~20 mins"}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() => jumpToBestFixLocation(f)}
                        className="px-2.5 py-1 rounded-lg bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-200 text-[11px] font-semibold flex items-center gap-1"
                      >
                        <Crosshair className="w-3 h-3 text-emerald-400" />
                        <span>View Fix in IDE</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setWorkspaceViewMode("RACI_GOVERNANCE")}
                        className="px-2.5 py-1 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-700/80 text-amber-200 text-[11px] font-semibold flex items-center gap-1"
                      >
                        <Users className="w-3 h-3 text-amber-400" />
                        <span>RACI</span>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* PILLAR 2: LIVE SBOM & SUPPLY-CHAIN INSPECTOR */}
      {sastPlusActiveTab === "SBOM" && (
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-zinc-900/80 border border-zinc-800 flex items-center justify-between flex-wrap gap-3">
            <div className="space-y-1">
              <div className="text-sm font-bold text-white flex items-center gap-2">
                <Package className="w-4 h-4 text-cyan-400" />
                Live Software Bill of Materials (CycloneDX v1.5 Specification)
              </div>
              <p className="text-xs text-zinc-400">
                Dynamically extracted from your workspace manifests (
                <code>requirements.txt</code>, <code>package.json</code>) and
                scanned runtime imports. Total:{" "}
                <strong className="text-white">
                  {sastPlusSuite?.total_sbom_components ?? 0}
                </strong>{" "}
                components ({sastPlusSuite?.pinned_components_count ?? 0} pinned,{" "}
                {sastPlusSuite?.unpinned_components_count ?? 0} floating).
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowRawCdx((v) => !v)}
                className="px-3 py-1.5 rounded-xl bg-zinc-950 hover:bg-zinc-800 border border-zinc-700 text-xs font-mono text-zinc-200"
              >
                {showRawCdx ? "Hide Raw CycloneDX JSON" : "Preview CycloneDX JSON"}
              </button>
              <button
                type="button"
                onClick={handleDownloadSbom}
                className="px-3.5 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download CycloneDX SBOM (.cdx.json)</span>
              </button>
            </div>
          </div>

          {showRawCdx && (
            <pre className="p-4 rounded-2xl bg-zinc-950 border border-cyan-800/70 text-[11px] font-mono text-cyan-300 max-h-72 overflow-auto">
              {JSON.stringify(sastPlusSuite?.cyclonedx_json || {}, null, 2)}
            </pre>
          )}

          <div className="rounded-2xl bg-zinc-900/60 border border-zinc-800 overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-zinc-950 border-b border-zinc-800 text-[10px] font-mono uppercase text-zinc-400">
                    <th className="p-3">Component / Package Name</th>
                    <th className="p-3">Version Spec</th>
                    <th className="p-3">Ecosystem</th>
                    <th className="p-3">Declared In (File:Line)</th>
                    <th className="p-3">Pinning &amp; Risk Posture</th>
                    <th className="p-3">Plain-English Role in Application</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/80 text-xs">
                  {sbomComponents.map((comp) => (
                    <tr
                      key={comp.id}
                      className="hover:bg-zinc-900/90 transition-colors"
                    >
                      <td className="p-3 font-mono font-bold text-white">
                        {comp.name}
                      </td>
                      <td className="p-3 font-mono text-cyan-300">
                        {comp.version}
                      </td>
                      <td className="p-3 text-zinc-300">{comp.ecosystem}</td>
                      <td className="p-3 font-mono text-emerald-400">
                        {comp.manifest_path}:L{comp.line_number}
                      </td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            comp.risk_status === "VERIFIED_PINNED"
                              ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                              : comp.risk_status === "REVIEW_REQUIRED"
                              ? "bg-red-950 text-red-300 border-red-700"
                              : "bg-amber-950 text-amber-300 border-amber-700"
                          }`}
                        >
                          {comp.risk_status}
                        </span>
                      </td>
                      <td className="p-3 text-zinc-300">
                        {comp.plain_english_role}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* PILLAR 3: API & CALLABLE ENTRYPOINT ATTACK SURFACE */}
      {sastPlusActiveTab === "ATTACK_SURFACE" && (
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-zinc-900/80 border border-zinc-800">
            <div className="text-sm font-bold text-white flex items-center gap-2 mb-1">
              <Compass className="w-4 h-4 text-amber-400" />
              Discovered Application Entrypoints &amp; API Attack Surface
            </div>
            <p className="text-xs text-zinc-400">
              Automatically scanned from source files in your active project to
              show every front door (HTTP routes, input handlers, and callable
              functions) and whether active vulnerabilities exist in that file.
            </p>
          </div>

          <div className="rounded-2xl bg-zinc-900/60 border border-zinc-800 overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-zinc-950 border-b border-zinc-800 text-[10px] font-mono uppercase text-zinc-400">
                    <th className="p-3">Entry Type / Method</th>
                    <th className="p-3">Route / Callable Signature</th>
                    <th className="p-3">Source Location</th>
                    <th className="p-3">Exposure Level</th>
                    <th className="p-3">Adjacent Flaws</th>
                    <th className="p-3">Plain-English Purpose</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/80 text-xs">
                  {endpoints.map((ep) => (
                    <tr
                      key={ep.id}
                      className="hover:bg-zinc-900/90 transition-colors"
                    >
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-700 font-mono font-bold text-[10px]">
                          {ep.method}
                        </span>
                      </td>
                      <td className="p-3 font-mono font-semibold text-white">
                        {ep.route_path}
                      </td>
                      <td className="p-3 font-mono text-emerald-400">
                        {ep.filepath}:L{ep.line_number}
                      </td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            ep.exposure_level === "HIGH_EXPOSURE"
                              ? "bg-red-950 text-red-300 border-red-700"
                              : ep.exposure_level === "INTERNAL_API"
                              ? "bg-amber-950 text-amber-300 border-amber-700"
                              : "bg-emerald-950 text-emerald-300 border-emerald-700"
                          }`}
                        >
                          {ep.exposure_level}
                        </span>
                      </td>
                      <td className="p-3 font-mono font-bold">
                        {ep.linked_findings_count > 0 ? (
                          <span className="text-red-400">
                            {ep.linked_findings_count} Active Flaw(s)
                          </span>
                        ) : (
                          <span className="text-emerald-400">0 Flaws</span>
                        )}
                      </td>
                      <td className="p-3 text-zinc-300">
                        {ep.plain_english_purpose}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* PILLAR 4: PRIORITIZED MANAGEMENT REMEDIATION ROADMAP */}
      {sastPlusActiveTab === "ROADMAP" && (
        <div className="space-y-4">
          {(
            [
              {
                key: "PHASE_1_IMMEDIATE",
                title:
                  "Phase 1: Immediate Stop-the-Bleeding (24–72 Hours • Critical Blockers)",
                border: "border-red-700/70",
                badge: "bg-red-950 text-red-300 border-red-700",
              },
              {
                key: "PHASE_2_SPRINT",
                title:
                  "Phase 2: Current Sprint Commitment (Within 14 Days • High Priority)",
                border: "border-amber-700/70",
                badge: "bg-amber-950 text-amber-300 border-amber-700",
              },
              {
                key: "PHASE_3_HARDENING",
                title:
                  "Phase 3: Architectural & Supply-Chain Hardening (Within 30 Days)",
                border: "border-cyan-700/70",
                badge: "bg-cyan-950 text-cyan-300 border-cyan-700",
              },
            ] as const
          ).map((phaseGroup) => {
            const items = roadmapItems.filter(
              (r) => r.phase === phaseGroup.key
            );
            return (
              <div
                key={phaseGroup.key}
                className={`rounded-2xl bg-zinc-900/70 border ${phaseGroup.border} p-4 space-y-3`}
              >
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <span
                      className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold border ${phaseGroup.badge}`}
                    >
                      {items.length} Action Item(s)
                    </span>
                    <span>{phaseGroup.title}</span>
                  </h3>
                </div>

                {items.length === 0 ? (
                  <div className="text-xs text-zinc-400 font-mono py-2">
                    Zero open vulnerabilities in this phase.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {items.map((item) => {
                      const fullF = findings.find(
                        (f) => f.id === item.finding_id
                      );
                      return (
                        <div
                          key={item.finding_id}
                          className="p-3 rounded-xl bg-zinc-950 border border-zinc-800 flex items-center justify-between gap-4 flex-wrap"
                        >
                          <div className="space-y-1 max-w-3xl">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-bold text-white">
                                {item.title}
                              </span>
                              <span className="text-[11px] font-mono text-emerald-400">
                                ({item.filepath}:L{item.line})
                              </span>
                            </div>
                            <p className="text-xs text-zinc-400">
                              {item.plain_english_fix}
                            </p>
                            <div className="flex items-center gap-3 text-[10px] font-mono pt-1">
                              <span className="text-emerald-300">
                                Owner: <strong>{item.responsible_role}</strong>
                              </span>
                              <span className="text-cyan-300">
                                Effort: <strong>{item.effort_estimate}</strong>
                              </span>
                              <span className="text-amber-300">
                                Risk Score Reduction:{" "}
                                <strong>+{item.risk_reduction_points} pts</strong>
                              </span>
                            </div>
                          </div>

                          {fullF && (
                            <button
                              type="button"
                              onClick={() => jumpToBestFixLocation(fullF)}
                              className="px-3 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-200 text-xs font-semibold flex items-center gap-1.5 shrink-0"
                            >
                              <Crosshair className="w-3.5 h-3.5 text-emerald-400" />
                              <span>Open BFL in IDE</span>
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* PILLAR 5: LIVE STRIDE THREAT MODEL & CI/CD PIPELINE PBOM SCORECARD */}
      {sastPlusActiveTab === "THREAT_MODEL" && (
        <div className="space-y-5">
          {/* Section A: Automated STRIDE Threat Model Mapped to Active Application */}
          <div className="rounded-2xl bg-zinc-900/75 border border-purple-700/50 p-4 space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-purple-400" />
                  <span>
                    Automated STRIDE Architectural Threat Model, Count Matrix &amp; Observations —{" "}
                    <span className="text-cyan-300">{activeAppName}</span>
                  </span>
                </h2>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Per-category STRIDE evaluation showing exact check counts,{" "}
                  <strong className="text-emerald-300">✔ What is OK</strong>,{" "}
                  <strong className="text-rose-300">✖ What is the Issue</strong>, and{" "}
                  <strong className="text-cyan-300">Detailed Observations</strong> with direct IDE code links.
                </p>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2.5 py-1 rounded-lg bg-emerald-950/90 border border-emerald-700 text-emerald-200 font-mono text-[11px] font-bold">
                  ✔ Total OK:{" "}
                  {strideThreats.reduce((a, t) => a + (t.ok_count ?? 1), 0)}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-rose-950/90 border border-rose-700 text-rose-200 font-mono text-[11px] font-bold">
                  ✖ Total Issues:{" "}
                  {strideThreats.reduce((a, t) => a + (t.issue_count ?? 0), 0)}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-purple-950/90 border border-purple-700 text-purple-200 font-mono text-[11px] font-bold">
                  Observations:{" "}
                  {strideThreats.reduce(
                    (a, t) => a + (t.observations?.length ?? t.observations_count ?? 0),
                    0
                  )}
                </span>
              </div>
            </div>

            {/* Executive STRIDE Count & Verdict Summary Table */}
            <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-950/80">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-zinc-950 text-zinc-300 border-b border-zinc-800 text-[10px] uppercase tracking-wider font-extrabold">
                    <th className="py-2 px-3">STRIDE Category</th>
                    <th className="py-2 px-3 text-center">Total Checks</th>
                    <th className="py-2 px-3 text-center text-emerald-300">✔ OK Count</th>
                    <th className="py-2 px-3 text-center text-rose-300">✖ Issue Count</th>
                    <th className="py-2 px-3 text-center text-cyan-300">Observations</th>
                    <th className="py-2 px-3">✔ What is OK</th>
                    <th className="py-2 px-3">✖ What is the Issue</th>
                    <th className="py-2 px-3 text-center">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/80">
                  {strideThreats.map((st) => {
                    const okC = st.ok_count ?? (st.what_passed?.length || 1);
                    const issC = st.issue_count ?? (st.status === "MITIGATED" ? 0 : 1);
                    const totC = st.total_checks_count ?? okC + issC;
                    const obsC = st.observations?.length ?? st.observations_count ?? 0;
                    const isOk = issC === 0 && st.status === "MITIGATED";
                    return (
                      <tr key={st.id} className="hover:bg-zinc-900/70">
                        <td className="py-2 px-3 font-mono font-bold text-purple-300">
                          [{st.stride_letter}] {st.stride_category.replace(/_/g, " ")}
                        </td>
                        <td className="py-2 px-3 text-center font-mono font-bold text-zinc-200">
                          {totC}
                        </td>
                        <td className="py-2 px-3 text-center font-mono font-extrabold text-emerald-300">
                          ✔ {okC} OK
                        </td>
                        <td
                          className={`py-2 px-3 text-center font-mono font-extrabold ${
                            issC > 0 ? "text-rose-300" : "text-emerald-400"
                          }`}
                        >
                          {issC > 0 ? `✖ ${issC} Issue${issC > 1 ? "s" : ""}` : "0 Issues"}
                        </td>
                        <td className="py-2 px-3 text-center font-mono text-cyan-300">
                          {obsC} Obs
                        </td>
                        <td className="py-2 px-3 text-emerald-200/90 max-w-xs">
                          {st.ok_summary || st.what_passed?.[0] || "Controls verified OK."}
                        </td>
                        <td
                          className={`py-2 px-3 max-w-xs ${
                            issC > 0 ? "text-rose-200 font-medium" : "text-zinc-400"
                          }`}
                        >
                          {st.issue_summary || (issC > 0 ? st.what_failed?.[0] : "0 Issues — All checks OK.")}
                        </td>
                        <td className="py-2 px-3 text-center">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              isOk
                                ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                                : "bg-rose-950 text-rose-300 border-rose-700"
                            }`}
                          >
                            {isOk ? "✔ OK" : `✖ ISSUE (${st.severity})`}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="grid grid-cols-1 gap-4">
              {strideThreats.map((threat) => {
                const okC = threat.ok_count ?? (threat.what_passed?.length || 1);
                const issC =
                  threat.issue_count ??
                  (threat.status === "MITIGATED" ? 0 : threat.linked_finding_ids?.length || 1);
                const totC = threat.total_checks_count ?? okC + issC;
                const obsList = threat.observations || [];
                const isOk = issC === 0 && threat.status === "MITIGATED";
                return (
                  <div
                    key={threat.id}
                    className={`rounded-xl p-4 border space-y-3 ${
                      !isOk
                        ? "bg-amber-950/20 border-amber-700/70"
                        : "bg-emerald-950/20 border-emerald-800/60"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap border-b border-zinc-800 pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="w-7 h-7 rounded-lg bg-purple-950 border border-purple-600 text-purple-200 font-mono text-xs font-extrabold flex items-center justify-center">
                          {threat.stride_letter}
                        </span>
                        <div>
                          <span className="text-[11px] font-mono font-bold text-purple-300">
                            STRIDE [{threat.stride_letter}] • {threat.stride_category.replace(/_/g, " ")}
                          </span>
                          <h3 className="text-sm font-bold text-white leading-snug">
                            {threat.title}
                          </h3>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap font-mono text-[11px]">
                        <span className="px-2 py-0.5 rounded bg-zinc-950 text-zinc-200 border border-zinc-700">
                          Total: {totC}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                          ✔ OK: {okC}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-bold border ${
                            issC > 0
                              ? "bg-rose-950 text-rose-300 border-rose-700"
                              : "bg-zinc-900 text-emerald-300 border-zinc-700"
                          }`}
                        >
                          ✖ Issues: {issC}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold">
                          Observations: {obsList.length}
                        </span>
                      </div>
                    </div>

                    {/* Two-column What is OK vs What is the Issue */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="bg-emerald-950/25 border border-emerald-700/50 rounded-lg p-3 space-y-1.5">
                        <div className="font-bold text-emerald-300 uppercase text-[10px]">
                          ✔ What is OK ({okC} Checks Passed)
                        </div>
                        <ul className="space-y-1 text-zinc-200">
                          {(threat.what_passed || [threat.ok_summary || "Verified OK"]).map(
                            (pItem, pIdx) => (
                              <li key={pIdx} className="flex items-start gap-1.5">
                                <span className="text-emerald-400 font-bold">✔</span>
                                <span>{pItem}</span>
                              </li>
                            )
                          )}
                        </ul>
                      </div>
                      <div
                        className={`rounded-lg p-3 space-y-1.5 border ${
                          issC > 0
                            ? "bg-rose-950/25 border-rose-700/60"
                            : "bg-zinc-950/70 border-zinc-800"
                        }`}
                      >
                        <div
                          className={`font-bold uppercase text-[10px] ${
                            issC > 0 ? "text-rose-300" : "text-emerald-300"
                          }`}
                        >
                          ✖ What is the Issue ({issC} Issue{issC === 1 ? "" : "s"} Detected)
                        </div>
                        <ul className="space-y-1 text-zinc-200">
                          {(threat.what_failed || [threat.issue_summary || "0 Issues Detected"]).map(
                            (fItem, fIdx) => (
                              <li key={fIdx} className="flex items-start gap-1.5">
                                <span className={issC > 0 ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                                  {issC > 0 ? "✖" : "✔"}
                                </span>
                                <span>{fItem}</span>
                              </li>
                            )
                          )}
                        </ul>
                      </div>
                    </div>

                    {/* Observations Breakdown */}
                    {obsList.length > 0 && (
                      <div className="bg-zinc-950/90 border border-zinc-800 rounded-lg p-3 space-y-2">
                        <div className="text-[11px] font-bold text-cyan-300 uppercase">
                          Observations Breakdown ({obsList.length} Recorded Observations)
                        </div>
                        <div className="space-y-2">
                          {obsList.map((obs, oIdx) => (
                            <div
                              key={obs.id || oIdx}
                              className={`p-2.5 rounded-lg border text-xs flex flex-wrap items-center justify-between gap-2 ${
                                obs.verdict === "ISSUE"
                                  ? "bg-rose-950/20 border-rose-800/60"
                                  : "bg-emerald-950/15 border-emerald-800/50"
                              }`}
                            >
                              <div className="space-y-0.5 max-w-3xl">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span
                                    className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold ${
                                      obs.verdict === "ISSUE"
                                        ? "bg-rose-950 text-rose-300 border border-rose-700"
                                        : "bg-emerald-950 text-emerald-300 border border-emerald-700"
                                    }`}
                                  >
                                    {obs.verdict === "ISSUE"
                                      ? `✖ ISSUE [${obs.severity}]`
                                      : "✔ OK [VERIFIED]"}
                                  </span>
                                  <span className="font-bold text-white">{obs.title}</span>
                                  <span className="font-mono text-amber-300">
                                    ({obs.filepath}:{obs.line})
                                  </span>
                                </div>
                                <div className="text-[11px] text-zinc-300">
                                  {obs.why_ok_or_issue}
                                </div>
                              </div>
                              <button
                                type="button"
                                onClick={() =>
                                  openCodeLocationInIde(
                                    obs.filepath,
                                    obs.line || 1,
                                    obs.linked_finding_id || undefined
                                  )
                                }
                                className="px-2.5 py-1 rounded bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-200 font-semibold text-[11px] flex items-center gap-1 shrink-0"
                              >
                                <Crosshair className="w-3 h-3 text-amber-400" />
                                Inspect ({obs.filepath}:{obs.line})
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between gap-2 flex-wrap text-[11px] text-emerald-200/90">
                      <div>
                        <strong className="text-emerald-400">Corrective Action: </strong>
                        {threat.mitigation_control}
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            openCodeLocationInIde(
                              threat.primary_filepath || threat.affected_components?.[0],
                              threat.primary_line || 1,
                              threat.linked_finding_ids?.[0]
                            )
                          }
                          className="px-2.5 py-1 rounded bg-amber-950/80 hover:bg-amber-900 border border-amber-700 text-amber-200 font-semibold text-[11px] flex items-center gap-1"
                        >
                          <Crosshair className="w-3 h-3 text-amber-400" />
                          Inspect Linked Code
                        </button>
                        <button
                          type="button"
                          onClick={() => setWorkspaceViewMode("THREAT_MODELING")}
                          className="px-2.5 py-1 rounded bg-purple-950/80 hover:bg-purple-900 border border-purple-700 text-purple-200 font-semibold text-[11px]"
                        >
                          Open Full Threat Modeling View →
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Section B: CI/CD Pipeline & Supply-Chain Integrity Scorecard (PBOM) */}
          <div className="rounded-2xl bg-zinc-900/75 border border-cyan-800/60 p-4 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                  <span>
                    CI/CD Pipeline &amp; Supply-Chain Integrity Scorecard (PBOM) —{" "}
                    <span className="text-cyan-300">{activeAppName}</span>
                  </span>
                </h2>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Verifies dependency pinning, cryptographic lockfiles, secret hygiene, runtime headers, and call-graph reachability across the build pipeline.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded-lg bg-cyan-950/90 border border-cyan-700 text-cyan-200 font-mono text-[11px] font-bold">
                {pipelineChecks.filter((c) => c.status === "PASS").length} / {pipelineChecks.length} Controls Passing
              </span>
            </div>

            <div className="space-y-2.5">
              {pipelineChecks.map((chk) => (
                <div
                  key={chk.id}
                  className={`p-3.5 rounded-xl border flex flex-col gap-1.5 ${
                    chk.status === "PASS"
                      ? "bg-emerald-950/15 border-emerald-800/60"
                      : chk.status === "WARNING"
                      ? "bg-amber-950/20 border-amber-700/70"
                      : "bg-red-950/25 border-red-700/70"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                          chk.status === "PASS"
                            ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                            : chk.status === "WARNING"
                            ? "bg-amber-950 text-amber-300 border-amber-600"
                            : "bg-red-950 text-red-300 border-red-600"
                        }`}
                      >
                        {chk.status === "PASS" ? "✅ PASS" : chk.status === "WARNING" ? "⚠️ WARNING" : "🚨 FAIL"}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-[10px] font-mono text-cyan-300">
                        {chk.category}
                      </span>
                      <span className="text-xs font-bold text-white">
                        {chk.title}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-emerald-300">
                      Evidence: {chk.evidence_path}
                    </span>
                  </div>

                  <p className="text-xs text-zinc-200 leading-relaxed">
                    <strong className="text-amber-300">Written Assessment: </strong>
                    {chk.details}
                  </p>
                  <p className="text-xs text-emerald-200/90 leading-relaxed">
                    <strong className="text-emerald-400">Action / Remediation: </strong>
                    {chk.remediation}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* PILLAR 6: NON-CODER SECURITY ACADEMY & GLOSSARY */}
      {sastPlusActiveTab === "ACADEMY" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {ACADEMY_GLOSSARY.map((item, idx) => (
            <div
              key={idx}
              className="rounded-2xl bg-zinc-900/75 border border-zinc-800 p-4 space-y-2.5 shadow-lg"
            >
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700/80 text-[10px] font-mono font-bold">
                  {item.category}
                </span>
                <span className="text-[10px] font-mono text-zinc-500">
                  Concept #{idx + 1}
                </span>
              </div>
              <h3 className="text-sm font-bold text-white">{item.term}</h3>
              <div className="p-2.5 rounded-xl bg-amber-950/25 border border-amber-800/50 text-xs text-amber-100 italic">
                <strong>Analogy:</strong> &ldquo;{item.analogy}&rdquo;
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed">
                <strong className="text-emerald-300">What It Is:</strong>{" "}
                {item.plainMeaning}
              </p>
              <p className="text-xs text-zinc-300 leading-relaxed">
                <strong className="text-cyan-300">
                  Why Management Cares:
                </strong>{" "}
                {item.managementWhy}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
