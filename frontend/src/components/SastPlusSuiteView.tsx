"use client";

import React, { useEffect, useState } from "react";
import dynamic from "next/dynamic";
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
  ShieldAlert,
  CheckCircle2,
  Users,
  Clock,
  Lightbulb,
  Briefcase,
  Search,
  Loader2,
} from "lucide-react";

const ApiOperationsExplorerView = dynamic(
  () =>
    import("@/components/ApiOperationsExplorerView").then(
      (mod) => mod.ApiOperationsExplorerView
    ),
  {
    ssr: false,
    loading: () => (
      <div className="py-16 flex flex-col items-center justify-center bg-white border border-slate-300 rounded-2xl text-slate-700 font-mono text-xs gap-2">
        <Loader2 className="w-5 h-5 animate-spin text-emerald-700" />
        <span>Loading API Endpoints &amp; Operations Explorer...</span>
      </div>
    ),
  }
);

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
      "Allows executives and auditors to prioritize fixes objectively (e.g., CVSS >= 9.0 Critical must be fixed within 7 days).",
  },
];

export interface SastPlusSuiteViewProps {
  embeddedTab?:
    | "TRANSLATOR"
    | "SBOM"
    | "ATTACK_SURFACE"
    | "ROADMAP"
    | "ACADEMY";
  embeddedActiveTab?:
    | "TRANSLATOR"
    | "SBOM"
    | "ATTACK_SURFACE"
    | "ROADMAP"
    | "ACADEMY";
  hideHeader?: boolean;
}

export function SastPlusSuiteView({
  embeddedTab,
  embeddedActiveTab,
  hideHeader = false,
}: SastPlusSuiteViewProps = {}) {
  const sastPlusSuite = useAuditStore((s) => s.sastPlusSuite);
  const fetchSastPlusSuite = useAuditStore((s) => s.fetchSastPlusSuite);
  const apiOperationsReport = useAuditStore((s) => s.apiOperationsReport);
  const fetchApiOperationsState = useAuditStore(
    (s) => s.fetchApiOperationsState
  );
  const sastPlusActiveTab = useAuditStore((s) => s.sastPlusActiveTab);
  const setSastPlusActiveTab = useAuditStore((s) => s.setSastPlusActiveTab);
  const findings = useAuditStore((s) => s.findings);
  const appTree = useAuditStore((s) => s.appTree);
  const projectPath = useAuditStore((s) => s.projectPath);
  const jumpToBestFixLocation = useAuditStore((s) => s.jumpToBestFixLocation);
  const openCodeLocationInIde = useAuditStore((s) => s.openCodeLocationInIde);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);

  const effectiveTab = embeddedTab ?? embeddedActiveTab ?? sastPlusActiveTab;
  const shouldHideHeader =
    hideHeader || Boolean(embeddedTab || embeddedActiveTab);

  const activeAppPath =
    appTree?.root_path || projectPath || "cpg-sast-platform";
  const activeAppName =
    activeAppPath.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ||
    "cpg-sast-platform";

  const [searchFilter, setSearchFilter] = useState("");
  const [showRawCdx, setShowRawCdx] = useState(false);

  useEffect(() => {
    fetchSastPlusSuite();
    void fetchApiOperationsState();
  }, [fetchSastPlusSuite, fetchApiOperationsState]);

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
  const totalDiscoveredEndpoints =
    apiOperationsReport?.total_endpoints ??
    sastPlusSuite?.discovered_endpoints_count ??
    endpoints.length;

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
    <div className="flex-1 h-full overflow-y-auto bg-[var(--surface-void)] p-5 text-[var(--ink-primary)] space-y-5">
      {!shouldHideHeader && (
        <>
          {/* Top Hero Banner */}
          <div className="rounded-2xl bg-white border border-slate-300 p-5 shadow-sm">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="space-y-1.5 max-w-3xl">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2.5 py-0.5 rounded-full bg-rose-50 text-rose-900 border border-rose-300 text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1">
                    <Sparkles className="w-3.5 h-3.5 text-rose-700" />
                    Ultimate SAST ++++++ ASPM &amp; Non-Coder Command Center
                  </span>
                  <span className="px-2.5 py-0.5 rounded-full bg-sky-50 text-sky-900 border border-sky-300 text-[10px] font-mono font-bold">
                    Application: {activeAppName}
                  </span>
                  <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-900 border border-emerald-300 text-[10px] font-mono font-bold">
                    {activeAppPath}
                  </span>
                </div>
                <h1 className="text-xl font-bold text-slate-900">
                  Plain-English Business Risk, Live CycloneDX SBOM &amp; API
                  Operations —{" "}
                  <span className="text-sky-800">{activeAppName}</span>
                </h1>
                <p className="text-xs text-slate-700 leading-relaxed">
                  {sastPlusSuite?.executive_plain_summary ||
                    "Translating compiler-grade Code Property Graph (CPG) discoveries into plain-English analogies, business impact, live supply-chain SBOM inventories, traced API operations, and phased management roadmaps."}
                </p>
              </div>

              {/* Maturity Scorecard */}
              <div className="flex items-center gap-4 bg-slate-50 border border-slate-200 rounded-xl p-3.5 shrink-0">
                <div>
                  <div className="text-[10px] font-mono uppercase text-slate-700 font-bold">
                    Security Maturity Grade
                  </div>
                  <div className="text-lg font-mono font-extrabold text-emerald-800">
                    {sastPlusSuite?.overall_maturity_grade || "B (Managed)"}
                  </div>
                  <div className="text-[10px] font-mono text-slate-700">
                    Score: {sastPlusSuite?.maturity_score ?? 82}/100
                  </div>
                </div>
                <div className="border-l border-slate-300 pl-4 space-y-1 text-[11px] font-mono">
                  <div className="text-sky-900">
                    SBOM Components:{" "}
                    <strong>{sastPlusSuite?.total_sbom_components ?? 0}</strong>
                  </div>
                  <div className="text-amber-900">
                    API Endpoints:{" "}
                    <strong>{totalDiscoveredEndpoints}</strong>
                  </div>
                  <div className="text-slate-900">
                    Reachable / Dormant:{" "}
                    <strong>
                      {sastPlusSuite?.reachable_findings_count ??
                        findings.length}{" "}
                      / {sastPlusSuite?.dormant_findings_count ?? 0}
                    </strong>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* 5-Pillar Navigation Bar */}
          <div className="flex items-center justify-between gap-2 flex-wrap border-b border-slate-200 pb-2.5">
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={() => setSastPlusActiveTab("TRANSLATOR")}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all border ${
                  effectiveTab === "TRANSLATOR"
                    ? "bg-emerald-700 text-white border-emerald-800 shadow-sm"
                    : "bg-white text-slate-800 hover:bg-slate-50 border-slate-300"
                }`}
              >
                <GraduationCap
                  className={`w-4 h-4 ${
                    effectiveTab === "TRANSLATOR"
                      ? "text-white"
                      : "text-emerald-700"
                  }`}
                />
                <span>
                  1. Plain-English Impact Translator ({findings.length})
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSastPlusActiveTab("SBOM")}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all border ${
                  effectiveTab === "SBOM"
                    ? "bg-sky-700 text-white border-sky-800 shadow-sm"
                    : "bg-white text-slate-800 hover:bg-slate-50 border-slate-300"
                }`}
              >
                <Package
                  className={`w-4 h-4 ${
                    effectiveTab === "SBOM" ? "text-white" : "text-sky-700"
                  }`}
                />
                <span>
                  2. Live SBOM &amp; Supply Chain ({sbomComponents.length})
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSastPlusActiveTab("ATTACK_SURFACE")}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all border ${
                  effectiveTab === "ATTACK_SURFACE"
                    ? "bg-emerald-700 text-white border-emerald-800 shadow-sm"
                    : "bg-white text-slate-800 hover:bg-slate-50 border-slate-300"
                }`}
              >
                <Compass
                  className={`w-4 h-4 ${
                    effectiveTab === "ATTACK_SURFACE"
                      ? "text-white"
                      : "text-amber-700"
                  }`}
                />
                <span>
                  3. API Endpoints &amp; Operations ({totalDiscoveredEndpoints})
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSastPlusActiveTab("ROADMAP")}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all border ${
                  effectiveTab === "ROADMAP"
                    ? "bg-amber-800 text-white border-amber-900 shadow-sm"
                    : "bg-white text-slate-800 hover:bg-slate-50 border-slate-300"
                }`}
              >
                <Layers
                  className={`w-4 h-4 ${
                    effectiveTab === "ROADMAP"
                      ? "text-white"
                      : "text-amber-800"
                  }`}
                />
                <span>
                  4. Management Remediation Roadmap ({roadmapItems.length})
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSastPlusActiveTab("ACADEMY")}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all border ${
                  effectiveTab === "ACADEMY"
                    ? "bg-rose-700 text-white border-rose-800 shadow-sm"
                    : "bg-white text-slate-800 hover:bg-slate-50 border-slate-300"
                }`}
              >
                <BookOpen
                  className={`w-4 h-4 ${
                    effectiveTab === "ACADEMY" ? "text-white" : "text-rose-700"
                  }`}
                />
                <span>5. Non-Coder Security Academy &amp; Glossary</span>
              </button>
            </div>
          </div>
        </>
      )}

      {/* PILLAR 1: PLAIN-ENGLISH BUSINESS IMPACT TRANSLATOR FOR NON-CODERS */}
      {effectiveTab === "TRANSLATOR" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3 flex-wrap bg-white border border-slate-300 p-3.5 rounded-xl shadow-sm">
            <div className="text-xs text-slate-700 flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-amber-700 shrink-0" />
              <span>
                <strong className="text-slate-900">No Coding Required:</strong>{" "}
                Every technical finding is translated below into a{" "}
                <strong className="text-emerald-900">
                  Plain-English Explanation
                </strong>
                , a{" "}
                <strong className="text-amber-900">Real-World Analogy</strong>,{" "}
                <strong className="text-rose-900">Business Impact</strong>, and
                a{" "}
                <strong className="text-sky-900">
                  3-Step Management Action Plan
                </strong>
                .
              </span>
            </div>
            <div className="relative w-64">
              <Search className="w-3.5 h-3.5 text-slate-600 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Filter by keyword or CWE..."
                className="w-full bg-slate-50 border border-slate-300 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-900 placeholder:text-slate-500 focus:outline-none focus:border-sky-700"
              />
            </div>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="rounded-2xl bg-white border border-slate-300 p-8 text-center space-y-1.5 shadow-sm">
              <CheckCircle2 className="w-6 h-6 text-emerald-700 mx-auto" />
              <div className="text-sm font-bold text-slate-900">
                Zero Active Security Findings to Translate
              </div>
              <p className="text-xs text-slate-700">
                {findings.length === 0
                  ? "Your active application currently has 0 active vulnerabilities across SAST, SCA, IaC, and Secrets."
                  : "No findings match your current search filter."}
              </p>
            </div>
          ) : (
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
                    className="rounded-2xl bg-white border border-slate-300 p-4 flex flex-col justify-between space-y-3.5 shadow-sm hover:border-slate-400 transition-all"
                  >
                    <div className="space-y-2.5">
                      {/* Header Badges */}
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              f.severity === "CRITICAL"
                                ? "bg-rose-700 text-white border-rose-800"
                                : f.severity === "HIGH"
                                ? "bg-amber-800 text-white border-amber-900"
                                : "bg-sky-50 text-sky-900 border-sky-300"
                            }`}
                          >
                            {f.severity}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-[10px] font-mono font-bold text-slate-800">
                            {f.scan_engine || "SAST"} • {f.cwe_id || "CWE"}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-rose-50 border border-rose-300 text-[10px] font-mono font-bold text-rose-900">
                            {f.financial_risk_tier || "Enterprise Risk"}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              f.reachability_status === "UNREACHABLE_DORMANT"
                                ? "bg-slate-100 text-slate-700 border-slate-300"
                                : f.reachability_status ===
                                  "CONDITIONALLY_REACHABLE"
                                ? "bg-amber-50 text-amber-950 border-amber-300"
                                : "bg-emerald-50 text-emerald-900 border-emerald-300"
                            }`}
                          >
                            {f.reachability_status === "UNREACHABLE_DORMANT"
                              ? "Dormant Path"
                              : f.reachability_status ===
                                "CONDITIONALLY_REACHABLE"
                              ? "Build/Dev Reachable"
                              : "Runtime Reachable"}
                          </span>
                          {typeof f.epss_score === "number" && (
                            <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-300 text-[10px] font-mono text-indigo-900 font-bold">
                              EPSS 30d: {(f.epss_score * 100).toFixed(1)}%
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] font-mono text-emerald-900 font-bold">
                          {fp}:L{ln}
                        </span>
                      </div>

                      <h3 className="text-sm font-bold text-slate-900">
                        {f.title}
                      </h3>

                      {/* Affected Third-Party Software / Flagged Code Statement */}
                      <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                        <div className="text-[10px] font-mono uppercase tracking-wider text-sky-900 font-bold">
                          {f.scan_engine === "SCA"
                            ? `Affected Third-Party Software (${
                                f.path_nodes?.length || 1
                              } package${
                                (f.path_nodes?.length || 1) === 1 ? "" : "s"
                              }):`
                            : `Affected Component / Code Statement (${fp}:L${ln}):`}
                        </div>
                        {f.scan_engine === "SCA" &&
                        f.path_nodes &&
                        f.path_nodes.length > 0 ? (
                          <div className="flex flex-wrap gap-1.5">
                            {f.path_nodes.map((pn, pIdx) => (
                              <span
                                key={pn.id || pIdx}
                                className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-950 font-mono text-[10px] font-semibold"
                              >
                                {pn.name} ({pn.filepath}:L{pn.start_line})
                              </span>
                            ))}
                          </div>
                        ) : (
                          <div className="text-[11px] font-mono text-slate-900 break-all">
                            {f.best_fix_location?.code_snippet ||
                              (f.path_nodes && f.path_nodes.length > 0
                                ? f.path_nodes[f.path_nodes.length - 1].code ||
                                  f.path_nodes[f.path_nodes.length - 1].name
                                : fp)}
                          </div>
                        )}
                      </div>

                      {/* Written Technical Explanation & Remediation */}
                      <div className="p-3 rounded-xl bg-amber-50/70 border border-amber-300 space-y-1.5">
                        <div className="text-[10px] font-mono uppercase tracking-wider text-amber-950 font-bold">
                          Written Observation Details (What Is Wrong &amp; Why)
                        </div>
                        <p className="text-xs text-slate-800 leading-relaxed">
                          {f.description}
                        </p>
                        {f.remediation && (
                          <div className="pt-1.5 border-t border-amber-200 text-xs text-emerald-950 leading-relaxed">
                            <strong className="text-emerald-900">
                              How to Fix:{" "}
                            </strong>
                            {f.remediation}
                          </div>
                        )}
                      </div>

                      {/* Plain English Box */}
                      <div className="p-3 rounded-xl bg-emerald-50/70 border border-emerald-300 space-y-1">
                        <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-900 font-bold flex items-center gap-1">
                          <GraduationCap className="w-3.5 h-3.5 text-emerald-800" />
                          In Plain English (For Non-Coders)
                        </div>
                        <p className="text-xs text-slate-800 leading-relaxed">
                          {f.plain_english_summary || f.description}
                        </p>
                      </div>

                      {/* Real-World Analogy Box */}
                      {f.non_coder_analogy && (
                        <div className="p-3 rounded-xl bg-amber-50 border border-amber-300 space-y-1">
                          <div className="text-[10px] font-mono uppercase tracking-wider text-amber-950 font-bold flex items-center gap-1">
                            <Lightbulb className="w-3.5 h-3.5 text-amber-800" />
                            Real-World Analogy
                          </div>
                          <p className="text-xs text-amber-950 italic leading-relaxed">
                            &ldquo;{f.non_coder_analogy}&rdquo;
                          </p>
                        </div>
                      )}

                      {/* Business & Regulatory Impact */}
                      {f.business_impact && (
                        <div className="p-3 rounded-xl bg-rose-50/80 border border-rose-300 space-y-1">
                          <div className="text-[10px] font-mono uppercase tracking-wider text-rose-900 font-bold flex items-center gap-1">
                            <Briefcase className="w-3.5 h-3.5 text-rose-800" />
                            Business, Financial &amp; Compliance Impact
                          </div>
                          <p className="text-xs text-slate-800 leading-relaxed">
                            {f.business_impact}
                          </p>
                        </div>
                      )}

                      {/* Step-by-Step Management Action Plan */}
                      {f.management_action_steps &&
                        f.management_action_steps.length > 0 && (
                          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                            <div className="text-[10px] font-mono uppercase tracking-wider text-sky-900 font-bold">
                              Management Action Checklist
                            </div>
                            <ul className="space-y-1 text-[11px] text-slate-800">
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
                    <div className="pt-3 border-t border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2 flex-wrap text-[10px] font-mono">
                        <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-bold">
                          R: {f.raci_responsible || "Lead Dev"}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-rose-50 border border-rose-300 text-rose-900 font-bold">
                          A: {f.raci_accountable || "Security Lead"}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-800 font-bold flex items-center gap-1">
                          <Clock className="w-3 h-3 text-sky-700" />
                          {f.effort_estimate || "~20 mins"}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => jumpToBestFixLocation(f)}
                          className="px-2.5 py-1 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-[11px] font-bold flex items-center gap-1 shadow-sm"
                        >
                          <Crosshair className="w-3 h-3 text-white" />
                          <span>View Fix in IDE</span>
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            setWorkspaceViewMode("RACI_GOVERNANCE")
                          }
                          className="px-2.5 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 border border-amber-300 text-amber-950 text-[11px] font-bold flex items-center gap-1"
                        >
                          <Users className="w-3 h-3 text-amber-800" />
                          <span>RACI</span>
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* PILLAR 2: LIVE SBOM & SUPPLY-CHAIN INSPECTOR */}
      {effectiveTab === "SBOM" && (
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-white border border-slate-300 shadow-sm flex items-center justify-between flex-wrap gap-3">
            <div className="space-y-1">
              <div className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Package className="w-4 h-4 text-sky-700" />
                Live Software Bill of Materials (CycloneDX v1.5 Specification)
              </div>
              <p className="text-xs text-slate-700">
                Dynamically extracted from your workspace manifests (
                <code className="px-1 py-0.5 rounded bg-slate-100 text-slate-900">
                  requirements.txt
                </code>
                ,{" "}
                <code className="px-1 py-0.5 rounded bg-slate-100 text-slate-900">
                  package.json
                </code>
                ) and scanned runtime imports. Total:{" "}
                <strong className="text-slate-900">
                  {sastPlusSuite?.total_sbom_components ?? 0}
                </strong>{" "}
                components ({sastPlusSuite?.pinned_components_count ?? 0}{" "}
                pinned, {sastPlusSuite?.unpinned_components_count ?? 0}{" "}
                floating).
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowRawCdx((v) => !v)}
                className="px-3 py-1.5 rounded-xl bg-white hover:bg-slate-100 border border-slate-300 text-xs font-mono font-bold text-slate-800"
              >
                {showRawCdx
                  ? "Hide Raw CycloneDX JSON"
                  : "Preview CycloneDX JSON"}
              </button>
              <button
                type="button"
                onClick={handleDownloadSbom}
                className="px-3.5 py-1.5 rounded-xl bg-sky-700 hover:bg-sky-800 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download CycloneDX SBOM (.cdx.json)</span>
              </button>
            </div>
          </div>

          {showRawCdx && (
            <pre className="p-4 rounded-2xl bg-slate-50 border border-slate-300 text-[11px] font-mono text-slate-900 max-h-72 overflow-auto">
              {JSON.stringify(sastPlusSuite?.cyclonedx_json || {}, null, 2)}
            </pre>
          )}

          <div className="rounded-2xl bg-white border border-slate-300 overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-100 border-b border-slate-200 text-[10px] font-mono font-extrabold uppercase text-slate-800">
                    <th className="p-3">Component / Package Name</th>
                    <th className="p-3">Version Spec</th>
                    <th className="p-3">Ecosystem</th>
                    <th className="p-3">Declared In (File:Line)</th>
                    <th className="p-3">Pinning &amp; Risk Posture</th>
                    <th className="p-3">Plain-English Role in Application</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-xs">
                  {sbomComponents.map((comp) => (
                    <tr
                      key={comp.id}
                      className="hover:bg-slate-50 transition-colors"
                    >
                      <td className="p-3 font-mono font-bold text-slate-900">
                        {comp.name}
                      </td>
                      <td className="p-3 font-mono font-semibold text-sky-900">
                        {comp.version}
                      </td>
                      <td className="p-3 text-slate-800">{comp.ecosystem}</td>
                      <td className="p-3 font-mono text-emerald-900 font-semibold">
                        {comp.manifest_path}:L{comp.line_number}
                      </td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            comp.risk_status === "VERIFIED_PINNED"
                              ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                              : comp.risk_status === "REVIEW_REQUIRED"
                              ? "bg-rose-50 text-rose-900 border-rose-300"
                              : "bg-amber-50 text-amber-950 border-amber-300"
                          }`}
                        >
                          {comp.risk_status}
                        </span>
                      </td>
                      <td className="p-3 text-slate-700">
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

      {/* PILLAR 3: INTERACTIVE API ENDPOINTS & OPERATIONS EXPLORER */}
      {effectiveTab === "ATTACK_SURFACE" && (
        <ApiOperationsExplorerView embedded />
      )}

      {/* PILLAR 4: PRIORITIZED MANAGEMENT REMEDIATION ROADMAP */}
      {effectiveTab === "ROADMAP" && (
        <div className="space-y-4">
          {(
            [
              {
                key: "PHASE_1_IMMEDIATE",
                title:
                  "Phase 1: Immediate Stop-the-Bleeding (24–72 Hours • Critical Blockers)",
                border: "border-rose-300",
                badge: "bg-rose-700 text-white border-rose-800",
              },
              {
                key: "PHASE_2_SPRINT",
                title:
                  "Phase 2: Current Sprint Commitment (Within 14 Days • High Priority)",
                border: "border-amber-300",
                badge: "bg-amber-800 text-white border-amber-900",
              },
              {
                key: "PHASE_3_HARDENING",
                title:
                  "Phase 3: Architectural & Supply-Chain Hardening (Within 30 Days)",
                border: "border-sky-300",
                badge: "bg-sky-700 text-white border-sky-800",
              },
            ] as const
          ).map((phaseGroup) => {
            const items = roadmapItems.filter(
              (r) => r.phase === phaseGroup.key
            );
            return (
              <div
                key={phaseGroup.key}
                className={`rounded-2xl bg-white border ${phaseGroup.border} p-4 space-y-3 shadow-sm`}
              >
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <span
                      className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold border ${phaseGroup.badge}`}
                    >
                      {items.length} Action Item(s)
                    </span>
                    <span>{phaseGroup.title}</span>
                  </h3>
                </div>

                {items.length === 0 ? (
                  <div className="text-xs text-slate-700 font-mono py-2">
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
                          className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-4 flex-wrap"
                        >
                          <div className="space-y-1 max-w-3xl">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-bold text-slate-900">
                                {item.title}
                              </span>
                              <span className="text-[11px] font-mono text-emerald-900 font-semibold">
                                ({item.filepath}:L{item.line})
                              </span>
                            </div>
                            <p className="text-xs text-slate-700">
                              {item.plain_english_fix}
                            </p>
                            <div className="flex items-center gap-3 text-[10px] font-mono pt-1">
                              <span className="text-emerald-900">
                                Owner: <strong>{item.responsible_role}</strong>
                              </span>
                              <span className="text-sky-900">
                                Effort: <strong>{item.effort_estimate}</strong>
                              </span>
                              <span className="text-amber-900">
                                Risk Score Reduction:{" "}
                                <strong>+{item.risk_reduction_points} pts</strong>
                              </span>
                            </div>
                          </div>

                          {fullF && (
                            <button
                              type="button"
                              onClick={() => jumpToBestFixLocation(fullF)}
                              className="px-3 py-1.5 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold flex items-center gap-1.5 shrink-0 shadow-sm"
                            >
                              <Crosshair className="w-3.5 h-3.5 text-white" />
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
      {effectiveTab === "THREAT_MODEL" && (
        <div className="space-y-5">
          {/* Section A: Automated STRIDE Threat Model Mapped to Active Application */}
          <div className="rounded-2xl bg-white border border-purple-300 p-4 space-y-4 shadow-sm">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-purple-800" />
                  <span>
                    Automated STRIDE Architectural Threat Model, Count Matrix
                    &amp; Observations —{" "}
                    <span className="text-sky-800">{activeAppName}</span>
                  </span>
                </h2>
                <p className="text-xs text-slate-700 mt-0.5">
                  Per-category STRIDE evaluation showing exact check counts,{" "}
                  <strong className="text-emerald-900">What is OK</strong>,{" "}
                  <strong className="text-rose-900">What is the Issue</strong>,
                  and{" "}
                  <strong className="text-sky-900">
                    Detailed Observations
                  </strong>{" "}
                  with direct IDE code links.
                </p>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2.5 py-1 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-900 font-mono text-[11px] font-bold">
                  Total OK:{" "}
                  {strideThreats.reduce((a, t) => a + (t.ok_count ?? 1), 0)}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-rose-50 border border-rose-300 text-rose-900 font-mono text-[11px] font-bold">
                  Total Issues:{" "}
                  {strideThreats.reduce((a, t) => a + (t.issue_count ?? 0), 0)}
                </span>
                <span className="px-2.5 py-1 rounded-lg bg-purple-50 border border-purple-300 text-purple-900 font-mono text-[11px] font-bold">
                  Observations:{" "}
                  {strideThreats.reduce(
                    (a, t) =>
                      a + (t.observations?.length ?? t.observations_count ?? 0),
                    0
                  )}
                </span>
              </div>
            </div>

            {/* Executive STRIDE Count & Verdict Summary Table */}
            <div className="overflow-x-auto rounded-xl border border-slate-300 bg-white">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-slate-800 border-b border-slate-200 text-[10px] uppercase tracking-wider font-extrabold">
                    <th className="py-2 px-3">STRIDE Category</th>
                    <th className="py-2 px-3 text-center">Total Checks</th>
                    <th className="py-2 px-3 text-center text-emerald-900">
                      OK Count
                    </th>
                    <th className="py-2 px-3 text-center text-rose-900">
                      Issue Count
                    </th>
                    <th className="py-2 px-3 text-center text-sky-900">
                      Observations
                    </th>
                    <th className="py-2 px-3">What is OK</th>
                    <th className="py-2 px-3">What is the Issue</th>
                    <th className="py-2 px-3 text-center">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {strideThreats.map((st) => {
                    const okC = st.ok_count ?? (st.what_passed?.length || 1);
                    const issC =
                      st.issue_count ?? (st.status === "MITIGATED" ? 0 : 1);
                    const totC = st.total_checks_count ?? okC + issC;
                    const obsC =
                      st.observations?.length ?? st.observations_count ?? 0;
                    const isOk = issC === 0 && st.status === "MITIGATED";
                    return (
                      <tr key={st.id} className="hover:bg-slate-50">
                        <td className="py-2 px-3 font-mono font-bold text-purple-900">
                          [{st.stride_letter}]{" "}
                          {st.stride_category.replace(/_/g, " ")}
                        </td>
                        <td className="py-2 px-3 text-center font-mono font-bold text-slate-900">
                          {totC}
                        </td>
                        <td className="py-2 px-3 text-center font-mono font-extrabold text-emerald-900">
                          {okC} OK
                        </td>
                        <td
                          className={`py-2 px-3 text-center font-mono font-extrabold ${
                            issC > 0 ? "text-rose-900" : "text-emerald-900"
                          }`}
                        >
                          {issC > 0
                            ? `${issC} Issue${issC > 1 ? "s" : ""}`
                            : "0 Issues"}
                        </td>
                        <td className="py-2 px-3 text-center font-mono text-sky-900 font-semibold">
                          {obsC} Obs
                        </td>
                        <td className="py-2 px-3 text-slate-800 max-w-xs">
                          {st.ok_summary ||
                            st.what_passed?.[0] ||
                            "Controls verified OK."}
                        </td>
                        <td
                          className={`py-2 px-3 max-w-xs ${
                            issC > 0
                              ? "text-rose-950 font-semibold"
                              : "text-slate-700"
                          }`}
                        >
                          {st.issue_summary ||
                            (issC > 0
                              ? st.what_failed?.[0]
                              : "0 Issues — All checks OK.")}
                        </td>
                        <td className="py-2 px-3 text-center">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              isOk
                                ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                                : "bg-rose-50 text-rose-900 border-rose-300"
                            }`}
                          >
                            {isOk ? "OK" : `ISSUE (${st.severity})`}
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
                const okC =
                  threat.ok_count ?? (threat.what_passed?.length || 1);
                const issC =
                  threat.issue_count ??
                  (threat.status === "MITIGATED"
                    ? 0
                    : threat.linked_finding_ids?.length || 1);
                const totC = threat.total_checks_count ?? okC + issC;
                const obsList = threat.observations || [];
                const isOk = issC === 0 && threat.status === "MITIGATED";
                return (
                  <div
                    key={threat.id}
                    className={`rounded-xl p-4 border space-y-3 ${
                      !isOk
                        ? "bg-amber-50/60 border-amber-300"
                        : "bg-emerald-50/50 border-emerald-300"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap border-b border-slate-200 pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="w-7 h-7 rounded-lg bg-purple-700 border border-purple-800 text-white font-mono text-xs font-extrabold flex items-center justify-center">
                          {threat.stride_letter}
                        </span>
                        <div>
                          <span className="text-[11px] font-mono font-bold text-purple-900">
                            STRIDE [{threat.stride_letter}] •{" "}
                            {threat.stride_category.replace(/_/g, " ")}
                          </span>
                          <h3 className="text-sm font-bold text-slate-900 leading-snug">
                            {threat.title}
                          </h3>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap font-mono text-[11px]">
                        <span className="px-2 py-0.5 rounded bg-white text-slate-900 border border-slate-300 font-bold">
                          Total: {totC}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-900 border border-emerald-300 font-bold">
                          OK: {okC}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-bold border ${
                            issC > 0
                              ? "bg-rose-50 text-rose-900 border-rose-300"
                              : "bg-white text-emerald-900 border-slate-300"
                          }`}
                        >
                          Issues: {issC}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-sky-50 text-sky-900 border border-sky-300 font-bold">
                          Observations: {obsList.length}
                        </span>
                      </div>
                    </div>

                    {/* Two-column What is OK vs What is the Issue */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="bg-white border border-emerald-300 rounded-lg p-3 space-y-1.5">
                        <div className="font-bold text-emerald-900 uppercase text-[10px]">
                          What is OK ({okC} Checks Passed)
                        </div>
                        <ul className="space-y-1 text-slate-800">
                          {(
                            threat.what_passed || [
                              threat.ok_summary || "Verified OK",
                            ]
                          ).map((pItem, pIdx) => (
                            <li
                              key={pIdx}
                              className="flex items-start gap-1.5"
                            >
                              <span className="text-emerald-800 font-bold">
                                ✓
                              </span>
                              <span>{pItem}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div
                        className={`rounded-lg p-3 space-y-1.5 border bg-white ${
                          issC > 0 ? "border-rose-300" : "border-slate-200"
                        }`}
                      >
                        <div
                          className={`font-bold uppercase text-[10px] ${
                            issC > 0 ? "text-rose-900" : "text-emerald-900"
                          }`}
                        >
                          What is the Issue ({issC} Issue
                          {issC === 1 ? "" : "s"} Detected)
                        </div>
                        <ul className="space-y-1 text-slate-800">
                          {(
                            threat.what_failed || [
                              threat.issue_summary || "0 Issues Detected",
                            ]
                          ).map((fItem, fIdx) => (
                            <li
                              key={fIdx}
                              className="flex items-start gap-1.5"
                            >
                              <span
                                className={
                                  issC > 0
                                    ? "text-rose-800 font-bold"
                                    : "text-emerald-800 font-bold"
                                }
                              >
                                {issC > 0 ? "✗" : "✓"}
                              </span>
                              <span>{fItem}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {/* Observations Breakdown */}
                    {obsList.length > 0 && (
                      <div className="bg-white border border-slate-200 rounded-lg p-3 space-y-2">
                        <div className="text-[11px] font-bold text-sky-900 uppercase">
                          Observations Breakdown ({obsList.length} Recorded
                          Observations)
                        </div>
                        <div className="space-y-2">
                          {obsList.map((obs, oIdx) => (
                            <div
                              key={obs.id || oIdx}
                              className={`p-2.5 rounded-lg border text-xs flex flex-wrap items-center justify-between gap-2 ${
                                obs.verdict === "ISSUE"
                                  ? "bg-rose-50/70 border-rose-300"
                                  : "bg-emerald-50/60 border-emerald-300"
                              }`}
                            >
                              <div className="space-y-0.5 max-w-3xl">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span
                                    className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold border ${
                                      obs.verdict === "ISSUE"
                                        ? "bg-rose-700 text-white border-rose-800"
                                        : "bg-emerald-700 text-white border-emerald-800"
                                    }`}
                                  >
                                    {obs.verdict === "ISSUE"
                                      ? `ISSUE [${obs.severity}]`
                                      : "OK [VERIFIED]"}
                                  </span>
                                  <span className="font-bold text-slate-900">
                                    {obs.title}
                                  </span>
                                  <span className="font-mono text-amber-950 font-semibold">
                                    ({obs.filepath}:{obs.line})
                                  </span>
                                </div>
                                <div className="text-[11px] text-slate-700">
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
                                className="px-2.5 py-1 rounded bg-white hover:bg-amber-50 border border-amber-300 text-amber-950 font-bold text-[11px] flex items-center gap-1 shrink-0"
                              >
                                <Crosshair className="w-3 h-3 text-amber-800" />
                                Inspect ({obs.filepath}:{obs.line})
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="pt-2 border-t border-slate-200 flex items-center justify-between gap-2 flex-wrap text-[11px] text-slate-800">
                      <div>
                        <strong className="text-emerald-900">
                          Corrective Action:{" "}
                        </strong>
                        {threat.mitigation_control}
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            openCodeLocationInIde(
                              threat.primary_filepath ||
                                threat.affected_components?.[0],
                              threat.primary_line || 1,
                              threat.linked_finding_ids?.[0]
                            )
                          }
                          className="px-2.5 py-1 rounded bg-white hover:bg-amber-50 border border-amber-300 text-amber-950 font-bold text-[11px] flex items-center gap-1"
                        >
                          <Crosshair className="w-3 h-3 text-amber-800" />
                          Inspect Linked Code
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            setWorkspaceViewMode("THREAT_MODELING")
                          }
                          className="px-2.5 py-1 rounded bg-purple-700 hover:bg-purple-800 text-white font-bold text-[11px] shadow-sm"
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
          <div className="rounded-2xl bg-white border border-sky-300 p-4 space-y-3 shadow-sm">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-sky-700" />
                  <span>
                    CI/CD Pipeline &amp; Supply-Chain Integrity Scorecard (PBOM)
                    — <span className="text-sky-800">{activeAppName}</span>
                  </span>
                </h2>
                <p className="text-xs text-slate-700 mt-0.5">
                  Verifies dependency pinning, cryptographic lockfiles, secret
                  hygiene, runtime headers, and call-graph reachability across
                  the build pipeline.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded-lg bg-sky-50 border border-sky-300 text-sky-900 font-mono text-[11px] font-bold">
                {pipelineChecks.filter((c) => c.status === "PASS").length} /{" "}
                {pipelineChecks.length} Controls Passing
              </span>
            </div>

            <div className="space-y-2.5">
              {pipelineChecks.map((chk) => (
                <div
                  key={chk.id}
                  className={`p-3.5 rounded-xl border flex flex-col gap-1.5 ${
                    chk.status === "PASS"
                      ? "bg-emerald-50/60 border-emerald-300"
                      : chk.status === "WARNING"
                      ? "bg-amber-50/70 border-amber-300"
                      : "bg-rose-50/70 border-rose-300"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                          chk.status === "PASS"
                            ? "bg-emerald-700 text-white border-emerald-800"
                            : chk.status === "WARNING"
                            ? "bg-amber-800 text-white border-amber-900"
                            : "bg-rose-700 text-white border-rose-800"
                        }`}
                      >
                        {chk.status === "PASS"
                          ? "PASS"
                          : chk.status === "WARNING"
                          ? "WARNING"
                          : "FAIL"}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-[10px] font-mono font-bold text-sky-900">
                        {chk.category}
                      </span>
                      <span className="text-xs font-bold text-slate-900">
                        {chk.title}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-emerald-900 font-semibold">
                      Evidence: {chk.evidence_path}
                    </span>
                  </div>

                  <p className="text-xs text-slate-800 leading-relaxed">
                    <strong className="text-amber-950">
                      Written Assessment:{" "}
                    </strong>
                    {chk.details}
                  </p>
                  <p className="text-xs text-emerald-950 leading-relaxed">
                    <strong className="text-emerald-900">
                      Action / Remediation:{" "}
                    </strong>
                    {chk.remediation}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* PILLAR 6: NON-CODER SECURITY ACADEMY & GLOSSARY */}
      {effectiveTab === "ACADEMY" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {ACADEMY_GLOSSARY.map((item, idx) => (
            <div
              key={idx}
              className="rounded-2xl bg-white border border-slate-300 p-4 space-y-2.5 shadow-sm"
            >
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-900 border border-rose-300 text-[10px] font-mono font-bold">
                  {item.category}
                </span>
                <span className="text-[10px] font-mono text-slate-600 font-semibold">
                  Concept #{idx + 1}
                </span>
              </div>
              <h3 className="text-sm font-bold text-slate-900">{item.term}</h3>
              <div className="p-2.5 rounded-xl bg-amber-50 border border-amber-300 text-xs text-amber-950 italic">
                <strong>Analogy:</strong> &ldquo;{item.analogy}&rdquo;
              </div>
              <p className="text-xs text-slate-700 leading-relaxed">
                <strong className="text-emerald-900">What It Is:</strong>{" "}
                {item.plainMeaning}
              </p>
              <p className="text-xs text-slate-700 leading-relaxed">
                <strong className="text-sky-900">Why Management Cares:</strong>{" "}
                {item.managementWhy}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
