"use client";

import React, { useEffect } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { ExecutiveAspmTab } from "@/types/cpg";
import { SastPlusSuiteView } from "./SastPlusSuiteView";
import { DeepDiveDashboard } from "./DeepDiveDashboard";
import { RaciGovernanceView } from "./RaciGovernanceView";
import {
  GraduationCap,
  Package,
  Compass,
  BarChart3,
  Users,
  Layers,
  BookOpen,
  Download,
  Award,
  ShieldCheck,
} from "lucide-react";

export const ExecutiveAspmWorkspace: React.FC = () => {
  const executiveAspmTab = useAuditStore((s) => s.executiveAspmTab);
  const setExecutiveAspmTab = useAuditStore((s) => s.setExecutiveAspmTab);
  const sastPlusSuite = useAuditStore((s) => s.sastPlusSuite);
  const raciGovernance = useAuditStore((s) => s.raciGovernance);
  const findings = useAuditStore((s) => s.findings);
  const fetchSastPlusSuite = useAuditStore((s) => s.fetchSastPlusSuite);
  const fetchDeepDiveAnalytics = useAuditStore((s) => s.fetchDeepDiveAnalytics);
  const fetchRaciGovernance = useAuditStore((s) => s.fetchRaciGovernance);

  useEffect(() => {
    if (!sastPlusSuite) fetchSastPlusSuite();
    if (!raciGovernance) fetchRaciGovernance();
    fetchDeepDiveAnalytics();
  }, [
    sastPlusSuite,
    raciGovernance,
    fetchSastPlusSuite,
    fetchRaciGovernance,
    fetchDeepDiveAnalytics,
  ]);

  const handleDownloadCycloneDxSbom = () => {
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

  const sbomCount =
    sastPlusSuite?.total_sbom_components ??
    sastPlusSuite?.sbom_components?.length ??
    0;
  const endpointsCount =
    sastPlusSuite?.discovered_endpoints_count ??
    sastPlusSuite?.endpoints?.length ??
    0;
  const roadmapCount = sastPlusSuite?.roadmap_items?.length ?? 0;
  const maturityGrade = sastPlusSuite?.overall_maturity_grade || "B (Managed)";
  const raciHealth = raciGovernance?.governance_health_score ?? 100;

  const tabs: Array<{
    id: ExecutiveAspmTab;
    label: string;
    icon: React.ReactNode;
    badge?: number | string;
  }> = [
    {
      id: "TRANSLATOR",
      label: "1. Plain-English Impact",
      icon: <GraduationCap className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />,
      badge: findings.length,
    },
    {
      id: "SBOM",
      label: "2. CycloneDX v1.5 SBOM",
      icon: <Package className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />,
      badge: sbomCount,
    },
    {
      id: "ATTACK_SURFACE",
      label: "3. API Attack Surface",
      icon: <Compass className="w-3.5 h-3.5 text-[var(--sig-gold)]" />,
      badge: endpointsCount,
    },
    {
      id: "ANALYTICS",
      label: "4. Compliance & Analytics",
      icon: <BarChart3 className="w-3.5 h-3.5 text-[var(--sig-cyan)]" />,
    },
    {
      id: "RACI",
      label: "5. RACI Governance",
      icon: <Users className="w-3.5 h-3.5 text-[var(--sig-gold)]" />,
      badge: `${raciHealth}%`,
    },
    {
      id: "ROADMAP",
      label: "6. Remediation Roadmap",
      icon: <Layers className="w-3.5 h-3.5 text-[var(--sig-emerald)]" />,
      badge: roadmapCount,
    },
    {
      id: "ACADEMY",
      label: "7. Security Academy",
      icon: <BookOpen className="w-3.5 h-3.5 text-[var(--sig-crimson)]" />,
    },
  ];

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden bg-[var(--surface-void)] text-[var(--ink-primary)]">
      {/* Sleek 38px Studio Sub-Navigation Bar */}
      <nav
        aria-label="Executive ASPM Sub-Navigation"
        className="h-[38px] px-3 bg-[var(--surface-panel)] border-b border-[var(--border-hairline)] flex items-center justify-between gap-2 shrink-0 overflow-x-auto select-none"
      >
        {/* Left: 7 Studio Sub-Tabs */}
        <div className="flex items-center gap-1 min-w-max">
          {tabs.map((tab) => {
            const isActive = executiveAspmTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setExecutiveAspmTab(tab.id)}
                className={`h-7 px-2.5 rounded-md text-[11px] font-semibold flex items-center gap-1.5 transition-all border ${
                  isActive
                    ? "bg-[var(--surface-elevated)] text-[var(--ink-primary)] border-[var(--sig-gold)]/60 shadow-sm"
                    : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)] hover:bg-[var(--surface-elevated)] border-transparent"
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
                {tab.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0 rounded text-[9.5px] font-mono font-bold border ${
                      isActive
                        ? "bg-[var(--surface-void)] text-[var(--sig-gold)] border-[var(--sig-gold)]/40"
                        : "bg-[var(--surface-void)] text-[var(--ink-muted)] border-[var(--border-hairline)]"
                    }`}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Right: Compact Executive KPI Summary Pills + 1-Click CycloneDX .cdx.json Export */}
        <div className="hidden xl:flex items-center gap-2 shrink-0 font-mono text-[10px]">
          <span
            title="Overall Application Security Maturity Grade"
            className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-[var(--ink-muted)] flex items-center gap-1"
          >
            <Award className="w-3 h-3 text-[var(--sig-emerald)]" />
            <span>Maturity:</span>
            <strong className="text-[var(--sig-emerald)]">
              {maturityGrade}
            </strong>
          </span>

          <span
            title="Live CycloneDX v1.5 SBOM Components"
            className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-[var(--ink-muted)] flex items-center gap-1"
          >
            <Package className="w-3 h-3 text-[var(--sig-cyan)]" />
            <span>SBOM:</span>
            <strong className="text-[var(--sig-cyan)]">{sbomCount}</strong>
          </span>

          <span
            title="PMI/COBIT RACI Governance Health Score"
            className="px-2 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-[var(--ink-muted)] flex items-center gap-1"
          >
            <ShieldCheck className="w-3 h-3 text-[var(--sig-gold)]" />
            <span>RACI Health:</span>
            <strong className="text-[var(--sig-gold)]">{raciHealth}%</strong>
          </span>

          <button
            type="button"
            onClick={handleDownloadCycloneDxSbom}
            title="1-Click Export CycloneDX v1.5 SBOM (.cdx.json)"
            className="px-2.5 py-1 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--sig-cyan)]/50 text-[var(--sig-cyan)] font-bold flex items-center gap-1 transition-colors"
          >
            <Download className="w-3 h-3" />
            <span>CycloneDX .cdx.json</span>
          </button>
        </div>
      </nav>

      {/* Active Sub-Workspace Content */}
      <div className="flex-1 flex min-w-0 min-h-0 overflow-hidden">
        {executiveAspmTab === "ANALYTICS" ? (
          <DeepDiveDashboard />
        ) : executiveAspmTab === "RACI" ? (
          <RaciGovernanceView />
        ) : (
          <SastPlusSuiteView embeddedTab={executiveAspmTab} hideHeader />
        )}
      </div>
    </div>
  );
};

export default ExecutiveAspmWorkspace;
