"use client";

import React, { useEffect, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { RaciValue } from "@/types/cpg";
import {
  Users,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  RotateCcw,
  Download,
  Ticket,
  Crosshair,
  GraduationCap,
  Briefcase,
  UserCheck,
  Info,
  Sparkles,
} from "lucide-react";

const RACI_CYCLE: RaciValue[] = ["R", "A", "C", "I", "-"];

function getRaciBadgeStyle(val: RaciValue): {
  bg: string;
  label: string;
  tooltip: string;
} {
  switch (val) {
    case "R":
      return {
        bg: "bg-emerald-950/90 text-emerald-300 border-emerald-600 shadow-sm shadow-emerald-950/50",
        label: "R • Responsible",
        tooltip: "Responsible (The Doer): Executes the task or writes the fix.",
      };
    case "A":
      return {
        bg: "bg-rose-950/90 text-rose-300 border-rose-600 shadow-sm shadow-rose-950/50",
        label: "A • Accountable",
        tooltip:
          "Accountable (The Approver): Single owner where the buck stops (exactly 1 per row).",
      };
    case "C":
      return {
        bg: "bg-amber-950/90 text-amber-300 border-amber-600",
        label: "C • Consulted",
        tooltip:
          "Consulted (Subject Expert): Provides two-way input before decisions are finalized.",
      };
    case "I":
      return {
        bg: "bg-cyan-950/80 text-cyan-300 border-cyan-700",
        label: "I • Informed",
        tooltip:
          "Informed (Stakeholder): Kept updated on status and milestones (one-way).",
      };
    default:
      return {
        bg: "bg-zinc-900/60 text-zinc-500 border-zinc-800",
        label: "—",
        tooltip: "Not directly involved in this activity.",
      };
  }
}

export function RaciGovernanceView() {
  const raciGovernance = useAuditStore((s) => s.raciGovernance);
  const fetchRaciGovernance = useAuditStore((s) => s.fetchRaciGovernance);
  const updateRaciCell = useAuditStore((s) => s.updateRaciCell);
  const updateFindingRaciOwner = useAuditStore((s) => s.updateFindingRaciOwner);
  const resetRaciGovernance = useAuditStore((s) => s.resetRaciGovernance);
  const findings = useAuditStore((s) => s.findings);
  const appTree = useAuditStore((s) => s.appTree);
  const projectPath = useAuditStore((s) => s.projectPath);
  const jumpToBestFixLocation = useAuditStore((s) => s.jumpToBestFixLocation);
  const createTicketForFinding = useAuditStore((s) => s.createTicketForFinding);

  const activeAppPath = appTree?.root_path || projectPath || "cpg-sast-platform";
  const activeAppName =
    activeAppPath.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ||
    "cpg-sast-platform";

  const [activeTab, setActiveTab] = useState<
    "MATRIX" | "FINDING_OWNERSHIP" | "ROLES_GUIDE"
  >("MATRIX");
  const [editingFindingId, setEditingFindingId] = useState<string | null>(null);
  const [ownerDraft, setOwnerDraft] = useState<string>("");
  const [sprintDraft, setSprintDraft] = useState<string>("");
  const [creatingTicketId, setCreatingTicketId] = useState<string | null>(null);

  useEffect(() => {
    fetchRaciGovernance();
  }, [fetchRaciGovernance]);

  const handleCellClick = async (
    activityId: string,
    roleId: string,
    currentVal: RaciValue
  ) => {
    const idx = RACI_CYCLE.indexOf(currentVal);
    const nextVal = RACI_CYCLE[(idx + 1) % RACI_CYCLE.length];
    await updateRaciCell(activityId, roleId, nextVal);
  };

  const handleExportRaci = () => {
    if (!raciGovernance) return;
    const blob = new Blob([JSON.stringify(raciGovernance, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "alastor-raci-governance-matrix.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleSaveFindingOwner = async (findingId: string) => {
    await updateFindingRaciOwner({
      finding_id: findingId,
      assigned_person: ownerDraft,
      target_sprint: sprintDraft,
    });
    setEditingFindingId(null);
  };

  const roles = raciGovernance?.roles || [];
  const activities = raciGovernance?.activities || [];
  const findingAssignments = raciGovernance?.finding_assignments || [];
  const healthScore = raciGovernance?.governance_health_score ?? 100;
  const warnings = raciGovernance?.validation_warnings || [];

  return (
    <div className="flex-1 h-full overflow-y-auto bg-zinc-950/90 p-5 text-zinc-100 space-y-5">
      {/* Top Executive & Non-Coder Header Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-amber-950/40 via-zinc-900/90 to-rose-950/40 border border-amber-700/50 p-5 shadow-xl">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="space-y-1.5 max-w-3xl">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2.5 py-0.5 rounded-full bg-amber-950 text-amber-300 border border-amber-700 text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1">
                <GraduationCap className="w-3.5 h-3.5 text-amber-400" />
                Management &amp; Non-Coder Governance Module
              </span>
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-200 border border-cyan-600 text-[10px] font-mono font-bold">
                Application: {activeAppName}
              </span>
              <span className="px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-mono font-bold">
                PMI / COBIT / ISO 27001 Aligned
              </span>
            </div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Users className="w-5 h-5 text-amber-400" />
              RACI Security Governance &amp; Accountability Matrix —{" "}
              <span className="text-cyan-300">{activeAppName}</span>
            </h1>
            <p className="text-xs text-zinc-300 leading-relaxed">
              Designed for{" "}
              <strong className="text-amber-300">
                Management Students, Project Managers, CISOs, and Team Leads
              </strong>
              : Clearly define who does the work (<strong>R</strong>esponsible),
              who makes the final decision (<strong>A</strong>ccountable), who
              provides expert advice (<strong>C</strong>onsulted), and who stays
              updated (<strong>I</strong>nformed) across every security workflow
              and discovered vulnerability—with zero coding required.
            </p>
          </div>

          {/* Governance Health Score Card */}
          <div className="flex items-center gap-3 bg-zinc-950/90 border border-zinc-800 rounded-xl p-3.5 shrink-0">
            <div className="text-right">
              <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400">
                RACI Governance Health
              </div>
              <div
                className={`text-2xl font-mono font-extrabold ${
                  healthScore === 100
                    ? "text-emerald-400"
                    : healthScore >= 80
                    ? "text-amber-400"
                    : "text-red-400"
                }`}
              >
                {healthScore}%
              </div>
              <div className="text-[10px] text-zinc-400">
                {raciGovernance?.valid_rows_count ?? 9}/
                {raciGovernance?.total_rows_count ?? 9} Activities Validated
              </div>
            </div>
            <div className="flex flex-col gap-1.5 border-l border-zinc-800 pl-3">
              <button
                type="button"
                onClick={() => resetRaciGovernance()}
                title="Reset RACI cells to the PMI/COBIT validated baseline"
                className="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[11px] font-medium text-zinc-200 flex items-center gap-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
                <span>Reset Default RACI</span>
              </button>
              <button
                type="button"
                onClick={handleExportRaci}
                className="px-2.5 py-1 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-700/80 text-[11px] font-semibold text-amber-200 flex items-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5 text-amber-400" />
                <span>Export Matrix (.json)</span>
              </button>
            </div>
          </div>
        </div>

        {/* 4 RACI Pillars Quick Legend for Non-Coders */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 mt-4">
          <div className="p-3 rounded-xl bg-zinc-950/90 border border-emerald-800/60">
            <div className="flex items-center justify-between mb-1">
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-mono font-bold text-xs">
                R — Responsible
              </span>
              <span className="text-[10px] font-mono text-emerald-400">
                &quot;The Doer&quot;
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 leading-relaxed">
              The team member who hands-on executes the task (e.g., Lead
              Developer patching a vulnerability or DevOps locking a container).
              Every row needs <b>at least one R</b>.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-zinc-950/90 border border-rose-800/60">
            <div className="flex items-center justify-between mb-1">
              <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 font-mono font-bold text-xs">
                A — Accountable
              </span>
              <span className="text-[10px] font-mono text-rose-400">
                &quot;The Approver&quot;
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 leading-relaxed">
              The single boss/authority who signs off that the work is complete
              and correct. Golden Rule: Every activity must have{" "}
              <b>
                only ONE &apos;A&apos;
              </b>{" "}
              so accountability is never confused.
            </p>
          </div>

          <div className="p-3 rounded-xl bg-zinc-950/90 border border-amber-800/60">
            <div className="flex items-center justify-between mb-1">
              <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 font-mono font-bold text-xs">
                C — Consulted
              </span>
              <span className="text-[10px] font-mono text-amber-400">
                &quot;The Advisor&quot;
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 leading-relaxed">
              Subject-matter experts whose input or review is needed{" "}
              <i>before</i> the work is finalized (two-way communication).
            </p>
          </div>

          <div className="p-3 rounded-xl bg-zinc-950/90 border border-cyan-800/60">
            <div className="flex items-center justify-between mb-1">
              <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700 font-mono font-bold text-xs">
                I — Informed
              </span>
              <span className="text-[10px] font-mono text-cyan-400">
                &quot;Kept Updated&quot;
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 leading-relaxed">
              Stakeholders who receive progress updates, dashboards, or final
              reports after decisions are made (one-way notification).
            </p>
          </div>
        </div>
      </div>

      {/* Validation Warnings Banner (if user edits create 0 or >1 Accountable) */}
      {warnings.length > 0 && (
        <div className="rounded-xl bg-red-950/50 border border-red-700/80 p-3.5 space-y-1">
          <div className="text-xs font-bold text-red-300 flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span>
              RACI Governance Rule Alert ({warnings.length} issue
              {warnings.length > 1 ? "s" : ""} detected by PMI/COBIT Validator):
            </span>
          </div>
          <ul className="list-disc list-inside text-[11px] text-red-200 space-y-0.5">
            {warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center justify-between flex-wrap gap-2 border-b border-zinc-800 pb-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab("MATRIX")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all ${
              activeTab === "MATRIX"
                ? "bg-amber-950 text-amber-300 border border-amber-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <Users className="w-4 h-4 text-amber-400" />
            <span>
              1. Interactive Security Lifecycle RACI Matrix ({activities.length}{" "}
              Activities)
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("FINDING_OWNERSHIP")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all ${
              activeTab === "FINDING_OWNERSHIP"
                ? "bg-emerald-950 text-emerald-300 border border-emerald-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <UserCheck className="w-4 h-4 text-emerald-400" />
            <span>
              2. Live Vulnerability Ownership &amp; Sprint Assignment (
              {findingAssignments.length} Real Findings)
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("ROLES_GUIDE")}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all ${
              activeTab === "ROLES_GUIDE"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-sm"
                : "bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800"
            }`}
          >
            <Briefcase className="w-4 h-4 text-cyan-400" />
            <span>3. Organizational Roles &amp; Student Study Guide</span>
          </button>
        </div>

        <span className="text-[11px] text-zinc-400 font-mono flex items-center gap-1">
          <Sparkles className="w-3.5 h-3.5 text-amber-400" />
          Tip: Click any R / A / C / I cell below to cycle its role assignment
          live!
        </span>
      </div>

      {/* TAB 1: INTERACTIVE LIFECYCLE RACI MATRIX TABLE */}
      {activeTab === "MATRIX" && (
        <div className="rounded-2xl bg-zinc-900/60 border border-zinc-800 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-zinc-950 border-b border-zinc-800 text-[11px] font-mono uppercase text-zinc-400">
                  <th className="p-3.5 min-w-[270px]">
                    Security Lifecycle Activity &amp; Plain-English Meaning
                  </th>
                  <th className="p-3.5 min-w-[160px]">
                    Concrete Management Deliverable
                  </th>
                  {roles.map((r) => (
                    <th
                      key={r.role_id}
                      className="p-3 text-center min-w-[105px] border-l border-zinc-800/80"
                      title={`${r.title} (${r.department}): ${r.plain_description}`}
                    >
                      <div className="font-bold text-zinc-200">
                        {r.short_code}
                      </div>
                      <div className="text-[9px] text-zinc-500 font-normal">
                        {r.department.split(" ")[0]}
                      </div>
                    </th>
                  ))}
                  <th className="p-3.5 min-w-[170px] border-l border-zinc-800">
                    PMI / COBIT Rule Check
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/80 text-xs">
                {activities.map((row) => {
                  const isValid = row.validation_status === "VALID";
                  return (
                    <tr
                      key={row.activity_id}
                      className="hover:bg-zinc-900/90 transition-colors"
                    >
                      <td className="p-3.5 align-top">
                        <div className="text-[10px] font-mono uppercase text-amber-400 font-semibold mb-0.5">
                          {row.phase}
                        </div>
                        <div className="font-bold text-zinc-100 text-xs mb-1">
                          {row.activity_name}
                        </div>
                        <p className="text-[11px] text-zinc-400 leading-relaxed">
                          {row.plain_explanation}
                        </p>
                      </td>
                      <td className="p-3.5 align-middle">
                        <span className="inline-block px-2.5 py-1 rounded-lg bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-300 font-medium">
                          {row.deliverable}
                        </span>
                      </td>
                      {roles.map((role) => {
                        const val: RaciValue =
                          row.assignments[role.role_id] || "-";
                        const style = getRaciBadgeStyle(val);
                        return (
                          <td
                            key={role.role_id}
                            className="p-2.5 text-center align-middle border-l border-zinc-800/60"
                          >
                            <button
                              type="button"
                              onClick={() =>
                                handleCellClick(
                                  row.activity_id,
                                  role.role_id,
                                  val
                                )
                              }
                              title={`${role.title} -> ${style.tooltip} (Click to change)`}
                              className={`w-12 h-9 rounded-lg border font-mono font-extrabold text-sm transition-transform active:scale-95 ${style.bg}`}
                            >
                              {val}
                            </button>
                          </td>
                        );
                      })}
                      <td className="p-3.5 align-middle border-l border-zinc-800">
                        <div
                          className={`p-2 rounded-lg border text-[10px] font-mono flex items-start gap-1.5 ${
                            isValid
                              ? "bg-emerald-950/40 border-emerald-800/70 text-emerald-300"
                              : "bg-red-950/60 border-red-700 text-red-300"
                          }`}
                        >
                          {isValid ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                          ) : (
                            <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                          )}
                          <span>{row.validation_message}</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: LIVE VULNERABILITY-TO-RACI OWNERSHIP & SPRINT ASSIGNMENT */}
      {activeTab === "FINDING_OWNERSHIP" && (
        <div className="space-y-3">
          <div className="p-3.5 rounded-xl bg-zinc-900/80 border border-zinc-800 flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2 text-xs text-zinc-300">
              <Info className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                Every row below is dynamically generated from the{" "}
                <strong className="text-white">
                  actual scanned vulnerabilities
                </strong>{" "}
                in your active workspace. You can edit the{" "}
                <strong>Assigned Person</strong> or{" "}
                <strong>Target Sprint</strong>, jump to the code chokepoint, or
                create a tracking ticket in 1 click.
              </span>
            </div>
          </div>

          <div className="rounded-2xl bg-zinc-900/60 border border-zinc-800 overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-zinc-950 border-b border-zinc-800 text-[10px] font-mono uppercase text-zinc-400">
                    <th className="p-3">Vulnerability &amp; Location</th>
                    <th className="p-3">R • Responsible (Doer)</th>
                    <th className="p-3">A • Accountable (Approver)</th>
                    <th className="p-3">Assigned Owner &amp; Sprint</th>
                    <th className="p-3">SLA Status</th>
                    <th className="p-3">Plain-English Management Action</th>
                    <th className="p-3 text-right">Quick Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/80 text-xs">
                  {findingAssignments.map((fa) => {
                    const fullFinding = findings.find(
                      (f) => f.id === fa.finding_id
                    );
                    const isEditing = editingFindingId === fa.finding_id;
                    return (
                      <tr
                        key={fa.finding_id}
                        className="hover:bg-zinc-900/90 transition-colors"
                      >
                        <td className="p-3 align-top max-w-[260px]">
                          <div className="flex items-center gap-1.5 mb-1">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                                fa.severity === "CRITICAL"
                                  ? "bg-red-950 text-red-300 border border-red-700"
                                  : fa.severity === "HIGH"
                                  ? "bg-amber-950 text-amber-300 border border-amber-700"
                                  : "bg-cyan-950 text-cyan-300 border border-cyan-800"
                              }`}
                            >
                              {fa.severity}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-[9px] font-mono text-zinc-400">
                              {fa.engine}
                            </span>
                          </div>
                          <div className="font-bold text-zinc-100 mb-0.5">
                            {fa.finding_title}
                          </div>
                          <div className="text-[11px] font-mono text-emerald-400">
                            {fa.filepath}:L{fa.line}
                          </div>
                        </td>

                        <td className="p-3 align-middle">
                          <span className="px-2 py-1 rounded-lg bg-emerald-950/70 border border-emerald-700/70 text-emerald-300 text-[11px] font-semibold inline-block">
                            {fa.responsible_role}
                          </span>
                        </td>

                        <td className="p-3 align-middle">
                          <span className="px-2 py-1 rounded-lg bg-rose-950/70 border border-rose-700/70 text-rose-300 text-[11px] font-semibold inline-block">
                            {fa.accountable_role}
                          </span>
                        </td>

                        <td className="p-3 align-middle min-w-[200px]">
                          {isEditing ? (
                            <div className="space-y-1.5">
                              <input
                                type="text"
                                value={ownerDraft}
                                onChange={(e) => setOwnerDraft(e.target.value)}
                                placeholder="Assigned Person..."
                                className="w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-100"
                              />
                              <input
                                type="text"
                                value={sprintDraft}
                                onChange={(e) => setSprintDraft(e.target.value)}
                                placeholder="Target Sprint..."
                                className="w-full bg-zinc-950 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-100"
                              />
                              <div className="flex items-center gap-1">
                                <button
                                  type="button"
                                  onClick={() =>
                                    handleSaveFindingOwner(fa.finding_id)
                                  }
                                  className="px-2 py-0.5 rounded bg-emerald-600 text-white text-[10px] font-bold"
                                >
                                  Save
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setEditingFindingId(null)}
                                  className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px]"
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div>
                              <div className="font-semibold text-zinc-200">
                                {fa.assigned_person}
                              </div>
                              <div className="text-[10px] font-mono text-amber-400">
                                {fa.target_sprint}
                              </div>
                              <button
                                type="button"
                                onClick={() => {
                                  setEditingFindingId(fa.finding_id);
                                  setOwnerDraft(fa.assigned_person);
                                  setSprintDraft(fa.target_sprint);
                                }}
                                className="text-[10px] text-cyan-400 hover:underline mt-0.5"
                              >
                                Edit Owner / Sprint
                              </button>
                            </div>
                          )}
                        </td>

                        <td className="p-3 align-middle">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                              fa.sla_status === "SLA_BREACHED"
                                ? "bg-red-950 text-red-300 border-red-700"
                                : fa.sla_status === "APPROACHING_SLA"
                                ? "bg-amber-950 text-amber-300 border-amber-700"
                                : "bg-emerald-950 text-emerald-300 border-emerald-700"
                            }`}
                          >
                            {fa.sla_status}
                          </span>
                        </td>

                        <td className="p-3 align-middle max-w-[290px]">
                          <p className="text-[11px] text-zinc-300 leading-relaxed">
                            {fa.plain_action_required}
                          </p>
                        </td>

                        <td className="p-3 align-middle text-right space-y-1">
                          {fullFinding && (
                            <button
                              type="button"
                              onClick={() =>
                                jumpToBestFixLocation(fullFinding)
                              }
                              className="w-full px-2.5 py-1 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/80 text-emerald-200 text-[10px] font-semibold flex items-center justify-center gap-1"
                            >
                              <Crosshair className="w-3 h-3 text-emerald-400" />
                              <span>Inspect BFL</span>
                            </button>
                          )}
                          <button
                            type="button"
                            disabled={creatingTicketId === fa.finding_id}
                            onClick={async () => {
                              setCreatingTicketId(fa.finding_id);
                              await createTicketForFinding(
                                fa.finding_id,
                                "JIRA",
                                {
                                  assignee: fa.assigned_person,
                                }
                              );
                              setCreatingTicketId(null);
                            }}
                            className="w-full px-2.5 py-1 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/80 text-indigo-200 text-[10px] font-semibold flex items-center justify-center gap-1"
                          >
                            <Ticket className="w-3 h-3 text-indigo-400" />
                            <span>
                              {fullFinding?.linked_ticket_id
                                ? `Ticket: ${fullFinding.linked_ticket_id}`
                                : "Assign Ticket"}
                            </span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: ORGANIZATIONAL ROLES & STUDENT STUDY GUIDE */}
      {activeTab === "ROLES_GUIDE" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {roles.map((r) => (
            <div
              key={r.role_id}
              className="p-4 rounded-2xl bg-zinc-900/70 border border-zinc-800 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700/80 text-[10px] font-mono font-bold">
                    {r.short_code}
                  </span>
                  <span className="text-[10px] font-mono text-zinc-400">
                    {r.department}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white">{r.title}</h3>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  {r.plain_description}
                </p>
              </div>
              <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px] font-mono text-zinc-400">
                <span>Default Seat:</span>
                <span className="text-cyan-300 font-semibold">
                  {r.default_owner}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
