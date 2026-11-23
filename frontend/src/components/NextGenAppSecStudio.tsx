"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Edge,
  Handle,
  MarkerType,
  MiniMap,
  Node,
  NodeProps,
  Position,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "reactflow";
import "reactflow/dist/style.css";
import { useAuditStore } from "@/store/useAuditStore";
import { isLikelyLocalProjectPath } from "@/lib/api";
import {
  ComplianceControlResult,
  ComplianceFrameworkId,
  CustomSecurityRule,
  MicroserviceGraphNodeData,
  MicroserviceRepoInput,
  PrDeltaClassification,
} from "@/types/cpg";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Edit3,
  FileCode2,
  FolderOpen,
  GitPullRequest,
  Loader2,
  Maximize2,
  Network,
  Play,
  Plus,
  Power,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  X,
} from "lucide-react";

type StudioSubView =
  | "PR_GATE"
  | "COMPLIANCE"
  | "CUSTOM_RULES"
  | "MICROSERVICE_GRAPH";

const COMPLIANCE_FRAMEWORKS_META: Array<{
  id: ComplianceFrameworkId;
  label: string;
  shortDesc: string;
}> = [
  { id: "PCI_DSS_4_0", label: "PCI-DSS 4.0", shortDesc: "Payment Card Security" },
  { id: "SOC2", label: "SOC 2", shortDesc: "Trust Services Criteria" },
  { id: "ISO_27001", label: "ISO 27001", shortDesc: "Annex A Controls" },
  { id: "HIPAA", label: "HIPAA", shortDesc: "ePHI Safeguards" },
  {
    id: "OWASP_ASVS_5_0",
    label: "OWASP ASVS 5.0",
    shortDesc: "App Verification Std",
  },
];

const ALL_COMPLIANCE_IDS: ComplianceFrameworkId[] = COMPLIANCE_FRAMEWORKS_META.map(
  (f) => f.id
);

const DEFAULT_SAMPLE_CODE = `import subprocess
import sqlite3

def run_report(user_input: str):
    # Vulnerable pattern example for sandbox testing
    cmd = "echo " + user_input
    return subprocess.check_output(cmd, shell=True)
`;

function getSeverityBadgeClass(severity: string): string {
  switch ((severity || "").toUpperCase()) {
    case "CRITICAL":
      return "bg-rose-700 text-white border-rose-800";
    case "HIGH":
      return "bg-amber-100 text-amber-950 border-amber-400";
    case "MEDIUM":
      return "bg-yellow-50 text-amber-950 border-amber-300";
    case "LOW":
      return "bg-sky-50 text-sky-950 border-sky-300";
    default:
      return "bg-slate-100 text-slate-800 border-slate-300";
  }
}

function getDeltaClassBadge(classification: PrDeltaClassification): {
  label: string;
  className: string;
} {
  switch (classification) {
    case "NEWLY_INTRODUCED":
      return {
        label: "NEWLY INTRODUCED",
        className: "bg-rose-700 text-white border-rose-800",
      };
    case "MODIFIED_CONTEXT":
      return {
        label: "MODIFIED CONTEXT",
        className: "bg-amber-100 text-amber-950 border-amber-400",
      };
    case "PRE_EXISTING":
    default:
      return {
        label: "PRE-EXISTING",
        className: "bg-slate-100 text-slate-800 border-slate-300",
      };
  }
}

function getComplianceStatusBadge(
  status: "COMPLIANT" | "AT_RISK" | "NON_COMPLIANT"
): string {
  switch (status) {
    case "COMPLIANT":
      return "bg-emerald-700 text-white border-emerald-800";
    case "AT_RISK":
      return "bg-amber-100 text-amber-950 border-amber-400";
    case "NON_COMPLIANT":
    default:
      return "bg-rose-700 text-white border-rose-800";
  }
}

function getControlStatusBadge(status: "PASS" | "WARNING" | "FAIL"): string {
  switch (status) {
    case "PASS":
      return "bg-emerald-50 text-emerald-900 border-emerald-300";
    case "WARNING":
      return "bg-amber-50 text-amber-950 border-amber-300";
    case "FAIL":
    default:
      return "bg-rose-50 text-rose-950 border-rose-300";
  }
}

function getNodeSeverityBorder(sev: string): string {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL":
      return "border-rose-600 bg-white";
    case "HIGH":
      return "border-amber-500 bg-white";
    case "MEDIUM":
      return "border-yellow-500 bg-white";
    case "LOW":
      return "border-sky-500 bg-white";
    default:
      return "border-emerald-500 bg-white";
  }
}

// ---------------------------------------------------------------------------
// Module-scoped ReactFlow custom node & type maps (prevents flicker/remount)
// ---------------------------------------------------------------------------
const MicroserviceNode: React.FC<NodeProps<MicroserviceGraphNodeData>> =
  React.memo(({ data }) => {
    const sev = (data?.highest_severity || "NONE").toUpperCase();
    const borderCls = getNodeSeverityBorder(sev);
    return (
      <div
        className={`w-[248px] rounded-xl border-2 shadow-sm p-3 text-slate-900 select-text ${borderCls}`}
      >
        <Handle
          type="target"
          position={Position.Left}
          className="!w-2.5 !h-2.5 !bg-indigo-700 !border-2 !border-white"
        />

        <div className="flex items-center justify-between gap-1.5 mb-1.5">
          {data?.is_entry ? (
            <span className="px-1.5 py-0.5 rounded bg-indigo-700 text-white font-mono text-[9px] font-extrabold uppercase">
              Entry Service
            </span>
          ) : (
            <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-700 font-mono text-[9px] font-bold uppercase">
              Downstream
            </span>
          )}
          <span
            className={`px-1.5 py-0.5 rounded border font-mono text-[9px] font-extrabold ${
              sev === "NONE"
                ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                : getSeverityBadgeClass(sev)
            }`}
          >
            {sev === "NONE" ? "CLEAN" : sev}
          </span>
        </div>

        <div className="flex items-center gap-1.5 font-extrabold text-xs text-slate-900 truncate">
          <Server className="w-3.5 h-3.5 text-indigo-700 shrink-0" />
          <span className="truncate" title={data?.service_name || "service"}>
            {data?.service_name || "service"}
          </span>
        </div>

        <div className="mt-2 pt-2 border-t border-slate-200 grid grid-cols-2 gap-1.5 text-[10px] font-mono">
          <div className="px-2 py-1 rounded bg-[#f8fafc] border border-slate-200">
            <span className="text-slate-600 block text-[9px]">Endpoints</span>
            <strong className="text-slate-900">{data?.endpoints_count ?? 0}</strong>
          </div>
          <div className="px-2 py-1 rounded bg-[#f8fafc] border border-slate-200">
            <span className="text-slate-600 block text-[9px]">Findings</span>
            <strong
              className={
                (data?.findings_count ?? 0) > 0
                  ? "text-rose-800"
                  : "text-emerald-800"
              }
            >
              {data?.findings_count ?? 0}
            </strong>
          </div>
        </div>

        <Handle
          type="source"
          position={Position.Right}
          className="!w-2.5 !h-2.5 !bg-indigo-700 !border-2 !border-white"
        />
      </div>
    );
  });
MicroserviceNode.displayName = "MicroserviceNode";

const microserviceNodeTypes = {
  serviceNode: MicroserviceNode,
};

const microserviceEdgeTypes = {};

interface MicroserviceCanvasProps {
  nodes: Node<MicroserviceGraphNodeData>[];
  edges: Edge[];
}

const MicroserviceGraphCanvasInner: React.FC<MicroserviceCanvasProps> = ({
  nodes: propNodes,
  edges: propEdges,
}) => {
  const { fitView } = useReactFlow();
  const [nodes, setNodes, onNodesChange] =
    useNodesState<MicroserviceGraphNodeData>(propNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(propEdges);

  useEffect(() => {
    setNodes(propNodes);
    setEdges(propEdges);
  }, [propNodes, propEdges, setNodes, setEdges]);

  useEffect(() => {
    if (propNodes.length === 0) return;
    const timer = window.setTimeout(() => {
      try {
        fitView({ padding: 0.22, duration: 240 });
      } catch {}
    }, 40);
    return () => window.clearTimeout(timer);
  }, [propNodes, propEdges, fitView]);

  return (
    <div className="w-full h-[420px] bg-[#f8fafc] border border-slate-200 rounded-xl overflow-hidden relative">
      <div className="absolute top-2.5 right-2.5 z-10">
        <button
          type="button"
          onClick={() => fitView({ padding: 0.22, duration: 240 })}
          className="px-2.5 py-1 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-[11px] font-bold flex items-center gap-1 shadow-sm"
        >
          <Maximize2 className="w-3 h-3 text-indigo-700" />
          <span>Fit Graph</span>
        </button>
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={microserviceNodeTypes}
        edgeTypes={microserviceEdgeTypes}
        fitView
        minZoom={0.25}
        maxZoom={2}
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#cbd5e1" gap={20} size={1.25} />
        <Controls
          showInteractive={false}
          className="!bg-white !border-slate-300 !text-slate-800 !shadow-md rounded-lg overflow-hidden"
        />
        <MiniMap
          nodeColor={(n) => {
            const sev = String(
              (n.data as MicroserviceGraphNodeData | undefined)
                ?.highest_severity || "NONE"
            ).toUpperCase();
            if (sev === "CRITICAL") return "#be123c";
            if (sev === "HIGH") return "#d97706";
            if (sev === "MEDIUM") return "#ca8a04";
            if (sev === "LOW") return "#0284c7";
            return "#059669";
          }}
          maskColor="rgba(241, 245, 249, 0.78)"
          className="!bg-white !border-slate-300 !shadow-md rounded-lg overflow-hidden"
        />
      </ReactFlow>
    </div>
  );
};

export const NextGenAppSecStudio: React.FC = () => {
  const projectPath = useAuditStore((s) => s.projectPath);
  const appTreeRoot = useAuditStore((s) => s.appTree?.root_path || "");
  const findings = useAuditStore((s) => s.findings);
  const openCodeLocationInIde = useAuditStore((s) => s.openCodeLocationInIde);

  const prDeltaResult = useAuditStore((s) => s.prDeltaResult);
  const complianceReport = useAuditStore((s) => s.complianceReport);
  const customRules = useAuditStore((s) => s.customRules);
  const customRuleTestResult = useAuditStore((s) => s.customRuleTestResult);
  const microserviceGraph = useAuditStore((s) => s.microserviceGraph);

  const isRunningPrGate = useAuditStore((s) => s.isRunningPrGate);
  const isEvaluatingCompliance = useAuditStore((s) => s.isEvaluatingCompliance);
  const isLoadingCustomRules = useAuditStore((s) => s.isLoadingCustomRules);
  const isSavingCustomRule = useAuditStore((s) => s.isSavingCustomRule);
  const isTestingCustomRule = useAuditStore((s) => s.isTestingCustomRule);
  const isStitchingMicroservices = useAuditStore(
    (s) => s.isStitchingMicroservices
  );
  const nextgenError = useAuditStore((s) => s.nextgenError);

  const runPrDeltaGateAction = useAuditStore((s) => s.runPrDeltaGateAction);
  const evaluateComplianceAction = useAuditStore(
    (s) => s.evaluateComplianceAction
  );
  const loadCustomRulesAction = useAuditStore((s) => s.loadCustomRulesAction);
  const saveCustomRuleAction = useAuditStore((s) => s.saveCustomRuleAction);
  const deleteCustomRuleAction = useAuditStore((s) => s.deleteCustomRuleAction);
  const testCustomRuleAction = useAuditStore((s) => s.testCustomRuleAction);
  const stitchMicroserviceGraphAction = useAuditStore(
    (s) => s.stitchMicroserviceGraphAction
  );
  const clearNextgenError = useAuditStore((s) => s.clearNextgenError);

  const effectiveProjectPath = useMemo(() => {
    const p1 = (projectPath || "").trim();
    const p2 = (appTreeRoot || "").trim();
    if (isLikelyLocalProjectPath(p1)) return p1;
    if (isLikelyLocalProjectPath(p2)) return p2;
    return "";
  }, [projectPath, appTreeRoot]);

  // Sub-view switcher
  const [subView, setSubView] = useState<StudioSubView>("PR_GATE");

  // Clipboard state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const copyTimerRef = useRef<number | null>(null);

  // 1. PR Delta Gate State
  const [baseRef, setBaseRef] = useState<string>("HEAD~1");
  const [headRef, setHeadRef] = useState<string>("HEAD");
  const [failOnSeverity, setFailOnSeverity] = useState<
    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  >("HIGH");
  const [blockOnNewSecrets, setBlockOnNewSecrets] = useState<boolean>(true);
  const [blockOnNewEv, setBlockOnNewEv] = useState<boolean>(true);
  const [includeCpgNeighbors, setIncludeCpgNeighbors] = useState<boolean>(true);
  const [showPrMarkdown, setShowPrMarkdown] = useState<boolean>(true);

  // 2. Continuous Compliance Autopilot State
  const [selectedFrameworks, setSelectedFrameworks] = useState<
    ComplianceFrameworkId[]
  >([...ALL_COMPLIANCE_IDS]);
  const [focusedFrameworkId, setFocusedFrameworkId] = useState<
    ComplianceFrameworkId | "ALL"
  >("ALL");
  const [controlStatusFilter, setControlStatusFilter] = useState<
    "ALL" | "FAIL" | "WARNING" | "PASS"
  >("ALL");

  // 3. Custom Rule Studio & ReDoS-Safe Sandbox State
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [ruleIdInput, setRuleIdInput] = useState<string>("CUSTOM-SUBPROC-01");
  const [ruleNameInput, setRuleNameInput] = useState<string>(
    "Subprocess Shell Execution"
  );
  const [ruleSeverity, setRuleSeverity] = useState<
    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
  >("HIGH");
  const [ruleCweInput, setRuleCweInput] = useState<string>("CWE-78");
  const [ruleLanguagesText, setRuleLanguagesText] = useState<string>(
    "python, javascript, typescript"
  );
  const [rulePatternInput, setRulePatternInput] = useState<string>(
    String.raw`subprocess\.(?:run|Popen|check_output)\([^)]*shell\s*=\s*True`
  );
  const [ruleAntiPatternInput, setRuleAntiPatternInput] = useState<string>(
    String.raw`shlex\.quote`
  );
  const [ruleDescriptionInput, setRuleDescriptionInput] = useState<string>(
    "Detects OS command execution with shell=True without input quoting."
  );
  const [ruleRemediationInput, setRuleRemediationInput] = useState<string>(
    "Pass an argument list with shell=False instead of invoking a shell."
  );
  const [ruleComplianceControlsText, setRuleComplianceControlsText] =
    useState<string>("6.2.4, V5.3");
  const [ruleEnabled, setRuleEnabled] = useState<boolean>(true);
  const [ruleFormNotice, setRuleFormNotice] = useState<string | null>(null);

  const [sandboxMode, setSandboxMode] = useState<"SAMPLE" | "WORKSPACE">(
    "SAMPLE"
  );
  const [sampleLanguage, setSampleLanguage] = useState<string>("python");
  const [sampleCode, setSampleCode] = useState<string>(DEFAULT_SAMPLE_CODE);

  // 4. Cross-Repo Microservice Attack-Graph Stitcher State
  const [serviceRows, setServiceRows] = useState<MicroserviceRepoInput[]>([
    {
      service_name: "api-gateway",
      repo_path: effectiveProjectPath,
      base_url_hint: "",
    },
    {
      service_name: "billing-service",
      repo_path: "",
      base_url_hint: "",
    },
  ]);
  const [scanPerServiceFindings, setScanPerServiceFindings] =
    useState<boolean>(true);
  const lastAutoPathRef = useRef<string>(effectiveProjectPath);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    void loadCustomRulesAction();
  }, [loadCustomRulesAction]);

  // Keep row 0 synced when active projectPath changes if untouched
  useEffect(() => {
    setServiceRows((prev) => {
      if (prev.length === 0) return prev;
      const first = prev[0];
      if (
        !first.repo_path.trim() ||
        first.repo_path === lastAutoPathRef.current
      ) {
        const next = [...prev];
        next[0] = { ...first, repo_path: effectiveProjectPath };
        return next;
      }
      return prev;
    });
    lastAutoPathRef.current = effectiveProjectPath;
  }, [effectiveProjectPath]);

  const handleCopyText = useCallback(async (key: string, value: string) => {
    if (!value) return;
    try {
      await navigator.clipboard?.writeText(value);
      setCopiedKey(key);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedKey(null);
        copyTimerRef.current = null;
      }, 1800);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  }, []);

  const findingIdSet = useMemo(
    () => new Set(findings.map((f) => f.id)),
    [findings]
  );

  // CLI Command Hint
  const cliPrGateHint = `alastor pr-gate --repo . --base ${
    baseRef.trim() || "HEAD~1"
  } --head ${headRef.trim() || "HEAD"}`;

  // PR Delta Gate Submit
  const handleRunPrGate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    await runPrDeltaGateAction({
      project_path: effectiveProjectPath,
      base_ref: baseRef.trim() || "HEAD~1",
      head_ref: headRef.trim() || "HEAD",
      fail_on_new_severity: failOnSeverity,
      block_on_new_secrets: blockOnNewSecrets,
      block_on_new_ev_confirmed: blockOnNewEv,
      include_cpg_neighbors: includeCpgNeighbors,
    });
  };

  // Compliance Autopilot
  const toggleFrameworkSelection = (id: ComplianceFrameworkId) => {
    setSelectedFrameworks((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleEvaluateCompliance = async () => {
    const frameworksToEval =
      selectedFrameworks.length > 0 ? selectedFrameworks : ALL_COMPLIANCE_IDS;
    setFocusedFrameworkId("ALL");
    await evaluateComplianceAction(frameworksToEval, effectiveProjectPath);
  };

  const filteredControls = useMemo(() => {
    if (!complianceReport) return [];
    const rows: Array<{
      frameworkId: ComplianceFrameworkId;
      frameworkName: string;
      control: ComplianceControlResult;
    }> = [];
    for (const fw of complianceReport.frameworks) {
      if (
        focusedFrameworkId !== "ALL" &&
        fw.framework_id !== focusedFrameworkId
      ) {
        continue;
      }
      for (const ctrl of fw.controls) {
        if (
          controlStatusFilter !== "ALL" &&
          ctrl.status !== controlStatusFilter
        ) {
          continue;
        }
        rows.push({
          frameworkId: fw.framework_id,
          frameworkName: fw.framework_name,
          control: ctrl,
        });
      }
    }
    return rows;
  }, [complianceReport, focusedFrameworkId, controlStatusFilter]);

  // Custom Rule Form Helpers
  const buildDraftRule = (): CustomSecurityRule => {
    const langs = ruleLanguagesText
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    const controls = ruleComplianceControlsText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    return {
      rule_id: ruleIdInput.trim(),
      name: ruleNameInput.trim(),
      severity: ruleSeverity,
      cwe_id: ruleCweInput.trim() || "CWE-20",
      languages: langs,
      pattern: rulePatternInput,
      anti_pattern: ruleAntiPatternInput.trim() || null,
      description: ruleDescriptionInput.trim(),
      remediation: ruleRemediationInput.trim(),
      enabled: ruleEnabled,
      compliance_controls: controls,
    };
  };

  const resetRuleFormToCreate = () => {
    setEditingRuleId(null);
    setRuleIdInput("CUSTOM-RULE-01");
    setRuleNameInput("");
    setRuleSeverity("HIGH");
    setRuleCweInput("CWE-20");
    setRuleLanguagesText("python, javascript, typescript");
    setRulePatternInput("");
    setRuleAntiPatternInput("");
    setRuleDescriptionInput("");
    setRuleRemediationInput("");
    setRuleComplianceControlsText("");
    setRuleEnabled(true);
    setRuleFormNotice(null);
  };

  const loadRuleIntoEditor = (rule: CustomSecurityRule) => {
    setEditingRuleId(rule.rule_id);
    setRuleIdInput(rule.rule_id);
    setRuleNameInput(rule.name);
    setRuleSeverity(rule.severity);
    setRuleCweInput(rule.cwe_id);
    setRuleLanguagesText((rule.languages || []).join(", "));
    setRulePatternInput(rule.pattern);
    setRuleAntiPatternInput(rule.anti_pattern || "");
    setRuleDescriptionInput(rule.description || "");
    setRuleRemediationInput(rule.remediation || "");
    setRuleComplianceControlsText((rule.compliance_controls || []).join(", "));
    setRuleEnabled(Boolean(rule.enabled));
    setRuleFormNotice(null);
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setRuleFormNotice(null);
    const draft = buildDraftRule();
    const isUpdate = editingRuleId !== null;
    const saved = await saveCustomRuleAction(draft, isUpdate);
    if (saved) {
      setRuleFormNotice(
        `${isUpdate ? "Updated" : "Created"} rule '${saved.rule_id}' in .alastor_vault/custom_rules.json.`
      );
      if (!isUpdate) {
        setEditingRuleId(saved.rule_id);
      }
    }
  };

  const handleToggleRuleEnabled = async (rule: CustomSecurityRule) => {
    setRuleFormNotice(null);
    const saved = await saveCustomRuleAction(
      { ...rule, enabled: !rule.enabled },
      true
    );
    if (saved && editingRuleId === saved.rule_id) {
      setRuleEnabled(saved.enabled);
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    setRuleFormNotice(null);
    const ok = await deleteCustomRuleAction(ruleId);
    if (ok && editingRuleId === ruleId) {
      resetRuleFormToCreate();
    }
  };

  const handleRunSandboxTest = async () => {
    const draft = buildDraftRule();
    if (!draft.rule_id) {
      draft.rule_id = "SANDBOX-PREVIEW";
    }
    if (!draft.name) {
      draft.name = "Sandbox Preview Rule";
    }
    if (sandboxMode === "SAMPLE") {
      await testCustomRuleAction({
        rule: draft,
        sample_code: sampleCode,
        sample_language: sampleLanguage,
      });
    } else {
      await testCustomRuleAction({
        rule: draft,
        project_path: effectiveProjectPath,
      });
    }
  };

  // Microservice Graph Helpers
  const handleAddServiceRow = () => {
    setServiceRows((prev) => [
      ...prev,
      {
        service_name: `service-${prev.length + 1}`,
        repo_path: "",
        base_url_hint: "",
      },
    ]);
  };

  const handleRemoveServiceRow = (idx: number) => {
    setServiceRows((prev) =>
      prev.length <= 1 ? prev : prev.filter((_, i) => i !== idx)
    );
  };

  const handleUpdateServiceRow = (
    idx: number,
    field: keyof MicroserviceRepoInput,
    value: string
  ) => {
    setServiceRows((prev) =>
      prev.map((row, i) => (i === idx ? { ...row, [field]: value } : row))
    );
  };

  const handleStitchMicroservices = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleaned = serviceRows.map((row) => ({
      service_name: row.service_name.trim(),
      repo_path: row.repo_path.trim(),
      ...(row.base_url_hint && row.base_url_hint.trim()
        ? { base_url_hint: row.base_url_hint.trim() }
        : {}),
    }));
    await stitchMicroserviceGraphAction({
      services: cleaned,
      scan_findings: scanPerServiceFindings,
    });
  };

  const flowNodes = useMemo<Node<MicroserviceGraphNodeData>[]>(() => {
    if (!microserviceGraph?.reactflow_nodes) return [];
    return microserviceGraph.reactflow_nodes.map((raw, idx) => ({
      id: String(raw.id || `svc-node-${idx}`),
      type: "serviceNode",
      position:
        raw.position &&
        typeof raw.position.x === "number" &&
        typeof raw.position.y === "number"
          ? { x: raw.position.x, y: raw.position.y }
          : { x: idx * 340, y: 0 },
      data: {
        service_name: String(raw.data?.service_name || raw.id || "service"),
        endpoints_count: Number(raw.data?.endpoints_count ?? 0),
        findings_count: Number(raw.data?.findings_count ?? 0),
        highest_severity: String(raw.data?.highest_severity || "NONE"),
        is_entry: Boolean(raw.data?.is_entry),
      },
    }));
  }, [microserviceGraph]);

  const flowEdges = useMemo<Edge[]>(() => {
    if (!microserviceGraph?.reactflow_edges) return [];
    return microserviceGraph.reactflow_edges.map((raw, idx) => {
      const isAtk = Boolean(raw.data?.is_attack_path || raw.animated);
      return {
        id: String(raw.id || `ms-edge-${idx}`),
        source: String(raw.source || ""),
        target: String(raw.target || ""),
        label: raw.label ? String(raw.label) : undefined,
        animated: isAtk,
        type: "smoothstep",
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isAtk ? "#be123c" : "#475569",
        },
        style: {
          stroke: isAtk ? "#be123c" : "#64748b",
          strokeWidth: isAtk ? 2.5 : 1.5,
        },
        labelStyle: {
          fill: isAtk ? "#9f1239" : "#334155",
          fontWeight: 700,
          fontSize: 10,
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        },
        labelBgStyle: {
          fill: "#ffffff",
          fillOpacity: 0.94,
        },
        labelBgPadding: [4, 3] as [number, number],
        labelBgBorderRadius: 4,
      };
    });
  }, [microserviceGraph]);

  const subTabs: Array<{
    id: StudioSubView;
    label: string;
    icon: React.ReactNode;
    badge?: string | number;
  }> = [
    {
      id: "PR_GATE",
      label: "1. PR Delta Gate",
      icon: <GitPullRequest className="w-3.5 h-3.5" />,
      badge: prDeltaResult ? prDeltaResult.gate_decision : undefined,
    },
    {
      id: "COMPLIANCE",
      label: "2. Compliance Autopilot (5)",
      icon: <ShieldCheck className="w-3.5 h-3.5" />,
      badge: complianceReport
        ? `${complianceReport.overall_score_percent.toFixed(0)}%`
        : "5 Frameworks",
    },
    {
      id: "CUSTOM_RULES",
      label: "3. Custom Rule Studio",
      icon: <FileCode2 className="w-3.5 h-3.5" />,
      badge: customRules.length,
    },
    {
      id: "MICROSERVICE_GRAPH",
      label: "4. Microservice Attack Graph",
      icon: <Network className="w-3.5 h-3.5" />,
      badge: microserviceGraph
        ? `${microserviceGraph.cross_service_attack_paths_count} Paths`
        : undefined,
    },
  ];

  return (
    <div className="flex-1 min-w-0 min-h-0 overflow-y-auto bg-[#f8fafc] text-slate-900 p-4 sm:p-5 select-text">
      <div className="max-w-7xl mx-auto space-y-4">
        {/* Studio Header */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-200 text-indigo-700 flex items-center justify-center shrink-0">
                <Sparkles className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h1 className="text-base font-extrabold text-slate-900">
                    ALASTOR v5.0 Next-Gen AppSec Studio
                  </h1>
                  <span className="px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900 font-mono text-[10px] font-extrabold">
                    $0 DETERMINISTIC ENGINES
                  </span>
                </div>
                <p className="text-xs text-slate-600 mt-0.5">
                  Git-diff PR Delta Merge Gate, 5-Framework Continuous Compliance
                  Autopilot, ReDoS-safe Custom Rule Studio, and Cross-Repo
                  Microservice Attack-Graph Stitcher.
                </p>
              </div>
            </div>

            <div className="px-3 py-1.5 rounded-lg bg-[#f8fafc] border border-slate-200 text-xs font-mono text-slate-700 flex items-center gap-1.5 max-w-full">
              <FolderOpen className="w-3.5 h-3.5 text-indigo-700 shrink-0" />
              <span className="font-bold text-slate-900 shrink-0">
                Workspace:
              </span>
              <span
                className="truncate max-w-[260px]"
                title={effectiveProjectPath || "None selected"}
              >
                {effectiveProjectPath || "(Select or scan a local repo first)"}
              </span>
            </div>
          </div>

          {/* 4 Sub-View Tabs */}
          <div
            role="tablist"
            aria-label="Next-Gen AppSec Studio Sub-Views"
            className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-slate-200"
          >
            {subTabs.map((tab) => {
              const active = subView === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setSubView(tab.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold border flex items-center gap-1.5 transition-colors ${
                    active
                      ? "bg-indigo-700 text-white border-indigo-800 shadow-sm"
                      : "bg-[#f8fafc] hover:bg-slate-100 text-slate-700 border-slate-200"
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                  {tab.badge !== undefined && (
                    <span
                      className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-extrabold ${
                        active
                          ? "bg-indigo-800 text-white"
                          : "bg-white border border-slate-300 text-slate-800"
                      }`}
                    >
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Global Studio Error Banner */}
        {nextgenError && (
          <div
            role="alert"
            className="p-3 rounded-xl bg-rose-50 border border-rose-300 text-rose-950 text-xs flex items-start justify-between gap-2 shadow-sm"
          >
            <div className="flex items-start gap-2 min-w-0">
              <AlertTriangle className="w-4 h-4 text-rose-700 shrink-0 mt-0.5" />
              <div className="font-semibold break-words">{nextgenError}</div>
            </div>
            <button
              type="button"
              onClick={clearNextgenError}
              aria-label="Dismiss error"
              className="p-1 rounded hover:bg-rose-100 text-rose-800 shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* ================================================================ */}
        {/* SUB-VIEW 1: PR DELTA GATE                                        */}
        {/* ================================================================ */}
        {subView === "PR_GATE" && (
          <div className="space-y-4">
            <form
              onSubmit={handleRunPrGate}
              className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-sm font-extrabold text-slate-900 flex items-center gap-1.5">
                    <GitPullRequest className="w-4 h-4 text-indigo-700" />
                    <span>PR / Git-Diff Incremental Security Gate</span>
                  </h2>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Separates <b>NEWLY_INTRODUCED</b> findings in PR diff hunks
                    from <b>MODIFIED_CONTEXT</b> (including 1-hop CPG
                    neighbors) and <b>PRE_EXISTING</b> debt.
                  </p>
                </div>
                <button
                  type="submit"
                  disabled={isRunningPrGate || !effectiveProjectPath}
                  className="px-4 py-2 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white text-xs font-extrabold flex items-center gap-1.5 shadow-sm"
                >
                  {isRunningPrGate ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5 fill-current" />
                  )}
                  <span>
                    {isRunningPrGate
                      ? "Evaluating PR Delta..."
                      : "Evaluate PR Merge Gate"}
                  </span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                    Base Git Ref
                  </label>
                  <input
                    type="text"
                    value={baseRef}
                    onChange={(e) => setBaseRef(e.target.value)}
                    placeholder="HEAD~1"
                    className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-600"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-[11px] font-mono font-bold text-slate-700">
                      Head Git Ref
                    </label>
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => setHeadRef("HEAD")}
                        className={`px-1.5 py-0.5 rounded font-mono text-[9px] font-bold border ${
                          headRef === "HEAD"
                            ? "bg-indigo-700 text-white border-indigo-800"
                            : "bg-slate-100 text-slate-700 border-slate-300"
                        }`}
                      >
                        HEAD
                      </button>
                      <button
                        type="button"
                        onClick={() => setHeadRef("WORKTREE")}
                        className={`px-1.5 py-0.5 rounded font-mono text-[9px] font-bold border ${
                          headRef === "WORKTREE"
                            ? "bg-indigo-700 text-white border-indigo-800"
                            : "bg-slate-100 text-slate-700 border-slate-300"
                        }`}
                      >
                        WORKTREE
                      </button>
                    </div>
                  </div>
                  <input
                    type="text"
                    value={headRef}
                    onChange={(e) => setHeadRef(e.target.value)}
                    placeholder="HEAD or WORKTREE"
                    className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-600"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                    Fail On New Severity (&ge;)
                  </label>
                  <select
                    aria-label="Fail on new severity"
                    value={failOnSeverity}
                    onChange={(e) =>
                      setFailOnSeverity(
                        e.target.value as
                          | "CRITICAL"
                          | "HIGH"
                          | "MEDIUM"
                          | "LOW"
                      )
                    }
                    className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900 focus:outline-none focus:border-indigo-600"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH (Recommended)</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-4 pt-1 text-xs text-slate-800">
                <label className="flex items-center gap-2 cursor-pointer font-semibold">
                  <input
                    type="checkbox"
                    checked={blockOnNewSecrets}
                    onChange={(e) => setBlockOnNewSecrets(e.target.checked)}
                    className="accent-indigo-700 w-3.5 h-3.5"
                  />
                  <span>Block on New Secrets</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer font-semibold">
                  <input
                    type="checkbox"
                    checked={blockOnNewEv}
                    onChange={(e) => setBlockOnNewEv(e.target.checked)}
                    className="accent-indigo-700 w-3.5 h-3.5"
                  />
                  <span>Block on New EV-Confirmed Exploits</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer font-semibold">
                  <input
                    type="checkbox"
                    checked={includeCpgNeighbors}
                    onChange={(e) => setIncludeCpgNeighbors(e.target.checked)}
                    className="accent-indigo-700 w-3.5 h-3.5"
                  />
                  <span>Include 1-Hop CPG Neighbors</span>
                </label>
              </div>

              {/* CLI Hint Strip */}
              <div className="p-2.5 rounded-lg bg-[#f8fafc] border border-slate-200 flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 text-[11px] font-mono text-slate-700 min-w-0">
                  <Terminal className="w-3.5 h-3.5 text-indigo-700 shrink-0" />
                  <span className="font-bold text-slate-900 shrink-0">
                    CI/CD CLI:
                  </span>
                  <code className="truncate text-slate-800">
                    {cliPrGateHint}
                  </code>
                </div>
                <button
                  type="button"
                  onClick={() => void handleCopyText("cli-pr-gate", cliPrGateHint)}
                  className="px-2 py-1 rounded bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 font-mono text-[10px] font-bold flex items-center gap-1 shrink-0"
                >
                  {copiedKey === "cli-pr-gate" ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-700" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy CLI</span>
                    </>
                  )}
                </button>
              </div>
            </form>

            {prDeltaResult ? (
              <div className="space-y-4">
                {/* Decision Banner */}
                <div
                  className={`p-4 rounded-xl border flex flex-wrap items-center justify-between gap-3 shadow-sm ${
                    prDeltaResult.gate_decision === "PASS"
                      ? "bg-emerald-50 border-emerald-300 text-emerald-950"
                      : "bg-rose-50 border-rose-300 text-rose-950"
                  }`}
                >
                  <div className="flex items-start gap-2.5 min-w-0">
                    {prDeltaResult.gate_decision === "PASS" ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-700 shrink-0 mt-0.5" />
                    ) : (
                      <ShieldAlert className="w-5 h-5 text-rose-700 shrink-0 mt-0.5" />
                    )}
                    <div className="space-y-0.5 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[11px] font-extrabold ${
                            prDeltaResult.gate_decision === "PASS"
                              ? "bg-emerald-700 text-white"
                              : "bg-rose-700 text-white"
                          }`}
                        >
                          {prDeltaResult.gate_decision}
                        </span>
                        <span className="font-mono text-xs font-bold">
                          {prDeltaResult.base_ref} .. {prDeltaResult.head_ref}
                        </span>
                      </div>
                      <p className="text-xs font-semibold leading-snug">
                        {prDeltaResult.gate_reason}
                      </p>
                    </div>
                  </div>
                </div>

                {/* 4 KPI Cards */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Newly Introduced
                    </div>
                    <div className="text-2xl font-extrabold text-rose-700 mt-1">
                      {prDeltaResult.newly_introduced_count}
                    </div>
                  </div>
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Modified Context
                    </div>
                    <div className="text-2xl font-extrabold text-amber-700 mt-1">
                      {prDeltaResult.modified_context_count}
                    </div>
                  </div>
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Pre-Existing
                    </div>
                    <div className="text-2xl font-extrabold text-slate-800 mt-1">
                      {prDeltaResult.pre_existing_count}
                    </div>
                  </div>
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Blocking Count
                    </div>
                    <div
                      className={`text-2xl font-extrabold mt-1 ${
                        prDeltaResult.blocking_count > 0
                          ? "text-rose-700"
                          : "text-emerald-700"
                      }`}
                    >
                      {prDeltaResult.blocking_count}
                    </div>
                  </div>
                </div>

                {/* Changed & Neighbor Files Pills */}
                <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-mono font-bold uppercase text-slate-700">
                      Changed Files in Diff ({prDeltaResult.changed_files.length})
                    </div>
                    {prDeltaResult.changed_files.length === 0 ? (
                      <div className="text-xs text-slate-600">
                        No changed files reported between{" "}
                        <code>{prDeltaResult.base_ref}</code> and{" "}
                        <code>{prDeltaResult.head_ref}</code>.
                      </div>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {prDeltaResult.changed_files.map((fp) => (
                          <span
                            key={fp}
                            className="px-2 py-0.5 rounded-md bg-indigo-50 border border-indigo-200 text-indigo-900 font-mono text-[11px] font-semibold"
                          >
                            {fp}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="space-y-1.5 pt-2 border-t border-slate-200">
                    <div className="text-[11px] font-mono font-bold uppercase text-slate-700">
                      1-Hop CPG Impacted Neighbor Files (
                      {prDeltaResult.impacted_neighbor_files.length})
                    </div>
                    {prDeltaResult.impacted_neighbor_files.length === 0 ? (
                      <div className="text-xs text-slate-600">
                        No 1-hop CPG call-graph neighbor files impacted.
                      </div>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {prDeltaResult.impacted_neighbor_files.map((fp) => (
                          <span
                            key={fp}
                            className="px-2 py-0.5 rounded-md bg-amber-50 border border-amber-300 text-amber-950 font-mono text-[11px] font-semibold"
                          >
                            {fp}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* PR Annotations Table */}
                <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-xs font-extrabold uppercase tracking-wide text-slate-800">
                      PR Inline Annotations ({prDeltaResult.annotations.length})
                    </h3>
                  </div>

                  {prDeltaResult.annotations.length === 0 ? (
                    <div className="p-4 rounded-lg bg-[#f8fafc] border border-slate-200 text-xs text-slate-600 text-center">
                      Zero annotations generated for this diff range.
                    </div>
                  ) : (
                    <div className="overflow-x-auto rounded-lg border border-slate-200">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                            <th className="py-2 px-3">Classification</th>
                            <th className="py-2 px-3">Severity</th>
                            <th className="py-2 px-3">Rule / CWE</th>
                            <th className="py-2 px-3">Location</th>
                            <th className="py-2 px-3">Finding &amp; Message</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200">
                          {prDeltaResult.annotations.map((ann, idx) => {
                            const clsMeta = getDeltaClassBadge(
                              ann.classification
                            );
                            return (
                              <tr
                                key={`${ann.finding_id}-${idx}`}
                                className="bg-white hover:bg-[#f8fafc]"
                              >
                                <td className="py-2 px-3 whitespace-nowrap">
                                  <span
                                    className={`px-2 py-0.5 rounded border font-mono text-[10px] font-extrabold ${clsMeta.className}`}
                                  >
                                    {clsMeta.label}
                                  </span>
                                </td>
                                <td className="py-2 px-3 whitespace-nowrap">
                                  <span
                                    className={`px-2 py-0.5 rounded border font-mono text-[10px] font-extrabold ${getSeverityBadgeClass(
                                      ann.severity
                                    )}`}
                                  >
                                    {ann.severity}
                                  </span>
                                </td>
                                <td className="py-2 px-3 font-mono text-[11px] text-slate-800 whitespace-nowrap">
                                  <div className="font-bold">{ann.rule_id}</div>
                                  {ann.cwe_id && (
                                    <div className="text-slate-600">
                                      {ann.cwe_id}
                                    </div>
                                  )}
                                </td>
                                <td className="py-2 px-3 font-mono text-[11px] whitespace-nowrap">
                                  <button
                                    type="button"
                                    onClick={() =>
                                      openCodeLocationInIde(
                                        ann.filepath,
                                        ann.line,
                                        ann.finding_id
                                      )
                                    }
                                    className="text-indigo-700 hover:underline font-bold"
                                  >
                                    {ann.filepath}:{ann.line}
                                  </button>
                                </td>
                                <td className="py-2 px-3">
                                  <div className="font-bold text-slate-900">
                                    {ann.title}
                                  </div>
                                  <div className="text-[11px] text-slate-600 mt-0.5">
                                    {ann.message}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Expandable Plain-Text PR Markdown Summary */}
                <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => setShowPrMarkdown((prev) => !prev)}
                      className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5"
                    >
                      {showPrMarkdown ? (
                        <ChevronUp className="w-4 h-4 text-slate-600" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-600" />
                      )}
                      <span>PR Review Markdown Summary</span>
                    </button>

                    <button
                      type="button"
                      disabled={!prDeltaResult.pr_markdown_summary}
                      onClick={() =>
                        void handleCopyText(
                          "pr-markdown",
                          prDeltaResult.pr_markdown_summary
                        )
                      }
                      className="px-2.5 py-1 rounded-lg bg-[#f8fafc] hover:bg-slate-100 disabled:opacity-50 border border-slate-300 text-slate-800 font-mono text-[11px] font-bold flex items-center gap-1"
                    >
                      {copiedKey === "pr-markdown" ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-700" />
                          <span>Copied PR Markdown</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy PR Markdown</span>
                        </>
                      )}
                    </button>
                  </div>

                  {showPrMarkdown && (
                    <pre className="p-3 rounded-lg bg-[#f8fafc] border border-slate-200 font-mono text-[11px] text-slate-900 overflow-x-auto whitespace-pre-wrap break-words max-h-80">
                      {prDeltaResult.pr_markdown_summary ||
                        "No Markdown summary returned."}
                    </pre>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-white border border-dashed border-slate-300 rounded-xl p-8 text-center space-y-1.5">
                <GitPullRequest className="w-7 h-7 mx-auto text-slate-400" />
                <div className="text-sm font-bold text-slate-900">
                  No PR Delta Evaluation Run Yet
                </div>
                <p className="text-xs text-slate-600 max-w-xl mx-auto">
                  Specify base and head git refs (or <code>WORKTREE</code> for
                  uncommitted changes) and click{" "}
                  <b>Evaluate PR Merge Gate</b>.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ================================================================ */}
        {/* SUB-VIEW 2: CONTINUOUS COMPLIANCE AUTOPILOT (5 FRAMEWORKS)       */}
        {/* ================================================================ */}
        {subView === "COMPLIANCE" && (
          <div className="space-y-4">
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-extrabold text-slate-900 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-700" />
                    <span>Continuous Compliance Autopilot (5 Frameworks)</span>
                  </h2>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Maps active SAST/SCA/IaC/Custom Rule findings and live EV
                    runtime confirmations to concrete control attestations.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      setSelectedFrameworks([...ALL_COMPLIANCE_IDS])
                    }
                    className="px-2.5 py-1.5 rounded-lg bg-[#f8fafc] hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold"
                  >
                    Select All (5)
                  </button>
                  <button
                    type="button"
                    disabled={isEvaluatingCompliance || !effectiveProjectPath}
                    onClick={() => void handleEvaluateCompliance()}
                    className="px-4 py-2 rounded-xl bg-emerald-700 hover:bg-emerald-800 disabled:opacity-50 text-white text-xs font-extrabold flex items-center gap-1.5 shadow-sm"
                  >
                    {isEvaluatingCompliance ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <ShieldCheck className="w-4 h-4" />
                    )}
                    <span>
                      {isEvaluatingCompliance
                        ? "Evaluating Posture..."
                        : "Evaluate Live Compliance"}
                    </span>
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {COMPLIANCE_FRAMEWORKS_META.map((fw) => {
                  const selected = selectedFrameworks.includes(fw.id);
                  return (
                    <button
                      key={fw.id}
                      type="button"
                      onClick={() => toggleFrameworkSelection(fw.id)}
                      className={`px-3 py-1.5 rounded-lg border text-xs font-bold flex items-center gap-1.5 transition-colors ${
                        selected
                          ? "bg-indigo-50 border-indigo-500 text-indigo-950"
                          : "bg-[#f8fafc] border-slate-200 text-slate-600 hover:bg-slate-100"
                      }`}
                    >
                      <span>{fw.label}</span>
                      <span className="text-[10px] font-normal text-slate-600">
                        ({fw.shortDesc})
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {complianceReport ? (
              <div className="space-y-4">
                {/* Overall Posture Banner */}
                <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div
                      className={`px-3 py-2 rounded-xl border text-center ${
                        complianceReport.overall_score_percent >= 85
                          ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                          : complianceReport.overall_score_percent >= 60
                          ? "bg-amber-50 border-amber-300 text-amber-950"
                          : "bg-rose-50 border-rose-300 text-rose-950"
                      }`}
                    >
                      <div className="text-[10px] font-mono uppercase font-bold">
                        Overall Score
                      </div>
                      <div className="text-2xl font-extrabold">
                        {complianceReport.overall_score_percent.toFixed(1)}%
                      </div>
                    </div>
                    <div className="space-y-0.5">
                      <div className="text-sm font-extrabold text-slate-900">
                        {complianceReport.frameworks.length} Frameworks Evaluated
                      </div>
                      <div className="text-xs text-slate-600 font-mono">
                        {complianceReport.total_findings_evaluated} active
                        findings analyzed • Evaluated{" "}
                        {complianceReport.evaluated_at}
                      </div>
                    </div>
                  </div>
                </div>

                {/* 5 Framework Score Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
                  {complianceReport.frameworks.map((fw) => {
                    const isFocused = focusedFrameworkId === fw.framework_id;
                    return (
                      <button
                        key={fw.framework_id}
                        type="button"
                        onClick={() =>
                          setFocusedFrameworkId((prev) =>
                            prev === fw.framework_id ? "ALL" : fw.framework_id
                          )
                        }
                        className={`text-left bg-white rounded-xl p-3.5 border shadow-sm transition-all space-y-2 ${
                          isFocused
                            ? "border-indigo-600 ring-2 ring-indigo-600/20"
                            : "border-slate-200 hover:border-slate-300"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1.5">
                          <span className="text-xs font-extrabold text-slate-900 truncate">
                            {fw.framework_name}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded border font-mono text-[9px] font-extrabold shrink-0 ${getComplianceStatusBadge(
                              fw.status
                            )}`}
                          >
                            {fw.status.replace(/_/g, " ")}
                          </span>
                        </div>

                        <div className="flex items-baseline justify-between">
                          <span className="text-2xl font-extrabold text-slate-900">
                            {fw.score_percent.toFixed(0)}%
                          </span>
                          <span className="text-[10px] font-mono text-slate-600">
                            v{fw.version}
                          </span>
                        </div>

                        <div className="grid grid-cols-3 gap-1 text-center font-mono text-[10px] pt-1 border-t border-slate-200">
                          <div className="rounded bg-emerald-50 text-emerald-900 py-0.5 font-bold">
                            {fw.passed_controls} Pass
                          </div>
                          <div className="rounded bg-amber-50 text-amber-950 py-0.5 font-bold">
                            {fw.warning_controls} Warn
                          </div>
                          <div className="rounded bg-rose-50 text-rose-950 py-0.5 font-bold">
                            {fw.failed_controls} Fail
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>

                {/* Interactive Per-Control Attestation Table */}
                <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-xs font-extrabold uppercase tracking-wide text-slate-800">
                        Control Attestation Matrix ({filteredControls.length})
                      </h3>
                      {focusedFrameworkId !== "ALL" && (
                        <button
                          type="button"
                          onClick={() => setFocusedFrameworkId("ALL")}
                          className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-900 font-mono text-[10px] font-bold"
                        >
                          Show All Frameworks &times;
                        </button>
                      )}
                    </div>

                    <div className="flex items-center gap-1">
                      {(["ALL", "FAIL", "WARNING", "PASS"] as const).map(
                        (st) => (
                          <button
                            key={st}
                            type="button"
                            onClick={() => setControlStatusFilter(st)}
                            className={`px-2 py-1 rounded-md font-mono text-[10px] font-bold border ${
                              controlStatusFilter === st
                                ? "bg-indigo-700 text-white border-indigo-800"
                                : "bg-[#f8fafc] text-slate-700 border-slate-200 hover:bg-slate-100"
                            }`}
                          >
                            {st}
                          </button>
                        )
                      )}
                    </div>
                  </div>

                  <div className="overflow-x-auto rounded-lg border border-slate-200">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-mono uppercase text-slate-700">
                          <th className="py-2 px-3">Framework</th>
                          <th className="py-2 px-3">Control ID</th>
                          <th className="py-2 px-3">Control Title</th>
                          <th className="py-2 px-3">Status</th>
                          <th className="py-2 px-3">Matched CWEs</th>
                          <th className="py-2 px-3">Findings</th>
                          <th className="py-2 px-3">Evidence Summary</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {filteredControls.length === 0 ? (
                          <tr>
                            <td
                              colSpan={7}
                              className="py-6 px-3 text-center text-slate-600"
                            >
                              No controls match the active framework/status
                              filter.
                            </td>
                          </tr>
                        ) : (
                          filteredControls.map(
                            ({ frameworkId, frameworkName, control }) => {
                              const firstActiveFindingId =
                                control.matched_finding_ids.find((fid) =>
                                  findingIdSet.has(fid)
                                );
                              return (
                                <tr
                                  key={`${frameworkId}-${control.control_id}`}
                                  className="bg-white hover:bg-[#f8fafc]"
                                >
                                  <td className="py-2 px-3 font-mono text-[11px] font-bold text-slate-800 whitespace-nowrap">
                                    {frameworkName}
                                  </td>
                                  <td className="py-2 px-3 font-mono text-[11px] font-extrabold text-indigo-800 whitespace-nowrap">
                                    {control.control_id}
                                  </td>
                                  <td className="py-2 px-3 min-w-[200px]">
                                    <div className="font-bold text-slate-900">
                                      {control.title}
                                    </div>
                                    <div className="text-[11px] text-slate-600">
                                      {control.description}
                                    </div>
                                  </td>
                                  <td className="py-2 px-3 whitespace-nowrap">
                                    <span
                                      className={`px-2 py-0.5 rounded border font-mono text-[10px] font-extrabold ${getControlStatusBadge(
                                        control.status
                                      )}`}
                                    >
                                      {control.status}
                                    </span>
                                  </td>
                                  <td className="py-2 px-3">
                                    {control.matched_cwes.length === 0 ? (
                                      <span className="text-slate-500 font-mono text-[10px]">
                                        —
                                      </span>
                                    ) : (
                                      <div className="flex flex-wrap gap-1">
                                        {control.matched_cwes.map((cwe) => (
                                          <span
                                            key={cwe}
                                            className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300 font-mono text-[10px] font-bold text-slate-800"
                                          >
                                            {cwe}
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                  </td>
                                  <td className="py-2 px-3 whitespace-nowrap font-mono text-[11px]">
                                    {firstActiveFindingId ? (
                                      <button
                                        type="button"
                                        onClick={() =>
                                          openCodeLocationInIde(
                                            undefined,
                                            undefined,
                                            firstActiveFindingId
                                          )
                                        }
                                        className="px-2 py-0.5 rounded bg-rose-50 hover:bg-rose-100 border border-rose-300 text-rose-900 font-bold"
                                      >
                                        {control.matched_finding_ids.length}{" "}
                                        finding(s) →
                                      </button>
                                    ) : (
                                      <span className="font-bold text-slate-700">
                                        {control.matched_finding_ids.length}
                                      </span>
                                    )}
                                  </td>
                                  <td className="py-2 px-3 text-[11px] text-slate-700 min-w-[220px]">
                                    {control.evidence_summary}
                                  </td>
                                </tr>
                              );
                            }
                          )
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-white border border-dashed border-slate-300 rounded-xl p-8 text-center space-y-1.5">
                <ShieldCheck className="w-7 h-7 mx-auto text-slate-400" />
                <div className="text-sm font-bold text-slate-900">
                  Continuous Compliance Not Yet Evaluated
                </div>
                <p className="text-xs text-slate-600 max-w-xl mx-auto">
                  Click <b>Evaluate Live Compliance</b> to attest active
                  findings and runtime verification signals across PCI-DSS 4.0,
                  SOC 2, ISO 27001, HIPAA, and OWASP ASVS 5.0.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ================================================================ */}
        {/* SUB-VIEW 3: CUSTOM RULE STUDIO & ReDoS-SAFE SANDBOX              */}
        {/* ================================================================ */}
        {subView === "CUSTOM_RULES" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
            {/* Left: Saved Custom Rules List */}
            <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div>
                  <h2 className="text-sm font-extrabold text-slate-900">
                    Saved Custom Rules ({customRules.length})
                  </h2>
                  <p className="text-[11px] font-mono text-slate-600">
                    Vault: <code>.alastor_vault/custom_rules.json</code>
                  </p>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => void loadCustomRulesAction()}
                    disabled={isLoadingCustomRules}
                    className="px-2.5 py-1 rounded-lg bg-[#f8fafc] hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1"
                  >
                    <RefreshCw
                      className={`w-3.5 h-3.5 ${
                        isLoadingCustomRules ? "animate-spin" : ""
                      }`}
                    />
                    <span>Refresh</span>
                  </button>
                  <button
                    type="button"
                    onClick={resetRuleFormToCreate}
                    className="px-2.5 py-1 rounded-lg bg-indigo-700 hover:bg-indigo-800 text-white text-xs font-bold flex items-center gap-1"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>New Rule</span>
                  </button>
                </div>
              </div>

              {isLoadingCustomRules && customRules.length === 0 ? (
                <div className="py-8 flex items-center justify-center gap-2 text-xs font-mono text-slate-600">
                  <Loader2 className="w-4 h-4 animate-spin text-indigo-700" />
                  <span>Loading custom rules vault...</span>
                </div>
              ) : customRules.length === 0 ? (
                <div className="p-6 rounded-xl bg-[#f8fafc] border border-dashed border-slate-300 text-center space-y-2">
                  <FileCode2 className="w-6 h-6 mx-auto text-slate-400" />
                  <div className="text-xs font-bold text-slate-900">
                    No Custom Security Rules Persisted Yet
                  </div>
                  <p className="text-[11px] text-slate-600">
                    Author a ReDoS-safe regex rule on the right and test it in
                    the live sandbox before saving to the vault.
                  </p>
                </div>
              ) : (
                <div className="space-y-2.5 max-h-[680px] overflow-y-auto pr-1">
                  {customRules.map((rule) => (
                    <div
                      key={rule.rule_id}
                      className={`p-3 rounded-xl border space-y-2 transition-colors ${
                        editingRuleId === rule.rule_id
                          ? "bg-indigo-50/60 border-indigo-400"
                          : "bg-[#f8fafc] border-slate-200"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span
                              className={`px-1.5 py-0.5 rounded border font-mono text-[9.5px] font-extrabold ${getSeverityBadgeClass(
                                rule.severity
                              )}`}
                            >
                              {rule.severity}
                            </span>
                            <span className="font-mono text-[11px] font-extrabold text-indigo-800">
                              {rule.rule_id}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-white border border-slate-300 font-mono text-[9.5px] font-bold text-slate-700">
                              {rule.cwe_id}
                            </span>
                          </div>
                          <div className="text-xs font-bold text-slate-900 mt-1">
                            {rule.name}
                          </div>
                        </div>

                        <span
                          className={`px-2 py-0.5 rounded font-mono text-[9.5px] font-extrabold border shrink-0 ${
                            rule.enabled
                              ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                              : "bg-slate-100 text-slate-600 border-slate-300"
                          }`}
                        >
                          {rule.enabled ? "ENABLED" : "DISABLED"}
                        </span>
                      </div>

                      <div className="p-2 rounded bg-white border border-slate-200 font-mono text-[10.5px] text-slate-800 break-all">
                        {rule.pattern}
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                        <div className="flex flex-wrap gap-1">
                          {(rule.languages || []).length > 0 ? (
                            (rule.languages || []).map((lang) => (
                              <span
                                key={lang}
                                className="px-1.5 py-0.5 rounded bg-white border border-slate-200 font-mono text-[9.5px] text-slate-700"
                              >
                                {lang}
                              </span>
                            ))
                          ) : (
                            <span className="px-1.5 py-0.5 rounded bg-white border border-slate-200 font-mono text-[9.5px] text-slate-600">
                              all languages
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1">
                          <button
                            type="button"
                            disabled={isSavingCustomRule}
                            onClick={() => void handleToggleRuleEnabled(rule)}
                            title={rule.enabled ? "Disable rule" : "Enable rule"}
                            className="px-2 py-1 rounded bg-white hover:bg-slate-100 border border-slate-300 text-slate-800 text-[10px] font-bold flex items-center gap-1"
                          >
                            <Power className="w-3 h-3" />
                            <span>{rule.enabled ? "Disable" : "Enable"}</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => loadRuleIntoEditor(rule)}
                            className="px-2 py-1 rounded bg-white hover:bg-slate-100 border border-slate-300 text-indigo-800 text-[10px] font-bold flex items-center gap-1"
                          >
                            <Edit3 className="w-3 h-3" />
                            <span>Edit</span>
                          </button>
                          <button
                            type="button"
                            disabled={isSavingCustomRule}
                            onClick={() => void handleDeleteRule(rule.rule_id)}
                            className="px-2 py-1 rounded bg-rose-50 hover:bg-rose-100 border border-rose-300 text-rose-900 text-[10px] font-bold flex items-center gap-1"
                          >
                            <Trash2 className="w-3 h-3" />
                            <span>Delete</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Right: Rule Authoring Form + Test Rule in Sandbox */}
            <div className="lg:col-span-7 space-y-4">
              <form
                onSubmit={handleSaveRule}
                className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3"
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div>
                    <h2 className="text-sm font-extrabold text-slate-900">
                      {editingRuleId
                        ? `Edit Custom Rule: ${editingRuleId}`
                        : "Author New Custom Security Rule"}
                    </h2>
                    <p className="text-[11px] text-slate-600">
                      All patterns undergo AST-level ReDoS validation (&le; 400
                      chars, no nested quantifiers or backreferences).
                    </p>
                  </div>
                  {editingRuleId && (
                    <button
                      type="button"
                      onClick={resetRuleFormToCreate}
                      className="px-2.5 py-1 rounded-lg bg-[#f8fafc] hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-bold"
                    >
                      Cancel Edit
                    </button>
                  )}
                </div>

                {ruleFormNotice && (
                  <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-900 text-xs font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-700 shrink-0" />
                    <span>{ruleFormNotice}</span>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Rule ID *
                    </label>
                    <input
                      type="text"
                      required
                      disabled={editingRuleId !== null}
                      value={ruleIdInput}
                      onChange={(e) => setRuleIdInput(e.target.value)}
                      placeholder="CUSTOM-RULE-01"
                      className="w-full bg-[#f8fafc] disabled:bg-slate-100 border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Rule Name *
                    </label>
                    <input
                      type="text"
                      required
                      value={ruleNameInput}
                      onChange={(e) => setRuleNameInput(e.target.value)}
                      placeholder="Unsafe Eval or Shell Call"
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-900"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Severity
                    </label>
                    <select
                      aria-label="Custom rule severity"
                      value={ruleSeverity}
                      onChange={(e) =>
                        setRuleSeverity(
                          e.target.value as
                            | "CRITICAL"
                            | "HIGH"
                            | "MEDIUM"
                            | "LOW"
                            | "INFO"
                        )
                      }
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                      <option value="INFO">INFO</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      CWE ID
                    </label>
                    <input
                      type="text"
                      value={ruleCweInput}
                      onChange={(e) => setRuleCweInput(e.target.value)}
                      placeholder="CWE-78"
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Languages (comma-sep)
                    </label>
                    <input
                      type="text"
                      value={ruleLanguagesText}
                      onChange={(e) => setRuleLanguagesText(e.target.value)}
                      placeholder="python, javascript, typescript (leave blank for all languages)"
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-[11px] font-mono font-bold text-slate-700">
                      Detection Regex Pattern *
                    </label>
                    <span
                      className={`font-mono text-[10px] font-bold ${
                        rulePatternInput.length > 400
                          ? "text-rose-700"
                          : "text-slate-600"
                      }`}
                    >
                      {rulePatternInput.length}/400 chars
                    </span>
                  </div>
                  <input
                    type="text"
                    required
                    value={rulePatternInput}
                    onChange={(e) => setRulePatternInput(e.target.value)}
                    placeholder="e.g. eval\s*\("
                    className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Anti-Pattern Suppression (Optional)
                    </label>
                    <input
                      type="text"
                      value={ruleAntiPatternInput}
                      onChange={(e) => setRuleAntiPatternInput(e.target.value)}
                      placeholder="e.g. shlex\.quote"
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Compliance Controls (comma-sep)
                    </label>
                    <input
                      type="text"
                      value={ruleComplianceControlsText}
                      onChange={(e) =>
                        setRuleComplianceControlsText(e.target.value)
                      }
                      placeholder="6.2.4, V5.3"
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Description
                    </label>
                    <textarea
                      rows={2}
                      value={ruleDescriptionInput}
                      onChange={(e) => setRuleDescriptionInput(e.target.value)}
                      placeholder="Explain why this pattern introduces risk..."
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-mono font-bold text-slate-700 mb-1">
                      Remediation Guidance
                    </label>
                    <textarea
                      rows={2}
                      value={ruleRemediationInput}
                      onChange={(e) => setRuleRemediationInput(e.target.value)}
                      placeholder="Recommended safe API or validation..."
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-900"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                  <label className="flex items-center gap-2 text-xs font-semibold text-slate-800 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={ruleEnabled}
                      onChange={(e) => setRuleEnabled(e.target.checked)}
                      className="accent-indigo-700 w-3.5 h-3.5"
                    />
                    <span>Rule Enabled in Live Scans &amp; PR Gate</span>
                  </label>

                  <button
                    type="submit"
                    disabled={
                      isSavingCustomRule ||
                      !ruleIdInput.trim() ||
                      !ruleNameInput.trim() ||
                      !rulePatternInput.trim()
                    }
                    className="px-4 py-2 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white text-xs font-extrabold flex items-center gap-1.5 shadow-sm"
                  >
                    {isSavingCustomRule ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4" />
                    )}
                    <span>
                      {editingRuleId ? "Update Rule" : "Create Rule"}
                    </span>
                  </button>
                </div>
              </form>

              {/* Test Rule in Sandbox Panel */}
              <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-extrabold text-slate-900">
                      Test Rule in ReDoS-Safe Sandbox
                    </h3>
                    <p className="text-[11px] text-slate-600">
                      Dry-run the regex and anti-pattern before saving to vault.
                    </p>
                  </div>

                  <div className="flex items-center gap-1 bg-[#f8fafc] p-1 rounded-lg border border-slate-200">
                    <button
                      type="button"
                      onClick={() => setSandboxMode("SAMPLE")}
                      className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition-colors ${
                        sandboxMode === "SAMPLE"
                          ? "bg-indigo-700 text-white"
                          : "text-slate-700 hover:bg-white"
                      }`}
                    >
                      Sample Code Snippet
                    </button>
                    <button
                      type="button"
                      onClick={() => setSandboxMode("WORKSPACE")}
                      className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition-colors ${
                        sandboxMode === "WORKSPACE"
                          ? "bg-indigo-700 text-white"
                          : "text-slate-700 hover:bg-white"
                      }`}
                    >
                      Active Confined Workspace
                    </button>
                  </div>
                </div>

                {sandboxMode === "SAMPLE" ? (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <label className="text-[11px] font-mono font-bold text-slate-700">
                        Sample Language:
                      </label>
                      <select
                        aria-label="Sandbox sample language"
                        value={sampleLanguage}
                        onChange={(e) => setSampleLanguage(e.target.value)}
                        className="bg-[#f8fafc] border border-slate-300 rounded-lg px-2.5 py-1 text-xs font-mono text-slate-900"
                      >
                        <option value="python">python</option>
                        <option value="javascript">javascript</option>
                        <option value="typescript">typescript</option>
                        <option value="go">go</option>
                        <option value="java">java</option>
                        <option value="ruby">ruby</option>
                        <option value="php">php</option>
                      </select>
                    </div>
                    <textarea
                      rows={6}
                      value={sampleCode}
                      onChange={(e) => setSampleCode(e.target.value)}
                      placeholder="Paste sample code snippet to test against your regex..."
                      className="w-full bg-[#f8fafc] border border-slate-300 rounded-lg p-2.5 text-xs font-mono text-slate-900"
                    />
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-[#f8fafc] border border-slate-200 text-xs font-mono text-slate-700">
                    Active Confined Workspace:{" "}
                    <strong className="text-slate-900">
                      {effectiveProjectPath || "(No local workspace selected)"}
                    </strong>
                  </div>
                )}

                <div className="flex items-center justify-end">
                  <button
                    type="button"
                    disabled={
                      isTestingCustomRule ||
                      !rulePatternInput.trim() ||
                      (sandboxMode === "WORKSPACE" && !effectiveProjectPath)
                    }
                    onClick={() => void handleRunSandboxTest()}
                    className="px-4 py-2 rounded-xl bg-emerald-700 hover:bg-emerald-800 disabled:opacity-50 text-white text-xs font-extrabold flex items-center gap-1.5 shadow-sm"
                  >
                    {isTestingCustomRule ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Play className="w-3.5 h-3.5 fill-current" />
                    )}
                    <span>
                      {isTestingCustomRule
                        ? "Testing Rule..."
                        : "Run Sandbox Test"}
                    </span>
                  </button>
                </div>

                {customRuleTestResult && (
                  <div className="pt-3 border-t border-slate-200 space-y-2.5">
                    <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                      <span
                        className={`px-2 py-0.5 rounded border font-extrabold ${
                          customRuleTestResult.regex_safe
                            ? "bg-emerald-50 text-emerald-900 border-emerald-300"
                            : "bg-rose-50 text-rose-950 border-rose-300"
                        }`}
                      >
                        {customRuleTestResult.regex_safe
                          ? "ReDoS AST SAFE"
                          : "REGEX UNSAFE"}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-900 font-bold">
                        Matches: {customRuleTestResult.matches_count}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-amber-950 font-bold">
                        Suppressed by Anti-Pattern:{" "}
                        {customRuleTestResult.suppressed_count}
                      </span>
                    </div>

                    {customRuleTestResult.warnings.length > 0 && (
                      <div className="p-2 rounded-lg bg-amber-50 border border-amber-300 text-amber-950 text-[11px] space-y-0.5">
                        {customRuleTestResult.warnings.map((w, idx) => (
                          <div key={idx}>{w}</div>
                        ))}
                      </div>
                    )}

                    {customRuleTestResult.matches.length === 0 ? (
                      <div className="p-3 rounded-lg bg-[#f8fafc] border border-slate-200 text-xs text-slate-600">
                        Zero lines matched this pattern.
                      </div>
                    ) : (
                      <div className="space-y-1.5 max-h-60 overflow-y-auto">
                        {customRuleTestResult.matches.map((m, idx) => (
                          <div
                            key={`${m.filepath}-${m.line}-${idx}`}
                            className="p-2 rounded-lg bg-[#f8fafc] border border-slate-200 text-[11px] space-y-1"
                          >
                            <div className="flex items-center justify-between gap-2 font-mono">
                              <span className="font-bold text-indigo-800">
                                {m.filepath}:{m.line}
                              </span>
                              {m.suppressed_by_anti_pattern && (
                                <span className="px-1.5 py-0.5 rounded bg-amber-100 border border-amber-300 text-amber-950 text-[9.5px] font-bold">
                                  SUPPRESSED
                                </span>
                              )}
                            </div>
                            <code className="block font-mono text-[11px] text-slate-900 break-all">
                              {m.matched_excerpt}
                            </code>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ================================================================ */}
        {/* SUB-VIEW 4: CROSS-REPO MICROSERVICE ATTACK-GRAPH STITCHER        */}
        {/* ================================================================ */}
        {subView === "MICROSERVICE_GRAPH" && (
          <div className="space-y-4">
            <form
              onSubmit={handleStitchMicroservices}
              className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-sm font-extrabold text-slate-900 flex items-center gap-1.5">
                    <Network className="w-4 h-4 text-indigo-700" />
                    <span>Cross-Repo Microservice Attack-Graph Stitcher</span>
                  </h2>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Connects inbound HTTP/gRPC/Queue endpoints and outbound
                    service calls across multiple confined repositories to trace
                    multi-hop attack paths.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleAddServiceRow}
                    className="px-3 py-1.5 rounded-lg bg-[#f8fafc] hover:bg-slate-100 border border-slate-300 text-slate-800 text-xs font-bold flex items-center gap-1"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Add Service</span>
                  </button>
                  <button
                    type="submit"
                    disabled={
                      isStitchingMicroservices ||
                      serviceRows.some(
                        (r) => !r.service_name.trim() || !r.repo_path.trim()
                      )
                    }
                    className="px-4 py-2 rounded-xl bg-indigo-700 hover:bg-indigo-800 disabled:opacity-50 text-white text-xs font-extrabold flex items-center gap-1.5 shadow-sm"
                  >
                    {isStitchingMicroservices ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Network className="w-4 h-4" />
                    )}
                    <span>
                      {isStitchingMicroservices
                        ? "Stitching Graph..."
                        : "Stitch Cross-Repo Attack Graph"}
                    </span>
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                {serviceRows.map((row, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-xl bg-[#f8fafc] border border-slate-200 grid grid-cols-1 md:grid-cols-12 gap-2 items-end"
                  >
                    <div className="md:col-span-3">
                      <label className="block text-[10px] font-mono font-bold text-slate-700 mb-1">
                        Service Name *
                      </label>
                      <input
                        type="text"
                        required
                        value={row.service_name}
                        onChange={(e) =>
                          handleUpdateServiceRow(
                            idx,
                            "service_name",
                            e.target.value
                          )
                        }
                        placeholder="api-gateway"
                        className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900"
                      />
                    </div>
                    <div className="md:col-span-5">
                      <label className="block text-[10px] font-mono font-bold text-slate-700 mb-1">
                        Confined Local Repo Path *
                      </label>
                      <input
                        type="text"
                        required
                        value={row.repo_path}
                        onChange={(e) =>
                          handleUpdateServiceRow(
                            idx,
                            "repo_path",
                            e.target.value
                          )
                        }
                        placeholder="C:\Projects\...\service-repo"
                        className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900"
                      />
                    </div>
                    <div className="md:col-span-3">
                      <label className="block text-[10px] font-mono font-bold text-slate-700 mb-1">
                        Base URL Hint (Optional)
                      </label>
                      <input
                        type="text"
                        value={row.base_url_hint || ""}
                        onChange={(e) =>
                          handleUpdateServiceRow(
                            idx,
                            "base_url_hint",
                            e.target.value
                          )
                        }
                        placeholder="http://billing-service:8080"
                        className="w-full bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-900"
                      />
                    </div>
                    <div className="md:col-span-1 flex justify-end">
                      <button
                        type="button"
                        disabled={serviceRows.length <= 1}
                        onClick={() => handleRemoveServiceRow(idx)}
                        title="Remove service row"
                        className="px-2.5 py-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 disabled:opacity-40 border border-rose-300 text-rose-900 text-xs font-bold"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              <label className="inline-flex items-center gap-2 text-xs font-semibold text-slate-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={scanPerServiceFindings}
                  onChange={(e) => setScanPerServiceFindings(e.target.checked)}
                  className="accent-indigo-700 w-3.5 h-3.5"
                />
                <span>Scan Per-Service Findings</span>
              </label>
            </form>

            {microserviceGraph ? (
              <div className="space-y-4">
                {/* KPI Strip */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Services
                    </div>
                    <div className="text-2xl font-extrabold text-slate-900 mt-1">
                      {microserviceGraph.services_analyzed}
                    </div>
                  </div>
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Endpoints
                    </div>
                    <div className="text-2xl font-extrabold text-indigo-700 mt-1">
                      {microserviceGraph.total_inbound_endpoints}
                    </div>
                  </div>
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Stitched Edges
                    </div>
                    <div className="text-2xl font-extrabold text-sky-700 mt-1">
                      {microserviceGraph.stitched_edges_count}
                    </div>
                  </div>
                  <div className="bg-white border border-slate-200 rounded-xl p-3.5 shadow-sm">
                    <div className="text-[10px] font-mono uppercase font-bold text-slate-600">
                      Cross-Service Attack Paths
                    </div>
                    <div
                      className={`text-2xl font-extrabold mt-1 ${
                        microserviceGraph.cross_service_attack_paths_count > 0
                          ? "text-rose-700"
                          : "text-emerald-700"
                      }`}
                    >
                      {microserviceGraph.cross_service_attack_paths_count}
                    </div>
                  </div>
                </div>

                {microserviceGraph.warnings.length > 0 && (
                  <div className="p-3 rounded-xl bg-amber-50 border border-amber-300 text-amber-950 text-xs space-y-1">
                    {microserviceGraph.warnings.map((w, idx) => (
                      <div key={idx} className="font-semibold">
                        {w}
                      </div>
                    ))}
                  </div>
                )}

                {/* ReactFlow Interactive Canvas wrapped in ReactFlowProvider */}
                <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span className="font-extrabold text-slate-900">
                      Interactive Service Call &amp; Attack-Path Topology
                    </span>
                    <div className="flex items-center gap-3 font-mono text-[10px]">
                      <span className="flex items-center gap-1 text-rose-800 font-bold">
                        <span className="w-3 h-0.5 bg-rose-700 inline-block" />
                        Attack-Path Edge
                      </span>
                      <span className="flex items-center gap-1 text-slate-700 font-bold">
                        <span className="w-3 h-0.5 bg-slate-500 inline-block" />
                        Service Call Edge
                      </span>
                    </div>
                  </div>

                  <ReactFlowProvider>
                    <MicroserviceGraphCanvasInner
                      nodes={flowNodes}
                      edges={flowEdges}
                    />
                  </ReactFlowProvider>
                </div>

                {/* Discovered Multi-Repo Attack Paths */}
                <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                  <h3 className="text-xs font-extrabold uppercase tracking-wide text-slate-800">
                    Discovered Multi-Repo Attack Paths (
                    {microserviceGraph.attack_paths.length})
                  </h3>

                  {microserviceGraph.attack_paths.length === 0 ? (
                    <div className="p-4 rounded-lg bg-[#f8fafc] border border-slate-200 text-xs text-slate-600 text-center">
                      No cross-service vulnerability chains stitched across the
                      supplied repositories.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                      {microserviceGraph.attack_paths.map((path) => (
                        <div
                          key={path.path_id}
                          className="p-3.5 rounded-xl bg-[#f8fafc] border border-slate-200 space-y-2"
                        >
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`px-2 py-0.5 rounded border font-mono text-[10px] font-extrabold ${getSeverityBadgeClass(
                                  path.composite_severity
                                )}`}
                              >
                                {path.composite_severity}
                              </span>
                              <span className="px-2 py-0.5 rounded bg-white border border-slate-300 font-mono text-[10px] font-bold text-slate-800">
                                {path.hop_count}{" "}
                                {path.hop_count === 1 ? "Hop" : "Hops"}
                              </span>
                            </div>
                            <span className="font-mono text-[10px] text-slate-600">
                              {path.path_id}
                            </span>
                          </div>

                          <div className="text-xs font-extrabold text-slate-900">
                            {path.title}
                          </div>

                          <div className="flex flex-wrap items-center gap-1">
                            {path.services.map((svc, idx) => (
                              <React.Fragment key={`${path.path_id}-${svc}-${idx}`}>
                                <span className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-900 font-mono text-[10px] font-bold">
                                  {svc}
                                </span>
                                {idx < path.services.length - 1 && (
                                  <ArrowRight className="w-3 h-3 text-rose-700" />
                                )}
                              </React.Fragment>
                            ))}
                          </div>

                          {path.finding_ids.length > 0 && (
                            <div className="flex flex-wrap items-center gap-1 pt-0.5">
                              <span className="text-[10px] font-mono font-bold text-slate-600">
                                Linked Findings:
                              </span>
                              {path.finding_ids.map((fid) =>
                                findingIdSet.has(fid) ? (
                                  <button
                                    key={fid}
                                    type="button"
                                    onClick={() =>
                                      openCodeLocationInIde(
                                        undefined,
                                        undefined,
                                        fid
                                      )
                                    }
                                    className="px-1.5 py-0.5 rounded bg-rose-50 hover:bg-rose-100 border border-rose-300 text-rose-900 font-mono text-[10px] font-bold"
                                  >
                                    {fid} →
                                  </button>
                                ) : (
                                  <span
                                    key={fid}
                                    className="px-1.5 py-0.5 rounded bg-white border border-slate-300 text-slate-700 font-mono text-[10px] font-bold"
                                  >
                                    {fid}
                                  </span>
                                )
                              )}
                            </div>
                          )}

                          <p className="text-[11px] text-slate-700 leading-relaxed">
                            {path.narrative}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-white border border-dashed border-slate-300 rounded-xl p-8 text-center space-y-1.5">
                <Network className="w-7 h-7 mx-auto text-slate-400" />
                <div className="text-sm font-bold text-slate-900">
                  No Cross-Repo Microservice Graph Stitched Yet
                </div>
                <p className="text-xs text-slate-600 max-w-xl mx-auto">
                  Enter two or more confined local microservice repository paths
                  above and click <b>Stitch Cross-Repo Attack Graph</b>.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default NextGenAppSecStudio;
