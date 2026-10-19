"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { IssueTicket, TestConnectionResponse } from "@/types/cpg";
import {
  Ticket,
  CheckCircle2,
  RefreshCw,
  X,
  ExternalLink,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  Copy,
  Check,
  MessageSquare,
  Send,
  ShieldAlert,
  PlugZap,
  ArrowLeftRight,
  Code2,
} from "lucide-react";

export function IntegrationHubModal() {
  const isOpen = useAuditStore((s) => s.isIntegrationModalOpen);
  const setOpen = useAuditStore((s) => s.setIntegrationModalOpen);
  const integrationState = useAuditStore((s) => s.integrationState);
  const fetchIntegrations = useAuditStore((s) => s.fetchIntegrations);
  const updateIntegrationConfig = useAuditStore((s) => s.updateIntegrationConfig);
  const testIntegrationConnection = useAuditStore((s) => s.testIntegrationConnection);
  const createTicketForFinding = useAuditStore((s) => s.createTicketForFinding);
  const updateTicket = useAuditStore((s) => s.updateTicket);
  const deleteTicket = useAuditStore((s) => s.deleteTicket);
  const autoSyncTickets = useAuditStore((s) => s.autoSyncTickets);
  const findings = useAuditStore((s) => s.findings);
  const selectFinding = useAuditStore((s) => s.selectFinding);
  const setWorkspaceViewMode = useAuditStore((s) => s.setWorkspaceViewMode);
  const activeOperator = useAuditStore((s) => s.activeOperator);

  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);

  // Local editable form state for Jira & GitHub connectors (no dummy pre-filled values)
  const [jiraUrl, setJiraUrl] = useState("");
  const [jiraProjectKey, setJiraProjectKey] = useState("SEC");
  const [jiraIssueType, setJiraIssueType] = useState("Task");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraApiToken, setJiraApiToken] = useState("");
  const [showJiraToken, setShowJiraToken] = useState(false);
  const [testingJira, setTestingJira] = useState(false);
  const [jiraTestResult, setJiraTestResult] = useState<TestConnectionResponse | null>(null);

  const [githubRepo, setGithubRepo] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [githubLabelsInput, setGithubLabelsInput] = useState("security, alastor-cpg, automated-bfl");
  const [showGithubToken, setShowGithubToken] = useState(false);
  const [testingGithub, setTestingGithub] = useState(false);
  const [githubTestResult, setGithubTestResult] = useState<TestConnectionResponse | null>(null);

  // Manual ticket creation state
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [manualProvider, setManualProvider] = useState<"JIRA" | "GITHUB_ISSUES">("JIRA");
  const [manualPriority, setManualPriority] = useState<"HIGHEST" | "HIGH" | "MEDIUM" | "LOW">("HIGH");
  const [manualAssignee, setManualAssignee] = useState<string>("Unassigned");
  const [manualNotes, setManualNotes] = useState<string>("");
  const [creatingManual, setCreatingManual] = useState(false);

  // Ticket filter & inspector drawer state
  const [providerFilter, setProviderFilter] = useState<"ALL" | "JIRA" | "GITHUB_ISSUES">("ALL");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "OPEN" | "IN_PROGRESS" | "RESOLVED">("ALL");
  const [ticketSearch, setTicketSearch] = useState<string>("");
  const [inspectedTicketId, setInspectedTicketId] = useState<string | null>(null);
  const [commentDraft, setCommentDraft] = useState<string>("");
  const [copiedPayload, setCopiedPayload] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchIntegrations();
    }
  }, [isOpen, fetchIntegrations]);

  const cfg = integrationState?.config;
  const tickets = integrationState?.tickets || [];

  useEffect(() => {
    if (cfg) {
      setJiraUrl(cfg.jira_url || "");
      setJiraProjectKey(cfg.jira_project_key || "SEC");
      setJiraIssueType(cfg.jira_issue_type || "Task");
      setJiraEmail(cfg.jira_email || "");
      setGithubRepo(cfg.github_repo || "");
      setGithubLabelsInput((cfg.github_labels || ["security", "alastor-cpg", "automated-bfl"]).join(", "));
      if (cfg.default_provider === "GITHUB_ISSUES") {
        setManualProvider("GITHUB_ISSUES");
      } else {
        setManualProvider("JIRA");
      }
    }
  }, [
    cfg?.jira_url,
    cfg?.jira_project_key,
    cfg?.jira_issue_type,
    cfg?.jira_email,
    cfg?.github_repo,
    cfg?.default_provider,
  ]);

  useEffect(() => {
    if (findings.length > 0 && !selectedFindingId) {
      setSelectedFindingId(findings[0].id);
    }
  }, [findings, selectedFindingId]);

  const inspectedTicket: IssueTicket | null = useMemo(() => {
    if (!inspectedTicketId) return null;
    return tickets.find((t) => t.id === inspectedTicketId || t.ticket_key === inspectedTicketId) || null;
  }, [tickets, inspectedTicketId]);

  const filteredTickets = useMemo(() => {
    return tickets.filter((t) => {
      if (providerFilter !== "ALL" && t.provider !== providerFilter) return false;
      if (statusFilter !== "ALL" && t.status !== statusFilter) return false;
      if (ticketSearch.trim()) {
        const q = ticketSearch.toLowerCase();
        const matchKey = t.ticket_key.toLowerCase().includes(q);
        const matchTitle = t.finding_title.toLowerCase().includes(q);
        const matchFile = t.filepath.toLowerCase().includes(q);
        const matchAssignee = t.assignee.toLowerCase().includes(q);
        if (!matchKey && !matchTitle && !matchFile && !matchAssignee) return false;
      }
      return true;
    });
  }, [tickets, providerFilter, statusFilter, ticketSearch]);

  if (!isOpen) return null;

  const flashBanner = (msg: string) => {
    setSyncMessage(msg);
    setTimeout(() => setSyncMessage(null), 5000);
  };

  const handleSaveJiraConfig = async () => {
    await updateIntegrationConfig({
      jira_url: jiraUrl.trim(),
      jira_project_key: jiraProjectKey.trim().toUpperCase() || "SEC",
      jira_issue_type: jiraIssueType.trim() || "Task",
      jira_email: jiraEmail.trim(),
      ...(jiraApiToken.trim() ? { jira_api_token: jiraApiToken.trim() } : {}),
    });
    setJiraApiToken("");
    flashBanner(`Saved Jira connector settings (${jiraProjectKey.toUpperCase()}).`);
  };

  const handleTestJiraConnection = async () => {
    setTestingJira(true);
    setJiraTestResult(null);
    const res = await testIntegrationConnection({
      provider: "JIRA",
      jira_url: jiraUrl.trim(),
      jira_project_key: jiraProjectKey.trim().toUpperCase() || "SEC",
      jira_email: jiraEmail.trim(),
      jira_api_token: jiraApiToken.trim() || undefined,
    });
    setTestingJira(false);
    if (res) {
      setJiraTestResult(res);
      flashBanner(res.message);
    }
  };

  const handleSaveGithubConfig = async () => {
    const parsedLabels = githubLabelsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    await updateIntegrationConfig({
      github_repo: githubRepo.trim(),
      github_labels: parsedLabels.length > 0 ? parsedLabels : ["security", "alastor-cpg"],
      ...(githubToken.trim() ? { github_token: githubToken.trim() } : {}),
    });
    setGithubToken("");
    flashBanner(`Saved GitHub Issues connector settings (${githubRepo || "No repository configured"}).`);
  };

  const handleTestGithubConnection = async () => {
    setTestingGithub(true);
    setGithubTestResult(null);
    const res = await testIntegrationConnection({
      provider: "GITHUB_ISSUES",
      github_repo: githubRepo.trim(),
      github_token: githubToken.trim() || undefined,
    });
    setTestingGithub(false);
    if (res) {
      setGithubTestResult(res);
      flashBanner(res.message);
    }
  };

  const handleAutoSyncNow = async () => {
    setIsSyncing(true);
    await autoSyncTickets();
    setIsSyncing(false);
    flashBanner(
      "Generated local tickets for active findings matching severity threshold."
    );
  };

  const handleCreateManualTicket = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFindingId) return;
    setCreatingManual(true);
    const parsedLabels = githubLabelsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const created = await createTicketForFinding(selectedFindingId, manualProvider, {
      assignee: manualAssignee.trim() || "Unassigned",
      priority: manualPriority,
      labels: parsedLabels,
      custom_notes: manualNotes.trim() || undefined,
    });
    setCreatingManual(false);
    if (created) {
      setManualNotes("");
      setInspectedTicketId(created.id);
      flashBanner(
        `Created ${created.provider} ticket ${created.ticket_key} (${created.sync_mode}) for "${created.finding_title}".`
      );
    }
  };

  const handleStatusChange = async (
    ticketId: string,
    newStatus: "OPEN" | "IN_PROGRESS" | "RESOLVED"
  ) => {
    const updated = await updateTicket(ticketId, {
      status: newStatus,
      comment_author: activeOperator?.name || "Local Operator",
    });
    if (updated) {
      flashBanner(
        `Updated ticket ${updated.ticket_key} status to ${newStatus}${
          cfg?.bidirectional_triage_sync ? " (synced with CPG finding triage)" : ""
        }.`
      );
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inspectedTicket || !commentDraft.trim()) return;
    const updated = await updateTicket(inspectedTicket.id, {
      comment: commentDraft.trim(),
      comment_author: activeOperator?.name || "Local Operator",
    });
    if (updated) {
      setCommentDraft("");
      flashBanner(`Added comment to ${updated.ticket_key}.`);
    }
  };

  const handleCopyPayload = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 select-none">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl w-full max-w-6xl max-h-[92vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-5 py-3.5 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-700 flex items-center justify-center">
              <Ticket className="w-4 h-4 text-indigo-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                ALASTOR Integration Hub — Local Issue Tracker &amp; Cloud Connectors
                <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] font-mono">
                  LOCAL TRACKER + OPTIONAL CLOUD API
                </span>
              </h2>
              <p className="text-[11px] text-zinc-400">
                Local ticket creation &amp; bi-directional triage sync work out of the box. External Jira/GitHub cloud push is marked Not Working For Now until API credentials are provided.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setOpen(false)}
            className="p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {syncMessage && (
          <div className="px-5 py-2 bg-emerald-950/90 border-b border-emerald-700 text-emerald-200 text-xs font-mono flex items-center justify-between gap-2 shrink-0">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{syncMessage}</span>
            </div>
            <button
              type="button"
              onClick={() => setSyncMessage(null)}
              className="text-emerald-400 hover:text-emerald-200 text-[10px]"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs">
          {/* Connectors Grid: Jira & GitHub Issues */}
          {cfg && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Connector 1: Atlassian Jira */}
              <div className="p-4 rounded-2xl bg-zinc-900/60 border border-zinc-800 space-y-3">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2.5">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-700 font-mono text-[10px] font-bold">
                        ATLASSIAN JIRA
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border flex items-center gap-1 ${
                          cfg.jira_connection_status === "LIVE_API"
                            ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                            : "bg-amber-950 text-amber-300 border-amber-700"
                        }`}
                      >
                        {cfg.jira_connection_status === "LIVE_API"
                          ? "LIVE CLOUD API CONNECTED"
                          : "CLOUD PUSH: NOT WORKING FOR NOW (NO CREDENTIALS)"}
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-white mt-1">
                      Jira Security &amp; Engineering Connector
                    </h3>
                  </div>

                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <span className="text-zinc-400">Enabled</span>
                    <input
                      type="checkbox"
                      checked={cfg.jira_enabled}
                      onChange={(e) =>
                        updateIntegrationConfig({ jira_enabled: e.target.checked })
                      }
                      className="accent-cyan-500"
                    />
                  </label>
                </div>

                {cfg.jira_connection_status !== "LIVE_API" && (
                  <div className="p-2.5 rounded-xl bg-amber-950/30 border border-amber-800/70 text-[11px] text-amber-200/90">
                    <b>Remote Jira Cloud Sync: Not Working For Now</b> — No Atlassian Cloud URL or API Token is configured. Tickets created below are saved in ALASTOR&apos;s Local Issue Tracker.
                  </div>
                )}

                <div className="grid grid-cols-3 gap-2">
                  <div className="col-span-2">
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Jira Instance URL
                    </label>
                    <input
                      type="text"
                      value={jiraUrl}
                      onChange={(e) => setJiraUrl(e.target.value)}
                      placeholder="https://your-domain.atlassian.net (not configured)"
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Project Key
                    </label>
                    <input
                      type="text"
                      value={jiraProjectKey}
                      onChange={(e) => setJiraProjectKey(e.target.value.toUpperCase())}
                      placeholder="SEC"
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-cyan-300 font-bold focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Jira Account Email
                    </label>
                    <input
                      type="text"
                      value={jiraEmail}
                      onChange={(e) => setJiraEmail(e.target.value)}
                      placeholder="Not configured"
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      API Token
                    </label>
                    <div className="relative flex items-center">
                      <input
                        type={showJiraToken ? "text" : "password"}
                        value={jiraApiToken}
                        onChange={(e) => setJiraApiToken(e.target.value)}
                        placeholder={cfg.jira_api_token_masked || "Not configured"}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded pl-2.5 pr-7 py-1.5 text-xs font-mono text-zinc-200 focus:border-cyan-500 focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowJiraToken((v) => !v)}
                        className="absolute right-2 text-zinc-400 hover:text-zinc-200"
                      >
                        {showJiraToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Issue Type
                    </label>
                    <select
                      value={jiraIssueType}
                      onChange={(e) => setJiraIssueType(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2 py-1.5 text-xs font-mono text-zinc-200"
                    >
                      <option value="Task">Task</option>
                      <option value="Bug">Bug</option>
                      <option value="Security Vulnerability">Security Vulnerability</option>
                      <option value="Story">Story</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2 pt-1">
                  <button
                    type="button"
                    onClick={handleTestJiraConnection}
                    disabled={testingJira}
                    className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-cyan-300 font-mono text-[11px] font-semibold flex items-center gap-1.5"
                  >
                    <PlugZap className={`w-3.5 h-3.5 ${testingJira ? "animate-pulse" : ""}`} />
                    <span>{testingJira ? "Probing Jira..." : "Test Jira Connection"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSaveJiraConfig}
                    className="px-3 py-1.5 rounded-lg bg-blue-950 hover:bg-blue-900 border border-blue-700 text-blue-200 font-mono text-[11px] font-semibold"
                  >
                    Save Jira Settings
                  </button>
                </div>

                {jiraTestResult && (
                  <div
                    className={`p-2.5 rounded-xl border text-[11px] font-mono ${
                      jiraTestResult.ok
                        ? "bg-emerald-950/60 border-emerald-700/80 text-emerald-200"
                        : "bg-amber-950/60 border-amber-700/80 text-amber-200"
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold mb-0.5">
                      <span>
                        Mode: {jiraTestResult.mode} (HTTP {jiraTestResult.http_status})
                      </span>
                      <span>{jiraTestResult.latency_ms} ms</span>
                    </div>
                    <div className="text-[10px] opacity-90">{jiraTestResult.message}</div>
                  </div>
                )}
              </div>

              {/* Connector 2: GitHub Issues */}
              <div className="p-4 rounded-2xl bg-zinc-900/60 border border-zinc-800 space-y-3">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2.5">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-700 font-mono text-[10px] font-bold">
                        GITHUB ISSUES
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border flex items-center gap-1 ${
                          cfg.github_connection_status === "LIVE_API"
                            ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                            : "bg-amber-950 text-amber-300 border-amber-700"
                        }`}
                      >
                        {cfg.github_connection_status === "LIVE_API"
                          ? "LIVE GITHUB WRITE API"
                          : "CLOUD PUSH: NOT WORKING FOR NOW (NO PAT CONFIGURED)"}
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-white mt-1">
                      GitHub Issues &amp; Security Advisory Connector
                    </h3>
                  </div>

                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <span className="text-zinc-400">Enabled</span>
                    <input
                      type="checkbox"
                      checked={cfg.github_issues_enabled}
                      onChange={(e) =>
                        updateIntegrationConfig({
                          github_issues_enabled: e.target.checked,
                        })
                      }
                      className="accent-cyan-500"
                    />
                  </label>
                </div>

                {cfg.github_connection_status !== "LIVE_API" && (
                  <div className="p-2.5 rounded-xl bg-amber-950/30 border border-amber-800/70 text-[11px] text-amber-200/90">
                    <b>Remote GitHub Issue Creation: Not Working For Now</b> — No repository &amp; GitHub Personal Access Token (PAT) are configured. Tickets created below are saved in ALASTOR&apos;s Local Issue Tracker.
                  </div>
                )}

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Owner / Repository (or GitHub URL)
                    </label>
                    <input
                      type="text"
                      value={githubRepo}
                      onChange={(e) => setGithubRepo(e.target.value)}
                      placeholder="owner/repo (not configured)"
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-purple-300 focus:border-purple-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Personal Access Token (PAT)
                    </label>
                    <div className="relative flex items-center">
                      <input
                        type={showGithubToken ? "text" : "password"}
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                        placeholder={cfg.github_token_masked || "Not configured"}
                        className="w-full bg-zinc-950 border border-zinc-800 rounded pl-2.5 pr-7 py-1.5 text-xs font-mono text-zinc-200 focus:border-purple-500 focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowGithubToken((v) => !v)}
                        className="absolute right-2 text-zinc-400 hover:text-zinc-200"
                      >
                        {showGithubToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Automatic Issue Labels (comma-separated)
                    </label>
                    <input
                      type="text"
                      value={githubLabelsInput}
                      onChange={(e) => setGithubLabelsInput(e.target.value)}
                      placeholder="security, alastor-cpg, automated-bfl"
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:border-purple-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                      Default Ticket Provider
                    </label>
                    <select
                      value={cfg.default_provider}
                      onChange={(e) =>
                        updateIntegrationConfig({
                          default_provider: e.target.value as any,
                        })
                      }
                      className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200"
                    >
                      <option value="JIRA">Jira Primary</option>
                      <option value="GITHUB_ISSUES">GitHub Issues Primary</option>
                      <option value="BOTH">Dual Sync (Jira + GitHub Issues)</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2 pt-1">
                  <button
                    type="button"
                    onClick={handleTestGithubConnection}
                    disabled={testingGithub}
                    className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-purple-300 font-mono text-[11px] font-semibold flex items-center gap-1.5"
                  >
                    <PlugZap className={`w-3.5 h-3.5 ${testingGithub ? "animate-pulse" : ""}`} />
                    <span>{testingGithub ? "Probing GitHub API..." : "Test GitHub API Live"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleSaveGithubConfig}
                    className="px-3 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 border border-purple-700 text-purple-200 font-mono text-[11px] font-semibold"
                  >
                    Save GitHub Settings
                  </button>
                </div>

                {githubTestResult && (
                  <div
                    className={`p-2.5 rounded-xl border text-[11px] font-mono ${
                      githubTestResult.ok
                        ? "bg-emerald-950/60 border-emerald-700/80 text-emerald-200"
                        : "bg-amber-950/60 border-amber-700/80 text-amber-200"
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold mb-0.5">
                      <span>
                        Mode: {githubTestResult.mode} (HTTP {githubTestResult.http_status})
                      </span>
                      <span>{githubTestResult.latency_ms} ms</span>
                    </div>
                    <div className="text-[10px] opacity-90">{githubTestResult.message}</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Automation Policy & Bi-Directional Sync Bar */}
          {cfg && (
            <div className="p-4 rounded-2xl bg-zinc-900/60 border border-zinc-800 grid grid-cols-1 md:grid-cols-4 gap-3 items-center">
              <div className="flex items-center justify-between md:justify-start gap-2.5 p-2.5 rounded-xl bg-zinc-950 border border-zinc-800">
                <div>
                  <div className="font-bold text-zinc-100 text-xs">Auto-Ticket Generation</div>
                  <div className="text-[10px] text-zinc-400">Create issues on scan/confirm</div>
                </div>
                <input
                  type="checkbox"
                  checked={cfg.auto_create_tickets}
                  onChange={(e) =>
                    updateIntegrationConfig({ auto_create_tickets: e.target.checked })
                  }
                  className="accent-cyan-500 cursor-pointer w-4 h-4"
                />
              </div>

              <div>
                <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                  Severity Threshold
                </label>
                <select
                  value={cfg.auto_severity_threshold}
                  onChange={(e) =>
                    updateIntegrationConfig({
                      auto_severity_threshold: e.target.value as any,
                    })
                  }
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-amber-300 font-bold"
                >
                  <option value="CRITICAL">CRITICAL Only</option>
                  <option value="HIGH">HIGH &amp; CRITICAL (Recommended)</option>
                  <option value="MEDIUM">MEDIUM, HIGH &amp; CRITICAL</option>
                  <option value="ALL">ALL Severities</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                  Auto-Trigger Event
                </label>
                <select
                  value={cfg.auto_trigger_on}
                  onChange={(e) =>
                    updateIntegrationConfig({
                      auto_trigger_on: e.target.value as any,
                    })
                  }
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-cyan-300"
                >
                  <option value="SCAN_COMPLETE">On Scan Complete</option>
                  <option value="ON_CONFIRMED">When Marked Confirmed</option>
                  <option value="MANUAL">Manual Only</option>
                </select>
              </div>

              <div className="flex items-center justify-between gap-2.5 p-2.5 rounded-xl bg-zinc-950 border border-zinc-800">
                <div>
                  <div className="font-bold text-zinc-100 text-xs flex items-center gap-1">
                    <ArrowLeftRight className="w-3.5 h-3.5 text-emerald-400" />
                    <span>2-Way Triage Sync</span>
                  </div>
                  <div className="text-[10px] text-zinc-400">
                    Ticket RESOLVED ⇄ Finding RESOLVED
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={cfg.bidirectional_triage_sync ?? true}
                  onChange={(e) =>
                    updateIntegrationConfig({
                      bidirectional_triage_sync: e.target.checked,
                    })
                  }
                  className="accent-emerald-500 cursor-pointer w-4 h-4"
                />
              </div>
            </div>
          )}

          {/* Create Single Ticket Composer */}
          <form
            onSubmit={handleCreateManualTicket}
            className="p-4 rounded-2xl bg-zinc-900/60 border border-zinc-800 space-y-3"
          >
            <div className="flex items-center justify-between">
              <div className="font-bold text-white text-xs flex items-center gap-1.5">
                <Plus className="w-4 h-4 text-cyan-400" />
                <span>Create Linked Bug Tracker Issue for Any Finding</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-400">
                Automatically attaches CPG Source-to-Sink Trace &amp; Best Fixed Location (BFL) Patch
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-2.5 items-end">
              <div className="md:col-span-4">
                <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                  Target Vulnerability Finding
                </label>
                <select
                  value={selectedFindingId}
                  onChange={(e) => setSelectedFindingId(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200"
                >
                  {findings.map((f) => (
                    <option key={f.id} value={f.id}>
                      [{f.severity}] {f.title} ({f.cwe_id || f.rule_id})
                    </option>
                  ))}
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                  Provider
                </label>
                <select
                  value={manualProvider}
                  onChange={(e) => setManualProvider(e.target.value as any)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-indigo-300 font-bold"
                >
                  <option value="JIRA">JIRA</option>
                  <option value="GITHUB_ISSUES">GITHUB_ISSUES</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                  Priority
                </label>
                <select
                  value={manualPriority}
                  onChange={(e) => setManualPriority(e.target.value as any)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-amber-300"
                >
                  <option value="HIGHEST">HIGHEST (P0)</option>
                  <option value="HIGH">HIGH (P1)</option>
                  <option value="MEDIUM">MEDIUM (P2)</option>
                  <option value="LOW">LOW (P3)</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-[10px] font-mono text-zinc-400 mb-1">
                  Assignee
                </label>
                <input
                  type="text"
                  value={manualAssignee}
                  onChange={(e) => setManualAssignee(e.target.value)}
                  placeholder="dev@alastor.io"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-200"
                />
              </div>

              <div className="md:col-span-2">
                <button
                  type="submit"
                  disabled={creatingManual || findings.length === 0}
                  className="w-full py-1.5 px-3 rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-sm"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>{creatingManual ? "Creating..." : "Create Ticket"}</span>
                </button>
              </div>
            </div>

            <div>
              <input
                type="text"
                value={manualNotes}
                onChange={(e) => setManualNotes(e.target.value)}
                placeholder="Optional engineering remediation notes or SLA instructions to include in ticket description..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs font-mono text-zinc-300 placeholder-zinc-600"
              />
            </div>
          </form>

          {/* Live Linked Bug Tracker Tickets Table */}
          <div className="rounded-2xl bg-zinc-900/60 border border-zinc-800 p-4 space-y-3.5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Ticket className="w-4 h-4 text-cyan-400" />
                  Active Linked Bug Tracker Issues ({filteredTickets.length} of {tickets.length})
                </h3>
                <p className="text-[11px] text-zinc-400">
                  Click any ticket to inspect its full Markdown payload &amp; CPG trace, change its status (syncs back to finding triage), or open the ticket page
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <input
                  type="text"
                  value={ticketSearch}
                  onChange={(e) => setTicketSearch(e.target.value)}
                  placeholder="Search key, title, file..."
                  className="bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 w-44"
                />

                <select
                  value={providerFilter}
                  onChange={(e) => setProviderFilter(e.target.value as any)}
                  className="bg-zinc-950 border border-zinc-800 rounded-lg px-2 py-1.5 text-xs font-mono text-zinc-300"
                >
                  <option value="ALL">All Providers</option>
                  <option value="JIRA">Jira Only</option>
                  <option value="GITHUB_ISSUES">GitHub Only</option>
                </select>

                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value as any)}
                  className="bg-zinc-950 border border-zinc-800 rounded-lg px-2 py-1.5 text-xs font-mono text-zinc-300"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="OPEN">OPEN</option>
                  <option value="IN_PROGRESS">IN_PROGRESS</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>

                <button
                  type="button"
                  disabled={isSyncing}
                  onClick={handleAutoSyncNow}
                  className="px-3 py-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-bold text-xs flex items-center gap-1.5 shadow-sm"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? "animate-spin" : ""}`} />
                  <span>Auto-Sync Threshold Tickets</span>
                </button>
              </div>
            </div>

            <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-950">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-900/80 text-[10px] font-mono uppercase text-zinc-400">
                    <th className="py-2.5 px-3">Ticket Key</th>
                    <th className="py-2.5 px-3">Provider / Mode</th>
                    <th className="py-2.5 px-3">Status (2-Way Sync)</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Issue Summary &amp; Assignee</th>
                    <th className="py-2.5 px-3">Best Fixed Location (BFL)</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/70">
                  {filteredTickets.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-zinc-500 font-mono">
                        No tickets match the current filter. Click &quot;Auto-Sync Threshold Tickets&quot; or create a ticket above.
                      </td>
                    </tr>
                  ) : (
                    filteredTickets.map((t) => {
                      const isInspected = inspectedTicket?.id === t.id;
                      return (
                        <tr
                          key={t.id}
                          className={`hover:bg-zinc-900/60 transition-colors ${
                            isInspected ? "bg-indigo-950/30" : ""
                          }`}
                        >
                          <td className="py-2.5 px-3 font-mono font-bold">
                            <button
                              type="button"
                              onClick={() =>
                                setInspectedTicketId(isInspected ? null : t.id)
                              }
                              className="text-cyan-300 hover:underline flex items-center gap-1"
                              title="Click to inspect full ticket payload & comments"
                            >
                              <span>{t.ticket_key}</span>
                            </button>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[10px]">
                            <div className="flex flex-col gap-0.5">
                              <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 w-fit font-bold">
                                {t.provider}
                              </span>
                              <span className="text-[9px] text-zinc-400">
                                {t.sync_mode === "LIVE_API" ? "LIVE API" : "LOCAL TRACKER"}
                              </span>
                            </div>
                          </td>
                          <td className="py-2.5 px-3 font-mono">
                            <select
                              value={t.status}
                              onChange={(e) =>
                                handleStatusChange(
                                  t.id,
                                  e.target.value as "OPEN" | "IN_PROGRESS" | "RESOLVED"
                                )
                              }
                              className={`px-2 py-1 rounded text-[10px] font-bold border cursor-pointer focus:outline-none ${
                                t.status === "RESOLVED"
                                  ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                                  : t.status === "IN_PROGRESS"
                                  ? "bg-blue-950 text-blue-300 border-blue-700"
                                  : "bg-amber-950 text-amber-300 border-amber-700"
                              }`}
                            >
                              <option value="OPEN">OPEN</option>
                              <option value="IN_PROGRESS">IN_PROGRESS</option>
                              <option value="RESOLVED">RESOLVED</option>
                            </select>
                          </td>
                          <td className="py-2.5 px-3 font-mono">
                            <div className="flex flex-col gap-0.5">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold border w-fit ${
                                  t.severity === "CRITICAL"
                                    ? "bg-red-950 text-red-300 border-red-700"
                                    : t.severity === "HIGH"
                                    ? "bg-amber-950 text-amber-300 border-amber-700"
                                    : "bg-cyan-950 text-cyan-300 border-cyan-800"
                                }`}
                              >
                                {t.severity}
                              </span>
                              <span className="text-[9px] text-zinc-400">
                                Prio: {t.priority || "HIGH"}
                              </span>
                            </div>
                          </td>
                          <td className="py-2.5 px-3">
                            <div className="text-zinc-100 font-medium">{t.finding_title}</div>
                            <div className="text-[10px] font-mono text-zinc-400 mt-0.5">
                              Assignee: <span className="text-zinc-300">{t.assignee}</span> •{" "}
                              {t.comments?.length || 0} comment(s)
                            </div>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px] text-emerald-300 max-w-xs truncate" title={t.bfl_summary}>
                            {t.bfl_summary}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                onClick={() =>
                                  setInspectedTicketId(isInspected ? null : t.id)
                                }
                                className={`px-2 py-1 rounded border text-[10px] font-mono flex items-center gap-1 ${
                                  isInspected
                                    ? "bg-indigo-950 text-indigo-200 border-indigo-600"
                                    : "bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border-zinc-700"
                                }`}
                                title="Inspect full Markdown payload & add comments"
                              >
                                <MessageSquare className="w-3 h-3" />
                                <span>Inspect</span>
                              </button>

                              <a
                                href={t.external_url}
                                target="_blank"
                                rel="noreferrer"
                                className="px-2 py-1 rounded bg-zinc-900 hover:bg-indigo-950 text-indigo-300 border border-zinc-700 text-[10px] font-mono flex items-center gap-1"
                                title="Open standalone ticket view in browser tab"
                              >
                                <span>Open</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>

                              <button
                                type="button"
                                onClick={() => {
                                  const f = findings.find(
                                    (item) => item.id === t.finding_id
                                  );
                                  if (f) {
                                    selectFinding(f);
                                    setOpen(false);
                                    setWorkspaceViewMode("REMEDIATION_IDE");
                                  }
                                }}
                                className="px-2 py-1 rounded bg-zinc-800 hover:bg-cyan-950 text-cyan-300 border border-zinc-700 text-[10px] font-mono flex items-center gap-1"
                                title="Jump to vulnerable code in Remediation IDE"
                              >
                                <Code2 className="w-3 h-3" />
                                <span>Code</span>
                              </button>

                              <button
                                type="button"
                                onClick={async () => {
                                  const ok = await deleteTicket(t.id);
                                  if (ok) {
                                    if (inspectedTicketId === t.id) {
                                      setInspectedTicketId(null);
                                    }
                                    flashBanner(`Removed ticket ${t.ticket_key}.`);
                                  }
                                }}
                                className="p-1 rounded bg-zinc-900 hover:bg-red-950 text-zinc-400 hover:text-red-300 border border-zinc-800"
                                title="Delete ticket"
                              >
                                <Trash2 className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Ticket Inspector & Activity Drawer */}
            {inspectedTicket && (
              <div className="mt-4 p-4 rounded-2xl bg-zinc-950 border border-indigo-800/80 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 pb-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-700 font-mono text-xs font-bold">
                      {inspectedTicket.ticket_key}
                    </span>
                    <span className="text-sm font-bold text-white">
                      {inspectedTicket.finding_title}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-[10px] font-mono text-emerald-300">
                      BFL: {inspectedTicket.filepath}:L{inspectedTicket.line}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleCopyPayload(inspectedTicket.payload_preview)}
                      className="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 font-mono text-[10px] flex items-center gap-1"
                    >
                      {copiedPayload ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span>Copied Markdown!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Issue Markdown</span>
                        </>
                      )}
                    </button>

                    <a
                      href={inspectedTicket.external_url}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2.5 py-1 rounded-lg bg-indigo-950 hover:bg-indigo-900 border border-indigo-700 text-indigo-200 font-mono text-[10px] flex items-center gap-1"
                    >
                      <span>Open Full Ticket Page</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>

                    <button
                      type="button"
                      onClick={() => setInspectedTicketId(null)}
                      className="p-1 rounded bg-zinc-900 hover:bg-zinc-800 text-zinc-400"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* Left: Generated Ticket Markdown Payload */}
                  <div className="space-y-1.5">
                    <div className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">
                      Generated {inspectedTicket.provider} Issue Body (CPG Proof + BFL Patch)
                    </div>
                    <pre className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap max-h-56 overflow-y-auto leading-relaxed">
                      {inspectedTicket.payload_preview}
                    </pre>
                  </div>

                  {/* Right: Comments & Activity Log */}
                  <div className="space-y-2 flex flex-col justify-between">
                    <div className="space-y-2">
                      <div className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">
                        Ticket Audit Trail &amp; Engineering Comments (
                        {inspectedTicket.comments?.length || 0})
                      </div>
                      <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                        {(inspectedTicket.comments || []).map((c) => (
                          <div
                            key={c.id}
                            className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs"
                          >
                            <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400 mb-1">
                              <span className="text-cyan-300 font-bold">{c.author}</span>
                              <span>{c.created_at}</span>
                            </div>
                            <div className="text-zinc-200 text-[11px]">{c.body}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <form onSubmit={handleAddComment} className="flex items-center gap-2 pt-1">
                      <input
                        type="text"
                        value={commentDraft}
                        onChange={(e) => setCommentDraft(e.target.value)}
                        placeholder="Add remediation update or verification comment..."
                        className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200"
                      />
                      <button
                        type="submit"
                        className="px-3 py-1.5 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white font-bold text-xs flex items-center gap-1"
                      >
                        <Send className="w-3 h-3" />
                        <span>Post</span>
                      </button>
                    </form>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
