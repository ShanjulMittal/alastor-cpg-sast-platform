"use client";

import React, { useEffect, useState } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import {
  Users,
  Building2,
  ShieldCheck,
  KeyRound,
  Sliders,
  CheckCircle2,
  Lock,
  Plus,
  History,
  UserCheck,
  FolderGit2,
} from "lucide-react";

export const UserAccountProfileView: React.FC = () => {
  const {
    userAccountsState,
    fetchUserAccounts,
    createAccount,
    createUserProfile,
    switchUserOrAccount,
    projects,
    fetchProjects,
    platformSettings,
    fetchPlatformSettings,
  } = useAuditStore();

  const [showNewAccountModal, setShowNewAccountModal] = useState(false);
  const [showNewUserModal, setShowNewUserModal] = useState(false);

  // New Account Form
  const [acctName, setAcctName] = useState("");
  const [acctOrgUnit, setAcctOrgUnit] = useState("");
  const [acctTier, setAcctTier] = useState("PRODUCTION");
  const [acctIsolation, setAcctIsolation] = useState("STRICT");
  const [acctCompliance, setAcctCompliance] = useState(
    "OWASP Top 10 2025 + PCI-DSS 4.0 + SOC2 Type II"
  );

  // New User Profile Form
  const [userName, setUserName] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [userRole, setUserRole] = useState("SECURITY_AUDITOR");
  const [userTitle, setUserTitle] = useState("");
  const [userDept, setUserDept] = useState("Application Security");
  const [userAcctId, setUserAcctId] = useState("acct-enterprise-hq");
  const [userPresetId, setUserPresetId] = useState("preset-optimized");

  useEffect(() => {
    fetchUserAccounts();
    if (projects.length === 0) fetchProjects();
    if (!platformSettings) fetchPlatformSettings();
  }, [fetchUserAccounts, fetchProjects, fetchPlatformSettings, projects.length, platformSettings]);

  const accounts = userAccountsState?.accounts || [];
  const users = userAccountsState?.users || [];
  const auditLog = userAccountsState?.audit_log || [];
  const activeAccountId =
    userAccountsState?.active_account_id || "acct-enterprise-hq";
  const activeUserId =
    userAccountsState?.active_user_id || "usr-architect-01";

  const activeAccount =
    accounts.find((a) => a.id === activeAccountId) || accounts[0];
  const activeUser = users.find((u) => u.id === activeUserId) || users[0];

  const handleCreateAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!acctName.trim()) return;
    await createAccount({
      name: acctName.trim(),
      organization_unit: acctOrgUnit.trim() || "Security Operations",
      environment_tier: acctTier,
      isolation_mode: acctIsolation,
      compliance_mandate: acctCompliance,
      assigned_project_ids: [],
    });
    setAcctName("");
    setAcctOrgUnit("");
    setShowNewAccountModal(false);
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userName.trim() || !userEmail.trim()) return;
    await createUserProfile({
      name: userName.trim(),
      email: userEmail.trim(),
      role: userRole,
      title: userTitle.trim() || userRole.replace("_", " "),
      department: userDept.trim(),
      account_id: userAcctId,
      default_test_profile_id: userPresetId,
    });
    setUserName("");
    setUserEmail("");
    setUserTitle("");
    setShowNewUserModal(false);
  };

  return (
    <div className="flex-1 h-full overflow-y-auto bg-slate-950/95 text-slate-100 p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl">
        <div className="flex items-start gap-3.5">
          <div className="w-11 h-11 rounded-xl bg-violet-500/15 border border-violet-500/40 flex items-center justify-center text-violet-400 shrink-0">
            <Users className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-lg font-extrabold tracking-tight text-slate-100">
                User Profiling, RBAC & Multi-Tenant Account Separation
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-violet-500/20 text-violet-300 border border-violet-500/40">
                Strict Tenant Isolation + Role Clearance
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Isolate projects, test profiles, and secret key visibility across separate organizational tenant accounts and role-based user profiles.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowNewAccountModal(true)}
            className="px-3.5 py-2 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            New Tenant Account
          </button>
          <button
            onClick={() => setShowNewUserModal(true)}
            className="px-3.5 py-2 rounded-lg text-xs font-bold bg-violet-500 hover:bg-violet-400 text-slate-950 flex items-center gap-1.5 shadow-lg"
          >
            <Plus className="w-3.5 h-3.5" />
            New User Profile
          </button>
        </div>
      </div>

      {/* Active Session Identity Banner */}
      {activeUser && activeAccount && (
        <div className="bg-gradient-to-r from-violet-950/40 via-slate-900 to-amber-950/30 border border-violet-500/40 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-full bg-violet-500/25 border border-violet-400/60 flex items-center justify-center font-mono text-sm font-extrabold text-violet-200">
              {activeUser.avatar_badge}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-violet-300 uppercase tracking-wider">
                  Active Operator Session:
                </span>
                <span className="text-sm font-extrabold text-slate-100">
                  {activeUser.name}
                </span>
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  {activeUser.role}
                </span>
                <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-cyan-300 border border-slate-700">
                  {activeUser.clearance_level}
                </span>
              </div>
              <div className="text-xs text-slate-300 mt-0.5">
                Isolated Tenant Account:{" "}
                <span className="font-bold text-amber-300">
                  {activeAccount.name}
                </span>{" "}
                ({activeAccount.organization_unit} • {activeAccount.isolation_mode} Isolation)
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
            <span
              className={`px-2.5 py-1 rounded border ${
                activeUser.can_reveal_secrets
                  ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/40"
                  : "bg-slate-800 text-slate-500 border-slate-700"
              }`}
            >
              🔑 Reveal Secrets: {activeUser.can_reveal_secrets ? "YES" : "NO"}
            </span>
            <span
              className={`px-2.5 py-1 rounded border ${
                activeUser.can_edit_rules
                  ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/40"
                  : "bg-slate-800 text-slate-500 border-slate-700"
              }`}
            >
              ⚙️ Edit Rules: {activeUser.can_edit_rules ? "YES" : "NO"}
            </span>
            <span
              className={`px-2.5 py-1 rounded border ${
                activeUser.can_triage_findings
                  ? "bg-amber-500/15 text-amber-300 border-amber-500/40"
                  : "bg-slate-800 text-slate-500 border-slate-700"
              }`}
            >
              🛡️ Triage Findings: {activeUser.can_triage_findings ? "YES" : "NO"}
            </span>
          </div>
        </div>
      )}

      {/* SECTION 1: Multi-Tenant Account Separation Cards */}
      <div className="space-y-3">
        <h2 className="text-xs font-extrabold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <Building2 className="w-4 h-4 text-cyan-400" />
          1. Isolated Tenant Accounts & Organizational Separation ({accounts.length})
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {accounts.map((acct) => {
            const isCurrent = acct.id === activeAccountId;
            const acctProjects = projects.filter(
              (p) =>
                p.account_id === acct.id ||
                acct.assigned_project_ids.includes(p.id)
            );
            return (
              <div
                key={acct.id}
                className={`rounded-xl border p-5 flex flex-col justify-between gap-4 transition-all ${
                  isCurrent
                    ? "bg-cyan-950/20 border-cyan-400 shadow-lg shadow-cyan-950/30"
                    : "bg-slate-900/90 border-slate-800 hover:border-slate-700"
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold">
                        {acct.organization_unit}
                      </div>
                      <h3 className="text-sm font-extrabold text-slate-100 mt-0.5">
                        {acct.name}
                      </h3>
                    </div>
                    <span
                      className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border ${
                        acct.isolation_mode === "STRICT"
                          ? "bg-rose-500/15 text-rose-300 border-rose-500/40"
                          : "bg-amber-500/15 text-amber-300 border-amber-500/40"
                      }`}
                    >
                      {acct.isolation_mode}
                    </span>
                  </div>

                  <div className="text-xs text-slate-400 space-y-1">
                    <div>
                      <span className="text-slate-500">Mandate:</span>{" "}
                      <span className="text-slate-200 font-medium">
                        {acct.compliance_mandate}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Tier:</span>{" "}
                      <span className="font-mono text-amber-300">
                        {acct.environment_tier}
                      </span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1">
                      <FolderGit2 className="w-3 h-3 text-emerald-400" />
                      Assigned Isolated Repositories ({acctProjects.length})
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {acctProjects.map((proj) => (
                        <span
                          key={proj.id}
                          className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-950 text-emerald-300 border border-slate-800"
                        >
                          {proj.name}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => switchUserOrAccount({ account_id: acct.id })}
                  className={`w-full py-2 px-3 rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 transition-all ${
                    isCurrent
                      ? "bg-cyan-500/20 text-cyan-200 border border-cyan-400/60"
                      : "bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                  }`}
                >
                  {isCurrent ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                      Active Tenant Account
                    </>
                  ) : (
                    <>Switch to Account</>
                  )}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* SECTION 2: RBAC User Profiles & Role Separation */}
      <div className="space-y-3">
        <h2 className="text-xs font-extrabold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <UserCheck className="w-4 h-4 text-violet-400" />
          2. RBAC User Profiles & Clearance Matrix ({users.length})
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {users.map((usr) => {
            const isCurrent = usr.id === activeUserId;
            return (
              <div
                key={usr.id}
                className={`rounded-xl border p-4 flex flex-col justify-between gap-4 transition-all ${
                  isCurrent
                    ? "bg-violet-950/25 border-violet-400 shadow-lg shadow-violet-950/30"
                    : "bg-slate-900/90 border-slate-800 hover:border-slate-700"
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="w-9 h-9 rounded-full bg-violet-500/20 border border-violet-500/40 flex items-center justify-center font-mono text-xs font-bold text-violet-200">
                        {usr.avatar_badge}
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-slate-100">
                          {usr.name}
                        </h3>
                        <div className="text-[11px] text-slate-400">
                          {usr.title} • {usr.email}
                        </div>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-violet-500/20 text-violet-300 border border-violet-500/40">
                      {usr.role}
                    </span>
                  </div>

                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-2.5 text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Account Partition:</span>
                      <span className="font-semibold text-cyan-300">
                        {usr.account_name}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Clearance:</span>
                      <span className="font-mono text-amber-300">
                        {usr.clearance_level}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Default Test Profile:</span>
                      <span className="font-mono text-emerald-300">
                        {usr.default_test_profile_id}
                      </span>
                    </div>
                  </div>

                  {/* Capability Matrix */}
                  <div className="grid grid-cols-2 gap-1.5 text-[10px] font-mono">
                    <div
                      className={`px-2 py-1 rounded border flex items-center gap-1 ${
                        usr.can_reveal_secrets
                          ? "bg-emerald-950/30 text-emerald-300 border-emerald-500/30"
                          : "bg-slate-950 text-slate-500 border-slate-800"
                      }`}
                    >
                      <KeyRound className="w-3 h-3" />
                      Secrets: {usr.can_reveal_secrets ? "Reveal" : "Masked"}
                    </div>
                    <div
                      className={`px-2 py-1 rounded border flex items-center gap-1 ${
                        usr.can_edit_rules
                          ? "bg-cyan-950/30 text-cyan-300 border-cyan-500/30"
                          : "bg-slate-950 text-slate-500 border-slate-800"
                      }`}
                    >
                      <Sliders className="w-3 h-3" />
                      Rules: {usr.can_edit_rules ? "Write" : "Read-Only"}
                    </div>
                    <div
                      className={`px-2 py-1 rounded border flex items-center gap-1 ${
                        usr.can_triage_findings
                          ? "bg-amber-950/30 text-amber-300 border-amber-500/30"
                          : "bg-slate-950 text-slate-500 border-slate-800"
                      }`}
                    >
                      <ShieldCheck className="w-3 h-3" />
                      Triage: {usr.can_triage_findings ? "Allowed" : "View"}
                    </div>
                    <div
                      className={`px-2 py-1 rounded border flex items-center gap-1 ${
                        usr.can_manage_accounts
                          ? "bg-violet-950/30 text-violet-300 border-violet-500/30"
                          : "bg-slate-950 text-slate-500 border-slate-800"
                      }`}
                    >
                      <Lock className="w-3 h-3" />
                      Tenants: {usr.can_manage_accounts ? "Admin" : "Scoped"}
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => switchUserOrAccount({ user_id: usr.id })}
                  className={`w-full py-2 px-3 rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 transition-all ${
                    isCurrent
                      ? "bg-violet-500/25 text-violet-200 border border-violet-400/60"
                      : "bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                  }`}
                >
                  {isCurrent ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-violet-300" />
                      Active Operator Profile
                    </>
                  ) : (
                    <>Assume Operator Profile</>
                  )}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* SECTION 3: Multi-Tenant Security Audit Log */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
        <h3 className="text-xs font-extrabold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <History className="w-4 h-4 text-amber-400" />
          3. Account Separation & Operator Audit Trail
        </h3>
        <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
          {auditLog.map((entry, idx) => (
            <div
              key={idx}
              className="bg-slate-950/80 border border-slate-800 rounded-lg px-3.5 py-2 flex flex-wrap items-center justify-between gap-2 text-xs"
            >
              <div className="flex items-center gap-2.5">
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-slate-800 text-amber-300 border border-slate-700">
                  {entry.action}
                </span>
                <span className="font-bold text-slate-200">{entry.actor}</span>
                <span className="text-slate-400">— {entry.details}</span>
              </div>
              <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                <span className="text-cyan-300">{entry.account}</span>
                <span>•</span>
                <span>{entry.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* New Tenant Account Modal */}
      {showNewAccountModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateAccount}
            className="bg-slate-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl"
          >
            <h3 className="text-sm font-extrabold text-slate-100 flex items-center gap-2">
              <Building2 className="w-4 h-4 text-cyan-400" />
              Create Isolated Tenant Account
            </h3>
            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Account Name
                </label>
                <input
                  type="text"
                  required
                  value={acctName}
                  onChange={(e) => setAcctName(e.target.value)}
                  placeholder="e.g., Cloud FinTech PCI Enclave"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                />
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Organization Unit / Business Division
                </label>
                <input
                  type="text"
                  value={acctOrgUnit}
                  onChange={(e) => setAcctOrgUnit(e.target.value)}
                  placeholder="e.g., Core Banking Security"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[11px] font-bold text-slate-300 mb-1">
                    Environment Tier
                  </label>
                  <select
                    value={acctTier}
                    onChange={(e) => setAcctTier(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                  >
                    <option value="PRODUCTION">PRODUCTION</option>
                    <option value="GOVERNANCE">GOVERNANCE</option>
                    <option value="RED_TEAM">RED_TEAM</option>
                    <option value="STAGING">STAGING</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-bold text-slate-300 mb-1">
                    Isolation Mode
                  </label>
                  <select
                    value={acctIsolation}
                    onChange={(e) => setAcctIsolation(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                  >
                    <option value="STRICT">STRICT</option>
                    <option value="SHARED_READ">SHARED_READ</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Compliance Mandate
                </label>
                <input
                  type="text"
                  value={acctCompliance}
                  onChange={(e) => setAcctCompliance(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowNewAccountModal(false)}
                className="px-3 py-1.5 rounded-lg text-xs bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg text-xs font-bold bg-cyan-500 text-slate-950"
              >
                Create Account
              </button>
            </div>
          </form>
        </div>
      )}

      {/* New User Profile Modal */}
      {showNewUserModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateUser}
            className="bg-slate-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl"
          >
            <h3 className="text-sm font-extrabold text-slate-100 flex items-center gap-2">
              <Users className="w-4 h-4 text-violet-400" />
              Create RBAC User Profile
            </h3>
            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={userName}
                  onChange={(e) => setUserName(e.target.value)}
                  placeholder="e.g., Priya Nair"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                />
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  value={userEmail}
                  onChange={(e) => setUserEmail(e.target.value)}
                  placeholder="priya.nair@alastor.security"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[11px] font-bold text-slate-300 mb-1">
                    RBAC Role
                  </label>
                  <select
                    value={userRole}
                    onChange={(e) => setUserRole(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                  >
                    <option value="APPSEC_ARCHITECT">APPSEC_ARCHITECT</option>
                    <option value="CISO_EXEC">CISO_EXEC</option>
                    <option value="SECURITY_AUDITOR">SECURITY_AUDITOR</option>
                    <option value="DEVSECOPS_ENG">DEVSECOPS_ENG</option>
                    <option value="DEVELOPER">DEVELOPER</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] font-bold text-slate-300 mb-1">
                    Job Title
                  </label>
                  <input
                    type="text"
                    value={userTitle}
                    onChange={(e) => setUserTitle(e.target.value)}
                    placeholder="Lead Security Reviewer"
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                  />
                </div>
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Assign to Tenant Account
                </label>
                <select
                  value={userAcctId}
                  onChange={(e) => setUserAcctId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                >
                  {accounts.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.organization_unit})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-300 mb-1">
                  Default Test Profile
                </label>
                <select
                  value={userPresetId}
                  onChange={(e) => setUserPresetId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100"
                >
                  {(platformSettings?.presets || []).map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} [{p.badge}]
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowNewUserModal(false)}
                className="px-3 py-1.5 rounded-lg text-xs bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg text-xs font-bold bg-violet-500 text-slate-950"
              >
                Create & Activate Profile
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
