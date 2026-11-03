import React, { useState, useEffect, useCallback } from "react";
import {
  Check,
  Copy,
  Search,
  Plus,
  RefreshCw,
  Sliders,
  ShieldCheck,
  ShieldAlert,
  FlaskConical,
  FileCode,
  FileText,
  AlertCircle,
  AlertTriangle,
  Clock,
  User,
  Filter,
  Layers,
  Archive,
  ChevronRight,
  FolderGit2,
} from "lucide-react";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { api } from "../services/api";
import {
  Detection,
  ActiveDetectionRuleResponse,
  DetectionRuleDraftResponse,
  RuleValidationReportResponse,
} from "../types";
import { CreateRuleDraftModal } from "../components/rules/CreateRuleDraftModal";
import { RuleValidationModal } from "../components/rules/RuleValidationModal";
import { ApproveRejectDraftModal } from "../components/rules/ApproveRejectDraftModal";
import { UpdateRuleStatusModal } from "../components/rules/UpdateRuleStatusModal";
import { RuleAuditLedger } from "../components/rules/RuleAuditLedger";

type RuleTab = "active" | "drafts" | "standard" | "audit";

export const DetectionRules: React.FC = () => {
  const [activeTab, setActiveTab] = useState<RuleTab>("active");

  // Detections for firing counts
  const [detections, setDetections] = useState<Detection[]>([]);

  // Active Custom Rules state
  const [activeRules, setActiveRules] = useState<ActiveDetectionRuleResponse[]>([]);
  const [activeRulesLoading, setActiveRulesLoading] = useState(false);
  const [activeRulesError, setActiveRulesError] = useState<string | null>(null);
  const [activeRuleStatusFilter, setActiveRuleStatusFilter] = useState<string>("");
  const [selectedActiveRule, setSelectedActiveRule] = useState<ActiveDetectionRuleResponse | null>(null);
  const [statusModalOpen, setStatusModalOpen] = useState(false);

  // Rule Drafts state
  const [drafts, setDrafts] = useState<DetectionRuleDraftResponse[]>([]);
  const [draftsLoading, setDraftsLoading] = useState(false);
  const [draftsError, setDraftsError] = useState<string | null>(null);
  const [draftStatusFilter, setDraftStatusFilter] = useState<string>("");
  const [draftSeverityFilter, setDraftSeverityFilter] = useState<string>("");
  const [draftIncludeArchived, setDraftIncludeArchived] = useState(false);
  const [createDraftModalOpen, setCreateDraftModalOpen] = useState(false);
  const [selectedDraftForValidation, setSelectedDraftForValidation] = useState<DetectionRuleDraftResponse | null>(null);
  const [validationModalOpen, setValidationModalOpen] = useState(false);
  const [selectedDraftForGovernance, setSelectedDraftForGovernance] = useState<DetectionRuleDraftResponse | null>(null);
  const [governanceMode, setGovernanceMode] = useState<"approve" | "reject">("approve");
  const [governanceModalOpen, setGovernanceModalOpen] = useState(false);

  // Standard Rules Catalog state
  const [selectedStandardRuleId, setSelectedStandardRuleId] = useState<string>("DET-001");
  const [copied, setCopied] = useState(false);
  const [standardSearch, setStandardSearch] = useState("");

  // Notification Banner
  const [bannerMessage, setBannerMessage] = useState<string | null>(null);

  // Fetch detections
  const fetchDetections = useCallback(async () => {
    try {
      const dets = await api.getDetections();
      setDetections(dets);
    } catch (err) {
      console.error("Failed to load detections for rule counts:", err);
    }
  }, []);

  // Fetch Active Custom Rules
  const fetchActiveRules = useCallback(async () => {
    setActiveRulesLoading(true);
    setActiveRulesError(null);
    try {
      const res = await api.listActiveRules({
        status: activeRuleStatusFilter || undefined,
        limit: 100,
      });
      setActiveRules(res.items);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load active detection rules.";
      setActiveRulesError(msg);
    } finally {
      setActiveRulesLoading(false);
    }
  }, [activeRuleStatusFilter]);

  // Fetch Rule Drafts
  const fetchDrafts = useCallback(async () => {
    setDraftsLoading(true);
    setDraftsError(null);
    try {
      const res = await api.listRuleDrafts({
        status: draftStatusFilter || undefined,
        severity: draftSeverityFilter || undefined,
        include_archived: draftIncludeArchived,
        limit: 100,
      });
      setDrafts(res.items);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load rule drafts.";
      setDraftsError(msg);
    } finally {
      setDraftsLoading(false);
    }
  }, [draftStatusFilter, draftSeverityFilter, draftIncludeArchived]);

  useEffect(() => {
    fetchDetections();
  }, [fetchDetections]);

  useEffect(() => {
    if (activeTab === "active") fetchActiveRules();
    if (activeTab === "drafts") fetchDrafts();
  }, [activeTab, fetchActiveRules, fetchDrafts]);

  // Standard rules definitions
  const standardRules = [
    {
      id: "DET-001",
      title: "Brute Force Authentication Burst",
      severity: "medium",
      tactic: "Credential Access",
      technique: "T1110.001 - Password Guessing",
      description:
        "Detects 5 or more failed authentication events for the same username within a 300-second temporal window.",
      yaml: `title: Brute Force Authentication Burst
id: 5a8e1f02-9c3b-4e12-b184-7a38e89f2101
status: production
description: Detects rapid consecutive failed logons targeting a single identity.
references:
  - https://attack.mitre.org/techniques/T1110/001/
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  category: authentication
  product: linux / windows
detection:
  selection:
    category: authentication
    action: logon_failure
  timeframe: 300s
  condition: selection | count(username) >= 5
severity: medium`,
    },
    {
      id: "DET-002",
      title: "Logon Success After Failed Attempts",
      severity: "high",
      tactic: "Initial Access",
      technique: "T1078.002 - Valid Accounts",
      description:
        "Detects a successful authentication event occurring within 300 seconds of a recognized brute-force failure cluster.",
      yaml: `title: Logon Success After Failed Attempts
id: 7b2d9e44-1f8a-4c23-9e12-88f1234abc02
status: production
description: Identifies valid account compromise immediately following password spray.
references:
  - https://attack.mitre.org/techniques/T1078/002/
tags:
  - attack.initial_access
  - attack.t1078.002
logsource:
  category: authentication
detection:
  condition: sequence(logon_failure >= 5, logon_success) by username within 300s
severity: high`,
    },
    {
      id: "DET-003",
      title: "Unauthorized Sudo Token Elevation",
      severity: "high",
      tactic: "Privilege Escalation",
      technique: "T1548.003 - Sudo and Sudo Caching",
      description:
        "Detects standard operator or deployment accounts executing sudo or token elevation to gain root privileges.",
      yaml: `title: Unauthorized Sudo Token Elevation
id: 8c3e0a15-4d7b-4819-a032-11e9876def03
status: production
description: Detects unexpected elevation to root or system privileges.
references:
  - https://attack.mitre.org/techniques/T1548/003/
tags:
  - attack.privilege_escalation
  - attack.t1548.003
logsource:
  category: authentication
  product: linux
detection:
  selection:
    action: privilege_elevation
    status: success
  condition: selection
severity: high`,
    },
    {
      id: "DET-004",
      title: "Anomalous Outbound Network Activity",
      severity: "critical",
      tactic: "Exfiltration",
      technique: "T1041 - Exfiltration Over C2 Channel",
      description:
        "Detects outbound network transmission exceeding 50,000,000 bytes (50 MB) to untrusted external destination IP addresses.",
      yaml: `title: Anomalous Outbound Network Activity
id: 9d4f1b26-5e8c-4920-b143-22f0987ghi04
status: production
description: Identifies anomalous large volume outbound egress.
references:
  - https://attack.mitre.org/techniques/T1041/
tags:
  - attack.exfiltration
  - attack.t1041
logsource:
  category: network_connection
detection:
  selection:
    category: network_connection
    bytes_out: > 50000000
  condition: selection
severity: critical`,
    },
  ];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const selectedStandardRule =
    standardRules.find((r) => r.id === selectedStandardRuleId) || standardRules[0];

  const filteredStandardRules = standardRules.filter((r) => {
    if (!standardSearch) return true;
    const q = standardSearch.toLowerCase();
    return (
      r.id.toLowerCase().includes(q) ||
      r.title.toLowerCase().includes(q) ||
      r.tactic.toLowerCase().includes(q) ||
      r.technique.toLowerCase().includes(q)
    );
  });

  const getFiringCount = (ruleIdOrCode: string) => {
    return detections.filter(
      (d) => d.rule_id === ruleIdOrCode || (d as any).rule_code === ruleIdOrCode
    ).length;
  };

  const handleOpenValidation = (draft: DetectionRuleDraftResponse) => {
    setSelectedDraftForValidation(draft);
    setValidationModalOpen(true);
  };

  const handleOpenGovernance = (draft: DetectionRuleDraftResponse, mode: "approve" | "reject") => {
    setSelectedDraftForGovernance(draft);
    setGovernanceMode(mode);
    setGovernanceModalOpen(true);
  };

  const handleArchiveDraft = async (draft: DetectionRuleDraftResponse) => {
    if (!window.confirm(`Archive detection rule draft '${draft.name}'?`)) return;
    try {
      await api.archiveRuleDraft(draft.id);
      setBannerMessage(`Draft '${draft.name}' has been archived.`);
      fetchDrafts();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to archive draft.";
      alert(msg);
    }
  };

  const handleValidationSuccess = (report: RuleValidationReportResponse) => {
    setBannerMessage(
      `Pre-flight simulation completed (${report.duration_ms.toFixed(1)}ms). Status: ${report.status}. Evaluated against ${report.historical_metrics?.events_scanned ?? 0} historical events.`
    );
    fetchDrafts();
  };

  const handleGovernanceSuccess = () => {
    setBannerMessage(
      governanceMode === "approve"
        ? "Four-eyes governance approval complete! Production custom rule code allocated and active in pipeline."
        : "Rule draft rejected and returned to editable DRAFT status for author rework."
    );
    fetchDrafts();
    fetchActiveRules();
  };

  const handleStatusUpdateSuccess = () => {
    setBannerMessage("Active rule status successfully updated and committed to audit ledger.");
    fetchActiveRules();
  };

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Detection Engineering & Governance
            </h1>
            <span className="text-[11px] px-2 py-0.5 rounded-md bg-[#24282C] text-[#B58A61] border border-[#B58A61]/30 font-medium font-mono">
              Phase 6.3 / 6.4 Pipeline
            </span>
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            Author, simulate, and govern detection rules with pre-flight empirical verification and demonstration four-eyes review gates.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCreateDraftModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#B58A61] hover:bg-[#9E744D] text-[#111315] text-xs font-semibold transition-colors cursor-pointer shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Rule Draft</span>
          </button>

          <button
            onClick={() => {
              if (activeTab === "active") fetchActiveRules();
              else if (activeTab === "drafts") fetchDrafts();
              fetchDetections();
            }}
            title="Refresh active view"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1D2125] hover:bg-[#24282C] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] text-xs font-medium transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Global Notification Banner */}
      {bannerMessage && (
        <div className="p-3 rounded-lg bg-[#76A58B]/15 border border-[#76A58B]/30 flex items-center justify-between text-xs text-[#E9ECEF] animate-fade-in">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#76A58B] shrink-0" />
            <span>{bannerMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setBannerMessage(null)}
            className="text-[11px] text-[#A0A7AE] hover:text-[#E9ECEF] underline cursor-pointer ml-3 shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Tabs Navigation */}
      <div className="flex items-center gap-2 border-b border-[#30363C] pb-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab("active")}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 cursor-pointer ${
            activeTab === "active"
              ? "border-[#B58A61] text-[#E9ECEF] bg-[#1D2125]"
              : "border-transparent text-[#737D87] hover:text-[#A0A7AE] hover:bg-[#1D2125]/50"
          }`}
        >
          <Sliders className="w-3.5 h-3.5 text-[#B58A61]" />
          <span>Active Custom Rules</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#111315] text-[#A0A7AE] border border-[#30363C]">
            {activeRules.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("drafts")}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 cursor-pointer ${
            activeTab === "drafts"
              ? "border-[#B58A61] text-[#E9ECEF] bg-[#1D2125]"
              : "border-transparent text-[#737D87] hover:text-[#A0A7AE] hover:bg-[#1D2125]/50"
          }`}
        >
          <FlaskConical className="w-3.5 h-3.5 text-[#B58A61]" />
          <span>Rule Drafts & Pre-flight</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#111315] text-[#A0A7AE] border border-[#30363C]">
            {drafts.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("standard")}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 cursor-pointer ${
            activeTab === "standard"
              ? "border-[#B58A61] text-[#E9ECEF] bg-[#1D2125]"
              : "border-transparent text-[#737D87] hover:text-[#A0A7AE] hover:bg-[#1D2125]/50"
          }`}
        >
          <FileCode className="w-3.5 h-3.5 text-[#737D87]" />
          <span>Standard Sigma Catalog</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#111315] text-[#A0A7AE] border border-[#30363C]">
            4
          </span>
        </button>

        <button
          onClick={() => setActiveTab("audit")}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 cursor-pointer ${
            activeTab === "audit"
              ? "border-[#B58A61] text-[#E9ECEF] bg-[#1D2125]"
              : "border-transparent text-[#737D87] hover:text-[#A0A7AE] hover:bg-[#1D2125]/50"
          }`}
        >
          <FileText className="w-3.5 h-3.5 text-[#737D87]" />
          <span>Governance Audit Ledger</span>
        </button>
      </div>

      {/* ===================================================================== */}
      {/* Tab 1: Active Custom Detection Rules */}
      {/* ===================================================================== */}
      {activeTab === "active" && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="p-3 rounded-lg bg-[#1D2125] border border-[#30363C] flex items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-[#737D87]" />
              <span className="text-[#A0A7AE] font-semibold">Filter Status:</span>
              <select
                value={activeRuleStatusFilter}
                onChange={(e) => setActiveRuleStatusFilter(e.target.value)}
                className="px-2.5 py-1 rounded bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] outline-none"
              >
                <option value="">All Statuses</option>
                <option value="ACTIVE">ACTIVE Only</option>
                <option value="DISABLED">DISABLED Only</option>
                <option value="DEPRECATED">DEPRECATED Only</option>
              </select>
            </div>

            <div className="text-[11px] text-[#737D87]">
              Sequential production allocation: <span className="font-mono text-[#B58A61]">CUST-xxx</span>
            </div>
          </div>

          {activeRulesError && (
            <div className="p-3 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{activeRulesError}</span>
            </div>
          )}

          {activeRulesLoading && activeRules.length === 0 ? (
            <div className="p-12 text-center text-xs text-[#737D87]">
              <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-[#B58A61]" />
              <span>Loading active custom detection rules...</span>
            </div>
          ) : activeRules.length === 0 ? (
            <div className="p-10 rounded-xl bg-[#1D2125] border border-[#30363C] text-center space-y-3">
              <Sliders className="w-8 h-8 mx-auto text-[#737D87] opacity-40" />
              <h3 className="text-sm font-semibold text-[#E9ECEF]">
                No Custom Detection Rules Deployed Yet
              </h3>
              <p className="text-xs text-[#737D87] max-w-md mx-auto">
                Promote a saved threat hunt or create a new detection rule draft, run pre-flight simulation, and approve it via four-eyes governance to deploy your first sequential custom rule (CUST-001).
              </p>
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => setActiveTab("drafts")}
                  className="px-3.5 py-1.5 rounded-lg bg-[#24282C] hover:bg-[#2B2722] text-[#B58A61] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-semibold transition-colors cursor-pointer inline-flex items-center gap-1.5"
                >
                  <span>Go to Rule Drafts</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {activeRules.map((rule) => {
                const firingCount = getFiringCount(rule.rule_code);
                return (
                  <div
                    key={rule.id}
                    className="p-4 rounded-xl bg-[#1D2125] border border-[#30363C] hover:border-[#30363C]/80 transition-colors space-y-3 shadow-card"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-mono text-sm font-bold text-[#B58A61] bg-[#111315] px-2.5 py-1 rounded border border-[#30363C]">
                          {rule.rule_code}
                        </span>
                        <SeverityBadge severity={rule.severity} size="sm" />
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            rule.status === "ACTIVE"
                              ? "bg-[#76A58B]/15 text-[#76A58B] border-[#76A58B]/30"
                              : rule.status === "DISABLED"
                              ? "bg-[#D99A54]/15 text-[#D99A54] border-[#D99A54]/30"
                              : "bg-[#C94A4A]/15 text-[#F87171] border-[#C94A4A]/30"
                          }`}
                        >
                          {rule.status}
                        </span>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#111315] text-[#737D87] border border-[#30363C]">
                          v{rule.version}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span
                          className={`text-xs font-mono px-2.5 py-1 rounded font-medium ${
                            firingCount > 0
                              ? "bg-[#D99A54]/15 text-[#D99A54] border border-[#D99A54]/30"
                              : "bg-[#111315] text-[#737D87] border border-[#30363C]"
                          }`}
                        >
                          {firingCount} Live Firings
                        </span>

                        <button
                          type="button"
                          onClick={() => {
                            setSelectedActiveRule(rule);
                            setStatusModalOpen(true);
                          }}
                          className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#24282C] hover:bg-[#2B2722] text-[#E9ECEF] border border-[#30363C] text-xs font-medium transition-colors cursor-pointer"
                        >
                          <Sliders className="w-3.5 h-3.5 text-[#B58A61]" />
                          <span>Update Status</span>
                        </button>
                      </div>
                    </div>

                    <div>
                      <h3 className="text-sm font-semibold text-[#E9ECEF]">{rule.name}</h3>
                      {rule.description && (
                        <p className="text-xs text-[#A0A7AE] mt-0.5 leading-relaxed">
                          {rule.description}
                        </p>
                      )}
                    </div>

                    {/* Metadata & Governance Attribution */}
                    <div className="flex items-center justify-between gap-2 text-xs text-[#737D87] pt-2 border-t border-[#30363C]/60 flex-wrap">
                      <div className="flex items-center gap-3">
                        {rule.mitre_attack_id && (
                          <span className="text-[11px]">
                            MITRE: <code className="text-[#A0A7AE] font-mono">{rule.mitre_attack_id}</code>
                          </span>
                        )}
                        {rule.mitre_tactic && (
                          <span className="text-[11px] px-2 py-0.5 rounded bg-[#111315] text-[#A0A7AE] border border-[#30363C]">
                            {rule.mitre_tactic}
                          </span>
                        )}
                        <span className="text-[11px]">
                          Source Draft: <span className="font-mono text-[#A0A7AE]">{rule.source_draft_id}</span>
                        </span>
                      </div>

                      <div className="flex items-center gap-2 text-[11px]">
                        <span className="flex items-center gap-1">
                          <User className="w-3 h-3" />
                          <span>Approved by: <strong className="font-mono text-[#E9ECEF]">{rule.approved_by}</strong></span>
                        </span>
                        <span>•</span>
                        <span className="flex items-center gap-1 font-mono text-[10px]">
                          <Clock className="w-3 h-3" />
                          {rule.approved_at.replace("T", " ").slice(0, 19)}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* Tab 2: Rule Drafts & Pre-flight Simulation */}
      {/* ===================================================================== */}
      {activeTab === "drafts" && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="p-3.5 rounded-lg bg-[#1D2125] border border-[#30363C] flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-[#737D87]" />
                <span className="text-[#A0A7AE] font-semibold">Status:</span>
                <select
                  value={draftStatusFilter}
                  onChange={(e) => setDraftStatusFilter(e.target.value)}
                  className="px-2.5 py-1 rounded bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] outline-none"
                >
                  <option value="">All Statuses</option>
                  <option value="DRAFT">DRAFT</option>
                  <option value="VALIDATED">VALIDATED</option>
                  <option value="APPROVED">APPROVED</option>
                  <option value="REJECTED">REJECTED</option>
                  <option value="ARCHIVED">ARCHIVED</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-[#A0A7AE] font-semibold">Severity:</span>
                <select
                  value={draftSeverityFilter}
                  onChange={(e) => setDraftSeverityFilter(e.target.value)}
                  className="px-2.5 py-1 rounded bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] outline-none"
                >
                  <option value="">All Severities</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <label className="flex items-center gap-1.5 text-[#737D87] hover:text-[#A0A7AE] cursor-pointer">
                <input
                  type="checkbox"
                  checked={draftIncludeArchived}
                  onChange={(e) => setDraftIncludeArchived(e.target.checked)}
                  className="rounded border-[#30363C] text-[#B58A61] focus:ring-0 focus:ring-offset-0 cursor-pointer"
                />
                <span>Include Archived Drafts</span>
              </label>
            </div>

            <button
              type="button"
              onClick={() => setCreateDraftModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#B58A61] hover:bg-[#9E744D] text-[#111315] font-semibold text-xs transition-colors cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create Rule Draft</span>
            </button>
          </div>

          {draftsError && (
            <div className="p-3 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{draftsError}</span>
            </div>
          )}

          {draftsLoading && drafts.length === 0 ? (
            <div className="p-12 text-center text-xs text-[#737D87]">
              <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-[#B58A61]" />
              <span>Loading detection rule drafts...</span>
            </div>
          ) : drafts.length === 0 ? (
            <div className="p-10 rounded-xl bg-[#1D2125] border border-[#30363C] text-center space-y-3">
              <FileCode className="w-8 h-8 mx-auto text-[#737D87] opacity-40" />
              <h3 className="text-sm font-semibold text-[#E9ECEF]">
                No Detection Rule Drafts Found
              </h3>
              <p className="text-xs text-[#737D87] max-w-md mx-auto">
                Create a draft rule from scratch or promote an existing query from the Threat Hunting view to start pre-flight validation.
              </p>
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => setCreateDraftModalOpen(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-[#B58A61] hover:bg-[#9E744D] text-[#111315] text-xs font-semibold transition-colors cursor-pointer inline-flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Create First Draft</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {drafts.map((draft) => {
                const isStale = draft.latest_validation?.is_stale ?? false;
                const hasBenignWarning = draft.latest_validation?.has_benign_baseline_warning ?? false;
                const canGovern = draft.status === "VALIDATED" && !isStale && !draft.is_archived;

                return (
                  <div
                    key={draft.id}
                    className={`p-4 rounded-xl bg-[#1D2125] border transition-colors space-y-3 shadow-card ${
                      draft.is_archived
                        ? "border-[#30363C]/40 opacity-60"
                        : "border-[#30363C] hover:border-[#30363C]/80"
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-mono text-xs text-[#B58A61] bg-[#111315] px-2 py-0.5 rounded border border-[#30363C]">
                          {draft.id}
                        </span>
                        <SeverityBadge severity={draft.severity} size="sm" />
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            draft.status === "VALIDATED"
                              ? "bg-[#76A58B]/15 text-[#76A58B] border-[#76A58B]/30"
                              : draft.status === "APPROVED"
                              ? "bg-[#5E8B72]/20 text-[#76A58B] border-[#5E8B72]/40"
                              : draft.status === "REJECTED"
                              ? "bg-[#C94A4A]/15 text-[#F87171] border-[#C94A4A]/30"
                              : "bg-[#24282C] text-[#A0A7AE] border-[#30363C]"
                          }`}
                        >
                          {draft.status}
                        </span>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#111315] text-[#737D87] border border-[#30363C]">
                          v{draft.version}
                        </span>
                        {draft.is_archived && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#C94A4A]/15 text-[#F87171] border border-[#C94A4A]/30">
                            Archived
                          </span>
                        )}
                        {isStale && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#D99A54]/15 text-[#D99A54] border border-[#D99A54]/30 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            <span>Stale Simulation</span>
                          </span>
                        )}
                        {hasBenignWarning && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#C94A4A]/15 text-[#F87171] border border-[#C94A4A]/30 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            <span>Benign Baseline Warning</span>
                          </span>
                        )}
                      </div>

                      {/* Draft Action Buttons */}
                      <div className="flex items-center gap-2">
                        {!draft.is_archived && (
                          <button
                            type="button"
                            onClick={() => handleOpenValidation(draft)}
                            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#B58A61]/15 hover:bg-[#B58A61]/25 text-[#B58A61] border border-[#B58A61]/30 text-xs font-semibold transition-colors cursor-pointer"
                          >
                            <FlaskConical className="w-3.5 h-3.5" />
                            <span>{draft.latest_validation ? "Re-validate / Simulation" : "Run Pre-flight"}</span>
                          </button>
                        )}

                        {canGovern && (
                          <>
                            <button
                              type="button"
                              onClick={() => handleOpenGovernance(draft, "approve")}
                              title="Submit for four-eyes review and production activation"
                              className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[#76A58B]/20 hover:bg-[#76A58B]/30 text-[#76A58B] border border-[#76A58B]/40 text-xs font-semibold transition-colors cursor-pointer"
                            >
                              <ShieldCheck className="w-3.5 h-3.5" />
                              <span>Four-Eyes Approve</span>
                            </button>

                            <button
                              type="button"
                              onClick={() => handleOpenGovernance(draft, "reject")}
                              title="Reject draft with reviewer rationale"
                              className="flex items-center gap-1 px-2 py-1 rounded-lg bg-[#C94A4A]/15 hover:bg-[#C94A4A]/25 text-[#F87171] border border-[#C94A4A]/30 text-xs font-semibold transition-colors cursor-pointer"
                            >
                              <ShieldAlert className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                          </>
                        )}

                        {!draft.is_archived && (
                          <button
                            type="button"
                            onClick={() => handleArchiveDraft(draft)}
                            title="Soft delete / archive draft"
                            className="p-1 rounded-lg bg-[#111315] hover:bg-[#C94A4A]/20 text-[#737D87] hover:text-[#F87171] border border-[#30363C] transition-colors cursor-pointer"
                          >
                            <Archive className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>

                    <div>
                      <h3 className="text-sm font-semibold text-[#E9ECEF]">{draft.name}</h3>
                      {draft.description && (
                        <p className="text-xs text-[#A0A7AE] mt-0.5 leading-relaxed">
                          {draft.description}
                        </p>
                      )}
                    </div>

                    {/* Pre-flight Simulation Metrics Card */}
                    {draft.latest_validation && (
                      <div className="p-3 rounded-lg bg-[#111315] border border-[#30363C] flex items-center justify-between text-xs gap-3 flex-wrap">
                        <div className="flex items-center gap-3">
                          <span className="flex items-center gap-1 text-[#A0A7AE]">
                            <Layers className="w-3.5 h-3.5 text-[#B58A61]" />
                            <span>Telemetry Matches: <strong className="text-[#E9ECEF] font-mono">{draft.latest_validation.matches_found}</strong></span>
                          </span>
                          <span>•</span>
                          <span className="text-[#A0A7AE]">
                            Est. Volume: <strong className="text-[#E9ECEF] font-mono">{draft.latest_validation.estimated_daily_alert_volume.toFixed(1)}/day</strong>
                          </span>
                        </div>

                        <span className="text-[11px] text-[#737D87] font-mono">
                          Validated: {draft.latest_validation.run_at.replace("T", " ").slice(0, 19)}
                        </span>
                      </div>
                    )}

                    {/* Attribution & Lineage */}
                    <div className="flex items-center justify-between gap-2 text-xs text-[#737D87] pt-2 border-t border-[#30363C]/60 flex-wrap">
                      <div className="flex items-center gap-3">
                        {draft.source_hunt_id && (
                          <span className="flex items-center gap-1 text-[11px] text-[#A0A7AE]">
                            <FolderGit2 className="w-3 h-3 text-[#B58A61]" />
                            <span>Source Hunt: <code className="font-mono text-[#E9ECEF]">{draft.source_hunt_id}</code> (v{draft.source_hunt_version})</span>
                          </span>
                        )}
                        {draft.mitre_attack_id && (
                          <span className="text-[11px]">
                            MITRE: <code className="text-[#A0A7AE] font-mono">{draft.mitre_attack_id}</code>
                          </span>
                        )}
                        {draft.mitre_tactic && (
                          <span className="text-[11px] px-2 py-0.5 rounded bg-[#111315] text-[#A0A7AE] border border-[#30363C]">
                            {draft.mitre_tactic}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2 text-[11px]">
                        <span className="flex items-center gap-1">
                          <User className="w-3 h-3" />
                          <span>Author: <strong className="font-mono text-[#E9ECEF]">{draft.created_by}</strong> (demo identity)</span>
                        </span>
                        <span>•</span>
                        <span className="font-mono text-[10px]">
                          {draft.created_at.replace("T", " ").slice(0, 19)}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* Tab 3: Standard Sigma-compatible Rules Catalog */}
      {/* ===================================================================== */}
      {activeTab === "standard" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3 pb-1">
            <span className="text-xs text-[#A0A7AE]">
              Built-in baseline detection specifications mapped to MITRE ATT&CK techniques.
            </span>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#1D2125] border border-[#30363C] text-xs">
              <Search className="w-3.5 h-3.5 text-[#737D87]" />
              <input
                type="text"
                placeholder="Search rule ID, technique..."
                value={standardSearch}
                onChange={(e) => setStandardSearch(e.target.value)}
                className="bg-transparent text-[#E9ECEF] placeholder-[#737D87] outline-none w-48 text-xs font-sans"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
            {/* Left Column (5 Cols): Rule List */}
            <div className="lg:col-span-5 space-y-3">
              <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
                <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
                  <span className="text-xs font-semibold text-[#E9ECEF]">
                    Standard Rules ({filteredStandardRules.length})
                  </span>
                  <span className="text-xs text-[#737D87]">Live Firing Counts</span>
                </div>

                <div className="divide-y divide-[#30363C]">
                  {filteredStandardRules.map((r) => {
                    const count = getFiringCount(r.id);
                    return (
                      <div
                        key={r.id}
                        onClick={() => setSelectedStandardRuleId(r.id)}
                        className={`p-3.5 cursor-pointer transition-colors ${
                          r.id === selectedStandardRuleId
                            ? "bg-[#2B2722] border-l-2 border-[#B58A61]"
                            : "hover:bg-[#24282C]/50"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-semibold text-[#B58A61]">{r.id}</span>
                            <SeverityBadge severity={r.severity} size="sm" />
                          </div>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium ${
                              count > 0
                                ? "bg-[#D99A54]/12 text-[#D99A54] border border-[#D99A54]/25"
                                : "bg-[#24282C] text-[#737D87]"
                            }`}
                          >
                            {count} Active Firings
                          </span>
                        </div>

                        <div className="text-xs font-medium text-[#E9ECEF] mt-0.5">
                          {r.title}
                        </div>

                        <div className="text-[11px] text-[#737D87] mt-0.5 truncate">
                          {r.technique}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Right Column (7 Cols): Rule Detail & Sigma YAML Specification */}
            <div className="lg:col-span-7 space-y-4">
              <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-5 space-y-4 shadow-card">
                <div className="flex items-start justify-between gap-4 pb-3 border-b border-[#30363C]">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono font-semibold text-[#B58A61]">
                        {selectedStandardRule.id}
                      </span>
                      <SeverityBadge severity={selectedStandardRule.severity} size="sm" />
                      <span className="text-[11px] px-2 py-0.5 rounded bg-[#24282C] text-[#A0A7AE] border border-[#30363C]">
                        {selectedStandardRule.tactic}
                      </span>
                    </div>
                    <h2 className="text-base font-semibold text-[#E9ECEF]">
                      {selectedStandardRule.title}
                    </h2>
                    <div className="text-xs text-[#737D87] mt-0.5">
                      MITRE ATT&CK: <span className="text-[#A0A7AE] font-mono text-xs">{selectedStandardRule.technique}</span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleCopy(selectedStandardRule.yaml)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-medium transition-colors shrink-0 cursor-pointer"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-[#76A58B]" />
                        <span className="text-[#76A58B]">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-[#737D87]" />
                        <span>Copy Rule YAML</span>
                      </>
                    )}
                  </button>
                </div>

                <p className="text-xs text-[#A0A7AE] leading-relaxed bg-[#24282C] p-3.5 rounded-md border border-[#30363C]">
                  {selectedStandardRule.description}
                </p>

                {/* Sigma YAML Code Block */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-[#737D87]">
                    <span className="font-semibold text-[#E9ECEF]">
                      Sigma-Compatible Rule Specification
                    </span>
                    <span className="text-[11px] text-[#737D87] font-mono">Format: YAML / Sigma subset</span>
                  </div>
                  <pre className="p-4 rounded-lg bg-[#191C1F] border border-[#30363C] text-xs font-mono text-[#A0A7AE] leading-relaxed overflow-x-auto">
                    {selectedStandardRule.yaml}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* Tab 4: Governance Audit Ledger */}
      {/* ===================================================================== */}
      {activeTab === "audit" && <RuleAuditLedger />}

      {/* Modals */}
      <CreateRuleDraftModal
        isOpen={createDraftModalOpen}
        onClose={() => setCreateDraftModalOpen(false)}
        onDraftCreated={(newDraft) => {
          setBannerMessage(`Draft rule '${newDraft.name}' (ID: ${newDraft.id}) created successfully!`);
          fetchDrafts();
          setActiveTab("drafts");
        }}
      />

      <RuleValidationModal
        isOpen={validationModalOpen}
        onClose={() => {
          setValidationModalOpen(false);
          setSelectedDraftForValidation(null);
        }}
        draft={selectedDraftForValidation}
        onValidationSuccess={handleValidationSuccess}
        onProceedToGovernance={(draft) => {
          setSelectedDraftForGovernance(draft);
          setGovernanceMode("approve");
          setGovernanceModalOpen(true);
        }}
      />

      <ApproveRejectDraftModal
        isOpen={governanceModalOpen}
        onClose={() => {
          setGovernanceModalOpen(false);
          setSelectedDraftForGovernance(null);
        }}
        draft={selectedDraftForGovernance}
        mode={governanceMode}
        onSuccess={handleGovernanceSuccess}
      />

      <UpdateRuleStatusModal
        isOpen={statusModalOpen}
        onClose={() => {
          setStatusModalOpen(false);
          setSelectedActiveRule(null);
        }}
        rule={selectedActiveRule}
        onSuccess={handleStatusUpdateSuccess}
      />
    </div>
  );
};
