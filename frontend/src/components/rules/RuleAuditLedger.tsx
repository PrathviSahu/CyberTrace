import React, { useState, useEffect, useCallback } from "react";
import {
  FileText,
  RefreshCw,
  Search,
  Filter,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  User,
  Clock,
  Code2,
} from "lucide-react";
import { api } from "../../services/api";
import { RuleAuditEntryResponse } from "../../types";

export const RuleAuditLedger: React.FC = () => {
  const [entries, setEntries] = useState<RuleAuditEntryResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [targetType, setTargetType] = useState<string>("");
  const [action, setAction] = useState<string>("");
  const [actorSearch, setActorSearch] = useState<string>("");
  const [expandedEntryId, setExpandedEntryId] = useState<string | null>(null);

  const fetchAuditLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listRuleAuditEntries({
        target_type: targetType || undefined,
        action: action || undefined,
        actor: actorSearch.trim() || undefined,
        limit: 100,
      });
      setEntries(res.items);
      setTotal(res.total);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load rule audit ledger.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [targetType, action, actorSearch]);

  useEffect(() => {
    fetchAuditLogs();
  }, [fetchAuditLogs]);

  const getActionBadgeClass = (act: string) => {
    switch (act) {
      case "APPROVE_DRAFT":
      case "ACTIVATE_RULE":
      case "REACTIVATE_RULE":
        return "bg-[#76A58B]/15 text-[#76A58B] border-[#76A58B]/30";
      case "DEACTIVATE_RULE":
        return "bg-[#D99A54]/15 text-[#D99A54] border-[#D99A54]/30";
      case "REJECT_DRAFT":
      case "DEPRECATE_RULE":
        return "bg-[#C94A4A]/15 text-[#F87171] border-[#C94A4A]/30";
      case "CREATE_DRAFT":
      case "VALIDATE_DRAFT":
      default:
        return "bg-[#1D2125] text-[#A0A7AE] border-[#30363C]";
    }
  };

  return (
    <div className="space-y-4">
      {/* Header and Filter Controls */}
      <div className="p-4 rounded-xl bg-[#1D2125] border border-[#30363C] space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#B58A61]/15 text-[#B58A61] border border-[#B58A61]/30">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[#E9ECEF] flex items-center gap-2">
                <span>Rule Governance Audit Ledger</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#111315] text-[#B58A61] border border-[#30363C]">
                  {total} records
                </span>
              </h3>
              <p className="text-xs text-[#737D87]">
                Append-only ledger recording all candidate draft and active rule state transitions.
              </p>
            </div>
          </div>

          <button
            onClick={fetchAuditLogs}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] text-xs font-medium transition-colors cursor-pointer shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-[#B58A61]" : ""}`} />
            <span>Refresh Ledger</span>
          </button>
        </div>

        {/* Security / Storage Notice */}
        <div className="px-3.5 py-2 rounded-lg bg-[#111315] border border-[#30363C] flex items-center justify-between text-xs text-[#737D87]">
          <span>
            Storage Classification: <strong className="text-[#A0A7AE] font-mono">application_level_append_only</strong>
          </span>
          <span className="text-[11px]">Honest attribution: Caller-supplied demo identities</span>
        </div>

        {/* Filters */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111315] border border-[#30363C] text-xs">
            <Filter className="w-3.5 h-3.5 text-[#737D87]" />
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              className="bg-transparent text-[#E9ECEF] outline-none w-full text-xs"
            >
              <option value="" className="bg-[#1D2125]">All Target Entities</option>
              <option value="DRAFT" className="bg-[#1D2125]">Rule Drafts (DRAFT)</option>
              <option value="ACTIVE_RULE" className="bg-[#1D2125]">Active Rules (ACTIVE_RULE)</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111315] border border-[#30363C] text-xs">
            <Filter className="w-3.5 h-3.5 text-[#737D87]" />
            <select
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="bg-transparent text-[#E9ECEF] outline-none w-full text-xs"
            >
              <option value="" className="bg-[#1D2125]">All Actions</option>
              <option value="CREATE_DRAFT" className="bg-[#1D2125]">CREATE_DRAFT</option>
              <option value="VALIDATE_DRAFT" className="bg-[#1D2125]">VALIDATE_DRAFT</option>
              <option value="APPROVE_DRAFT" className="bg-[#1D2125]">APPROVE_DRAFT</option>
              <option value="REJECT_DRAFT" className="bg-[#1D2125]">REJECT_DRAFT</option>
              <option value="ACTIVATE_RULE" className="bg-[#1D2125]">ACTIVATE_RULE</option>
              <option value="DEACTIVATE_RULE" className="bg-[#1D2125]">DEACTIVATE_RULE</option>
              <option value="REACTIVATE_RULE" className="bg-[#1D2125]">REACTIVATE_RULE</option>
              <option value="DEPRECATE_RULE" className="bg-[#1D2125]">DEPRECATE_RULE</option>
              <option value="ARCHIVE_DRAFT" className="bg-[#1D2125]">ARCHIVE_DRAFT</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111315] border border-[#30363C] text-xs">
            <Search className="w-3.5 h-3.5 text-[#737D87]" />
            <input
              type="text"
              value={actorSearch}
              onChange={(e) => setActorSearch(e.target.value)}
              placeholder="Filter by actor (e.g. lead_bob)..."
              className="bg-transparent text-[#E9ECEF] placeholder-[#737D87] outline-none w-full text-xs"
            />
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-xl bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2.5">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Entries List */}
      <div className="rounded-xl bg-[#1D2125] border border-[#30363C] overflow-hidden divide-y divide-[#30363C]">
        {loading && entries.length === 0 ? (
          <div className="p-8 text-center text-xs text-[#737D87]">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-[#B58A61]" />
            <span>Loading audit records...</span>
          </div>
        ) : entries.length === 0 ? (
          <div className="p-8 text-center text-xs text-[#737D87]">
            <FileText className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p className="font-semibold text-[#A0A7AE]">No audit entries match the current filter</p>
            <p className="mt-1">Lifecycle events will populate here as drafts are validated, approved, or toggled.</p>
          </div>
        ) : (
          entries.map((entry) => {
            const isExpanded = expandedEntryId === entry.id;
            return (
              <div key={entry.id} className="p-4 hover:bg-[#24282C]/40 transition-colors space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${getActionBadgeClass(
                        entry.action
                      )}`}
                    >
                      {entry.action}
                    </span>
                    <span className="text-xs text-[#737D87]">on</span>
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#111315] text-[#B58A61] border border-[#30363C]">
                      {entry.target_type}: {entry.target_id}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-xs text-[#737D87]">
                    <span className="flex items-center gap-1">
                      <User className="w-3.5 h-3.5 text-[#A0A7AE]" />
                      <span className="font-mono text-[#E9ECEF]">{entry.actor}</span>
                    </span>
                    <span>•</span>
                    <span className="flex items-center gap-1 font-mono text-[11px]">
                      <Clock className="w-3 h-3" />
                      {entry.timestamp.replace("T", " ").slice(0, 19)}
                    </span>
                  </div>
                </div>

                {/* Justification Text */}
                <div className="text-xs text-[#A0A7AE] bg-[#111315] p-2.5 rounded-lg border border-[#30363C]/80">
                  <strong className="text-[#737D87] font-semibold">Justification: </strong>
                  <span>{entry.justification}</span>
                </div>

                {/* State Diff Toggle */}
                <div className="flex items-center justify-end pt-1">
                  <button
                    type="button"
                    onClick={() => setExpandedEntryId(isExpanded ? null : entry.id)}
                    className="text-xs text-[#B58A61] hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <Code2 className="w-3 h-3" />
                    <span>{isExpanded ? "Hide State Diff" : "Inspect State Diff"}</span>
                    {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>
                </div>

                {/* Expanded Diff Viewer */}
                {isExpanded && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-[11px] font-mono">
                    <div className="p-3 rounded-lg bg-[#111315] border border-[#30363C] space-y-1 overflow-x-auto">
                      <span className="text-xs font-semibold text-[#737D87] block font-sans">State Before</span>
                      <pre className="text-[#A0A7AE]">{JSON.stringify(entry.state_before, null, 2)}</pre>
                    </div>
                    <div className="p-3 rounded-lg bg-[#111315] border border-[#30363C] space-y-1 overflow-x-auto">
                      <span className="text-xs font-semibold text-[#76A58B] block font-sans">State After</span>
                      <pre className="text-[#76A58B]">{JSON.stringify(entry.state_after, null, 2)}</pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
