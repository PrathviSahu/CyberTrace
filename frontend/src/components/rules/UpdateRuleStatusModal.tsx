import React, { useState, useEffect } from "react";
import {
  X,
  Sliders,
  AlertCircle,
  AlertTriangle,
  Info,
  Check,
} from "lucide-react";
import { api } from "../../services/api";
import {
  ActiveDetectionRuleResponse,
  ActiveRuleStatus,
} from "../../types";

interface UpdateRuleStatusModalProps {
  isOpen: boolean;
  onClose: () => void;
  rule: ActiveDetectionRuleResponse | null;
  onSuccess: () => void;
}

export const UpdateRuleStatusModal: React.FC<UpdateRuleStatusModalProps> = ({
  isOpen,
  onClose,
  rule,
  onSuccess,
}) => {
  const [status, setStatus] = useState<ActiveRuleStatus>("ACTIVE");
  const [justification, setJustification] = useState("");
  const [actor, setActor] = useState("soc_operator");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && rule) {
      // Default to toggling opposite if active/disabled
      const nextStatus = rule.status === "ACTIVE" ? "DISABLED" : "ACTIVE";
      setStatus(nextStatus);
      setJustification("");
      setActor("soc_operator");
      setError(null);
    }
  }, [isOpen, rule]);

  if (!isOpen || !rule) return null;

  const isDeprecatedTerminal = rule.status === "DEPRECATED";
  const isTargetDeprecated = status === "DEPRECATED";
  const isJustificationValid = justification.trim().length >= 10;
  const canSubmit = isJustificationValid && !submitting && !isDeprecatedTerminal;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;

    setSubmitting(true);
    setError(null);

    try {
      await api.updateActiveRuleStatus(rule.id, {
        version: rule.version,
        status,
        justification: justification.trim(),
        actor: actor.trim() || "soc_operator",
      });
      onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to update rule status.";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-lg rounded-xl bg-[#1D2125] border border-[#30363C] shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-4 bg-[#24282C] border-b border-[#30363C] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#B58A61]/15 text-[#B58A61] border border-[#B58A61]/30">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[#E9ECEF]">
                Update Rule Status & Lifecycle State
              </h3>
              <p className="text-xs text-[#737D87]">
                Rule: <span className="text-[#B58A61] font-mono font-semibold">{rule.rule_code}</span> — {rule.name}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#737D87] hover:text-[#E9ECEF] hover:bg-[#30363C] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Security & Audit Notice */}
        <div className="px-5 py-2.5 bg-[#2B2722]/50 border-b border-[#B58A61]/25 flex items-start gap-2 text-xs text-[#D99A54]">
          <Info className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="leading-tight">
            <strong>Append-Only Audit Ledger: </strong>
            <span>
              All state transitions are permanently recorded in the immutable audit log with full before/after diffs, timestamp, and operator identity.
            </span>
          </div>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {isDeprecatedTerminal && (
            <div className="p-3.5 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/40 text-xs text-[#F87171] flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold">Rule Permanently Deprecated:</strong>
                <span>
                  This rule was transitioned to DEPRECATED terminal state. The governance policy prohibits re-activating deprecated rules.
                </span>
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
              Current Status:{" "}
              <span className="font-mono text-[#E9ECEF] uppercase font-bold">{rule.status}</span> (v{rule.version})
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(["ACTIVE", "DISABLED", "DEPRECATED"] as ActiveRuleStatus[]).map((st) => (
                <button
                  key={st}
                  type="button"
                  disabled={isDeprecatedTerminal}
                  onClick={() => setStatus(st)}
                  className={`py-2 px-3 rounded-lg text-xs font-semibold border transition-colors flex items-center justify-center gap-1.5 ${
                    status === st
                      ? st === "ACTIVE"
                        ? "bg-[#76A58B]/20 border-[#76A58B] text-[#76A58B]"
                        : st === "DISABLED"
                        ? "bg-[#D99A54]/20 border-[#D99A54] text-[#D99A54]"
                        : "bg-[#C94A4A]/20 border-[#C94A4A] text-[#F87171]"
                      : "bg-[#111315] border-[#30363C] text-[#737D87] hover:text-[#A0A7AE]"
                  }`}
                >
                  <span>{st}</span>
                </button>
              ))}
            </div>
          </div>

          {isTargetDeprecated && !isDeprecatedTerminal && (
            <div className="p-3 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                <strong>Warning:</strong> DEPRECATED is a permanent terminal state. Once deprecated, this rule cannot be reactivated in the pipeline.
              </span>
            </div>
          )}

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-semibold text-[#A0A7AE]">
                Mandatory Operational Justification <span className="text-[#F87171]">*</span>
              </label>
              <span
                className={`text-[10px] font-mono ${
                  isJustificationValid ? "text-[#76A58B]" : "text-[#737D87]"
                }`}
              >
                {justification.trim().length} / 10 chars min
              </span>
            </div>
            <textarea
              rows={3}
              required
              disabled={isDeprecatedTerminal}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="State the reason for this status transition (e.g., temporary maintenance, false positive mitigation, retirement)..."
              className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] placeholder-[#737D87] focus:outline-none focus:border-[#B58A61] resize-none disabled:opacity-50"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
              Operator Demo Identity
            </label>
            <input
              type="text"
              required
              disabled={isDeprecatedTerminal}
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              placeholder="e.g. soc_operator"
              className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] placeholder-[#737D87] focus:outline-none focus:border-[#B58A61] disabled:opacity-50"
            />
          </div>

          {/* Footer */}
          <div className="pt-3 border-t border-[#30363C] flex items-center justify-end gap-2.5">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] hover:bg-[#24282C] border border-[#30363C] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[#B58A61] hover:bg-[#9E744D] text-[#111315] text-xs font-semibold transition-colors disabled:opacity-40 cursor-pointer"
            >
              {submitting ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-[#111315] border-t-transparent rounded-full animate-spin" />
                  <span>Updating...</span>
                </>
              ) : (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Commit Status Change</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

