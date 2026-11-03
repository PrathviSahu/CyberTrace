import React, { useState, useEffect } from "react";
import {
  X,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  AlertTriangle,
  Info,
  Check,
} from "lucide-react";
import { api } from "../../services/api";
import { DetectionRuleDraftResponse } from "../../types";

interface ApproveRejectDraftModalProps {
  isOpen: boolean;
  onClose: () => void;
  draft: DetectionRuleDraftResponse | null;
  mode: "approve" | "reject";
  onSuccess: () => void;
}

export const ApproveRejectDraftModal: React.FC<ApproveRejectDraftModalProps> = ({
  isOpen,
  onClose,
  draft,
  mode,
  onSuccess,
}) => {
  const [reviewerId, setReviewerId] = useState("lead_bob");
  const [justification, setJustification] = useState("");
  const [activateImmediately, setActivateImmediately] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setReviewerId(mode === "approve" ? "lead_bob" : "secops_reviewer");
      setJustification("");
      setActivateImmediately(true);
      setError(null);
    }
  }, [isOpen, mode]);

  if (!isOpen || !draft) return null;

  const isFourEyesViolation =
    mode === "approve" &&
    reviewerId.trim().toLowerCase() === draft.created_by.trim().toLowerCase();

  const isJustificationValid = justification.trim().length >= 10;
  const canSubmit = isJustificationValid && !isFourEyesViolation && !submitting;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;

    setSubmitting(true);
    setError(null);

    try {
      if (mode === "approve") {
        await api.approveRuleDraft(draft.id, {
          draft_version: draft.version,
          approver_id: reviewerId.trim(),
          justification: justification.trim(),
          activate_immediately: activateImmediately,
        });
      } else {
        await api.rejectRuleDraft(draft.id, {
          draft_version: draft.version,
          reviewer_id: reviewerId.trim(),
          justification: justification.trim(),
        });
      }
      onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Governance action failed.";
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
            <div
              className={`p-2 rounded-lg border ${
                mode === "approve"
                  ? "bg-[#76A58B]/15 text-[#76A58B] border-[#76A58B]/30"
                  : "bg-[#C94A4A]/15 text-[#F87171] border-[#C94A4A]/30"
              }`}
            >
              {mode === "approve" ? (
                <ShieldCheck className="w-5 h-5" />
              ) : (
                <ShieldAlert className="w-5 h-5" />
              )}
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[#E9ECEF]">
                {mode === "approve"
                  ? "Four-Eyes Governance: Approve Rule Draft"
                  : "Governance Review: Reject Rule Draft"}
              </h3>
              <p className="text-xs text-[#737D87]">
                Rule: <span className="text-[#E9ECEF] font-medium">{draft.name}</span> (v{draft.version})
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

        {/* Security / Four-Eyes Disclaimer */}
        <div className="px-5 py-2.5 bg-[#2B2722]/50 border-b border-[#B58A61]/25 flex items-start gap-2 text-xs text-[#D99A54]">
          <Info className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="leading-tight">
            <strong>Demonstration Four-Eyes Gate: </strong>
            <span>
              Enforces peer separation between author (<code className="font-mono text-[#E9ECEF]">{draft.created_by}</code>) and reviewer. Caller-supplied demo identities; no cryptographic authentication.
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

          {/* Four-Eyes Violation Notice if author === reviewer */}
          {isFourEyesViolation && (
            <div className="p-3 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/40 text-xs text-[#F87171] flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-[#F87171]" />
              <div>
                <strong className="block font-semibold">Four-Eyes Separation Violation:</strong>
                <span>
                  The rule author (<strong className="font-mono">{draft.created_by}</strong>) cannot approve their own rule. Switch reviewer identity to a peer lead (e.g. <code className="font-mono bg-[#111315] px-1 py-0.5 rounded">lead_bob</code>) to proceed.
                </span>
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
              Reviewer Demo Identity <span className="text-[#F87171]">*</span>
            </label>
            <input
              type="text"
              required
              value={reviewerId}
              onChange={(e) => setReviewerId(e.target.value)}
              placeholder="e.g. lead_bob"
              className={`w-full px-3 py-2 rounded-lg bg-[#111315] border text-xs text-[#E9ECEF] focus:outline-none ${
                isFourEyesViolation
                  ? "border-[#C94A4A] focus:border-[#C94A4A]"
                  : "border-[#30363C] focus:border-[#B58A61]"
              }`}
            />
            <div className="flex items-center justify-between text-[10px] text-[#737D87] mt-1">
              <span>Author: <span className="font-mono text-[#A0A7AE]">{draft.created_by}</span></span>
              <span>Must be distinct from author for four-eyes approval</span>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-semibold text-[#A0A7AE]">
                Mandatory {mode === "approve" ? "Approval" : "Rejection"} Justification <span className="text-[#F87171]">*</span>
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
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder={
                mode === "approve"
                  ? "Detail validation review findings, benign baseline check, and rule readiness justification..."
                  : "Detail reasons for rejection, identified false alarm risks, or required query refinements..."
              }
              className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] placeholder-[#737D87] focus:outline-none focus:border-[#B58A61] resize-none"
            />
          </div>

          {mode === "approve" && (
            <div className="flex items-center gap-2.5 p-3 rounded-lg bg-[#111315] border border-[#30363C]">
              <input
                type="checkbox"
                id="activateImmediately"
                checked={activateImmediately}
                onChange={(e) => setActivateImmediately(e.target.checked)}
                className="rounded border-[#30363C] text-[#B58A61] focus:ring-0 focus:ring-offset-0 cursor-pointer"
              />
              <label htmlFor="activateImmediately" className="text-xs text-[#E9ECEF] cursor-pointer">
                <strong>Activate immediately in CyberTrace detection engine</strong>
                <span className="block text-[11px] text-[#737D87]">
                  Allocates sequential rule code (e.g. CUST-001) and begins real-time evaluation in pipeline.
                </span>
              </label>
            </div>
          )}

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
              className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold transition-colors disabled:opacity-40 cursor-pointer ${
                mode === "approve"
                  ? "bg-[#76A58B] hover:bg-[#5E8B72] text-[#111315]"
                  : "bg-[#C94A4A] hover:bg-[#B03A3A] text-[#E9ECEF]"
              }`}
            >
              {submitting ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  <span>Processing...</span>
                </>
              ) : (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>{mode === "approve" ? "Approve & Activate Rule" : "Reject Rule Draft"}</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

