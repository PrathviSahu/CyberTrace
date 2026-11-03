import React, { useState, useEffect } from "react";
import {
  X,
  FileCode,
  AlertCircle,
  Sparkles,
  Info,
  FolderGit2,
} from "lucide-react";
import { api } from "../../services/api";
import {
  DetectionRuleDraftResponse,
  DetectionRuleDraftCreate,
  RuleSeverity,
  SavedHuntQueryDefinition,
} from "../../types";

interface CreateRuleDraftModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDraftCreated: (draft: DetectionRuleDraftResponse) => void;
  sourceHunt?: {
    id: string;
    name: string;
    version: number;
    queryDefinition: SavedHuntQueryDefinition;
  } | null;
}

const MITRE_TACTICS = [
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
];

export const CreateRuleDraftModal: React.FC<CreateRuleDraftModalProps> = ({
  isOpen,
  onClose,
  onDraftCreated,
  sourceHunt,
}) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<RuleSeverity>("medium");
  const [mitreAttackId, setMitreAttackId] = useState("");
  const [mitreTactic, setMitreTactic] = useState("");
  const [createdBy, setCreatedBy] = useState("analyst_alice");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      if (sourceHunt) {
        setName(`Rule: ${sourceHunt.name}`);
        setDescription(`Promoted from saved threat hunt '${sourceHunt.name}' (v${sourceHunt.version})`);
      } else {
        setName("");
        setDescription("");
      }
      setSeverity("medium");
      setMitreAttackId("");
      setMitreTactic("");
      setCreatedBy("analyst_alice");
      setError(null);
    }
  }, [isOpen, sourceHunt]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) {
      setError("Rule title is required.");
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const payload: DetectionRuleDraftCreate = {
        name: trimmedName,
        description: description.trim() || undefined,
        severity,
        mitre_attack_id: mitreAttackId.trim() || undefined,
        mitre_tactic: mitreTactic.trim() || undefined,
        created_by: createdBy.trim() || "analyst_alice",
      };

      if (sourceHunt) {
        payload.source_hunt_id = sourceHunt.id;
      } else {
        // Scratch rule default baseline query definition
        payload.query_definition = {
          filter_group: {
            logic: "AND",
            conditions: [
              {
                field: "category",
                operator: "eq",
                value: "process_creation",
              },
            ],
          },
          sort_by: "timestamp",
          sort_order: "desc",
        };
      }

      const draft = await api.createRuleDraft(payload);
      onDraftCreated(draft);
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create detection rule draft.";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-xl rounded-xl bg-[#1D2125] border border-[#30363C] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 bg-[#24282C] border-b border-[#30363C] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#B58A61]/15 text-[#B58A61] border border-[#B58A61]/30">
              <FileCode className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[#E9ECEF] flex items-center gap-2">
                {sourceHunt ? "Promote Saved Hunt to Rule Draft" : "Create Detection Rule Draft"}
              </h3>
              <p className="text-xs text-[#737D87]">
                {sourceHunt
                  ? `Promoting from saved hunt '${sourceHunt.name}' (v${sourceHunt.version})`
                  : "Draft detection rule from scratch for simulation and governance"}
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

        {/* Security Attribution Disclaimer */}
        <div className="px-5 py-2.5 bg-[#2B2722]/50 border-b border-[#B58A61]/25 flex items-start gap-2.5 text-xs text-[#D99A54]">
          <Info className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="leading-tight">
            <span className="font-semibold">Security Governance Notice: </span>
            <span>
              Author attribution uses caller-supplied demo metadata for workflow demonstration. No cryptographic identity verification or enterprise RBAC is enforced.
            </span>
          </div>
        </div>

        {/* Source Hunt Banner if Promoted */}
        {sourceHunt && (
          <div className="px-5 py-2 bg-[#24282C] border-b border-[#30363C] flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-[#A0A7AE]">
              <FolderGit2 className="w-3.5 h-3.5 text-[#B58A61]" />
              <span>Source Hunt ID: <span className="font-mono text-[#E9ECEF]">{sourceHunt.id}</span></span>
            </div>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#1D2125] text-[#B58A61] border border-[#30363C]">
              Version snapshot: v{sourceHunt.version}
            </span>
          </div>
        )}

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 overflow-y-auto">
          {error && (
            <div className="p-3 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
              Rule Title <span className="text-[#F87171]">*</span>
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Cobalt Strike Beacon Spawning Powershell"
              className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] placeholder-[#737D87] focus:outline-none focus:border-[#B58A61]"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
              Description & Objective
            </label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Detail the detection hypothesis, target malicious behavior, and correlation context..."
              className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] placeholder-[#737D87] focus:outline-none focus:border-[#B58A61] resize-none"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as RuleSeverity)}
                className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] focus:outline-none focus:border-[#B58A61]"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
                MITRE ATT&CK ID
              </label>
              <input
                type="text"
                value={mitreAttackId}
                onChange={(e) => setMitreAttackId(e.target.value)}
                placeholder="e.g. T1059.001"
                className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] placeholder-[#737D87] focus:outline-none focus:border-[#B58A61]"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
                MITRE ATT&CK Tactic
              </label>
              <select
                value={mitreTactic}
                onChange={(e) => setMitreTactic(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] focus:outline-none focus:border-[#B58A61]"
              >
                <option value="">None / Unassigned</option>
                {MITRE_TACTICS.map((tac) => (
                  <option key={tac} value={tac}>
                    {tac.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#A0A7AE] mb-1.5">
                Demo Author Identity
              </label>
              <input
                type="text"
                required
                value={createdBy}
                onChange={(e) => setCreatedBy(e.target.value)}
                placeholder="e.g. analyst_alice"
                className="w-full px-3 py-2 rounded-lg bg-[#111315] border border-[#30363C] text-xs text-[#E9ECEF] placeholder-[#737D87] focus:outline-none focus:border-[#B58A61]"
              />
              <span className="text-[10px] text-[#737D87] mt-0.5 block">
                Caller-supplied demo identifier
              </span>
            </div>
          </div>

          {/* Footer Actions */}
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
              disabled={submitting}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[#B58A61] hover:bg-[#9E744D] text-[#111315] text-xs font-semibold transition-colors disabled:opacity-50"
            >
              {submitting ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-[#111315] border-t-transparent rounded-full animate-spin" />
                  <span>Creating Draft...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Create Rule Draft</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
