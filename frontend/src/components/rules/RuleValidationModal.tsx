import React, { useState } from "react";
import {
  X,
  Play,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  Database,
  FlaskConical,
  Info,
  Clock,
  Layers,
  Sparkles,
} from "lucide-react";
import { api } from "../../services/api";
import {
  DetectionRuleDraftResponse,
  RuleValidationReportResponse,
  ValidationScope,
} from "../../types";

interface RuleValidationModalProps {
  isOpen: boolean;
  onClose: () => void;
  draft: DetectionRuleDraftResponse | null;
  onValidationSuccess: (report: RuleValidationReportResponse) => void;
  onProceedToGovernance?: (draft: DetectionRuleDraftResponse) => void;
}

export const RuleValidationModal: React.FC<RuleValidationModalProps> = ({
  isOpen,
  onClose,
  draft,
  onValidationSuccess,
  onProceedToGovernance,
}) => {
  const [scope, setScope] = useState<ValidationScope>("all");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<RuleValidationReportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showSampleEvents, setShowSampleEvents] = useState(false);

  if (!isOpen || !draft) return null;

  const handleRunValidation = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.validateRuleDraft(draft.id, { target_scope: scope });
      setReport(res);
      onValidationSuccess(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Validation simulation failed.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const isStale = report?.is_stale || (draft.latest_validation?.is_stale ?? false);
  const hasBenignWarning =
    report?.threatlab_metrics?.has_benign_baseline_warning ||
    (draft.latest_validation?.has_benign_baseline_warning ?? false);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-3xl rounded-xl bg-[#1D2125] border border-[#30363C] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 bg-[#24282C] border-b border-[#30363C] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#B58A61]/15 text-[#B58A61] border border-[#B58A61]/30">
              <FlaskConical className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-[#E9ECEF]">
                  Pre-flight Rule Simulation & Benchmark Validation
                </h3>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#111315] text-[#B58A61] border border-[#30363C]">
                  v{draft.version}
                </span>
                <span
                  className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                    draft.status === "VALIDATED"
                      ? "bg-[#76A58B]/15 text-[#76A58B] border-[#76A58B]/30"
                      : "bg-[#24282C] text-[#A0A7AE] border-[#30363C]"
                  }`}
                >
                  {draft.status}
                </span>
              </div>
              <p className="text-xs text-[#737D87] mt-0.5">
                Draft: <span className="text-[#E9ECEF] font-medium">{draft.name}</span> ({draft.id})
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

        {/* Provenance Transparency Alert */}
        <div className="px-5 py-2.5 bg-[#2B2722]/50 border-b border-[#B58A61]/25 flex items-start gap-2 text-xs text-[#D99A54]">
          <Info className="w-4 h-4 shrink-0 mt-0.5" />
          <span>
            <strong>Data Grounding Notice: </strong>
            Evaluates rule AST against historical telemetry and ThreatLab benchmark attack scenarios. Synthetic benchmark matches are categorized separately and not conflated with live alerts.
          </span>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 overflow-y-auto">
          {/* Controls Bar */}
          <div className="p-3.5 rounded-lg bg-[#111315] border border-[#30363C] flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-semibold text-[#A0A7AE] whitespace-nowrap">
                Simulation Scope:
              </span>
              <select
                value={scope}
                onChange={(e) => setScope(e.target.value as ValidationScope)}
                disabled={loading}
                className="px-3 py-1.5 rounded bg-[#1D2125] border border-[#30363C] text-xs text-[#E9ECEF] focus:outline-none focus:border-[#B58A61] flex-1 sm:flex-initial"
              >
                <option value="all">All (Telemetry + ThreatLab Benchmarks)</option>
                <option value="historical_telemetry">Historical Telemetry Only</option>
                <option value="threatlab_benchmarks">ThreatLab Benchmarks Only</option>
              </select>
            </div>

            <button
              onClick={handleRunValidation}
              disabled={loading}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-1.5 rounded-lg bg-[#B58A61] hover:bg-[#9E744D] text-[#111315] font-semibold text-xs transition-colors disabled:opacity-50 cursor-pointer shadow-sm"
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-[#111315] border-t-transparent rounded-full animate-spin" />
                  <span>Simulating Across Telemetry...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Run Pre-flight Simulation</span>
                </>
              )}
            </button>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-3.5 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold">Simulation Error:</strong>
                <span>{error}</span>
              </div>
            </div>
          )}

          {/* Stale Validation Warning */}
          {isStale && (
            <div className="p-3.5 rounded-lg bg-[#D99A54]/15 border border-[#D99A54]/30 text-xs text-[#D99A54] flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold">Stale Simulation Evidence:</strong>
                <span>
                  The rule draft was modified after this simulation ran. Re-run pre-flight validation to certify current version v{draft.version} before submitting for governance review.
                </span>
              </div>
            </div>
          )}

          {/* Benign Baseline Warning Banner */}
          {hasBenignWarning && (
            <div className="p-3.5 rounded-lg bg-[#C94A4A]/15 border border-[#C94A4A]/30 text-xs text-[#F87171] flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold">Benign Baseline False Alarm Warning (SCN-004):</strong>
                <span>
                  This rule triggered matches on benign administrative baseline telemetry. It is likely to generate alert noise in pipeline. Review and constrain filter conditions before four-eyes approval.
                </span>
              </div>
            </div>
          )}

          {/* Report Results */}
          {report && (
            <div className="space-y-4 animate-fade-in">
              {/* Summary Stats Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-[#111315] border border-[#30363C]">
                  <span className="text-[11px] text-[#737D87] block">Duration</span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <Clock className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span className="text-sm font-semibold text-[#E9ECEF] font-mono">
                      {report.duration_ms.toFixed(1)}ms
                    </span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#111315] border border-[#30363C]">
                  <span className="text-[11px] text-[#737D87] block">Estimated Daily Volume</span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <Layers className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span className="text-sm font-semibold text-[#E9ECEF] font-mono">
                      {report.historical_metrics?.estimated_daily_alert_volume.toFixed(1) ?? "0.0"} / day
                    </span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#111315] border border-[#30363C]">
                  <span className="text-[11px] text-[#737D87] block">Telemetry Matches</span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <Database className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span className="text-sm font-semibold text-[#E9ECEF] font-mono">
                      {report.historical_metrics?.matches_found ?? 0} / {report.historical_metrics?.events_scanned ?? 0}
                    </span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#111315] border border-[#30363C]">
                  <span className="text-[11px] text-[#737D87] block">Benchmark Scenarios</span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <FlaskConical className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span className="text-sm font-semibold text-[#E9ECEF] font-mono">
                      {report.threatlab_metrics?.scenarios_evaluated ?? 0} evaluated
                    </span>
                  </div>
                </div>
              </div>

              {/* Historical Telemetry Breakdown */}
              {report.historical_metrics && (
                <div className="p-4 rounded-lg bg-[#111315] border border-[#30363C] space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-semibold text-[#E9ECEF] flex items-center gap-2">
                      <Database className="w-3.5 h-3.5 text-[#B58A61]" />
                      <span>Historical Database Telemetry Simulation</span>
                    </h4>
                    <span className="text-[11px] text-[#737D87]">
                      Observation period: {report.historical_metrics.observation_duration_days.toFixed(1)} days
                    </span>
                  </div>

                  <p className="text-[11px] text-[#737D87]">
                    Calculation formula: <code className="text-[#A0A7AE] font-mono">{report.historical_metrics.daily_volume_formula}</code>
                  </p>

                  {/* Provenance Breakdown Chips */}
                  {report.historical_metrics.provenance_breakdown && (
                    <div className="space-y-1.5">
                      <span className="text-[11px] text-[#737D87]">Provenance Breakdown of Evaluated Events:</span>
                      <div className="flex items-center gap-2 flex-wrap">
                        {Object.entries(report.historical_metrics.provenance_breakdown).map(([prov, count]) => (
                          <div
                            key={prov}
                            className="px-2.5 py-1 rounded bg-[#1D2125] border border-[#30363C] text-xs font-mono flex items-center gap-1.5"
                          >
                            <span className="text-[#A0A7AE] capitalize">{prov.replace(/_/g, " ")}:</span>
                            <span className="font-semibold text-[#E9ECEF]">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Sample Matches Collapsible */}
                  {report.historical_metrics.sample_matched_event_ids.length > 0 && (
                    <div>
                      <button
                        type="button"
                        onClick={() => setShowSampleEvents(!showSampleEvents)}
                        className="text-xs text-[#B58A61] hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        <span>
                          {showSampleEvents
                            ? "Hide sample matched event IDs"
                            : `View ${report.historical_metrics.sample_matched_event_ids.length} sample matched event IDs`}
                        </span>
                      </button>
                      {showSampleEvents && (
                        <div className="mt-2 p-2.5 rounded bg-[#1D2125] border border-[#30363C] text-[11px] font-mono text-[#A0A7AE] flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                          {report.historical_metrics.sample_matched_event_ids.map((id) => (
                            <span key={id} className="px-2 py-0.5 rounded bg-[#111315] border border-[#30363C]">
                              {id}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* ThreatLab Benchmarks Breakdown */}
              {report.threatlab_metrics && report.threatlab_metrics.scenario_results.length > 0 && (
                <div className="p-4 rounded-lg bg-[#111315] border border-[#30363C] space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-semibold text-[#E9ECEF] flex items-center gap-2">
                      <FlaskConical className="w-3.5 h-3.5 text-[#B58A61]" />
                      <span>ThreatLab Attack Scenario Ground-Truth Benchmark</span>
                    </h4>
                    <span className="text-[11px] text-[#737D87]">
                      {report.threatlab_metrics.total_matches} total detections across scenarios
                    </span>
                  </div>

                  <div className="divide-y divide-[#30363C] rounded-lg border border-[#30363C] overflow-hidden">
                    {report.threatlab_metrics.scenario_results.map((sc) => (
                      <div
                        key={sc.scenario_id}
                        className={`p-2.5 flex items-center justify-between gap-3 text-xs ${
                          sc.is_benign_baseline_warning
                            ? "bg-[#C94A4A]/10"
                            : "bg-[#1D2125]"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold text-[#B58A61]">
                            {sc.scenario_id}
                          </span>
                          <span className="text-[#E9ECEF] font-medium">{sc.name}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#111315] text-[#737D87] border border-[#30363C]">
                            {sc.category}
                          </span>
                        </div>

                        <div className="flex items-center gap-3">
                          <span className="font-mono text-xs text-[#A0A7AE]">
                            {sc.matches_found} matches / {sc.total_events} events
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              sc.classification === "benign_baseline_warning"
                                ? "bg-[#C94A4A]/20 text-[#F87171] border-[#C94A4A]/40"
                                : sc.classification === "true_positive"
                                ? "bg-[#76A58B]/20 text-[#76A58B] border-[#76A58B]/40"
                                : "bg-[#24282C] text-[#A0A7AE] border-[#30363C]"
                            }`}
                          >
                            {sc.classification.replace(/_/g, " ")}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 bg-[#24282C] border-t border-[#30363C] flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-[#737D87]">
            {report?.draft_status_updated && (
              <span className="flex items-center gap-1 text-[#76A58B]">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Draft status updated to VALIDATED</span>
              </span>
            )}
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] hover:bg-[#1D2125] border border-[#30363C] transition-colors"
            >
              Close
            </button>

            {onProceedToGovernance && draft.status === "VALIDATED" && !isStale && (
              <button
                type="button"
                onClick={() => {
                  onProceedToGovernance(draft);
                  onClose();
                }}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[#76A58B] hover:bg-[#5E8B72] text-[#111315] font-semibold text-xs transition-colors cursor-pointer"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Submit to Four-Eyes Governance</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

