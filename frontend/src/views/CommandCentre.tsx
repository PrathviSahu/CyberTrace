import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  Flame,
  Server,
  Activity,
  Filter,
  UploadCloud,
  ChevronRight,
} from "lucide-react";
import { api } from "../services/api";
import { IncidentSummary, OverviewMetrics } from "../types";
import { MetricCard } from "../components/common/MetricCard";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";

interface CommandCentreProps {
  onOpenUpload: () => void;
}

export const CommandCentre: React.FC<CommandCentreProps> = ({ onOpenUpload }) => {
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      const [m, incs] = await Promise.all([api.getOverviewMetrics(), api.getIncidents()]);
      setMetrics(m);
      setIncidents(incs);
      setLoading(false);
    }
    loadData();
  }, []);

  const filteredIncidents = incidents.filter((inc) => {
    if (severityFilter !== "all" && inc.severity !== severityFilter) return false;
    return true;
  });

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Top Banner & Quick Ingest */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border-subtle">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-mono font-bold text-white tracking-wide">
              SECURITY OPERATIONS COMMAND CENTRE
            </h1>
            {metrics?.provenance && <DataProvenanceBadge provenance={metrics.provenance} size="sm" />}
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Continuous threat detection, autonomous correlation, and evidence-grounded AI investigation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-mono font-bold text-xs transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)]"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Ingest Security Log</span>
          </button>
        </div>
      </div>

      {/* Top Key Performance Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Active Incidents"
          value={metrics ? metrics.openIncidents : "..."}
          subValue="Prioritized by threat blast radius"
          trend={{ value: "+2 new in 1h", isPositive: false }}
          icon={<ShieldAlert className="w-5 h-5" />}
          accentColor="red"
          provenance={metrics?.provenance}
        />
        <MetricCard
          label="Critical Threats"
          value={metrics ? metrics.criticalAlerts : "..."}
          subValue="Immediate containment required"
          trend={{ value: "1 Active Exfiltration", isPositive: false }}
          icon={<Flame className="w-5 h-5" />}
          accentColor="red"
          provenance={metrics?.provenance}
        />
        <MetricCard
          label="Monitored Assets"
          value={metrics ? metrics.monitoredAssets : "..."}
          subValue="Tier 1 Domain & App Workloads"
          trend={{ value: "100% Agent Coverage", isPositive: true }}
          icon={<Server className="w-5 h-5" />}
          accentColor="cyan"
          provenance={metrics?.provenance}
        />
        <MetricCard
          label="Detection Coverage"
          value={metrics ? `${metrics.detectionCoveragePercent}%` : "..."}
          subValue="Mapped to MITRE ATT&CK Matrix"
          trend={{ value: "F1 Score: 1.00", isPositive: true }}
          icon={<Activity className="w-5 h-5" />}
          accentColor="indigo"
          provenance={metrics?.provenance}
        />
      </div>

      {/* Middle Grid: Telemetry Ingest & AI Architecture Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Ingestion & Telemetry Health */}
        <div className="p-5 rounded-xl bg-bg-surface1 border border-border-subtle backdrop-blur-md flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-bold uppercase text-slate-300">
                Log Ingestion Telemetry
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ACTIVE STREAM
              </span>
            </div>
            <div className="text-2xl font-bold font-mono text-white">
              {metrics ? metrics.eventsIngested24h.toLocaleString() : "..."}
              <span className="text-xs font-normal text-slate-400 font-mono ml-2">events (24h)</span>
            </div>
            <p className="text-xs font-mono text-slate-400 mt-2 leading-relaxed">
              Real-time normalization through Common Event Schema (CES). Supports Linux syslog, Windows Security XML/CSV, and Zeek Conn logs.
            </p>
          </div>

          <div className="pt-4 mt-4 border-t border-border-subtle flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">Mean Triage Latency:</span>
            <span className="text-cyan-400 font-bold">{metrics?.meanTimeToTriageMin} mins</span>
          </div>
        </div>

        {/* AI & Provider Operational Health */}
        <div className="p-5 rounded-xl bg-bg-surface1 border border-border-subtle backdrop-blur-md flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-bold uppercase text-slate-300">
                AI Investigation System
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                BHARATCODE QWEN
              </span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between p-2 rounded bg-bg-surface2/60 border border-border-subtle">
                <span className="text-slate-300">Model:</span>
                <span className="text-cyan-300 font-bold">qwen-3.8-27b</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-bg-surface2/60 border border-border-subtle">
                <span className="text-slate-300">Evidence Verifier:</span>
                <span className="text-emerald-400 font-bold">100% Strict Grounding</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-bg-surface2/60 border border-border-subtle">
                <span className="text-slate-300">Deterministic Engine:</span>
                <span className="text-amber-400 font-bold">Authoritative Gate</span>
              </div>
            </div>
          </div>

          <div className="pt-3 mt-3 border-t border-border-subtle flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Stateless API • Tool Calling Enabled</span>
            <span className="text-emerald-400">Online</span>
          </div>
        </div>

        {/* Quick Operational SLA & Correlation Status */}
        <div className="p-5 rounded-xl bg-bg-surface1 border border-border-subtle backdrop-blur-md flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-bold uppercase text-slate-300">
                Incident Correlation Engine
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                GRAPH-LINKED
              </span>
            </div>
            <p className="text-xs font-mono text-slate-400 leading-relaxed">
              Multi-entity graph correlation connects temporal events across shared users, hosts, and internal endpoints with anti-hub isolation safeguards.
            </p>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2 rounded bg-bg-surface2/40 border border-border-subtle">
                <div className="text-slate-400 text-[10px]">Max Incident Window</div>
                <div className="text-white font-bold">24 Hours</div>
              </div>
              <div className="p-2 rounded bg-bg-surface2/40 border border-border-subtle">
                <div className="text-slate-400 text-[10px]">Temporal Proximity</div>
                <div className="text-white font-bold">600 Seconds</div>
              </div>
            </div>
          </div>

          <div className="pt-3 mt-3 border-t border-border-subtle flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">Hub Node Isolation:</span>
            <span className="text-emerald-400 font-bold">Enforced</span>
          </div>
        </div>
      </div>

      {/* Correlated Incidents Table Section */}
      <div className="rounded-xl bg-bg-surface1 border border-border-subtle overflow-hidden shadow-card">
        {/* Table Header & Controls */}
        <div className="p-4 border-b border-border-subtle bg-bg-surface2/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider">
              Correlated Security Incidents
            </h3>
            <span className="px-2 py-0.5 text-xs font-mono rounded bg-bg-surface2 text-cyan-400 border border-border-subtle">
              {filteredIncidents.length} active
            </span>
          </div>

          {/* Severity Filter Pills */}
          <div className="flex items-center gap-1.5 bg-bg-surface1 p-1 rounded-lg border border-border-subtle text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-slate-500 ml-1.5" />
            {(["all", "critical", "high", "medium"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded capitalize transition-colors ${
                  severityFilter === s
                    ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Table Body */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-border-subtle bg-bg-surface2/20 text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title & Context</th>
                <th className="py-3 px-4">Involved Entities</th>
                <th className="py-3 px-4">Detections</th>
                <th className="py-3 px-4">Time Window</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-mono">
                    Loading telemetry incidents...
                  </td>
                </tr>
              ) : filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-mono">
                    No active incidents matching the selected filter.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => navigate(`/incidents/${inc.id}`)}
                    className="hover:bg-bg-hover cursor-pointer transition-colors group"
                  >
                    <td className="py-3.5 px-4 font-bold text-cyan-400 flex items-center gap-2">
                      <span>{inc.id}</span>
                      {inc.provenance && (
                        <span
                          className={`text-[9px] px-1 rounded ${
                            inc.provenance === "live_telemetry"
                              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                              : "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30"
                          }`}
                        >
                          {inc.provenance === "live_telemetry" ? "LIVE" : "DEMO"}
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={inc.severity} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 max-w-sm">
                      <div className="font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors line-clamp-1">
                        {inc.title}
                      </div>
                      <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                        {inc.description}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1">
                        {inc.entities.slice(0, 3).map((ent, idx) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.5 rounded bg-bg-surface2 text-slate-300 border border-border-subtle text-[10px]"
                          >
                            {ent.entity_value}
                          </span>
                        ))}
                        {inc.entities.length > 3 && (
                          <span className="text-[10px] text-slate-500 font-mono">
                            +{inc.entities.length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 font-bold">
                        {inc.detections_count || inc.entities.length}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      <div>{inc.first_seen.slice(11, 19)} UTC</div>
                      <div className="text-slate-500 text-[10px]">to {inc.last_seen.slice(11, 19)} UTC</div>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/incidents/${inc.id}`);
                        }}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-bg-surface2 hover:bg-cyan-500 hover:text-black border border-border-subtle group-hover:border-cyan-500/40 text-slate-300 text-xs font-mono font-medium transition-all"
                      >
                        <span>Investigate</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
