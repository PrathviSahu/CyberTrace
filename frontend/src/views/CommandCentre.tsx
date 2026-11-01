import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  UploadCloud,
  ChevronRight,
  RefreshCw,
  Search,
  ExternalLink,
  User,
  Globe,
  Radio,
  FileCheck2,
  Clock,
} from "lucide-react";
import { api } from "../services/api";
import { IncidentSummary, OverviewMetrics, Detection, CommonEvent } from "../types";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";

interface CommandCentreProps {
  onOpenUpload: () => void;
}

export const CommandCentre: React.FC<CommandCentreProps> = ({ onOpenUpload }) => {
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [recentEvents, setRecentEvents] = useState<CommonEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [selectedEvent, setSelectedEvent] = useState<CommonEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const loadData = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);

    try {
      const [m, incs, dets, evts] = await Promise.all([
        api.getOverviewMetrics(),
        api.getIncidents(),
        api.getDetections(100),
        api.getEvents(12),
      ]);
      setMetrics(m);
      setIncidents(incs);
      setDetections(dets);
      setRecentEvents(evts);
    } catch (err) {
      console.error("Failed to load command centre telemetry:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const filteredIncidents = incidents.filter((inc) => {
    if (severityFilter !== "all" && inc.severity !== severityFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const matchTitle = inc.title.toLowerCase().includes(q);
      const matchId = inc.id.toLowerCase().includes(q);
      const matchEntity = (inc.entities || []).some((e) =>
        e.entity_value.toLowerCase().includes(q)
      );
      if (!matchTitle && !matchId && !matchEntity) return false;
    }
    return true;
  });

  return (
    <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* A. Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Security Operations
            </h1>
            <DataProvenanceBadge
              provenance={metrics?.provenance || "observed_telemetry"}
              size="sm"
            />
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            Real-time incident correlation, telemetry ingestion buffer, and deterministic alert triage.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => loadData(true)}
            title="Refresh operational telemetry"
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/40 text-[#A0A7AE] hover:text-[#E9ECEF] text-xs font-medium transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-[#B58A61]" : ""}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] font-medium text-xs transition-colors shadow-sm cursor-pointer"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Ingest Telemetry</span>
          </button>
        </div>
      </div>

      {/* B. Metric Summary — Restrained Horizontal Aligned Strip */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-[#30363C] overflow-hidden shadow-card">
        {/* Metric 1 */}
        <div className="p-3.5 flex flex-col justify-between">
          <span className="text-xs text-[#A0A7AE] font-medium">Active Incidents</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-[#E9ECEF] tracking-tight font-sans">
              {metrics ? metrics.openIncidents : incidents.length}
            </span>
            {metrics && metrics.criticalAlerts > 0 ? (
              <span className="text-xs font-medium text-[#E06C68]">
                {metrics.criticalAlerts} Critical
              </span>
            ) : (
              <span className="text-xs text-[#737D87]">None Critical</span>
            )}
          </div>
          <span className="text-[11px] text-[#737D87] mt-0.5">
            Correlated attack trajectories
          </span>
        </div>

        {/* Metric 2 */}
        <div className="p-3.5 flex flex-col justify-between">
          <span className="text-xs text-[#A0A7AE] font-medium">Implicated Assets</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-[#E9ECEF] tracking-tight font-sans">
              {metrics ? metrics.monitoredAssets : "N/A"}
            </span>
            <span className="text-xs text-[#737D87]">Entities</span>
          </div>
          <span className="text-[11px] text-[#737D87] mt-0.5">
            Observed hostnames & IPs
          </span>
        </div>

        {/* Metric 3 */}
        <div className="p-3.5 flex flex-col justify-between">
          <span className="text-xs text-[#A0A7AE] font-medium">Telemetry Buffer</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-[#E9ECEF] tracking-tight font-sans">
              {metrics ? metrics.eventsIngestedSample : recentEvents.length}
            </span>
            <span className="text-xs text-[#737D87]">Loaded</span>
          </div>
          <span className="text-[11px] text-[#737D87] mt-0.5">
            Persisted CES event sample
          </span>
        </div>

        {/* Metric 4 */}
        <div className="p-3.5 flex flex-col justify-between">
          <span className="text-xs text-[#A0A7AE] font-medium">Active Detections</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-[#E9ECEF] tracking-tight font-sans">
              {detections.length}
            </span>
            <span className="text-xs font-medium text-[#76A58B]">Rules Fired</span>
          </div>
          <span className="text-[11px] text-[#737D87] mt-0.5">
            {detections.length >= 100 ? "Sample capped (100)" : "Deterministic rule matches"}
          </span>
        </div>
      </div>

      {/* C & D. Main Workspace Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        {/* Left Primary Column (8 Cols on XL, 12 on Tablet): Incident Queue & Recent Event Timeline */}
        <div className="xl:col-span-8 flex flex-col gap-5 min-w-0">
          {/* Section 1: Active Incident Queue — Content-Sized (No Forced Stretching) */}
          <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
            {/* Queue Header & Filters */}
            <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#E06C68]" />
                <span className="text-xs font-semibold text-[#E9ECEF]">
                  Active Incident Queue
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-[#1D2125] text-[#A0A7AE] border border-[#30363C] font-mono">
                  {filteredIncidents.length} of {incidents.length}
                </span>
              </div>

              <div className="flex items-center gap-2">
                {/* Search Bar */}
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#1D2125] border border-[#30363C] text-xs">
                  <Search className="w-3.5 h-3.5 text-[#737D87]" />
                  <input
                    type="text"
                    placeholder="Filter incidents or entities..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="bg-transparent text-[#E9ECEF] placeholder-[#737D87] outline-none w-36 sm:w-44 text-xs font-sans"
                  />
                </div>

                {/* Severity Filter */}
                <div className="flex items-center bg-[#1D2125] p-0.5 rounded-md border border-[#30363C] text-xs">
                  {(["all", "critical", "high", "medium"] as const).map((s) => (
                    <button
                      key={s}
                      onClick={() => setSeverityFilter(s)}
                      className={`px-2 py-0.5 rounded capitalize transition-colors cursor-pointer text-xs font-medium ${
                        severityFilter === s
                          ? "bg-[#24282C] text-[#E9ECEF]"
                          : "text-[#737D87] hover:text-[#E9ECEF]"
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Incident Table / List */}
            {loading ? (
              <div className="py-12 flex items-center justify-center text-xs text-[#737D87]">
                <RefreshCw className="w-4 h-4 animate-spin mr-2 text-[#B58A61]" />
                Loading correlated incident queue...
              </div>
            ) : filteredIncidents.length === 0 ? (
              <div className="py-10 text-center text-xs text-[#737D87]">
                No incidents match the active search filter.
              </div>
            ) : (
              <>
                {/* 1. Desktop 7-Column Table (Visible on xl and above >= 1280px) */}
                <div className="overflow-x-auto w-full hidden xl:block">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#30363C] bg-[#24282C]/50 text-[#737D87] text-[11px] font-medium">
                        <th className="py-2 px-2.5 whitespace-nowrap w-[90px]">Incident ID</th>
                        <th className="py-2 px-2 whitespace-nowrap w-[70px]">Severity</th>
                        <th className="py-2 px-2 min-w-[200px]">Incident Summary</th>
                        <th className="py-2 px-2 w-[130px]">Entities</th>
                        <th className="py-2 px-1 text-center whitespace-nowrap w-[45px]">Detections</th>
                        <th className="py-2 px-2 whitespace-nowrap w-[75px]">Status</th>
                        <th className="py-2 px-2.5 text-right whitespace-nowrap w-[85px]">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#30363C]">
                      {filteredIncidents.map((inc) => {
                        const entities = inc.entities || [];
                        const displayEntities = entities.slice(0, 2);
                        const remainingCount = entities.length - 2;
                        const allEntitiesTooltip = entities.map((e) => e.entity_value).join(", ");

                        return (
                          <tr
                            key={inc.id}
                            onClick={() => navigate(`/incidents/${inc.id}`)}
                            className="hover:bg-[#24282C]/50 cursor-pointer transition-colors group"
                          >
                            <td className="py-3 px-2.5 font-mono text-xs font-semibold text-[#B58A61] whitespace-nowrap">
                              {inc.id}
                            </td>

                            <td className="py-3 px-2 whitespace-nowrap">
                              <SeverityBadge severity={inc.severity} size="sm" />
                            </td>

                            <td className="py-3 px-2">
                              <div
                                className="font-medium text-sm text-[#E9ECEF] group-hover:text-[#B58A61] transition-colors line-clamp-2 leading-snug"
                                title={inc.title}
                              >
                                {inc.title}
                              </div>
                              <div className="text-[11px] font-mono text-[#737D87] mt-0.5">
                                Observed: {inc.first_seen.replace("T", " ").slice(0, 19)} UTC
                              </div>
                            </td>

                            <td className="py-3 px-2">
                              <div className="flex items-center gap-1 flex-wrap" title={allEntitiesTooltip}>
                                {displayEntities.map((ent, idx) => (
                                  <span
                                    key={idx}
                                    className="px-1.5 py-0.5 rounded bg-[#24282C] border border-[#30363C] text-[10px] text-[#A0A7AE] font-mono truncate max-w-[85px]"
                                  >
                                    {ent.entity_value}
                                  </span>
                                ))}
                                {remainingCount > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-[#24282C] border border-[#30363C] text-[10px] text-[#737D87] font-mono">
                                    +{remainingCount}
                                  </span>
                                )}
                              </div>
                            </td>

                            <td className="py-3 px-1 text-center whitespace-nowrap">
                              <span className="px-1.5 py-0.5 rounded bg-[#24282C] text-[#E9ECEF] border border-[#30363C] text-xs font-mono font-medium">
                                {inc.detections_count ?? 1}
                              </span>
                            </td>

                            <td className="py-3 px-2 whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded text-[11px] font-medium border ${
                                  inc.status === "open"
                                    ? "bg-[#E06C68]/12 text-[#E06C68] border-[#E06C68]/25"
                                    : inc.status === "in_progress"
                                    ? "bg-[#D99A54]/12 text-[#D99A54] border-[#D99A54]/25"
                                    : inc.status === "contained"
                                    ? "bg-[#B58A61]/12 text-[#B58A61] border-[#B58A61]/25"
                                    : "bg-[#76A58B]/12 text-[#76A58B] border-[#76A58B]/25"
                                }`}
                              >
                                {inc.status === "open"
                                  ? "Open"
                                  : inc.status === "in_progress"
                                  ? "In Progress"
                                  : inc.status === "contained"
                                  ? "Contained"
                                  : "Resolved"}
                              </span>
                            </td>

                            <td className="py-3 px-2.5 text-right whitespace-nowrap">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  navigate(`/incidents/${inc.id}`);
                                }}
                                className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-medium transition-colors cursor-pointer"
                              >
                                <span>Investigate</span>
                                <ChevronRight className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* 2. Tablet & Mobile Stacked Incident Layout (Visible below xl < 1280px) */}
                <div className="divide-y divide-[#30363C] block xl:hidden">
                  {filteredIncidents.map((inc) => {
                    const entities = inc.entities || [];
                    const displayEntities = entities.slice(0, 3);
                    const remainingCount = entities.length - 3;

                    return (
                      <div
                        key={inc.id}
                        onClick={() => navigate(`/incidents/${inc.id}`)}
                        className="p-3.5 hover:bg-[#24282C]/50 cursor-pointer transition-colors space-y-2.5"
                      >
                        {/* Top row: ID, Severity, Status, and Investigate Action */}
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-semibold text-[#B58A61]">
                              {inc.id}
                            </span>
                            <SeverityBadge severity={inc.severity} size="sm" />
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-medium border ${
                                inc.status === "open"
                                  ? "bg-[#E06C68]/12 text-[#E06C68] border-[#E06C68]/25"
                                  : inc.status === "in_progress"
                                  ? "bg-[#D99A54]/12 text-[#D99A54] border-[#D99A54]/25"
                                  : inc.status === "contained"
                                  ? "bg-[#B58A61]/12 text-[#B58A61] border-[#B58A61]/25"
                                  : "bg-[#76A58B]/12 text-[#76A58B] border-[#76A58B]/25"
                              }`}
                            >
                              {inc.status === "open"
                                ? "Open"
                                : inc.status === "in_progress"
                                ? "In Progress"
                                : inc.status === "contained"
                                ? "Contained"
                                : "Resolved"}
                            </span>
                          </div>

                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/incidents/${inc.id}`);
                            }}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-[#24282C] hover:bg-[#2B2722] text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/50 text-xs font-medium transition-colors cursor-pointer shrink-0"
                          >
                            <span>Investigate</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>

                        {/* Middle row: Summary with 2-line clamp */}
                        <div>
                          <div
                            className="font-medium text-xs sm:text-sm text-[#E9ECEF] line-clamp-2 leading-snug"
                            title={inc.title}
                          >
                            {inc.title}
                          </div>
                          <div className="text-[11px] font-mono text-[#737D87] mt-0.5">
                            Observed: {inc.first_seen.replace("T", " ").slice(0, 19)} UTC
                          </div>
                        </div>

                        {/* Bottom row: Entities and Detections Count */}
                        <div className="flex items-center justify-between text-xs pt-1 border-t border-[#30363C]/40">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-[11px] text-[#737D87]">Entities:</span>
                            {displayEntities.map((ent, idx) => (
                              <span
                                key={idx}
                                className="px-1.5 py-0.5 rounded bg-[#24282C] border border-[#30363C] text-[10px] text-[#A0A7AE] font-mono truncate max-w-[110px]"
                              >
                                {ent.entity_value}
                              </span>
                            ))}
                            {remainingCount > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-[#24282C] border border-[#30363C] text-[10px] text-[#737D87] font-mono">
                                +{remainingCount}
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-1.5 shrink-0 text-[11px] text-[#737D87]">
                            <span>Detections:</span>
                            <span className="px-1.5 py-0.5 rounded bg-[#24282C] text-[#E9ECEF] border border-[#30363C] font-mono font-medium">
                              {inc.detections_count ?? 1}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>

          {/* Section 2: Recent Persisted Telemetry Events Timeline (Ground-Truth Data) */}
          <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
            <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#B58A61]" />
                <span className="text-xs font-semibold text-[#E9ECEF]">
                  Recent Observed Events (Persisted Buffer)
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-[#1D2125] text-[#A0A7AE] border border-[#30363C] font-mono">
                  {recentEvents.length} samples
                </span>
              </div>
              <button
                onClick={() => navigate("/hunting")}
                className="text-xs text-[#B58A61] hover:text-[#C69A70] transition-colors flex items-center gap-1 cursor-pointer font-medium"
              >
                <span>Threat Hunting</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>

            {recentEvents.length === 0 ? (
              <div className="py-10 text-center text-xs text-[#737D87]">
                No live telemetry events currently loaded.
              </div>
            ) : (
              <>
                {/* 1. Desktop Events Table (>= 1280px) */}
                <div className="overflow-x-auto w-full hidden xl:block">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#30363C] bg-[#24282C]/50 text-[#737D87] text-[11px] font-medium">
                        <th className="py-2 px-2.5 whitespace-nowrap w-[130px]">Timestamp (UTC)</th>
                        <th className="py-2 px-2 whitespace-nowrap w-[120px]">Event Category</th>
                        <th className="py-2 px-2 min-w-[130px]">Action</th>
                        <th className="py-2 px-2 min-w-[110px]">Entity / Host</th>
                        <th className="py-2 px-2 whitespace-nowrap w-[100px]">Source IP</th>
                        <th className="py-2 px-2 whitespace-nowrap w-[70px]">Severity</th>
                        <th className="py-2 px-2.5 text-right whitespace-nowrap w-[60px]">Detail</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#30363C]">
                      {recentEvents.slice(0, 7).map((evt) => {
                        const entityName = evt.username || evt.hostname || "—";
                        return (
                          <tr
                            key={evt.id}
                            onClick={() => {
                              setSelectedEvent(evt);
                              setDrawerOpen(true);
                            }}
                            className="hover:bg-[#24282C]/50 cursor-pointer transition-colors group"
                          >
                            <td className="py-2.5 px-2.5 font-mono text-[11px] text-[#737D87] whitespace-nowrap">
                              {evt.timestamp.replace("T", " ").slice(11, 19)}
                            </td>
                            <td className="py-2.5 px-2 text-[#A0A7AE] whitespace-nowrap font-medium text-xs">
                              {evt.category.replace(/_/g, " ")}
                            </td>
                            <td className="py-2.5 px-2 font-mono text-xs text-[#E9ECEF] group-hover:text-[#B58A61] transition-colors">
                              {evt.action}
                            </td>
                            <td className="py-2.5 px-2 text-xs">
                              <span className="font-mono text-[#E9ECEF]">{entityName}</span>
                            </td>
                            <td className="py-2.5 px-2 font-mono text-xs text-[#A0A7AE] whitespace-nowrap">
                              {evt.source_ip || "—"}
                            </td>
                            <td className="py-2.5 px-2 whitespace-nowrap">
                              <SeverityBadge severity={evt.severity || "informational"} size="sm" />
                            </td>
                            <td className="py-2.5 px-2.5 text-right whitespace-nowrap">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedEvent(evt);
                                  setDrawerOpen(true);
                                }}
                                className="px-2 py-0.5 rounded bg-[#24282C] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] text-[11px] font-mono transition-colors"
                              >
                                JSON
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* 2. Tablet & Mobile Stacked Events List (< 1280px) */}
                <div className="divide-y divide-[#30363C] block xl:hidden">
                  {recentEvents.slice(0, 7).map((evt) => {
                    const entityName = evt.username || evt.hostname || "—";
                    return (
                      <div
                        key={evt.id}
                        onClick={() => {
                          setSelectedEvent(evt);
                          setDrawerOpen(true);
                        }}
                        className="p-3 hover:bg-[#24282C]/50 cursor-pointer transition-colors space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-semibold text-[#E9ECEF]">{evt.action}</span>
                            <span className="text-[10px] uppercase text-[#737D87] font-mono">({evt.category})</span>
                          </div>
                          <SeverityBadge severity={evt.severity || "informational"} size="sm" />
                        </div>

                        <div className="flex items-center justify-between text-xs text-[#A0A7AE]">
                          <div className="flex items-center gap-2 font-mono text-[11px]">
                            <span className="text-[#E9ECEF]">{entityName}</span>
                            {evt.source_ip && (
                              <>
                                <span className="text-[#737D87]">•</span>
                                <span>{evt.source_ip}</span>
                              </>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[11px] text-[#737D87]">
                              {evt.timestamp.replace("T", " ").slice(11, 19)} UTC
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedEvent(evt);
                                setDrawerOpen(true);
                              }}
                              className="px-2 py-0.5 rounded bg-[#24282C] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] text-[10px] font-mono"
                            >
                              JSON
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right Secondary Column (4 Cols on XL, 12 on Tablet): Detection Activity & CES Health */}
        <div className="xl:col-span-4 flex flex-col gap-5 min-w-0">
          {/* Section 1: Recent Detection Activity */}
          <div className="rounded-lg bg-[#1D2125] border border-[#30363C] flex flex-col overflow-hidden shadow-card">
            <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Radio className="w-3.5 h-3.5 text-[#B58A61]" />
                <span className="text-xs font-semibold text-[#E9ECEF]">
                  Detection Activity
                </span>
              </div>
              <button
                onClick={() => navigate("/alerts")}
                className="text-xs text-[#B58A61] hover:text-[#C69A70] transition-colors flex items-center gap-1 cursor-pointer font-medium"
              >
                <span>View all ({detections.length})</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            </div>

            <div className="p-2.5 space-y-2 overflow-y-auto max-h-[380px]">
              {detections.length === 0 ? (
                <div className="py-10 text-center text-xs text-[#737D87]">
                  No detection firings recorded.
                </div>
              ) : (
                detections.slice(0, 5).map((det) => (
                  <div
                    key={det.id}
                    onClick={() => navigate("/alerts")}
                    className="p-2.5 rounded-md bg-[#24282C]/60 border border-[#30363C] hover:border-[#B58A61]/40 cursor-pointer transition-colors space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-medium text-[#B58A61]">
                          {det.rule_id}
                        </span>
                        <SeverityBadge severity={det.severity} size="sm" />
                      </div>
                      <span className="text-[11px] font-mono text-[#737D87]">
                        {det.detected_at?.slice(11, 19)} UTC
                      </span>
                    </div>

                    <div className="text-xs font-medium text-[#E9ECEF] truncate">
                      {det.rule_name}
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-[#A0A7AE]">
                      <span className="flex items-center gap-1.5 truncate max-w-[170px]">
                        {det.entity_type === "user" ? (
                          <User className="w-3 h-3 text-[#B58A61] shrink-0" />
                        ) : (
                          <Globe className="w-3 h-3 text-[#737D87] shrink-0" />
                        )}
                        <span className="text-[#E9ECEF] font-mono truncate">
                          {det.entity_value}
                        </span>
                      </span>
                      <span className="text-[#737D87] text-[11px] font-mono shrink-0">
                        {det.triggering_event_ids?.length || 1} event(s)
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Section 2: Ingestion Format & CES Telemetry Health */}
          <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-3.5 space-y-2.5 shadow-card">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#E9ECEF] flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-[#76A58B]" />
                CES Ingestion Standards
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-md bg-[#76A58B]/12 text-[#76A58B] border border-[#76A58B]/25 font-medium">
                Validated
              </span>
            </div>

            <div className="space-y-1 text-xs">
              <div className="flex justify-between items-center p-2 rounded bg-[#24282C] border border-[#30363C]">
                <span className="text-[#A0A7AE]">Linux Syslog / Auth</span>
                <span className="text-[#76A58B] font-medium text-[11px]">SSH, Sudo Auth</span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-[#24282C] border border-[#30363C]">
                <span className="text-[#A0A7AE]">Windows Security Events</span>
                <span className="text-[#76A58B] font-medium text-[11px]">XML/CSV 4624/4625</span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-[#24282C] border border-[#30363C]">
                <span className="text-[#A0A7AE]">Zeek Network Connection</span>
                <span className="text-[#76A58B] font-medium text-[11px]">conn.log TSV</span>
              </div>
            </div>

            <div className="pt-2 border-t border-[#30363C] flex items-center justify-between text-xs text-[#737D87]">
              <span>Correlation Engine:</span>
              <span className="text-[#E9ECEF] font-medium font-mono text-[11px]">BharatCode Qwen 27B</span>
            </div>
          </div>
        </div>
      </div>

      {/* Slide-over Evidence Drawer for Event Details */}
      <EvidenceDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        event={selectedEvent}
      />
    </div>
  );
};
