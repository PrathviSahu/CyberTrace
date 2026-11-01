import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  Crosshair,
  RefreshCw,
  User,
  Globe,
  Server,
  ChevronRight,
} from "lucide-react";
import { Detection, CommonEvent } from "../types";
import { api } from "../services/api";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { EvidenceCitation } from "../components/common/EvidenceCitation";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";

export const AlertInbox: React.FC = () => {
  const navigate = useNavigate();
  const [detections, setDetections] = useState<Detection[]>([]);
  const [events, setEvents] = useState<CommonEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<CommonEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");

  const loadAlerts = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);

    try {
      const [dets, evts] = await Promise.all([api.getDetections(), api.getEvents()]);
      setDetections(dets);
      setEvents(evts);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const handleOpenCitation = (eid: string) => {
    const found = events.find((e) => e.id === eid);
    if (found) {
      setSelectedEvent(found);
      setDrawerOpen(true);
    }
  };

  const filtered = detections.filter((d) => {
    if (selectedSeverity !== "all" && d.severity !== selectedSeverity) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        d.rule_id.toLowerCase().includes(q) ||
        d.rule_name.toLowerCase().includes(q) ||
        d.entity_value.toLowerCase().includes(q) ||
        d.explanation.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const counts = {
    all: detections.length,
    critical: detections.filter((d) => d.severity === "critical").length,
    high: detections.filter((d) => d.severity === "high").length,
    medium: detections.filter((d) => d.severity === "medium").length,
  };

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Alert Inbox
            </h1>
            <span className="text-[11px] px-2 py-0.5 rounded-md bg-[#24282C] text-[#A0A7AE] border border-[#30363C] font-medium">
              Deterministic Evaluation
            </span>
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            High-density triage of individual rule firings against normalized Common Event Schema (CES) telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Search Box */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#1D2125] border border-[#30363C] text-xs">
            <Search className="w-3.5 h-3.5 text-[#737D87]" />
            <input
              type="text"
              placeholder="Search rule, entity, text..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-transparent text-[#E9ECEF] placeholder-[#737D87] outline-none w-44 text-xs font-sans"
            />
          </div>

          {/* Severity Pills */}
          <div className="flex items-center bg-[#1D2125] p-0.5 rounded-md border border-[#30363C] text-xs">
            {(["all", "critical", "high", "medium"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSelectedSeverity(s)}
                className={`px-2 py-0.5 rounded capitalize transition-colors text-xs font-medium cursor-pointer ${
                  selectedSeverity === s
                    ? "bg-[#24282C] text-[#E9ECEF]"
                    : "text-[#737D87] hover:text-[#E9ECEF]"
                }`}
              >
                {s} ({counts[s]})
              </button>
            ))}
          </div>

          {/* Refresh */}
          <button
            onClick={() => loadAlerts(true)}
            title="Refresh alerts"
            disabled={refreshing}
            className="p-1.5 rounded-md bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/40 text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-[#B58A61]" : ""}`} />
          </button>
        </div>
      </div>

      {/* Analytical Data Grid */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
        <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-[#B58A61]" />
            <span className="text-xs font-semibold text-[#E9ECEF]">
              Alert Stream
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[#1D2125] text-[#A0A7AE] border border-[#30363C]">
              {filtered.length} of {detections.length}
            </span>
          </div>
          <span className="text-[11px] text-[#737D87]">
            Click row to view alert explanation & evidence
          </span>
        </div>

        {loading ? (
          <div className="py-24 flex items-center justify-center text-xs text-[#737D87]">
            <RefreshCw className="w-4 h-4 animate-spin mr-2 text-[#B58A61]" />
            Loading detection alert stream...
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-20 text-center text-xs text-[#737D87]">
            No detection alerts match the current filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#30363C] bg-[#24282C]/50 text-[#737D87] text-[11px] font-medium">
                  <th className="py-2.5 px-3.5 whitespace-nowrap">Severity</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Rule ID</th>
                  <th className="py-2.5 px-3 min-w-[260px]">Rule Title</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Target Entity</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Detected At (UTC)</th>
                  <th className="py-2.5 px-3 min-w-[140px]">Evidence Citations</th>
                  <th className="py-2.5 px-3.5 text-right whitespace-nowrap">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#30363C]">
                {filtered.map((det) => (
                  <tr
                    key={det.id}
                    onClick={() => {
                      if (det.triggering_event_ids && det.triggering_event_ids.length > 0) {
                        handleOpenCitation(det.triggering_event_ids[0]);
                      }
                    }}
                    className="hover:bg-[#24282C]/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 px-3.5 whitespace-nowrap">
                      <SeverityBadge severity={det.severity} size="sm" />
                    </td>
                    <td className="py-3 px-3 font-mono text-xs font-semibold text-[#B58A61] whitespace-nowrap">
                      {det.rule_id}
                    </td>
                    <td className="py-3 px-3 min-w-[260px]">
                      <div className="font-medium text-sm text-[#E9ECEF] group-hover:text-[#B58A61] transition-colors">
                        {det.rule_name}
                      </div>
                      <div className="text-[11px] text-[#737D87] truncate max-w-md mt-0.5">
                        {det.explanation}
                      </div>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        {det.entity_type === "user" ? (
                          <User className="w-3.5 h-3.5 text-[#B58A61]" />
                        ) : det.entity_type === "ip" ? (
                          <Globe className="w-3.5 h-3.5 text-[#737D87]" />
                        ) : (
                          <Server className="w-3.5 h-3.5 text-[#737D87]" />
                        )}
                        <span className="text-[#E9ECEF] font-mono text-xs">{det.entity_value}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#24282C] text-[#737D87] border border-[#30363C]">
                          {det.entity_type}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] text-[#A0A7AE] whitespace-nowrap">
                      {det.detected_at?.replace("T", " ").slice(0, 19)}
                    </td>
                    <td className="py-3 px-3 min-w-[140px]">
                      <div
                        className="flex items-center gap-1 flex-wrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {(det.triggering_event_ids || []).map((eid) => (
                          <EvidenceCitation
                            key={eid}
                            eventId={eid}
                            onClick={handleOpenCitation}
                          />
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-3.5 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate("/incidents/INC-001");
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-medium transition-colors cursor-pointer"
                      >
                        <span>Workspace</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <EvidenceDrawer
        event={selectedEvent}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />
    </div>
  );
};
