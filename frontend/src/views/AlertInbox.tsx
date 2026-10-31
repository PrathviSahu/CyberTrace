import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  Crosshair,
  ArrowRight,
} from "lucide-react";
import { Detection, CommonEvent } from "../types";
import { DEMO_INCIDENT_DETAIL_INC001 } from "../services/demoData";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { EvidenceCitation } from "../components/common/EvidenceCitation";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";

export const AlertInbox: React.FC = () => {
  const navigate = useNavigate();
  const [detections] = useState<Detection[]>(DEMO_INCIDENT_DETAIL_INC001.detections);
  const [events] = useState<CommonEvent[]>(DEMO_INCIDENT_DETAIL_INC001.events);
  const [selectedEvent, setSelectedEvent] = useState<CommonEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");

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

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border-subtle">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-mono font-bold text-white tracking-wide">
              DETECTION ALERT INBOX
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
              DETERMINISTIC ENGINE
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Individual rule firings evaluated against standardized Common Event Schema (CES) telemetry.
          </p>
        </div>

        {/* Search & Filter */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-surface1 border border-border-subtle text-xs font-mono">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by rule, entity, MITRE..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-transparent text-white placeholder-slate-500 outline-none w-48"
            />
          </div>

          <div className="flex items-center gap-1 bg-bg-surface1 p-1 rounded-lg border border-border-subtle text-xs font-mono">
            {(["all", "critical", "high", "medium"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSelectedSeverity(s)}
                className={`px-2 py-1 rounded capitalize transition-colors ${
                  selectedSeverity === s
                    ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Alert Stream Grid */}
      <div className="space-y-3">
        {filtered.map((det) => (
          <div
            key={det.id}
            className="p-4 rounded-xl bg-bg-surface1 border border-border-subtle hover:border-cyan-500/40 transition-all shadow-card space-y-3"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-bg-surface2 border border-border-subtle text-cyan-400">
                  <Crosshair className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{det.rule_id}</span>
                    <span className="font-mono text-sm font-semibold text-white">{det.rule_name}</span>
                    <SeverityBadge severity={det.severity} size="sm" />
                  </div>
                  <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 mt-1">
                    <span>Target: <strong className="text-white">{det.entity_value}</strong> ({det.entity_type})</span>
                    <span>•</span>
                    <span>Detected: {det.detected_at}</span>
                  </div>
                </div>
              </div>

              <button
                onClick={() => navigate("/incidents/INC-001")}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-bg-surface2 hover:bg-cyan-500 hover:text-black text-xs font-mono text-slate-300 transition-colors border border-border-subtle"
              >
                <span>View Incident</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <p className="text-xs font-mono text-slate-300 leading-relaxed bg-bg-surface2/40 p-3 rounded-lg border border-border-subtle">
              {det.explanation}
            </p>

            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-2">
                {det.mitre_tactic && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/30">
                    MITRE: {det.mitre_tactic} ({det.mitre_technique})
                  </span>
                )}
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-[10px] font-mono text-slate-500">Triggering Event:</span>
                {(det.triggering_event_ids || []).map((eid) => (
                  <EvidenceCitation key={eid} eventId={eid} onClick={handleOpenCitation} />
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      <EvidenceDrawer
        event={selectedEvent}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />
    </div>
  );
};
