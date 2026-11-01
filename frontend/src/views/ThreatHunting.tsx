import React, { useState, useEffect } from "react";
import {
  Play,
  Terminal,
  RefreshCw,
} from "lucide-react";
import { CommonEvent } from "../types";
import { api } from "../services/api";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";

export const ThreatHunting: React.FC = () => {
  const [query, setQuery] = useState('username == "svc_deploy"');
  const [allEvents, setAllEvents] = useState<CommonEvent[]>([]);
  const [filteredEvents, setFilteredEvents] = useState<CommonEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<CommonEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const loadEvents = async () => {
    setLoading(true);
    try {
      const data = await api.getEvents(200);
      setAllEvents(data);
      runHuntFilter(query, data);
    } catch (err) {
      console.error("Failed to load hunting events:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, []);

  const runHuntFilter = (q: string, list: CommonEvent[]) => {
    const trimmed = q.trim();
    if (!trimmed) {
      setFilteredEvents(list);
      return;
    }

    const lowerQ = trimmed.toLowerCase();
    const matches = list.filter((e) => {
      // Direct field heuristics or text match
      if (lowerQ.includes("bytes_out >") || lowerQ.includes("bytes_sent >")) {
        const threshold = parseInt(lowerQ.split(">")[1]?.trim() || "0", 10);
        return (e.bytes_out || 0) > threshold;
      }
      if (lowerQ.includes("svc_deploy")) {
        return (e.username || "").toLowerCase() === "svc_deploy";
      }
      if (lowerQ.includes("logon_failure")) {
        return (e.action || "").toLowerCase().includes("failure") || (e.action || "").toLowerCase().includes("denied");
      }
      if (lowerQ.includes("authentication")) {
        return (e.category || "").toLowerCase() === "authentication";
      }
      return (
        (e.username && e.username.toLowerCase().includes(lowerQ)) ||
        (e.hostname && e.hostname.toLowerCase().includes(lowerQ)) ||
        (e.source_ip && e.source_ip.includes(lowerQ)) ||
        (e.destination_ip && e.destination_ip.includes(lowerQ)) ||
        (e.action && e.action.toLowerCase().includes(lowerQ)) ||
        (e.source_type && e.source_type.toLowerCase().includes(lowerQ))
      );
    });

    setFilteredEvents(matches);
  };

  const handleExecute = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    runHuntFilter(query, allEvents);
  };

  const presets = [
    {
      name: "High-Volume Data Egress",
      q: "bytes_out > 10000000",
      description: "Find sessions with outbound data exceeding 10MB",
    },
    {
      name: "Authentication Failures by User",
      q: 'category == "authentication" AND action == "logon_failure"',
      description: "Detect brute-force or credential spray patterns",
    },
    {
      name: "Service Account Remote Access",
      q: 'username == "svc_deploy"',
      description: "Audit automated account interactive sessions",
    },
    {
      name: "All Telemetry Events",
      q: "",
      description: "Show all normalized CES events in dataset",
    },
  ];

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border-subtle">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-mono font-bold text-white tracking-wide">
              THREAT HUNTING STUDIO
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              CES QUERY ENGINE
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Hypothesis-driven search across normalized Common Event Schema telemetry.
          </p>
        </div>

        <button
          onClick={loadEvents}
          title="Refresh telemetry"
          className="p-2 rounded-lg bg-bg-surface1 border border-border-subtle text-slate-400 hover:text-white hover:border-cyan-500/40 transition-all self-start md:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
        </button>
      </div>

      {/* Query Bar */}
      <form onSubmit={handleExecute} className="p-4 rounded-xl bg-bg-surface1 border border-border-subtle space-y-3 shadow-card">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-cyan-400 shrink-0" />
          <div className="flex-1 flex items-center bg-black/40 border border-border-subtle rounded-lg px-3 py-2 font-mono text-xs text-white">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-transparent outline-none text-cyan-300 font-bold"
              placeholder='e.g. username == "svc_deploy" AND bytes_out > 10000000'
            />
          </div>
          <button
            type="submit"
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-mono font-bold transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)]"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Execute Hunt</span>
          </button>
        </div>

        {/* Preset Query Badges */}
        <div className="flex items-center gap-2 flex-wrap pt-1">
          <span className="text-[11px] font-mono text-slate-500">Preset Scenarios:</span>
          {presets.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setQuery(p.q);
                runHuntFilter(p.q, allEvents);
              }}
              className="px-2.5 py-1 rounded-md bg-bg-surface2 hover:bg-bg-hover text-[11px] font-mono text-slate-300 border border-border-subtle hover:border-cyan-500/30 transition-colors"
            >
              {p.name}
            </button>
          ))}
        </div>
      </form>

      {/* Results Table */}
      <div className="rounded-xl bg-bg-surface1 border border-border-subtle overflow-hidden shadow-card">
        <div className="p-4 border-b border-border-subtle bg-bg-surface2/40 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="font-bold text-white uppercase">Query Matches</span>
            <span className="px-2 py-0.5 rounded bg-bg-surface1 text-cyan-400 border border-border-subtle">
              {filteredEvents.length} Events Located
            </span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Click any row to open the complete Evidence Drawer
          </span>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
            <div className="flex items-center justify-center py-16 text-slate-400 font-mono text-xs">
              <RefreshCw className="w-4 h-4 animate-spin mr-2 text-cyan-400" />
              Loading telemetry stream...
            </div>
          ) : filteredEvents.length === 0 ? (
            <div className="py-16 text-center text-slate-500 font-mono text-xs">
              No security events match the specified hunt filter.
            </div>
          ) : (
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-surface2/20 text-slate-400 uppercase text-[10px] tracking-wider">
                  <th className="py-3 px-4">Event ID</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Source Type</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Host</th>
                  <th className="py-3 px-4">Source IP → Dest IP</th>
                  <th className="py-3 px-4 text-right">Bytes Out</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {filteredEvents.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => {
                      setSelectedEvent(evt);
                      setDrawerOpen(true);
                    }}
                    className="hover:bg-bg-hover cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-bold text-cyan-400">{evt.id}</td>
                    <td className="py-3 px-4 text-slate-300">
                      {evt.timestamp ? new Date(evt.timestamp).toISOString().replace("T", " ").slice(0, 19) : "—"}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{evt.source_type}</td>
                    <td className="py-3 px-4 text-slate-200 capitalize">
                      {evt.action ? evt.action.replace("_", " ") : "—"}
                    </td>
                    <td className="py-3 px-4 text-cyan-300">{evt.username || "—"}</td>
                    <td className="py-3 px-4 text-slate-300">{evt.hostname || "—"}</td>
                    <td className="py-3 px-4 text-slate-300">
                      {evt.source_ip || "—"} → {evt.destination_ip || "—"}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {evt.bytes_out ? (
                        <span className="text-red-400 font-bold">
                          {(evt.bytes_out / 1024 / 1024).toFixed(1)} MB
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <EvidenceDrawer
        event={selectedEvent}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />
    </div>
  );
};
