import React, { useState, useEffect } from "react";
import {
  Play,
  Terminal,
  RefreshCw,
  Info,
  Database,
} from "lucide-react";
import { CommonEvent } from "../types";
import { api } from "../services/api";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";

export const ThreatHunting: React.FC = () => {
  const [query, setQuery] = useState('username == "svc_deploy"');
  const [allEvents, setAllEvents] = useState<CommonEvent[]>([]);
  const [filteredEvents, setFilteredEvents] = useState<CommonEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<CommonEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Structured filters
  const [filterUser, setFilterUser] = useState("");
  const [filterHost, setFilterHost] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterCategory, setFilterCategory] = useState("");

  const loadEvents = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);

    try {
      const data = await api.getEvents(200);
      setAllEvents(data);
      runHuntFilter(query, data, filterUser, filterHost, filterAction, filterCategory);
    } catch (err) {
      console.error("Failed to load hunting events:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, []);

  const runHuntFilter = (
    q: string,
    list: CommonEvent[],
    u = filterUser,
    h = filterHost,
    a = filterAction,
    c = filterCategory
  ) => {
    let result = list;

    // Structured field filters
    if (u) result = result.filter((e) => (e.username || "").toLowerCase().includes(u.toLowerCase()));
    if (h) result = result.filter((e) => (e.hostname || "").toLowerCase().includes(h.toLowerCase()));
    if (a) result = result.filter((e) => (e.action || "").toLowerCase().includes(a.toLowerCase()));
    if (c) result = result.filter((e) => (e.category || "").toLowerCase().includes(c.toLowerCase()));

    // Free query text heuristics
    const trimmed = q.trim();
    if (trimmed) {
      const lowerQ = trimmed.toLowerCase();
      result = result.filter((e) => {
        if (lowerQ.includes("bytes_out >") || lowerQ.includes("bytes_sent >")) {
          const threshold = parseInt(lowerQ.split(">")[1]?.trim() || "0", 10);
          return (e.bytes_out || 0) > threshold;
        }
        if (lowerQ.includes("svc_deploy")) {
          return (e.username || "").toLowerCase() === "svc_deploy";
        }
        if (lowerQ.includes("logon_failure")) {
          return (
            (e.action || "").toLowerCase().includes("failure") ||
            (e.action || "").toLowerCase().includes("denied")
          );
        }
        if (lowerQ.includes("privilege_elevation")) {
          return (e.action || "").toLowerCase().includes("elevation") || (e.action || "").toLowerCase().includes("sudo");
        }
        return (
          (e.username && e.username.toLowerCase().includes(lowerQ)) ||
          (e.hostname && e.hostname.toLowerCase().includes(lowerQ)) ||
          (e.source_ip && e.source_ip.includes(lowerQ)) ||
          (e.destination_ip && e.destination_ip.includes(lowerQ)) ||
          (e.action && e.action.toLowerCase().includes(lowerQ)) ||
          (e.category && e.category.toLowerCase().includes(lowerQ))
        );
      });
    }

    setFilteredEvents(result);
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
      name: "Authentication Failures",
      q: "logon_failure",
      description: "Detect brute-force or credential spray patterns",
    },
    {
      name: "Service Account Remote Access",
      q: "svc_deploy",
      description: "Audit automated account interactive sessions",
    },
    {
      name: "Privilege Elevation Commands",
      q: "privilege_elevation",
      description: "Detect sudo / root elevation activity",
    },
    {
      name: "All Telemetry Events",
      q: "",
      description: "Show all normalized CES events in buffer",
    },
  ];

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Threat Hunting Studio
            </h1>
            <span className="text-[11px] px-2 py-0.5 rounded-md bg-[#24282C] text-[#A0A7AE] border border-[#30363C] font-medium">
              Buffer Filter (Phase 6.1 Baseline)
            </span>
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            Hypothesis-driven threat hunting across the currently ingested Common Event Schema (CES) telemetry pool.
          </p>
        </div>

        <button
          onClick={() => loadEvents(true)}
          title="Refresh telemetry"
          disabled={refreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/40 text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer text-xs font-medium"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-[#B58A61]" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Honest Architectural Disclosure Banner */}
      <div className="p-4 rounded-lg bg-[#1D2125] border border-[#30363C] flex items-start gap-3 text-xs text-[#A0A7AE] shadow-card">
        <Info className="w-5 h-5 text-[#B58A61] shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <div className="font-semibold text-[#E9ECEF]">
            Operational Telemetry Buffer Filter — Phase 6.1 Baseline
          </div>
          <p className="text-xs text-[#737D87] leading-relaxed">
            Current queries execute over the ingested in-memory telemetry buffer ({allEvents.length} events loaded). Server-side cross-table query execution, persistent indices, and full composite expression parsing are scheduled for the Phase 6.2 Query Engine architecture.
          </p>
        </div>
      </div>

      {/* Query Bar & Presets */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-4 space-y-3.5 shadow-card">
        <form onSubmit={handleExecute} className="space-y-3">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-4 h-4 text-[#B58A61] shrink-0" />
            <div className="flex-1 flex items-center bg-[#24282C] border border-[#30363C] rounded-md px-3 py-2 font-mono text-xs text-[#E9ECEF]">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full bg-transparent outline-none text-[#E9ECEF] font-medium placeholder-[#737D87]"
                placeholder='e.g. username == "svc_deploy" or bytes_out > 10000000'
              />
            </div>
            <button
              type="submit"
              className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] text-xs font-semibold transition-colors cursor-pointer shadow-sm"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Execute Hunt</span>
            </button>
          </div>

          {/* Structured Field Inputs */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-1 text-xs">
            <input
              type="text"
              placeholder="Filter Username..."
              value={filterUser}
              onChange={(e) => {
                setFilterUser(e.target.value);
                runHuntFilter(query, allEvents, e.target.value, filterHost, filterAction, filterCategory);
              }}
              className="px-2.5 py-1.5 rounded-md bg-[#24282C] border border-[#30363C] text-[#E9ECEF] placeholder-[#737D87] outline-none text-xs font-mono"
            />
            <input
              type="text"
              placeholder="Filter Hostname..."
              value={filterHost}
              onChange={(e) => {
                setFilterHost(e.target.value);
                runHuntFilter(query, allEvents, filterUser, e.target.value, filterAction, filterCategory);
              }}
              className="px-2.5 py-1.5 rounded-md bg-[#24282C] border border-[#30363C] text-[#E9ECEF] placeholder-[#737D87] outline-none text-xs font-mono"
            />
            <input
              type="text"
              placeholder="Filter Action (e.g. logon)..."
              value={filterAction}
              onChange={(e) => {
                setFilterAction(e.target.value);
                runHuntFilter(query, allEvents, filterUser, filterHost, e.target.value, filterCategory);
              }}
              className="px-2.5 py-1.5 rounded-md bg-[#24282C] border border-[#30363C] text-[#E9ECEF] placeholder-[#737D87] outline-none text-xs font-mono"
            />
            <input
              type="text"
              placeholder="Filter Category (e.g. auth)..."
              value={filterCategory}
              onChange={(e) => {
                setFilterCategory(e.target.value);
                runHuntFilter(query, allEvents, filterUser, filterHost, filterAction, e.target.value);
              }}
              className="px-2.5 py-1.5 rounded-md bg-[#24282C] border border-[#30363C] text-[#E9ECEF] placeholder-[#737D87] outline-none text-xs font-mono"
            />
          </div>

          {/* Preset Buttons */}
          <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-[#30363C]">
            <span className="text-[11px] text-[#737D87] font-medium">
              Presets:
            </span>
            {presets.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setQuery(p.q);
                  runHuntFilter(p.q, allEvents);
                }}
                className="px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#2B2722] text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] transition-colors cursor-pointer"
              >
                {p.name}
              </button>
            ))}
          </div>
        </form>
      </div>

      {/* Results Table */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
        <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-[#B58A61]" />
            <span className="text-xs font-semibold text-[#E9ECEF]">
              Matching Telemetry Records
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[#1D2125] text-[#A0A7AE] border border-[#30363C]">
              {filteredEvents.length} of {allEvents.length} loaded events
            </span>
          </div>
          <span className="text-[11px] text-[#737D87]">
            Click row to inspect full Common Event Schema record
          </span>
        </div>

        {loading ? (
          <div className="py-24 flex items-center justify-center text-xs text-[#737D87]">
            <RefreshCw className="w-4 h-4 animate-spin mr-2 text-[#B58A61]" />
            Loading telemetry buffer...
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="py-20 text-center text-xs text-[#737D87]">
            No telemetry events match the active hunt query or filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#30363C] bg-[#24282C]/50 text-[#737D87] text-[11px] font-medium">
                  <th className="py-2.5 px-3.5 whitespace-nowrap">Event ID</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Source Type</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Action</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">User</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Host</th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Source IP → Dest IP</th>
                  <th className="py-2.5 px-3.5 text-right whitespace-nowrap">Bytes Out</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#30363C]">
                {filteredEvents.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => {
                      setSelectedEvent(evt);
                      setDrawerOpen(true);
                    }}
                    className="hover:bg-[#24282C]/50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3.5 font-mono text-xs font-semibold text-[#B58A61] whitespace-nowrap">
                      {evt.id}
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] text-[#A0A7AE] whitespace-nowrap">
                      {evt.timestamp?.replace("T", " ").slice(0, 19)}
                    </td>
                    <td className="py-3 px-3 text-[#737D87] whitespace-nowrap">
                      {evt.source_type}
                    </td>
                    <td className="py-3 px-3 text-[#E9ECEF] capitalize whitespace-nowrap">
                      {evt.action?.replace("_", " ") || "—"}
                    </td>
                    <td className="py-3 px-3 font-mono text-xs text-[#B58A61] whitespace-nowrap">
                      {evt.username || "—"}
                    </td>
                    <td className="py-3 px-3 font-mono text-xs text-[#A0A7AE] whitespace-nowrap">
                      {evt.hostname || "—"}
                    </td>
                    <td className="py-3 px-3 font-mono text-xs text-[#737D87] whitespace-nowrap">
                      {evt.source_ip || "—"} → {evt.destination_ip || "—"}
                    </td>
                    <td className="py-3 px-3.5 text-right whitespace-nowrap font-mono text-xs">
                      {evt.bytes_out ? (
                        <span className="text-[#E06C68] font-medium">
                          {(evt.bytes_out / 1024 / 1024).toFixed(1)} MB
                        </span>
                      ) : (
                        <span className="text-[#737D87]">—</span>
                      )}
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
