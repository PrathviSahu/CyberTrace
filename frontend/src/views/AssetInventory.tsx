import React, { useState, useEffect } from "react";
import { Server, Search, Globe, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import { AssetSummary } from "../types";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";

export const AssetInventory: React.FC = () => {
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | "hostname" | "ip">("all");

  const loadAssets = async () => {
    setLoading(true);
    try {
      const data = await api.getAssets();
      setAssets(data);
    } catch (err) {
      console.error("Failed to load assets:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const filtered = assets.filter((a) => {
    if (typeFilter !== "all" && a.asset_type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return a.asset_value.toLowerCase().includes(q) || a.asset_type.toLowerCase().includes(q);
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
              MONITORED ASSET INVENTORY
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              OBSERVED TELEMETRY
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Enterprise hosts and IP entities derived directly from ingested security telemetry.
          </p>
        </div>

        {/* Search & Filters */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-surface1 border border-border-subtle text-xs font-mono">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search hostname, IP..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-transparent text-white placeholder-slate-500 outline-none w-48"
            />
          </div>

          <div className="flex items-center gap-1 bg-bg-surface1 p-1 rounded-lg border border-border-subtle text-xs font-mono">
            {(["all", "hostname", "ip"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={`px-2 py-1 rounded uppercase transition-colors ${
                  typeFilter === t
                    ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          <button
            onClick={loadAssets}
            title="Refresh inventory"
            className="p-2 rounded-lg bg-bg-surface1 border border-border-subtle text-slate-400 hover:text-white hover:border-cyan-500/40 transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Asset Cards Grid */}
      {loading ? (
        <div className="flex items-center justify-center py-20 text-slate-400 font-mono text-xs">
          <RefreshCw className="w-5 h-5 animate-spin mr-2 text-cyan-400" />
          Loading observed asset inventory...
        </div>
      ) : filtered.length === 0 ? (
        <div className="p-8 text-center rounded-xl bg-bg-surface1 border border-border-subtle text-slate-400 font-mono text-xs">
          No observed assets match the current filter or search criteria.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((ast) => (
            <div
              key={`${ast.asset_type}:${ast.asset_value}`}
              className="p-5 rounded-xl bg-bg-surface1 border border-border-subtle hover:border-cyan-500/40 transition-all shadow-card space-y-4"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-lg bg-bg-surface2 border border-border-subtle text-cyan-400">
                    {ast.asset_type === "hostname" ? (
                      <Server className="w-5 h-5" />
                    ) : (
                      <Globe className="w-5 h-5" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-base font-bold text-white truncate max-w-[180px]">
                        {ast.asset_value}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-bg-surface2 text-slate-300 border border-border-subtle">
                        {ast.asset_type}
                      </span>
                      <DataProvenanceBadge provenance={ast.provenance} size="sm" />
                    </div>
                  </div>
                </div>

                {/* Threat Status */}
                <div className="text-right">
                  <div className="text-[10px] font-mono uppercase text-slate-400">Incidents</div>
                  <div
                    className={`text-lg font-mono font-bold ${
                      ast.incident_count > 0 ? "text-red-400" : "text-emerald-400"
                    }`}
                  >
                    {ast.incident_count > 0 ? `${ast.incident_count} Active` : "0 Clean"}
                  </div>
                </div>
              </div>

              {/* Observed Telemetry Metrics */}
              <div className="grid grid-cols-3 gap-2 text-xs font-mono p-3 rounded-lg bg-bg-surface2/40 border border-border-subtle text-center">
                <div>
                  <span className="text-slate-400 text-[10px] uppercase">Events</span>
                  <div className="text-white font-bold mt-0.5">{ast.event_count}</div>
                </div>
                <div>
                  <span className="text-slate-400 text-[10px] uppercase">Detections</span>
                  <div
                    className={`font-bold mt-0.5 ${
                      ast.detection_count > 0 ? "text-amber-400" : "text-slate-300"
                    }`}
                  >
                    {ast.detection_count}
                  </div>
                </div>
                <div>
                  <span className="text-slate-400 text-[10px] uppercase">Last Seen</span>
                  <div className="text-slate-300 font-bold mt-0.5 text-[10px] truncate" title={ast.last_seen || ""}>
                    {ast.last_seen ? new Date(ast.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "N/A"}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
