import React, { useState } from "react";
import { Server, Search } from "lucide-react";
import { DEMO_ASSETS } from "../services/demoData";
import { AssetRecord } from "../types";

export const AssetInventory: React.FC = () => {
  const [assets] = useState<AssetRecord[]>(DEMO_ASSETS);
  const [search, setSearch] = useState("");

  const filtered = assets.filter(
    (a) =>
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.ip_address.includes(search) ||
      (a.owner && a.owner.toLowerCase().includes(search.toLowerCase()))
  );

  const getTierBadge = (tier: string) => {
    switch (tier) {
      case "tier_1":
        return <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 text-[10px] font-bold">TIER 1 (MISSION CRITICAL)</span>;
      case "tier_2":
        return <span className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30 text-[10px] font-bold">TIER 2 (BUSINESS CRITICAL)</span>;
      case "tier_3":
        return <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[10px] font-bold">TIER 3 (INTERNAL)</span>;
      default:
        return <span className="px-2 py-0.5 rounded bg-slate-500/10 text-slate-400 border border-slate-500/30 text-[10px] font-bold">TIER 4 (DEVELOPMENT)</span>;
    }
  };

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
              ENVIRONMENT TELEMETRY
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Enterprise infrastructure and identity workloads with automated risk-scoring and blast radius evaluation.
          </p>
        </div>

        {/* Search */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-surface1 border border-border-subtle text-xs font-mono">
          <Search className="w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search hostname, IP, owner..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent text-white placeholder-slate-500 outline-none w-60"
          />
        </div>
      </div>

      {/* Asset Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map((ast) => (
          <div
            key={ast.id}
            className="p-5 rounded-xl bg-bg-surface1 border border-border-subtle hover:border-cyan-500/40 transition-all shadow-card space-y-4"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-bg-surface2 border border-border-subtle text-cyan-400">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-base font-bold text-white">{ast.name}</span>
                    {getTierBadge(ast.criticality)}
                  </div>
                  <div className="text-xs font-mono text-slate-400 mt-1">
                    {ast.ip_address} • {ast.type.replace("_", " ").toUpperCase()}
                  </div>
                </div>
              </div>

              {/* Risk Score Gauge */}
              <div className="text-right">
                <div className="text-[10px] font-mono uppercase text-slate-400">Risk Score</div>
                <div
                  className={`text-xl font-mono font-bold ${
                    ast.risk_score > 70
                      ? "text-red-400"
                      : ast.risk_score > 40
                      ? "text-amber-400"
                      : "text-emerald-400"
                  }`}
                >
                  {ast.risk_score} / 100
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono p-3 rounded-lg bg-bg-surface2/40 border border-border-subtle">
              <div>
                <span className="text-slate-400">Owner Team:</span>
                <div className="text-slate-200 mt-0.5">{ast.owner || "Unassigned"}</div>
              </div>
              <div>
                <span className="text-slate-400">Active Incidents:</span>
                <div className="mt-0.5">
                  {ast.active_incident_count > 0 ? (
                    <span className="text-red-400 font-bold">
                      {ast.active_incident_count} Linked Incident
                    </span>
                  ) : (
                    <span className="text-emerald-400 font-bold">0 Clean</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
