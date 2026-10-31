import React from "react";
import { DataProvenance } from "../../types";

interface DataProvenanceBadgeProps {
  provenance: DataProvenance | string;
  size?: "sm" | "md";
}

export const DataProvenanceBadge: React.FC<DataProvenanceBadgeProps> = ({
  provenance,
  size = "sm",
}) => {
  const isLive = provenance === "live_telemetry";
  const isEvaluation = provenance === "calculated_evaluation";

  if (isLive) {
    return (
      <span
        title="Directly derived from live ingestion pipeline & SQLite database"
        className={`inline-flex items-center gap-1.5 font-mono uppercase font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded px-2 py-0.5 ${
          size === "sm" ? "text-[10px]" : "text-xs"
        }`}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]" />
        Live Telemetry
      </span>
    );
  }

  if (isEvaluation) {
    return (
      <span
        title="Formally calculated across benchmark scenarios"
        className={`inline-flex items-center gap-1.5 font-mono uppercase font-semibold text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 rounded px-2 py-0.5 ${
          size === "sm" ? "text-[10px]" : "text-xs"
        }`}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
        Calculated Evaluation
      </span>
    );
  }

  return (
    <span
      title="Verified synthetic benchmark scenario (Phase 1-3 dataset)"
      className={`inline-flex items-center gap-1.5 font-mono uppercase font-semibold text-indigo-300 bg-indigo-500/10 border border-indigo-500/30 rounded px-2 py-0.5 ${
        size === "sm" ? "text-[10px]" : "text-xs"
      }`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
      Demo Benchmark
    </span>
  );
};

