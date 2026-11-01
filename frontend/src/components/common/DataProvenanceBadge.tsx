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
  const isEvaluation = provenance === "calculated_evaluation";
  const isBenchmark =
    provenance === "synthetic_benchmark" ||
    provenance === "demo_benchmark" ||
    provenance === "simulated_attack";

  const sizeClass = size === "sm" ? "text-[11px] px-2 py-0.5" : "text-xs px-2.5 py-0.5";

  if (isEvaluation) {
    return (
      <span
        title="Formally calculated across benchmark scenarios"
        className={`inline-flex items-center gap-1.5 font-sans font-medium text-[#6EA59A] bg-[#6EA59A]/10 border border-[#6EA59A]/25 rounded-md ${sizeClass}`}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-[#6EA59A] shrink-0" />
        Calculated Evaluation
      </span>
    );
  }

  if (isBenchmark) {
    return (
      <span
        title="Evaluated against standardized synthetic attack trajectories"
        className={`inline-flex items-center gap-1.5 font-sans font-medium text-[#9B8FA8] bg-[#9B8FA8]/10 border border-[#9B8FA8]/25 rounded-md ${sizeClass}`}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-[#9B8FA8] shrink-0" />
        Synthetic Benchmark
      </span>
    );
  }

  // Default to Observed Telemetry (restrained warm bronze)
  return (
    <span
      title="Derived directly from observed security telemetry in database"
      className={`inline-flex items-center gap-1.5 font-sans font-medium text-[#B58A61] bg-[#B58A61]/10 border border-[#B58A61]/25 rounded-md ${sizeClass}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-[#B58A61] shrink-0" />
      Observed Telemetry
    </span>
  );
};
