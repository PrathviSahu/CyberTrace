import React from "react";
import { DataProvenance } from "../../types";
import { DataProvenanceBadge } from "./DataProvenanceBadge";

interface MetricCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  trend?: {
    value: string;
    isPositive?: boolean;
    isNeutral?: boolean;
  };
  icon: React.ReactNode;
  accentColor?: "cyan" | "indigo" | "red" | "emerald";
  provenance?: DataProvenance;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subValue,
  trend,
  icon,
  accentColor = "cyan",
  provenance,
}) => {
  const accentClasses = {
    cyan: "border-cyan-500/20 hover:border-cyan-500/40 hover:shadow-[0_0_15px_rgba(6,182,212,0.15)]",
    indigo: "border-indigo-500/20 hover:border-indigo-500/40 hover:shadow-[0_0_15px_rgba(99,102,241,0.15)]",
    red: "border-red-500/20 hover:border-red-500/40 hover:shadow-[0_0_15px_rgba(239,68,68,0.15)]",
    emerald: "border-emerald-500/20 hover:border-emerald-500/40 hover:shadow-[0_0_15px_rgba(16,185,129,0.15)]",
  };

  const iconBgClasses = {
    cyan: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
    indigo: "bg-indigo-500/10 text-indigo-400 border-indigo-500/30",
    red: "bg-red-500/10 text-red-400 border-red-500/30",
    emerald: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  };

  return (
    <div
      className={`relative overflow-hidden rounded-xl bg-bg-surface1/90 border p-5 backdrop-blur-md transition-all duration-200 ${accentClasses[accentColor]}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400 font-mono">
              {label}
            </span>
            {provenance && <DataProvenanceBadge provenance={provenance} size="sm" />}
          </div>
          <div className="text-2xl font-bold font-mono tracking-tight text-white mt-1">
            {value}
          </div>
          {(subValue || trend) && (
            <div className="flex items-center gap-2 mt-2 text-xs">
              {trend && (
                <span
                  className={`font-mono font-medium ${
                    trend.isNeutral
                      ? "text-slate-400"
                      : trend.isPositive
                      ? "text-emerald-400"
                      : "text-red-400"
                  }`}
                >
                  {trend.value}
                </span>
              )}
              {subValue && <span className="text-slate-500">{subValue}</span>}
            </div>
          )}
        </div>
        <div className={`p-3 rounded-lg border ${iconBgClasses[accentColor]} shrink-0 ml-3`}>
          {icon}
        </div>
      </div>
    </div>
  );
};

