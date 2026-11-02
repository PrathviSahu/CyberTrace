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
  icon?: React.ReactNode;
  accentColor?: "bronze" | "critical" | "steel";
  provenance?: DataProvenance;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subValue,
  trend,
  icon,
  accentColor = "bronze",
  provenance,
}) => {
  const isCritical = accentColor === "critical";

  return (
    <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-4 transition-colors">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-medium text-[#A0A7AE]">
              {label}
            </span>
            {provenance && <DataProvenanceBadge provenance={provenance} size="sm" />}
          </div>
          <div className="text-2xl font-semibold tracking-tight text-[#E9ECEF]">
            {value}
          </div>
          {(subValue || trend) && (
            <div className="flex items-center gap-2 mt-2 text-xs">
              {trend && (
                <span
                  className={`font-medium ${
                    trend.isNeutral
                      ? "text-[#A0A7AE]"
                      : trend.isPositive
                      ? "text-[#76A58B]"
                      : "text-[#E06C68]"
                  }`}
                >
                  {trend.value}
                </span>
              )}
              {subValue && <span className="text-[#737D87] text-xs">{subValue}</span>}
            </div>
          )}
        </div>
        {icon && (
          <div
            className={`p-2 rounded-md shrink-0 ml-3 ${
              isCritical
                ? "bg-[#E06C68]/12 text-[#E06C68]"
                : "bg-[#24282C] text-[#B58A61]"
            }`}
          >
            {icon}
          </div>
        )}
      </div>
    </div>
  );
};
