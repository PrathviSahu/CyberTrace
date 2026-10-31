import React from "react";
import { Severity } from "../../types";

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: "sm" | "md" | "lg";
  showDot?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = "md",
  showDot = true,
}) => {
  const norm = (severity || "low").toLowerCase() as Severity;

  const styles: Record<Severity, { bg: string; text: string; border: string; dot: string }> = {
    critical: {
      bg: "bg-red-500/10",
      text: "text-red-400",
      border: "border-red-500/30",
      dot: "bg-red-500 shadow-[0_0_8px_#ef4444]",
    },
    high: {
      bg: "bg-orange-500/10",
      text: "text-orange-400",
      border: "border-orange-500/30",
      dot: "bg-orange-400 shadow-[0_0_8px_#f97316]",
    },
    medium: {
      bg: "bg-amber-500/10",
      text: "text-amber-300",
      border: "border-amber-500/30",
      dot: "bg-amber-400 shadow-[0_0_6px_#f59e0b]",
    },
    low: {
      bg: "bg-sky-500/10",
      text: "text-sky-400",
      border: "border-sky-500/30",
      dot: "bg-sky-400",
    },
    informational: {
      bg: "bg-slate-500/10",
      text: "text-slate-400",
      border: "border-slate-500/30",
      dot: "bg-slate-400",
    },
  };

  const current = styles[norm] || styles.informational;

  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-[10px] tracking-wide",
    md: "px-2.5 py-1 text-xs tracking-wider",
    lg: "px-3 py-1.5 text-sm tracking-wider",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md font-mono uppercase font-semibold border ${current.bg} ${current.text} ${current.border} ${sizeClasses[size]}`}
    >
      {showDot && (
        <span
          className={`inline-block rounded-full ${norm === "critical" ? "animate-pulse" : ""} ${current.dot} ${
            size === "sm" ? "w-1.5 h-1.5" : "w-2 h-2"
          }`}
        />
      )}
      {norm}
    </span>
  );
};

