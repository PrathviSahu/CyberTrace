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

  const styles: Record<Severity, { bg: string; text: string; border: string; dot: string; label: string }> = {
    critical: {
      bg: "bg-[#E06C68]/12",
      text: "text-[#E06C68]",
      border: "border-[#E06C68]/25",
      dot: "bg-[#E06C68]",
      label: "Critical",
    },
    high: {
      bg: "bg-[#D99A54]/12",
      text: "text-[#D99A54]",
      border: "border-[#D99A54]/25",
      dot: "bg-[#D99A54]",
      label: "High",
    },
    medium: {
      bg: "bg-[#C9B86B]/12",
      text: "text-[#C9B86B]",
      border: "border-[#C9B86B]/25",
      dot: "bg-[#C9B86B]",
      label: "Medium",
    },
    low: {
      bg: "bg-[#76A58B]/12",
      text: "text-[#76A58B]",
      border: "border-[#76A58B]/25",
      dot: "bg-[#76A58B]",
      label: "Low",
    },
    informational: {
      bg: "bg-[#8A94A0]/12",
      text: "text-[#8A94A0]",
      border: "border-[#8A94A0]/25",
      dot: "bg-[#8A94A0]",
      label: "Info",
    },
  };

  const current = styles[norm] || styles.informational;

  const sizeClasses = {
    sm: "text-[11px] px-2 py-0.5",
    md: "text-xs px-2.5 py-0.5",
    lg: "text-sm px-3 py-1",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-sans font-medium border ${current.bg} ${current.text} ${current.border} ${sizeClasses[size]} select-none`}
    >
      {showDot && <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${current.dot}`} />}
      <span>{current.label}</span>
    </span>
  );
};
