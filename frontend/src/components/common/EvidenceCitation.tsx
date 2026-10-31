import React from "react";
import { CheckCircle2, ExternalLink } from "lucide-react";

interface EvidenceCitationProps {
  eventId: string;
  isVerified?: boolean;
  onClick?: (eventId: string) => void;
  className?: string;
}

export const EvidenceCitation: React.FC<EvidenceCitationProps> = ({
  eventId,
  isVerified = true,
  onClick,
  className = "",
}) => {
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick?.(eventId);
      }}
      title={`Inspect verified underlying log event ${eventId}`}
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[11px] font-medium transition-all cursor-pointer ${
        isVerified
          ? "bg-cyan-950/60 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-900/80 hover:border-cyan-400 hover:shadow-[0_0_8px_rgba(6,182,212,0.3)]"
          : "bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700"
      } ${className}`}
    >
      {isVerified ? (
        <CheckCircle2 className="w-3 h-3 text-cyan-400 shrink-0" />
      ) : (
        <ExternalLink className="w-3 h-3 text-slate-400 shrink-0" />
      )}
      <span>{eventId}</span>
    </button>
  );
};

