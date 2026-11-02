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
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[11px] font-medium transition-colors cursor-pointer ${
        isVerified
          ? "bg-[#24282C] text-[#B58A61] border border-[#30363C] hover:border-[#B58A61]/40 hover:bg-[#2B2722]"
          : "bg-[#24282C] text-[#A0A7AE] border border-[#30363C] hover:bg-[#1D2125]"
      } ${className}`}
    >
      {isVerified ? (
        <CheckCircle2 className="w-3 h-3 text-[#76A58B] shrink-0" />
      ) : (
        <ExternalLink className="w-3 h-3 text-[#737D87] shrink-0" />
      )}
      <span>{eventId}</span>
    </button>
  );
};
