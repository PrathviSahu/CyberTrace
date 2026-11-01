import React, { useState } from "react";
import { X, Copy, Check, ShieldCheck, Database, Calendar, Tag, Terminal } from "lucide-react";
import { CommonEvent } from "../../types";
import { SeverityBadge } from "./SeverityBadge";

interface EvidenceDrawerProps {
  event: CommonEvent | null;
  isOpen: boolean;
  onClose: () => void;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({ event, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<"fields" | "json">("fields");

  if (!isOpen || !event) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end animate-fadeIn">
      <div
        className="relative w-full max-w-2xl bg-[#1D2125] border-l border-[#30363C] h-full shadow-drawer flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363C] bg-[#24282C]">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#1D2125] border border-[#30363C] rounded-md text-[#B58A61]">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold text-[#E9ECEF]">{event.id}</span>
                <SeverityBadge severity={event.severity} size="sm" />
                <span className="text-[10px] px-2 py-0.5 rounded-md bg-[#2B2722] text-[#B58A61] border border-[#B58A61]/30 font-medium">
                  Verified Evidence
                </span>
              </div>
              <p className="text-xs text-[#A0A7AE] mt-0.5">
                CES Event • {event.category} • {event.action}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#30363C] bg-[#1D2125] hover:bg-[#24282C] text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#76A58B]" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? "Copied" : "Copy JSON"}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-md hover:bg-[#24282C] text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center px-6 border-b border-[#30363C] bg-[#1D2125]">
          <button
            onClick={() => setActiveTab("fields")}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors cursor-pointer ${
              activeTab === "fields"
                ? "border-[#B58A61] text-[#E9ECEF]"
                : "border-transparent text-[#737D87] hover:text-[#E9ECEF]"
            }`}
          >
            Structured Fields
          </button>
          <button
            onClick={() => setActiveTab("json")}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors cursor-pointer ${
              activeTab === "json"
                ? "border-[#B58A61] text-[#E9ECEF]"
                : "border-transparent text-[#737D87] hover:text-[#E9ECEF]"
            }`}
          >
            Raw CES JSON
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {activeTab === "fields" ? (
            <div className="space-y-5">
              {/* Core Context Grid */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <div className="flex items-center gap-1.5 text-[#737D87] text-xs mb-1">
                    <Calendar className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span>Timestamp</span>
                  </div>
                  <div className="font-mono text-xs text-[#E9ECEF]">{event.timestamp}</div>
                </div>

                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <div className="flex items-center gap-1.5 text-[#737D87] text-xs mb-1">
                    <Database className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span>Source Type</span>
                  </div>
                  <div className="font-mono text-xs text-[#E9ECEF]">{event.source_type}</div>
                </div>

                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <div className="flex items-center gap-1.5 text-[#737D87] text-xs mb-1">
                    <Tag className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span>Action / Operation</span>
                  </div>
                  <div className="text-xs text-[#E9ECEF] font-medium">{event.action}</div>
                </div>

                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <div className="flex items-center gap-1.5 text-[#737D87] text-xs mb-1">
                    <Terminal className="w-3.5 h-3.5 text-[#B58A61]" />
                    <span>Hostname</span>
                  </div>
                  <div className="font-mono text-xs text-[#E9ECEF]">{event.hostname || "N/A"}</div>
                </div>
              </div>

              {/* Identity & Network Breakdown */}
              <div className="bg-[#24282C] border border-[#30363C] rounded-lg p-4 space-y-3">
                <h4 className="text-xs font-semibold text-[#E9ECEF]">
                  Telemetry Attribution
                </h4>

                <div className="divide-y divide-[#30363C] text-xs">
                  <div className="py-2 flex justify-between">
                    <span className="text-[#737D87]">Username:</span>
                    <span className="text-[#B58A61] font-mono font-medium">{event.username || "—"}</span>
                  </div>
                  <div className="py-2 flex justify-between">
                    <span className="text-[#737D87]">Source IP / Port:</span>
                    <span className="text-[#E9ECEF] font-mono">
                      {event.source_ip ? `${event.source_ip}${event.source_port ? `:${event.source_port}` : ""}` : "—"}
                    </span>
                  </div>
                  <div className="py-2 flex justify-between">
                    <span className="text-[#737D87]">Destination IP / Port:</span>
                    <span className="text-[#E9ECEF] font-mono">
                      {event.destination_ip
                        ? `${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}`
                        : "—"}
                    </span>
                  </div>
                  {event.bytes_out !== undefined && (
                    <div className="py-2 flex justify-between">
                      <span className="text-[#737D87]">Bytes Out:</span>
                      <span className="text-[#E06C68] font-mono font-medium">
                        {event.bytes_out.toLocaleString()} bytes ({(event.bytes_out / 1024 / 1024).toFixed(2)} MB)
                      </span>
                    </div>
                  )}
                  {event.process_name && (
                    <div className="py-2 flex justify-between">
                      <span className="text-[#737D87]">Process Name:</span>
                      <span className="text-[#E9ECEF] font-mono">{event.process_name}</span>
                    </div>
                  )}
                  {event.source_file_hash && (
                    <div className="py-2 flex justify-between items-center">
                      <span className="text-[#737D87]">Ingestion SHA-256:</span>
                      <span className="text-[#737D87] font-mono text-[10px] truncate max-w-xs" title={event.source_file_hash}>
                        {event.source_file_hash}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Command line execution if available */}
              {event.process_command_line && (
                <div className="bg-[#191C1F] border border-[#30363C] rounded-lg p-3.5 space-y-2">
                  <div className="text-xs text-[#737D87]">Process Command Line:</div>
                  <pre className="font-mono text-xs text-[#76A58B] overflow-x-auto whitespace-pre-wrap p-2 bg-[#111315] rounded border border-[#30363C]">
                    {event.process_command_line}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-[#191C1F] border border-[#30363C] rounded-lg p-4 overflow-x-auto">
              <pre className="font-mono text-xs text-[#A0A7AE] leading-relaxed">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
