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
        className="relative w-full max-w-2xl bg-bg-surface1 border-l border-border-subtle h-full shadow-drawer flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-subtle bg-bg-surface2/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold text-white">{event.id}</span>
                <SeverityBadge severity={event.severity} size="sm" />
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  VERIFIED EVIDENCE
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                CES Event • {event.category} • {event.action}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-subtle bg-bg-surface2 hover:bg-bg-hover text-xs font-mono text-slate-300 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? "Copied" : "Copy JSON"}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-bg-hover text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center px-6 border-b border-border-subtle bg-bg-surface1">
          <button
            onClick={() => setActiveTab("fields")}
            className={`py-2.5 px-4 text-xs font-mono font-medium border-b-2 transition-colors ${
              activeTab === "fields"
                ? "border-cyan-400 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Structured Fields
          </button>
          <button
            onClick={() => setActiveTab("json")}
            className={`py-2.5 px-4 text-xs font-mono font-medium border-b-2 transition-colors ${
              activeTab === "json"
                ? "border-cyan-400 text-cyan-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Raw CES JSON
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === "fields" ? (
            <div className="space-y-6">
              {/* Core Context Grid */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-bg-surface2/50 border border-border-subtle rounded-lg">
                  <div className="flex items-center gap-1.5 text-slate-400 text-xs font-mono mb-1">
                    <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                    Timestamp
                  </div>
                  <div className="font-mono text-sm text-slate-200">{event.timestamp}</div>
                </div>

                <div className="p-3 bg-bg-surface2/50 border border-border-subtle rounded-lg">
                  <div className="flex items-center gap-1.5 text-slate-400 text-xs font-mono mb-1">
                    <Database className="w-3.5 h-3.5 text-cyan-400" />
                    Source Type
                  </div>
                  <div className="font-mono text-sm text-slate-200">{event.source_type}</div>
                </div>

                <div className="p-3 bg-bg-surface2/50 border border-border-subtle rounded-lg">
                  <div className="flex items-center gap-1.5 text-slate-400 text-xs font-mono mb-1">
                    <Tag className="w-3.5 h-3.5 text-cyan-400" />
                    Action / Operation
                  </div>
                  <div className="font-mono text-sm text-slate-200">{event.action}</div>
                </div>

                <div className="p-3 bg-bg-surface2/50 border border-border-subtle rounded-lg">
                  <div className="flex items-center gap-1.5 text-slate-400 text-xs font-mono mb-1">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    Hostname
                  </div>
                  <div className="font-mono text-sm text-slate-200">{event.hostname || "N/A"}</div>
                </div>
              </div>

              {/* Identity & Network Breakdown */}
              <div className="bg-bg-surface2/40 border border-border-subtle rounded-xl p-4 space-y-3">
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Telemetry Attribution
                </h4>

                <div className="divide-y divide-border-subtle text-xs font-mono">
                  <div className="py-2 flex justify-between">
                    <span className="text-slate-400">Username:</span>
                    <span className="text-cyan-300 font-semibold">{event.username || "—"}</span>
                  </div>
                  <div className="py-2 flex justify-between">
                    <span className="text-slate-400">Source IP / Port:</span>
                    <span className="text-slate-200">
                      {event.source_ip ? `${event.source_ip}${event.source_port ? `:${event.source_port}` : ""}` : "—"}
                    </span>
                  </div>
                  <div className="py-2 flex justify-between">
                    <span className="text-slate-400">Destination IP / Port:</span>
                    <span className="text-slate-200">
                      {event.destination_ip
                        ? `${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}`
                        : "—"}
                    </span>
                  </div>
                  {event.bytes_out !== undefined && (
                    <div className="py-2 flex justify-between">
                      <span className="text-slate-400">Bytes Out:</span>
                      <span className="text-red-400 font-bold">
                        {event.bytes_out.toLocaleString()} bytes ({(event.bytes_out / 1024 / 1024).toFixed(2)} MB)
                      </span>
                    </div>
                  )}
                  {event.process_name && (
                    <div className="py-2 flex justify-between">
                      <span className="text-slate-400">Process Name:</span>
                      <span className="text-slate-200 font-semibold">{event.process_name}</span>
                    </div>
                  )}
                  {event.source_file_hash && (
                    <div className="py-2 flex justify-between items-center">
                      <span className="text-slate-400">Ingestion SHA-256:</span>
                      <span className="text-slate-400 text-[10px] truncate max-w-xs" title={event.source_file_hash}>
                        {event.source_file_hash}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Command line execution if available */}
              {event.process_command_line && (
                <div className="bg-black/50 border border-border-subtle rounded-xl p-4 space-y-2">
                  <div className="text-xs font-mono text-slate-400">Process Command Line:</div>
                  <pre className="font-mono text-xs text-emerald-400 overflow-x-auto whitespace-pre-wrap p-2 bg-black/40 rounded border border-emerald-500/20">
                    {event.process_command_line}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-black/60 border border-border-subtle rounded-xl p-4 overflow-x-auto">
              <pre className="font-mono text-xs text-slate-300 leading-relaxed">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

