import React, { useState, useEffect } from "react";
import {
  Activity,
  UploadCloud,
} from "lucide-react";
import { api } from "../services/api";
import { OverviewMetrics } from "../types";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";

interface TelemetryPipelinesProps {
  onOpenUpload: () => void;
}

export const TelemetryPipelines: React.FC<TelemetryPipelinesProps> = ({ onOpenUpload }) => {
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);

  useEffect(() => {
    api
      .getOverviewMetrics()
      .then((m) => setMetrics(m))
      .catch((err) => console.error("Failed to load metrics:", err));
  }, []);

  const pipelines = [
    {
      name: "Linux Syslog & Auditd Ingest",
      category: "host / authentication",
      formats: ["auth.log", "secure", "syslog"],
      status: "ACTIVE",
      parser: "Regex & RFC 5424 Syslog Parser",
      cesMapping: "event.category: authentication, event.action: logon_success/logon_failure",
    },
    {
      name: "Windows Security Event Logs",
      category: "host / authentication",
      formats: ["Security.evtx", "Event IDs 4624, 4625, 4672, 4720"],
      status: "ACTIVE",
      parser: "Windows XML & Structured CSV Parser",
      cesMapping: "event.category: authentication, user.name: TargetUserName",
    },
    {
      name: "Zeek Network Connection Telemetry",
      category: "network / flow",
      formats: ["conn.log (TSV / JSON)"],
      status: "ACTIVE",
      parser: "Zeek Bro TSV Stream Normalizer",
      cesMapping: "network.source_ip: id.orig_h, network.bytes_out: orig_bytes",
    },
    {
      name: "CloudTrail & Cloud Audit Telemetry",
      category: "cloud / iam",
      formats: ["CloudTrail JSON", "GCP Audit Logs"],
      status: "EXPERIMENTAL",
      parser: "Cloud Identity Event Normalizer",
      cesMapping: "cloud.user: userIdentity.arn, event.action: eventName",
    },
  ];

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Telemetry & Ingestion Pipelines
            </h1>
            <DataProvenanceBadge provenance="observed_telemetry" size="sm" />
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            Common Event Schema (CES) normalization pipelines and real-time ingestion buffer status.
          </p>
        </div>

        <button
          onClick={onOpenUpload}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] font-semibold text-xs transition-colors cursor-pointer shadow-sm"
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span>Ingest Telemetry</span>
        </button>
      </div>

      {/* Telemetry Buffer Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-lg bg-[#1D2125] border border-[#30363C] space-y-1 shadow-card">
          <div className="flex items-center justify-between text-xs text-[#A0A7AE] font-medium">
            <span>Operational Buffer Events</span>
            <span className="text-[10px] text-[#76A58B] font-semibold">LIVE POOL</span>
          </div>
          <div className="text-2xl font-mono font-bold text-[#E9ECEF]">
            {metrics ? `${metrics.eventsIngestedSample} Events` : "..."}
          </div>
          <div className="text-[11px] text-[#737D87]">
            Current in-memory SQLite operational buffer
          </div>
        </div>

        <div className="p-4 rounded-lg bg-[#1D2125] border border-[#30363C] space-y-1 shadow-card">
          <div className="flex items-center justify-between text-xs text-[#A0A7AE] font-medium">
            <span>Schema Normalization</span>
            <span className="text-[10px] text-[#B58A61] font-semibold">100% CES</span>
          </div>
          <div className="text-2xl font-mono font-bold text-[#B58A61]">CES v1.0</div>
          <div className="text-[11px] text-[#737D87]">
            Standardized Common Event Schema fields
          </div>
        </div>

        <div className="p-4 rounded-lg bg-[#1D2125] border border-[#30363C] space-y-1 shadow-card">
          <div className="flex items-center justify-between text-xs text-[#A0A7AE] font-medium">
            <span>Parser Concurrency</span>
            <span className="text-[10px] text-[#76A58B] font-semibold">HEALTHY</span>
          </div>
          <div className="text-2xl font-medium text-[#E9ECEF]">FastAPI Async</div>
          <div className="text-[11px] text-[#737D87]">
            Non-blocking asynchronous stream processing
          </div>
        </div>
      </div>

      {/* Active Ingestion Connectors */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
        <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#B58A61]" />
            <span className="text-xs font-semibold text-[#E9ECEF]">
              Configured Log Ingestion Connectors
            </span>
          </div>
          <span className="text-xs text-[#737D87]">
            4 Supported Schemas
          </span>
        </div>

        <div className="divide-y divide-[#30363C]">
          {pipelines.map((p, idx) => (
            <div key={idx} className="p-4 space-y-2 hover:bg-[#24282C]/50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-[#E9ECEF]">{p.name}</span>
                  <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-[#24282C] text-[#737D87] border border-[#30363C]">
                    {p.category}
                  </span>
                </div>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium ${
                    p.status === "ACTIVE"
                      ? "bg-[#76A58B]/12 text-[#76A58B] border border-[#76A58B]/25"
                      : "bg-[#24282C] text-[#737D87] border border-[#30363C]"
                  }`}
                >
                  {p.status}
                </span>
              </div>

              <div className="text-xs text-[#A0A7AE]">
                Parser: <strong className="text-[#E9ECEF] font-medium">{p.parser}</strong>
              </div>

              <div className="text-xs text-[#737D87]">
                CES Mapping: <code className="text-[#B58A61] font-mono bg-[#191C1F] px-1.5 py-0.5 rounded border border-[#30363C] text-[11px]">{p.cesMapping}</code>
              </div>

              <div className="flex items-center gap-2 pt-1 text-xs text-[#737D87]">
                <span>Accepted formats:</span>
                {p.formats.map((f, fIdx) => (
                  <span key={fIdx} className="px-1.5 py-0.2 rounded bg-[#24282C] text-[#A0A7AE] border border-[#30363C] text-[11px] font-mono">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
