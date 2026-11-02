import React, { useState, useRef } from "react";
import { UploadCloud, CheckCircle2, AlertTriangle, FileText, X, Loader2 } from "lucide-react";
import { api, LogUploadResult } from "../../services/api";

interface LogUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadSuccess?: (result: LogUploadResult) => void;
}

export const LogUploadModal: React.FC<LogUploadModalProps> = ({
  isOpen,
  onClose,
  onUploadSuccess,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [result, setResult] = useState<LogUploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
      setResult(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setError(null);
    try {
      const data = await api.uploadLog(file);
      setResult(data);
      onUploadSuccess?.(data);
    } catch (err: any) {
      setError(err.message || "Failed to upload and ingest log file");
    } finally {
      setIsUploading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setResult(null);
    setError(null);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="relative w-full max-w-lg bg-[#1D2125] border border-[#30363C] rounded-xl shadow-modal overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363C] bg-[#24282C]">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#1D2125] border border-[#30363C] rounded-md text-[#B58A61]">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[#E9ECEF]">Ingest Security Telemetry</h3>
              <p className="text-xs text-[#A0A7AE]">
                Parses Linux Auth, Windows Event, Zeek Conn, CSV, and JSON logs
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {!result ? (
            <>
              <div
                onClick={() => fileInputRef.current?.click()}
                className={`border border-dashed rounded-lg p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-colors ${
                  file
                    ? "border-[#B58A61] bg-[#2B2722]/30"
                    : "border-[#30363C] hover:border-[#B58A61]/40 hover:bg-[#24282C]"
                }`}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept=".log,.txt,.csv,.json"
                  className="hidden"
                />
                {file ? (
                  <div className="space-y-2">
                    <FileText className="w-10 h-10 text-[#B58A61] mx-auto" />
                    <div className="text-sm text-[#E9ECEF] font-medium">{file.name}</div>
                    <div className="text-xs text-[#A0A7AE]">
                      {(file.size / 1024).toFixed(1)} KB • Ready for Ingestion
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <UploadCloud className="w-10 h-10 text-[#737D87] mx-auto" />
                    <div className="text-sm text-[#A0A7AE]">
                      Click to browse or drag security log file
                    </div>
                    <div className="text-xs text-[#737D87]">
                      Supports Linux Syslog, Windows Security XML/CSV, Zeek Conn, or CES JSON (max 50 MB)
                    </div>
                  </div>
                )}
              </div>

              {error && (
                <div className="p-3 rounded-md bg-[#E06C68]/10 border border-[#E06C68]/30 flex items-start gap-2 text-xs text-[#E06C68]">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}
            </>
          ) : (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[#76A58B]/10 border border-[#76A58B]/30 space-y-1">
                <div className="flex items-center gap-2 text-[#76A58B] font-semibold text-sm">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>Ingestion & Correlation Complete</span>
                </div>
                <p className="text-xs text-[#A0A7AE]">
                  File parsed, normalized into CES, and evaluated through deterministic rule engine.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <span className="text-[#737D87]">Format Detected:</span>
                  <div className="text-[#B58A61] font-semibold font-mono mt-0.5">{result.detected_format}</div>
                </div>
                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <span className="text-[#737D87]">Parsed CES Events:</span>
                  <div className="text-[#E9ECEF] font-semibold font-mono mt-0.5">{result.parsed_events_count}</div>
                </div>
                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <span className="text-[#737D87]">Triggered Detections:</span>
                  <div className="text-[#D99A54] font-semibold font-mono mt-0.5">{result.detections_count}</div>
                </div>
                <div className="p-3 bg-[#24282C] border border-[#30363C] rounded-md">
                  <span className="text-[#737D87]">Correlated Incidents:</span>
                  <div className="text-[#76A58B] font-semibold font-mono mt-0.5">{result.incidents_count}</div>
                </div>
              </div>

              <div className="p-2.5 bg-[#191C1F] border border-[#30363C] rounded-md text-[11px] font-mono text-[#737D87] truncate">
                <span>SHA-256: </span>{result.source_file_hash}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-[#30363C] bg-[#24282C] flex items-center justify-end gap-3">
          {!result ? (
            <>
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-md border border-[#30363C] text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] hover:bg-[#1D2125] transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!file || isUploading}
                onClick={handleUpload}
                className="px-4 py-2 rounded-md bg-[#B58A61] hover:bg-[#C69A70] disabled:opacity-50 disabled:cursor-not-allowed text-xs font-semibold text-[#111315] flex items-center gap-2 transition-colors cursor-pointer"
              >
                {isUploading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Parsing & Correlating...</span>
                  </>
                ) : (
                  <span>Ingest & Correlate</span>
                )}
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                onClick={handleReset}
                className="px-4 py-2 rounded-md border border-[#30363C] text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] hover:bg-[#1D2125] transition-colors cursor-pointer"
              >
                Upload Another
              </button>
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-xs font-semibold text-[#111315] transition-colors cursor-pointer"
              >
                View Incidents
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
