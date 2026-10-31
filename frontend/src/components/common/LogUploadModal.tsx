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
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/75 backdrop-blur-md flex items-center justify-center p-4">
      <div className="relative w-full max-w-lg bg-bg-surface1 border border-border-subtle rounded-2xl shadow-modal overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-subtle bg-bg-surface2/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-mono font-bold text-white">Ingest Security Logs</h3>
              <p className="text-xs text-slate-400 font-mono">
                Multi-format parser: Linux Auth, Windows Event, Zeek Conn, CSV, JSON
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {!result ? (
            <>
              <div
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-colors ${
                  file
                    ? "border-cyan-500/50 bg-cyan-950/20"
                    : "border-border-subtle hover:border-cyan-500/30 hover:bg-bg-surface2/50"
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
                    <FileText className="w-10 h-10 text-cyan-400 mx-auto" />
                    <div className="font-mono text-sm text-white font-medium">{file.name}</div>
                    <div className="text-xs font-mono text-slate-400">
                      {(file.size / 1024).toFixed(1)} KB • Ready for Ingestion
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <UploadCloud className="w-10 h-10 text-slate-500 mx-auto" />
                    <div className="font-mono text-sm text-slate-300">
                      Click to browse or drag security log file
                    </div>
                    <div className="text-xs font-mono text-slate-500">
                      Supports Linux Syslog, Windows Security XML/CSV, Zeek Conn, or CES JSON (max 50 MB)
                    </div>
                  </div>
                )}
              </div>

              {error && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-start gap-2 text-xs font-mono text-red-400">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}
            </>
          ) : (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 font-mono font-bold text-sm">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>Ingestion & Correlation Complete</span>
                </div>
                <p className="text-xs font-mono text-slate-300">
                  File successfully parsed, normalized into CES, and evaluated through deterministic rule engine.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-3 bg-bg-surface2/60 border border-border-subtle rounded-lg">
                  <span className="text-slate-400">Format Detected:</span>
                  <div className="text-cyan-300 font-bold mt-0.5">{result.detected_format}</div>
                </div>
                <div className="p-3 bg-bg-surface2/60 border border-border-subtle rounded-lg">
                  <span className="text-slate-400">Parsed CES Events:</span>
                  <div className="text-white font-bold mt-0.5">{result.parsed_events_count}</div>
                </div>
                <div className="p-3 bg-bg-surface2/60 border border-border-subtle rounded-lg">
                  <span className="text-slate-400">Triggered Detections:</span>
                  <div className="text-amber-400 font-bold mt-0.5">{result.detections_count}</div>
                </div>
                <div className="p-3 bg-bg-surface2/60 border border-border-subtle rounded-lg">
                  <span className="text-slate-400">Correlated Incidents:</span>
                  <div className="text-emerald-400 font-bold mt-0.5">{result.incidents_count}</div>
                </div>
              </div>

              <div className="p-3 bg-black/40 border border-border-subtle rounded-lg text-[11px] font-mono text-slate-400 truncate">
                <span className="text-slate-500">SHA-256 Provenance:</span> {result.source_file_hash}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border-subtle bg-bg-surface2/40 flex items-center justify-end gap-3">
          {!result ? (
            <>
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-lg border border-border-subtle text-xs font-mono text-slate-400 hover:text-white hover:bg-bg-hover transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!file || isUploading}
                onClick={handleUpload}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-xs font-mono font-bold text-black flex items-center gap-2 transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)]"
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
                className="px-4 py-2 rounded-lg border border-border-subtle text-xs font-mono text-slate-300 hover:bg-bg-hover transition-colors"
              >
                Upload Another
              </button>
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-xs font-mono font-bold text-black transition-all"
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

