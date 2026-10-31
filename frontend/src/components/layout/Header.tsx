import React, { useState, useEffect } from "react";
import {
  Shield,
  Search,
  UploadCloud,
  Cpu,
  ChevronDown,
  Bell,
  Clock,
} from "lucide-react";
import { api } from "../../services/api";

interface HeaderProps {
  onOpenCommandPalette: () => void;
  onOpenUpload: () => void;
  activeModel: string;
  onSelectModel: (model: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenCommandPalette,
  onOpenUpload,
  activeModel,
  onSelectModel,
}) => {
  const [isHealthy, setIsHealthy] = useState<boolean>(true);
  const [modelDropdownOpen, setModelDropdownOpen] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date().toUTCString().slice(17, 25) + " UTC");

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString().slice(17, 25) + " UTC");
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    api.getHealth().then((h) => setIsHealthy(h.isLive));
  }, []);

  const models = [
    {
      id: "qwen-3.8-27b",
      name: "BharatCode Qwen 27B",
      badge: "PRIMARY AI",
      color: "text-cyan-400",
    },
    {
      id: "deterministic",
      name: "Deterministic Fallback Engine",
      badge: "AUTHORITATIVE",
      color: "text-amber-400",
    },
    {
      id: "claude-3-5-sonnet",
      name: "Claude 3.5 Sonnet",
      badge: "BENCHMARK",
      color: "text-indigo-400",
    },
  ];

  const currentModel = models.find((m) => m.id === activeModel) || models[0];

  return (
    <header className="h-14 border-b border-border-subtle bg-bg-surface1/95 backdrop-blur-md px-4 flex items-center justify-between sticky top-0 z-40 select-none">
      {/* Brand & System Health */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-indigo-600 flex items-center justify-center shadow-[0_0_12px_rgba(6,182,212,0.4)]">
            <Shield className="w-5 h-5 text-white stroke-[2.5]" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5 leading-tight">
              <span className="font-mono text-sm font-black tracking-wider text-white">CYBERTRACE</span>
              <span className="text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 px-1 py-0.2 rounded">
                AI-SOC
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
              DEFENSIVE COMMAND
            </span>
          </div>
        </div>

        <div className="h-5 w-px bg-border-subtle mx-1" />

        {/* Health Pulse */}
        <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-bg-surface2/80 border border-border-subtle">
          <span
            className={`w-2 h-2 rounded-full ${
              isHealthy
                ? "bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]"
                : "bg-indigo-400 shadow-[0_0_8px_#818cf8]"
            }`}
          />
          <span className="font-mono text-[11px] text-slate-300">
            {isHealthy ? "SYSTEM HEALTHY" : "BENCHMARK MODE"}
          </span>
        </div>
      </div>

      {/* Global Search Bar (Cmd+K) */}
      <div className="flex-1 max-w-md mx-6">
        <button
          type="button"
          onClick={onOpenCommandPalette}
          className="w-full flex items-center justify-between px-3.5 py-1.5 rounded-lg bg-bg-surface2/60 border border-border-subtle hover:border-cyan-500/40 hover:bg-bg-hover transition-colors text-xs font-mono text-slate-400 group"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            <span>Search incidents, entities, rules...</span>
          </div>
          <kbd className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-bg-surface1 border border-border-subtle text-slate-400">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Controls, Model Selector, UTC Clock */}
      <div className="flex items-center gap-3">
        {/* Upload Log Button */}
        <button
          onClick={onOpenUpload}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-medium transition-colors"
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span>Ingest Log</span>
        </button>

        {/* Model Selector Dropdown */}
        <div className="relative">
          <button
            onClick={() => setModelDropdownOpen(!modelDropdownOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-bg-surface2 border border-border-subtle hover:border-border-accent text-xs font-mono text-slate-300 transition-colors"
          >
            <Cpu className="w-3.5 h-3.5 text-indigo-400" />
            <span className="font-semibold text-white">{currentModel.name}</span>
            <span className="text-[9px] px-1 py-0.2 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
              {currentModel.badge}
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {modelDropdownOpen && (
            <div className="absolute right-0 mt-2 w-64 rounded-xl bg-bg-surface1 border border-border-subtle shadow-modal p-1.5 z-50 animate-scaleUp">
              <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase text-slate-500 border-b border-border-subtle mb-1">
                Investigation Engine
              </div>
              {models.map((m) => (
                <button
                  key={m.id}
                  onClick={() => {
                    onSelectModel(m.id);
                    setModelDropdownOpen(false);
                  }}
                  className={`w-full flex items-center justify-between p-2 rounded-lg text-left text-xs font-mono transition-colors ${
                    m.id === activeModel
                      ? "bg-cyan-950/40 text-cyan-300 border border-cyan-500/30"
                      : "hover:bg-bg-hover text-slate-300"
                  }`}
                >
                  <div className="flex flex-col">
                    <span className="font-medium">{m.name}</span>
                    <span className="text-[10px] text-slate-500 font-mono">{m.id}</span>
                  </div>
                  <span className="text-[9px] px-1 py-0.5 rounded bg-bg-surface2 text-slate-400 border border-border-subtle">
                    {m.badge}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* UTC Clock */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-bg-surface2/60 border border-border-subtle text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span>{currentTime}</span>
        </div>

        {/* Notification Bell */}
        <button
          className="p-1.5 rounded-lg hover:bg-bg-hover text-slate-400 hover:text-white transition-colors relative"
          title="Active Alerts"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500 animate-pulse" />
        </button>
      </div>
    </header>
  );
};
