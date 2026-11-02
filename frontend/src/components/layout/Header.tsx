import React, { useState, useEffect } from "react";
import {
  Shield,
  Search,
  UploadCloud,
  Cpu,
  ChevronDown,
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
  const [currentTime, setCurrentTime] = useState(
    new Date().toUTCString().slice(17, 25) + " UTC"
  );

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString().slice(17, 25) + " UTC");
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    api
      .getHealth()
      .then((h) => setIsHealthy(h.isLive))
      .catch(() => setIsHealthy(false));
  }, []);

  const models = [
    {
      id: "qwen-3.8-27b",
      name: "Qwen 27B",
      fullName: "BharatCode Qwen 27B",
      badge: "Primary AI",
      desc: "Tool-calling analytical SOC agent",
    },
    {
      id: "deterministic",
      name: "Deterministic",
      fullName: "Deterministic Engine",
      badge: "Authoritative",
      desc: "Zero-hallucination ground truth gate",
    },
    {
      id: "claude-3-5-sonnet",
      name: "Claude 3.5",
      fullName: "Claude 3.5 Sonnet",
      badge: "Benchmark",
      desc: "External evaluation model",
    },
  ];

  const currentModel = models.find((m) => m.id === activeModel) || models[0];

  return (
    <header className="h-14 bg-[#191C1F] border-b border-[#30363C] px-5 flex items-center justify-between sticky top-0 z-40 select-none">
      {/* Brand & Compact Live Status */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-[#24282C] border border-[#30363C] flex items-center justify-center">
            <Shield className="w-4 h-4 text-[#B58A61] stroke-[2.2]" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="font-semibold text-sm tracking-tight text-[#E9ECEF]">CyberTrace</span>
            <span className="text-[10px] font-medium text-[#737D87] uppercase tracking-wider">
              SOC
            </span>
          </div>
        </div>

        <div className="h-4 w-px bg-[#30363C] mx-1" />

        {/* Compact Connection Status */}
        <div className="flex items-center gap-1.5 text-xs text-[#A0A7AE]">
          <span
            className={`w-2 h-2 rounded-full ${
              isHealthy ? "bg-[#76A58B]" : "bg-[#E06C68]"
            }`}
          />
          <span className="text-xs">
            {isHealthy ? "Backend Connected" : "Disconnected"}
          </span>
        </div>
      </div>

      {/* Global Search Bar (Cmd+K) - Clean single control */}
      <div className="flex-1 max-w-sm mx-6">
        <button
          type="button"
          onClick={onOpenCommandPalette}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded-md bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/40 text-xs text-[#737D87] hover:text-[#A0A7AE] transition-colors group cursor-pointer"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-[#737D87] group-hover:text-[#B58A61] transition-colors" />
            <span className="text-xs">Search incidents, entities, rules...</span>
          </div>
          <kbd className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#24282C] border border-[#30363C] text-[#737D87]">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Controls: Model Selector, Ingestion, UTC Clock */}
      <div className="flex items-center gap-2.5">
        {/* Model Selector Dropdown - Compact & Secondary */}
        <div className="relative">
          <button
            onClick={() => setModelDropdownOpen(!modelDropdownOpen)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md hover:bg-[#24282C] text-xs text-[#A0A7AE] hover:text-[#E9ECEF] transition-colors cursor-pointer"
            title="Active Investigation Engine"
          >
            <Cpu className="w-3.5 h-3.5 text-[#737D87]" />
            <span className="font-medium text-[#E9ECEF]">{currentModel.name}</span>
            <ChevronDown className="w-3 h-3 text-[#737D87]" />
          </button>

          {modelDropdownOpen && (
            <div className="absolute right-0 mt-2 w-64 rounded-lg bg-[#1D2125] border border-[#30363C] shadow-modal p-1.5 z-50">
              <div className="px-2.5 py-1 text-[11px] font-medium text-[#737D87] border-b border-[#30363C] mb-1">
                Investigation Engine
              </div>
              {models.map((m) => (
                <button
                  key={m.id}
                  onClick={() => {
                    onSelectModel(m.id);
                    setModelDropdownOpen(false);
                  }}
                  className={`w-full flex items-center justify-between p-2 rounded-md text-left text-xs transition-colors ${
                    m.id === activeModel
                      ? "bg-[#2B2722] text-[#E9ECEF]"
                      : "hover:bg-[#24282C] text-[#A0A7AE]"
                  }`}
                >
                  <div className="flex flex-col">
                    <span className="font-medium text-[#E9ECEF]">{m.fullName}</span>
                    <span className="text-[11px] text-[#737D87]">{m.desc}</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#24282C] text-[#A0A7AE]">
                    {m.badge}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Upload Log Button - Accessible without dominating */}
        <button
          onClick={onOpenUpload}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#24282C] hover:bg-[#2B2722] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-medium text-[#E9ECEF] transition-colors cursor-pointer"
        >
          <UploadCloud className="w-3.5 h-3.5 text-[#B58A61]" />
          <span>Ingest Logs</span>
        </button>

        {/* UTC Clock - Technical value in JetBrains Mono */}
        <div className="flex items-center gap-1.5 pl-2 text-xs font-mono text-[#737D87]">
          <Clock className="w-3.5 h-3.5 text-[#737D87]" />
          <span>{currentTime}</span>
        </div>
      </div>
    </header>
  );
};
