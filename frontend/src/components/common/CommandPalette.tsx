import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  LayoutDashboard,
  ShieldAlert,
  Inbox,
  Crosshair,
  FlaskConical,
  FileCode2,
  Server,
  UploadCloud,
  ChevronRight,
  X,
} from "lucide-react";

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onOpenUpload?: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onOpenUpload,
}) => {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onClose();
      }
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!isOpen) return null;

  const actions = [
    {
      id: "cmd_dashboard",
      title: "Command Centre Overview",
      category: "Navigation",
      icon: <LayoutDashboard className="w-4 h-4 text-[#B58A61]" />,
      run: () => navigate("/"),
    },
    {
      id: "cmd_inc001",
      title: "Incident INC-001: Multi-Stage Credential Stuffing & Exfiltration",
      category: "Active Incidents",
      icon: <ShieldAlert className="w-4 h-4 text-[#E06C68]" />,
      run: () => navigate("/incidents/INC-001"),
    },
    {
      id: "cmd_alerts",
      title: "Alert Inbox (Detections Stream)",
      category: "Operations",
      icon: <Inbox className="w-4 h-4 text-[#B58A61]" />,
      run: () => navigate("/alerts"),
    },
    {
      id: "cmd_hunting",
      title: "Threat Hunting (Telemetry Buffer Filter)",
      category: "Intelligence",
      icon: <Crosshair className="w-4 h-4 text-[#B58A61]" />,
      run: () => navigate("/hunting"),
    },
    {
      id: "cmd_threatlab",
      title: "ThreatLab Benchmark & Detection Evaluation",
      category: "Engineering",
      icon: <FlaskConical className="w-4 h-4 text-[#B58A61]" />,
      run: () => navigate("/threatlab"),
    },
    {
      id: "cmd_assets",
      title: "Asset & Identity Inventory",
      category: "Environment",
      icon: <Server className="w-4 h-4 text-[#B58A61]" />,
      run: () => navigate("/assets"),
    },
    {
      id: "cmd_rules",
      title: "Detection-as-Code & Sigma Catalog",
      category: "Engineering",
      icon: <FileCode2 className="w-4 h-4 text-[#B58A61]" />,
      run: () => navigate("/rules"),
    },
    {
      id: "cmd_upload",
      title: "Ingest Log File (Upload to Pipeline)",
      category: "Actions",
      icon: <UploadCloud className="w-4 h-4 text-[#B58A61]" />,
      run: () => {
        onClose();
        onOpenUpload?.();
      },
    },
  ];

  const filtered = actions.filter(
    (act) =>
      act.title.toLowerCase().includes(query.toLowerCase()) ||
      act.category.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-start justify-center pt-24 px-4">
      <div className="relative w-full max-w-xl bg-[#1D2125] border border-[#30363C] rounded-xl shadow-modal overflow-hidden animate-scaleUp">
        {/* Search Input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[#30363C] bg-[#24282C]">
          <Search className="w-4 h-4 text-[#B58A61] shrink-0" />
          <input
            autoFocus
            type="text"
            placeholder="Type a command, incident ID, or view name..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm font-sans text-[#E9ECEF] placeholder-[#737D87] outline-none"
          />
          <kbd className="px-2 py-0.5 text-[10px] font-mono bg-[#1D2125] text-[#737D87] border border-[#30363C] rounded">
            ESC
          </kbd>
          <button onClick={onClose} className="text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-2 space-y-1">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-[#737D87]">
              No commands or views matching "{query}"
            </div>
          ) : (
            filtered.map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  item.run();
                  onClose();
                }}
                className="w-full flex items-center justify-between p-3 rounded-lg hover:bg-[#24282C] group transition-colors text-left cursor-pointer"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-[#24282C] rounded-md border border-[#30363C] group-hover:border-[#B58A61]/40 transition-colors">
                    {item.icon}
                  </div>
                  <div>
                    <div className="text-xs font-medium text-[#E9ECEF]">
                      {item.title}
                    </div>
                    <div className="text-[11px] text-[#737D87]">
                      {item.category}
                    </div>
                  </div>
                </div>
                <ChevronRight className="w-4 h-4 text-[#737D87] group-hover:text-[#B58A61] transition-colors" />
              </button>
            ))
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-4 py-2 bg-[#24282C]/60 border-t border-[#30363C] flex items-center justify-between text-[11px] text-[#737D87]">
          <span>Tip: Press ⌘K anywhere to open</span>
          <div className="flex items-center gap-2">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
          </div>
        </div>
      </div>
    </div>
  );
};
