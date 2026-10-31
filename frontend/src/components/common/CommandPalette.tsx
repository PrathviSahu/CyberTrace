import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  ShieldAlert,
  Crosshair,
  FlaskConical,
  Server,
  FileCode2,
  LayoutDashboard,
  UploadCloud,
  X,
  ChevronRight,
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
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        if (isOpen) {
          onClose();
        } else {
          // Trigger parent opening if handled externally
        }
      }
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const actions = [
    {
      id: "cmd_dashboard",
      title: "Command Centre Overview",
      category: "Navigation",
      icon: <LayoutDashboard className="w-4 h-4 text-cyan-400" />,
      run: () => navigate("/"),
    },
    {
      id: "cmd_inc001",
      title: "Incident INC-001: Multi-Stage Credential Stuffing & Exfiltration",
      category: "Active Incidents",
      icon: <ShieldAlert className="w-4 h-4 text-red-400" />,
      run: () => navigate("/incidents/INC-001"),
    },
    {
      id: "cmd_inc002",
      title: "Incident INC-002: Sudo Token Injection Privilege Escalation",
      category: "Active Incidents",
      icon: <ShieldAlert className="w-4 h-4 text-orange-400" />,
      run: () => navigate("/incidents/INC-002"),
    },
    {
      id: "cmd_alerts",
      title: "Alert Inbox (Detections Stream)",
      category: "Operations",
      icon: <Crosshair className="w-4 h-4 text-amber-400" />,
      run: () => navigate("/alerts"),
    },
    {
      id: "cmd_hunting",
      title: "Threat Hunting (Structured Query Studio)",
      category: "Intelligence",
      icon: <Crosshair className="w-4 h-4 text-cyan-400" />,
      run: () => navigate("/hunting"),
    },
    {
      id: "cmd_threatlab",
      title: "ThreatLab Benchmark & Detection Evaluation",
      category: "Engineering",
      icon: <FlaskConical className="w-4 h-4 text-indigo-400" />,
      run: () => navigate("/threatlab"),
    },
    {
      id: "cmd_assets",
      title: "Asset & Identity Inventory",
      category: "Environment",
      icon: <Server className="w-4 h-4 text-emerald-400" />,
      run: () => navigate("/assets"),
    },
    {
      id: "cmd_rules",
      title: "Detection-as-Code & Sigma Catalog",
      category: "Engineering",
      icon: <FileCode2 className="w-4 h-4 text-purple-400" />,
      run: () => navigate("/rules"),
    },
    {
      id: "cmd_upload",
      title: "Ingest Log File (Upload to Pipeline)",
      category: "Actions",
      icon: <UploadCloud className="w-4 h-4 text-cyan-400" />,
      run: () => {
        onClose();
        onOpenUpload?.();
      },
    },
  ];

  const filtered = actions.filter((act) =>
    act.title.toLowerCase().includes(query.toLowerCase()) ||
    act.category.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/75 backdrop-blur-md flex items-start justify-center pt-24 px-4">
      <div className="relative w-full max-w-xl bg-bg-surface1 border border-border-subtle rounded-2xl shadow-modal overflow-hidden animate-scaleUp">
        {/* Search Input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-border-subtle bg-bg-surface2/60">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            autoFocus
            type="text"
            placeholder="Type a command, incident ID, or view name..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm font-mono text-white placeholder-slate-500 outline-none"
          />
          <kbd className="px-2 py-0.5 text-[10px] font-mono bg-bg-surface1 text-slate-400 border border-border-subtle rounded">
            ESC
          </kbd>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-2 space-y-1">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-slate-500">
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
                className="w-full flex items-center justify-between p-3 rounded-xl hover:bg-bg-hover group transition-colors text-left"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-bg-surface2 rounded-lg border border-border-subtle group-hover:border-cyan-500/40 transition-colors">
                    {item.icon}
                  </div>
                  <div>
                    <div className="text-xs font-mono font-medium text-slate-200 group-hover:text-white">
                      {item.title}
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                      {item.category}
                    </div>
                  </div>
                </div>
                <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors" />
              </button>
            ))
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-4 py-2 bg-bg-surface2/40 border-t border-border-subtle flex items-center justify-between text-[11px] font-mono text-slate-500">
          <span>Tip: Press ⌘K anywhere to reopen</span>
          <div className="flex items-center gap-2">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
          </div>
        </div>
      </div>
    </div>
  );
};

