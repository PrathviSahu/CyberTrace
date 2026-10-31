import React from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  Inbox,
  Crosshair,
  Share2,
  Grid,
  FlaskConical,
  FileCode2,
  Activity,
  Server,
  Users,
  Settings,
  ScrollText,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggleCollapse }) => {
  const navGroups = [
    {
      label: "COMMAND",
      items: [
        { to: "/", label: "Command Centre", icon: <LayoutDashboard className="w-4 h-4" /> },
        { to: "/incidents/INC-001", label: "Incident Workspace", icon: <ShieldAlert className="w-4 h-4" />, badge: "ACTIVE" },
        { to: "/alerts", label: "Alert Inbox", icon: <Inbox className="w-4 h-4" /> },
      ],
    },
    {
      label: "INTELLIGENCE",
      items: [
        { to: "/hunting", label: "Threat Hunting", icon: <Crosshair className="w-4 h-4" /> },
        { to: "/entities", label: "Attack Graph", icon: <Share2 className="w-4 h-4" /> },
        { to: "/mitre", label: "MITRE ATT&CK", icon: <Grid className="w-4 h-4" /> },
      ],
    },
    {
      label: "ENGINEERING",
      items: [
        { to: "/threatlab", label: "ThreatLab Benchmark", icon: <FlaskConical className="w-4 h-4" />, badge: "F1 1.0" },
        { to: "/rules", label: "Detection Rules", icon: <FileCode2 className="w-4 h-4" /> },
        { to: "/pipelines", label: "Log Pipelines", icon: <Activity className="w-4 h-4" /> },
      ],
    },
    {
      label: "ENVIRONMENT",
      items: [
        { to: "/assets", label: "Asset Inventory", icon: <Server className="w-4 h-4" /> },
        { to: "/identities", label: "Identities", icon: <Users className="w-4 h-4" /> },
      ],
    },
    {
      label: "ADMINISTRATION",
      items: [
        { to: "/settings", label: "System Config", icon: <Settings className="w-4 h-4" /> },
        { to: "/audit", label: "Audit Logs", icon: <ScrollText className="w-4 h-4" /> },
      ],
    },
  ];

  return (
    <aside
      className={`border-r border-border-subtle bg-bg-surface1 flex flex-col transition-all duration-300 select-none z-30 shrink-0 ${
        collapsed ? "w-16" : "w-60"
      }`}
    >
      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
        {navGroups.map((group) => (
          <div key={group.label} className="space-y-1">
            {!collapsed && (
              <div className="px-3 text-[10px] font-mono uppercase font-bold tracking-wider text-slate-500">
                {group.label}
              </div>
            )}
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                title={collapsed ? item.label : undefined}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-mono transition-colors relative group ${
                    isActive
                      ? "bg-cyan-500/15 text-cyan-300 font-semibold border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)]"
                      : "text-slate-400 hover:text-slate-200 hover:bg-bg-hover border border-transparent"
                  } ${collapsed ? "justify-center" : ""}`
                }
              >
                <div className="shrink-0">{item.icon}</div>
                {!collapsed && (
                  <div className="flex-1 flex items-center justify-between truncate">
                    <span className="truncate">{item.label}</span>
                    {item.badge && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-500/30 font-bold ml-1.5">
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </div>

      {/* Collapse Toggle Footer */}
      <div className="p-2 border-t border-border-subtle bg-bg-surface2/40">
        <button
          onClick={onToggleCollapse}
          className="w-full flex items-center justify-center p-2 rounded-lg text-slate-400 hover:text-white hover:bg-bg-hover transition-colors text-xs font-mono"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          {!collapsed && <span className="ml-2 text-[11px]">Collapse View</span>}
        </button>
      </div>
    </aside>
  );
};
