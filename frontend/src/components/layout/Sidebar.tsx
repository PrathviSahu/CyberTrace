import React from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  Inbox,
  Crosshair,
  FlaskConical,
  FileCode2,
  Activity,
  Server,
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
      label: "Operations",
      items: [
        { to: "/", label: "Command Centre", icon: <LayoutDashboard className="w-4 h-4" /> },
        { to: "/incidents/INC-001", label: "Incident Workspace", icon: <ShieldAlert className="w-4 h-4" />, badge: "Active" },
        { to: "/alerts", label: "Alert Inbox", icon: <Inbox className="w-4 h-4" /> },
      ],
    },
    {
      label: "Investigation",
      items: [
        { to: "/hunting", label: "Threat Hunting", icon: <Crosshair className="w-4 h-4" /> },
        { to: "/assets", label: "Assets & Identities", icon: <Server className="w-4 h-4" /> },
      ],
    },
    {
      label: "Detection & Evaluation",
      items: [
        { to: "/rules", label: "Detection Rules", icon: <FileCode2 className="w-4 h-4" /> },
        { to: "/threatlab", label: "ThreatLab Benchmark", icon: <FlaskConical className="w-4 h-4" />, badge: "Eval" },
        { to: "/telemetry", label: "Telemetry & Pipelines", icon: <Activity className="w-4 h-4" /> },
      ],
    },
  ];

  return (
    <aside
      className={`border-r border-[#30363C] bg-[#191C1F] flex flex-col transition-all duration-200 select-none z-30 shrink-0 ${
        collapsed ? "w-16" : "w-[244px]"
      }`}
    >
      {/* Navigation Groups */}
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
        {navGroups.map((group) => (
          <div key={group.label} className="space-y-1">
            {!collapsed && (
              <div className="px-3 text-[11px] font-medium text-[#737D87] mb-1.5">
                {group.label}
              </div>
            )}
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                title={collapsed ? item.label : undefined}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 text-xs font-medium transition-colors relative group ${
                    isActive
                      ? "bg-[#2B2722] text-[#E9ECEF] border-l-2 border-[#B58A61] rounded-r-md"
                      : "text-[#A0A7AE] hover:text-[#E9ECEF] hover:bg-[#24282C] rounded-md border-l-2 border-transparent"
                  } ${collapsed ? "justify-center" : ""}`
                }
              >
                <div className="shrink-0">{item.icon}</div>
                {!collapsed && (
                  <div className="flex-1 flex items-center justify-between truncate">
                    <span className="truncate">{item.label}</span>
                    {item.badge && (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#24282C] text-[#B58A61] font-medium ml-1.5">
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
      <div className="p-3 border-t border-[#30363C] bg-[#191C1F]">
        <button
          onClick={onToggleCollapse}
          className="w-full flex items-center justify-center p-1.5 rounded-md text-[#737D87] hover:text-[#E9ECEF] hover:bg-[#24282C] transition-colors text-xs cursor-pointer"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>
    </aside>
  );
};
