import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { Header } from "./components/layout/Header";
import { Sidebar } from "./components/layout/Sidebar";
import { CommandCentre } from "./views/CommandCentre";
import { IncidentWorkspace } from "./views/IncidentWorkspace";
import { AlertInbox } from "./views/AlertInbox";
import { ThreatHunting } from "./views/ThreatHunting";
import { ThreatLab } from "./views/ThreatLab";
import { AssetInventory } from "./views/AssetInventory";
import { DetectionRules } from "./views/DetectionRules";
import { TelemetryPipelines } from "./views/TelemetryPipelines";
import { CommandPalette } from "./components/common/CommandPalette";
import { LogUploadModal } from "./components/common/LogUploadModal";

export function App() {
  const [collapsed, setCollapsed] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [activeModel, setActiveModel] = useState("qwen-3.8-27b");

  return (
    <Router>
      <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#111315] text-[#E9ECEF] font-sans">
        {/* Persistent SOC Command Header */}
        <Header
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          onOpenUpload={() => setUploadModalOpen(true)}
          activeModel={activeModel}
          onSelectModel={setActiveModel}
        />

        {/* Main Body Split: Collapsible Sidebar + Dynamic View */}
        <div className="flex flex-1 overflow-hidden relative">
          <Sidebar
            collapsed={collapsed}
            onToggleCollapse={() => setCollapsed(!collapsed)}
          />

          <main className="flex-1 flex overflow-hidden relative bg-[#111315]">
            <Routes>
              <Route
                path="/"
                element={<CommandCentre onOpenUpload={() => setUploadModalOpen(true)} />}
              />
              <Route
                path="/incidents/:id"
                element={<IncidentWorkspace activeModel={activeModel} />}
              />
              <Route path="/incidents" element={<Navigate to="/" replace />} />
              <Route path="/alerts" element={<AlertInbox />} />
              <Route path="/hunting" element={<ThreatHunting />} />
              <Route path="/threatlab" element={<ThreatLab />} />
              <Route path="/assets" element={<AssetInventory />} />
              <Route path="/rules" element={<DetectionRules />} />
              <Route
                path="/telemetry"
                element={<TelemetryPipelines onOpenUpload={() => setUploadModalOpen(true)} />}
              />
              {/* Clean aliases for secondary paths */}
              <Route path="/entities" element={<Navigate to="/incidents/INC-001" replace />} />
              <Route path="/mitre" element={<Navigate to="/rules" replace />} />
              <Route path="/pipelines" element={<Navigate to="/telemetry" replace />} />
              <Route path="/identities" element={<Navigate to="/assets" replace />} />
              <Route path="/settings" element={<Navigate to="/telemetry" replace />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>

        {/* Global Modals */}
        <CommandPalette
          isOpen={commandPaletteOpen}
          onClose={() => setCommandPaletteOpen(false)}
          onOpenUpload={() => setUploadModalOpen(true)}
        />

        <LogUploadModal
          isOpen={uploadModalOpen}
          onClose={() => setUploadModalOpen(false)}
        />
      </div>
    </Router>
  );
}

export default App;
