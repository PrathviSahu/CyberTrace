import React, { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Node,
  Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ShieldAlert,
  Sparkles,
  User,
  Server,
  Globe,
  Crosshair,
  Check,
  ArrowRight,
} from "lucide-react";
import { api } from "../services/api";
import {
  IncidentDetail,
  InvestigationResponse,
  CommonEvent,
  IncidentStatus,
} from "../types";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";
import { EvidenceCitation } from "../components/common/EvidenceCitation";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";

interface IncidentWorkspaceProps {
  activeModel: string;
}

export const IncidentWorkspace: React.FC<IncidentWorkspaceProps> = ({ activeModel }) => {
  const { id = "INC-001" } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [dossier, setDossier] = useState<IncidentDetail | null>(null);
  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<CommonEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [approvedActions, setApprovedActions] = useState<Record<string, boolean>>({});
  const [incidentStatus, setIncidentStatus] = useState<IncidentStatus>("open");

  // ReactFlow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  const loadData = useCallback(async () => {
    setLoading(true);
    const detail = await api.getIncident(id);
    setDossier(detail);
    setIncidentStatus(detail.incident.status);

    const invs = await api.getInvestigations(id);
    if (invs && invs.length > 0) {
      setInvestigation(invs[0]);
    }

    // Build attack graph
    const { nodes: gNodes, edges: gEdges } = api.buildAttackGraph(
      detail.incident,
      detail.detections,
      detail.events
    );

    // Map to ReactFlow format with layout coordinates
    const rfNodes: Node[] = gNodes.map((n, idx) => {
      let x = 280;
      let y = 180;

      if (n.type === "incident") {
        x = 280;
        y = 180;
      } else if (n.type === "user") {
        x = 80;
        y = 60 + idx * 110;
      } else if (n.type === "host") {
        x = 280;
        y = 340;
      } else if (n.type === "ip") {
        x = 480;
        y = 120 + idx * 110;
      } else if (n.type === "detection") {
        x = 100 + idx * 140;
        y = 480;
      }

      const getNodeIcon = () => {
        if (n.type === "user") return <User className="w-4 h-4 text-cyan-400" />;
        if (n.type === "host") return <Server className="w-4 h-4 text-emerald-400" />;
        if (n.type === "ip") return <Globe className="w-4 h-4 text-red-400" />;
        if (n.type === "detection") return <Crosshair className="w-4 h-4 text-amber-400" />;
        return <ShieldAlert className="w-5 h-5 text-red-500" />;
      };

      return {
        id: n.id,
        position: { x, y },
        data: {
          label: (
            <div className="p-2.5 rounded-xl bg-bg-surface1 border border-border-subtle shadow-card hover:border-cyan-500/50 transition-all min-w-[140px] text-left">
              <div className="flex items-center gap-1.5 mb-1">
                {getNodeIcon()}
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                  {n.type}
                </span>
              </div>
              <div className="text-xs font-mono font-bold text-white truncate">{n.label}</div>
              {n.subLabel && (
                <div className="text-[10px] font-mono text-slate-400 truncate mt-0.5">
                  {n.subLabel}
                </div>
              )}
            </div>
          ),
        },
      };
    });

    const rfEdges: Edge[] = gEdges.map((e) => {
      let strokeColor = "#06b6d4"; // observed
      let strokeDash = undefined;

      if (e.edgeType === "correlated") {
        strokeColor = "#818cf8";
        strokeDash = "5 5";
      } else if (e.edgeType === "inferred") {
        strokeColor = "#f59e0b";
        strokeDash = "3 3";
      }

      return {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        type: "smoothstep",
        animated: e.edgeType === "observed",
        style: { stroke: strokeColor, strokeWidth: 1.5, strokeDasharray: strokeDash },
        labelStyle: { fill: "#94a3b8", fontFamily: "JetBrains Mono", fontSize: 10 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 14,
          height: 14,
        },
      };
    });

    setNodes(rfNodes);
    setEdges(rfEdges);
    setLoading(false);
  }, [id, setNodes, setEdges]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleRunInvestigation = async () => {
    if (!dossier) return;
    setInvestigating(true);
    try {
      const inv = await api.triggerInvestigation(dossier.incident.id, activeModel);
      setInvestigation(inv);
    } catch (err) {
      console.error("Investigation failed:", err);
    } finally {
      setInvestigating(false);
    }
  };

  const handleOpenEventCitation = (eventId: string) => {
    if (!dossier) return;
    const evt = dossier.events.find((e) => e.id === eventId);
    if (evt) {
      setSelectedEvent(evt);
      setDrawerOpen(true);
    }
  };

  const handleApproveAction = (index: number) => {
    setApprovedActions((prev) => ({ ...prev, [index]: true }));
  };

  if (loading || !dossier) {
    return (
      <div className="flex-1 flex items-center justify-center p-12 text-slate-400 font-mono text-xs">
        Loading Incident Dossier and Attack Graph...
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col h-[calc(100vh-3.5rem)] overflow-hidden bg-bg-base select-none">
      {/* Top Workspace Bar */}
      <div className="h-14 border-b border-border-subtle bg-bg-surface1 px-6 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate("/")}
            className="text-xs font-mono text-slate-400 hover:text-white"
          >
            ← Incidents
          </button>
          <span className="text-slate-600">/</span>
          <span className="text-base font-mono font-bold text-white tracking-wide">
            {dossier.incident.id}
          </span>
          <SeverityBadge severity={dossier.incident.severity} size="sm" />
          <DataProvenanceBadge provenance={dossier.incident.provenance} size="sm" />
          <span className="text-xs font-mono text-slate-300 font-semibold truncate max-w-md ml-1">
            {dossier.incident.title}
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* Status selector */}
          <select
            value={incidentStatus}
            onChange={(e) => setIncidentStatus(e.target.value as IncidentStatus)}
            className="px-2.5 py-1.5 rounded-lg bg-bg-surface2 border border-border-subtle text-xs font-mono text-slate-200 outline-none cursor-pointer"
          >
            <option value="open">STATUS: OPEN</option>
            <option value="in_progress">STATUS: IN PROGRESS</option>
            <option value="contained">STATUS: CONTAINED</option>
            <option value="resolved">STATUS: RESOLVED</option>
            <option value="closed">STATUS: CLOSED</option>
          </select>

          {/* Trigger AI Investigation Button */}
          <button
            onClick={handleRunInvestigation}
            disabled={investigating}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-indigo-600 hover:opacity-90 disabled:opacity-50 text-white font-mono font-bold text-xs transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)]"
          >
            <Sparkles className={`w-3.5 h-3.5 ${investigating ? "animate-spin" : ""}`} />
            <span>{investigating ? "Investigating..." : "Run AI Investigation"}</span>
          </button>
        </div>
      </div>

      {/* Flagship 3-Panel Split Layout */}
      <div className="flex-1 grid grid-cols-12 overflow-hidden">
        {/* PANEL 1: Left Dossier & Chronological Timeline (3 Cols) */}
        <div className="col-span-3 border-r border-border-subtle bg-bg-surface1/80 flex flex-col overflow-hidden">
          <div className="px-4 py-3 border-b border-border-subtle bg-bg-surface2/40 flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Evidence Dossier
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-bg-surface1 text-slate-400 border border-border-subtle">
              {dossier.events.length} Events • {dossier.detections.length} Rules
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* Incident Metadata Box */}
            <div className="p-3 bg-bg-surface2/40 border border-border-subtle rounded-xl space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-slate-400">Correlation Key:</span>
                <span className="text-cyan-300 font-bold truncate max-w-[140px]" title={dossier.incident.correlation_key}>
                  {dossier.incident.correlation_key}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">First Seen:</span>
                <span className="text-slate-200">{dossier.incident.first_seen.slice(11, 19)} UTC</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Last Seen:</span>
                <span className="text-slate-200">{dossier.incident.last_seen.slice(11, 19)} UTC</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Owner:</span>
                <span className="text-slate-200">{dossier.incident.owner || "Unassigned"}</span>
              </div>
            </div>

            {/* Entity Breakdown */}
            <div className="space-y-2">
              <div className="text-xs font-mono font-bold uppercase text-slate-400">
                Correlated Entities
              </div>
              <div className="space-y-1.5">
                {dossier.entities.map((ent, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-bg-surface2/50 border border-border-subtle flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center gap-2 truncate">
                      {ent.entity_type === "user" ? (
                        <User className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      ) : ent.entity_type === "destination_ip" ? (
                        <Globe className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      ) : (
                        <Server className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      )}
                      <span className="text-white font-medium truncate">{ent.entity_value}</span>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-bg-surface1 text-slate-400 border border-border-subtle shrink-0">
                      {ent.relationship.replace("_", " ")}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Chronological Event Timeline */}
            <div className="space-y-2">
              <div className="text-xs font-mono font-bold uppercase text-slate-400">
                Chronological Sequence
              </div>
              <div className="space-y-2 relative before:absolute before:top-2 before:bottom-2 before:left-3 before:w-0.5 before:bg-border-subtle">
                {dossier.events.map((evt) => (
                  <div
                    key={evt.id}
                    onClick={() => handleOpenEventCitation(evt.id)}
                    className="relative pl-7 cursor-pointer group"
                  >
                    <div className="absolute left-2 top-2.5 w-2 h-2 rounded-full bg-cyan-400 ring-4 ring-bg-surface1 group-hover:bg-cyan-300 transition-colors" />
                    <div className="p-2.5 rounded-lg bg-bg-surface2/60 border border-border-subtle group-hover:border-cyan-500/40 transition-colors">
                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                        <span>{evt.timestamp.slice(11, 19)} UTC</span>
                        <EvidenceCitation eventId={evt.id} onClick={handleOpenEventCitation} />
                      </div>
                      <div className="text-xs font-mono font-bold text-slate-200 capitalize">
                        {evt.action.replace("_", " ")}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                        {evt.username || evt.hostname || evt.source_type}
                      </div>
                      {evt.bytes_out && (
                        <div className="text-[10px] font-mono text-red-400 font-bold mt-1">
                          Egress: {(evt.bytes_out / 1024 / 1024).toFixed(1)} MB
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* PANEL 2: Center Interactive Attack Graph (5 Cols) */}
        <div className="col-span-5 border-r border-border-subtle relative bg-bg-base flex flex-col">
          <div className="px-4 py-3 border-b border-border-subtle bg-bg-surface1/60 flex items-center justify-between z-10">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Adversary Attack Graph
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                XYFLOW REACT
              </span>
            </div>

            {/* Edge Legend */}
            <div className="flex items-center gap-3 text-[10px] font-mono text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-0.5 bg-cyan-400 inline-block" /> Observed
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-0.5 border-t border-dashed border-indigo-400 inline-block" /> Correlated
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-0.5 border-t border-dotted border-amber-400 inline-block" /> Inferred
              </span>
            </div>
          </div>

          {/* Canvas */}
          <div className="flex-1 w-full h-full">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              fitView
              minZoom={0.5}
              maxZoom={1.5}
            >
              <Background color="#162035" gap={18} size={1} />
              <Controls />
              <MiniMap
                nodeColor="#0e1626"
                maskColor="rgba(8, 12, 20, 0.7)"
                style={{ backgroundColor: "#080c14", border: "1px solid rgba(255,255,255,0.08)" }}
              />
            </ReactFlow>
          </div>

          {/* Quick Bottom Bar */}
          <div className="px-4 py-2 border-t border-border-subtle bg-bg-surface1/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Graph correlation key: {dossier.incident.correlation_key}</span>
            <button
              onClick={() => handleOpenEventCitation(dossier.events[0]?.id)}
              className="text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1"
            >
              <span>Inspect Primary Event</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* PANEL 3: Right AI Investigation Findings (4 Cols) */}
        <div className="col-span-4 bg-bg-surface1/80 flex flex-col overflow-hidden">
          <div className="px-4 py-3 border-b border-border-subtle bg-bg-surface2/40 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                AI Investigation Findings
              </span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              100% EVIDENCE GROUNDED
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-5">
            {investigation ? (
              <>
                {/* Executive Summary */}
                <div className="p-3.5 rounded-xl bg-bg-surface2/50 border border-border-subtle space-y-2">
                  <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
                    <span>Executive Summary</span>
                    <span className="text-cyan-400">{investigation.model_id}</span>
                  </div>
                  <p className="text-xs font-mono text-slate-200 leading-relaxed">
                    {investigation.executive_summary}
                  </p>
                  <div className="pt-2 border-t border-border-subtle flex items-center justify-between text-[10px] font-mono text-slate-500">
                    <span>Tool Calls: {investigation.tool_call_count}</span>
                    <span>Triage Latency: {investigation.duration_seconds}s</span>
                  </div>
                </div>

                {/* Section 1: Observed Facts */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold uppercase text-slate-400">
                      Observed Facts ({investigation.structured_result.observed_facts.length})
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400">Ground Truth</span>
                  </div>
                  <div className="space-y-2">
                    {investigation.structured_result.observed_facts.map((fact, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-bg-surface2/40 border border-border-subtle space-y-2"
                      >
                        <p className="text-xs font-mono text-slate-200 leading-relaxed">
                          {fact.statement}
                        </p>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[10px] font-mono text-slate-500">Evidence:</span>
                          {fact.event_ids.map((eid) => (
                            <EvidenceCitation
                              key={eid}
                              eventId={eid}
                              onClick={handleOpenEventCitation}
                            />
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Section 2: Hypotheses & Caveats */}
                <div className="space-y-2">
                  <div className="text-xs font-mono font-bold uppercase text-slate-400">
                    Analytic Hypotheses ({investigation.structured_result.hypotheses.length})
                  </div>
                  <div className="space-y-2">
                    {investigation.structured_result.hypotheses.map((hyp, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-bg-surface2/40 border border-border-subtle space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                            Confidence: {hyp.confidence}
                          </span>
                          <div className="flex items-center gap-1">
                            {hyp.supporting_event_ids.map((eid) => (
                              <EvidenceCitation
                                key={eid}
                                eventId={eid}
                                onClick={handleOpenEventCitation}
                              />
                            ))}
                          </div>
                        </div>
                        <p className="text-xs font-mono text-slate-300">{hyp.statement}</p>
                        {hyp.caveats && hyp.caveats.length > 0 && (
                          <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-[11px] font-mono text-amber-300">
                            ⚠️ {hyp.caveats[0]}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Section 3: Unknowns & Information Gaps */}
                <div className="space-y-2">
                  <div className="text-xs font-mono font-bold uppercase text-slate-400">
                    Unknowns & Telemetry Gaps ({investigation.structured_result.unknowns.length})
                  </div>
                  <div className="space-y-2">
                    {investigation.structured_result.unknowns.map((unk, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-bg-surface2/30 border border-border-subtle text-xs font-mono"
                      >
                        <div className="text-slate-200 font-medium">{unk.question}</div>
                        <div className="text-[11px] text-slate-500 mt-1">{unk.reason}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Section 4: Recommended Actions (Human in the Loop) */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold uppercase text-slate-400">
                      Recommended Actions
                    </span>
                    <span className="text-[10px] font-mono text-amber-400">Requires Approval</span>
                  </div>
                  <div className="space-y-2">
                    {investigation.structured_result.recommended_actions.map((act, idx) => {
                      const isApproved = approvedActions[idx];
                      return (
                        <div
                          key={idx}
                          className={`p-3 rounded-xl border transition-all ${
                            isApproved
                              ? "bg-emerald-950/30 border-emerald-500/40"
                              : "bg-bg-surface2/40 border-border-subtle"
                          } space-y-2`}
                        >
                          <div className="flex items-center justify-between text-xs font-mono">
                            <span className="font-bold text-white">{act.action}</span>
                            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-bg-surface1 text-slate-400 border border-border-subtle">
                              {act.impact} impact
                            </span>
                          </div>
                          <p className="text-[11px] font-mono text-slate-400 leading-relaxed">
                            {act.rationale}
                          </p>

                          <div className="flex items-center justify-between pt-2 border-t border-border-subtle">
                            <div className="flex items-center gap-1">
                              {act.supporting_event_ids.map((eid) => (
                                <EvidenceCitation
                                  key={eid}
                                  eventId={eid}
                                  onClick={handleOpenEventCitation}
                                />
                              ))}
                            </div>

                            {isApproved ? (
                              <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400 font-bold">
                                <Check className="w-3.5 h-3.5" />
                                Action Approved
                              </span>
                            ) : (
                              <button
                                onClick={() => handleApproveAction(idx)}
                                className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500 hover:text-black border border-cyan-500/40 text-cyan-300 text-[11px] font-mono font-bold transition-all"
                              >
                                Approve Action
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            ) : (
              <div className="py-12 text-center space-y-3">
                <Sparkles className="w-8 h-8 text-cyan-400 mx-auto" />
                <div className="text-xs font-mono text-slate-300">
                  No automated investigation generated yet.
                </div>
                <button
                  onClick={handleRunInvestigation}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-mono font-bold transition-all"
                >
                  Start Investigation
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Slide-over Evidence Drawer */}
      <EvidenceDrawer
        event={selectedEvent}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />
    </div>
  );
};
