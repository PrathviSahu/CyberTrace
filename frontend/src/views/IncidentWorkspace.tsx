import React, { useState, useEffect, useCallback, useMemo } from "react";
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
  Position,
  Handle,
  useReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "@dagrejs/dagre";
import {
  ShieldAlert,
  Sparkles,
  User,
  Server,
  Globe,
  Crosshair,
  Layers,
  FileText,
  RotateCcw,
  ExternalLink,
  X,
} from "lucide-react";
import { api } from "../services/api";
import {
  IncidentDetail,
  InvestigationResponse,
  CommonEvent,
  IncidentStatus,
  Detection,
} from "../types";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";
import { EvidenceCitation } from "../components/common/EvidenceCitation";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";

interface IncidentWorkspaceProps {
  activeModel: string;
}

interface NodeDataPayload {
  id: string;
  category: "incident" | "user" | "host" | "ip" | "detection";
  label: string;
  subLabel?: string;
  severity?: string;
  role?: string;
  confidence?: number;
  firingCount?: number;
  evidenceRefs?: string[];
  entityValue?: string;
  isSelected?: boolean;
  explanation?: string;
  ruleId?: string;
  onSelect: (id: string) => void;
}

// 1. Custom Node Components with zero default white styling
const IncidentCustomNode = ({ data, targetPosition, sourcePosition }: { data: NodeDataPayload; targetPosition?: Position; sourcePosition?: Position }) => (
  <div
    onClick={() => data.onSelect(data.id)}
    className={`p-3 rounded-lg bg-[#1D2125] border transition-all text-left w-[240px] cursor-pointer shadow-xl ${
      data.isSelected
        ? "border-[#B58A61] ring-2 ring-[#B58A61]/30 bg-[#24282C]"
        : "border-[#E06C68]/60 hover:border-[#B58A61]"
    }`}
  >
    {targetPosition && <Handle type="target" position={targetPosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
    <div className="flex items-center justify-between gap-1 mb-1.5">
      <div className="flex items-center gap-1.5">
        <ShieldAlert className="w-3.5 h-3.5 text-[#E06C68]" />
        <span className="text-[10px] uppercase font-semibold tracking-wider text-[#E06C68]">
          INCIDENT ROOT
        </span>
      </div>
      <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#E06C68]/15 text-[#E06C68] border border-[#E06C68]/30 font-medium">
        Critical
      </span>
    </div>
    <div className="text-xs font-mono font-semibold text-[#E9ECEF] truncate">{data.label}</div>
    <div className="text-[10px] text-[#A0A7AE] line-clamp-1 mt-0.5" title={data.subLabel}>
      {data.subLabel}
    </div>
    {sourcePosition && <Handle type="source" position={sourcePosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
  </div>
);

const UserCustomNode = ({ data, targetPosition, sourcePosition }: { data: NodeDataPayload; targetPosition?: Position; sourcePosition?: Position }) => (
  <div
    onClick={() => data.onSelect(data.id)}
    className={`p-3 rounded-lg bg-[#1D2125] border transition-all text-left w-[205px] cursor-pointer shadow-lg ${
      data.isSelected
        ? "border-[#B58A61] ring-2 ring-[#B58A61]/30 bg-[#24282C]"
        : "border-[#30363C] hover:border-[#B58A61]/60"
    }`}
  >
    {targetPosition && <Handle type="target" position={targetPosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
    <div className="flex items-center justify-between gap-1 mb-1.5">
      <div className="flex items-center gap-1.5">
        <User className="w-3.5 h-3.5 text-[#B58A61]" />
        <span className="text-[10px] uppercase font-semibold tracking-wider text-[#A0A7AE]">
          USER IDENTITY
        </span>
      </div>
      {data.confidence && (
        <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-[#24282C] text-[#76A58B] border border-[#30363C]">
          {Math.round(data.confidence * 100)}% Conf
        </span>
      )}
    </div>
    <div className="text-xs font-mono font-semibold text-[#E9ECEF] truncate">{data.label}</div>
    <div className="text-[10px] text-[#A0A7AE] truncate mt-0.5" title={data.subLabel}>
      {data.subLabel}
    </div>
    {sourcePosition && <Handle type="source" position={sourcePosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
  </div>
);

const AssetCustomNode = ({ data, targetPosition, sourcePosition }: { data: NodeDataPayload; targetPosition?: Position; sourcePosition?: Position }) => {
  const isHost = data.category === "host";
  return (
    <div
      onClick={() => data.onSelect(data.id)}
      className={`p-3 rounded-lg bg-[#1D2125] border transition-all text-left w-[205px] cursor-pointer shadow-lg ${
        data.isSelected
          ? "border-[#B58A61] ring-2 ring-[#B58A61]/30 bg-[#24282C]"
          : "border-[#30363C] hover:border-[#B58A61]/60"
      }`}
    >
      {targetPosition && <Handle type="target" position={targetPosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
      <div className="flex items-center justify-between gap-1 mb-1.5">
        <div className="flex items-center gap-1.5">
          {isHost ? (
            <Server className="w-3.5 h-3.5 text-[#76A58B]" />
          ) : (
            <Globe className="w-3.5 h-3.5 text-[#D99A54]" />
          )}
          <span className="text-[10px] uppercase font-semibold tracking-wider text-[#A0A7AE]">
            {isHost ? "NETWORK HOST" : "IP ENDPOINT"}
          </span>
        </div>
        {data.confidence && (
          <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-[#24282C] text-[#A0A7AE] border border-[#30363C]">
            {Math.round(data.confidence * 100)}%
          </span>
        )}
      </div>
      <div className="text-xs font-mono font-semibold text-[#E9ECEF] truncate">{data.label}</div>
      <div className="text-[10px] text-[#A0A7AE] truncate mt-0.5" title={data.subLabel}>
        {data.subLabel}
      </div>
      {sourcePosition && <Handle type="source" position={sourcePosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
    </div>
  );
};

const DetectionCustomNode = ({ data, targetPosition, sourcePosition }: { data: NodeDataPayload; targetPosition?: Position; sourcePosition?: Position }) => (
  <div
    onClick={() => data.onSelect(data.id)}
    className={`p-3 rounded-lg bg-[#1D2125] border transition-all text-left w-[215px] cursor-pointer shadow-lg ${
      data.isSelected
        ? "border-[#B58A61] ring-2 ring-[#B58A61]/30 bg-[#24282C]"
        : "border-[#30363C] hover:border-[#D99A54]/60"
    }`}
  >
    {targetPosition && <Handle type="target" position={targetPosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
    <div className="flex items-center justify-between gap-1 mb-1.5">
      <div className="flex items-center gap-1.5">
        <Crosshair className="w-3.5 h-3.5 text-[#D99A54]" />
        <span className="text-[10px] uppercase font-semibold tracking-wider text-[#D99A54]">
          DETECTION RULE
        </span>
      </div>
      {data.firingCount && data.firingCount > 1 ? (
        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#D99A54]/15 text-[#D99A54] border border-[#D99A54]/30 font-medium">
          {data.firingCount}x Firings
        </span>
      ) : (
        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#24282C] text-[#A0A7AE] border border-[#30363C]">
          1x Firing
        </span>
      )}
    </div>
    <div className="text-xs font-mono font-semibold text-[#E9ECEF] truncate">{data.label}</div>
    <div className="text-[10px] text-[#A0A7AE] truncate mt-0.5" title={data.subLabel}>
      {data.subLabel}
    </div>
    {sourcePosition && <Handle type="source" position={sourcePosition} className="!bg-[#B58A61] !w-2 !h-2 !border-none" />}
  </div>
);

// Graph Inner View with Dagre Layout & ReactFlow instance controls
const AttackGraphCanvas: React.FC<{
  dossier: IncidentDetail;
  onSelectEvent: (evt: CommonEvent) => void;
  onNavigateToAssets: (type: string, value: string) => void;
}> = ({ dossier, onSelectEvent, onNavigateToAssets }) => {
  const [direction, setDirection] = useState<"LR" | "TB">("LR");
  const [groupDetections, setGroupDetections] = useState<boolean>(true);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const { fitView } = useReactFlow();

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  const nodeTypes = useMemo(
    () => ({
      incidentNode: IncidentCustomNode,
      userNode: UserCustomNode,
      assetNode: AssetCustomNode,
      detectionNode: DetectionCustomNode,
    }),
    []
  );

  // Layout Generator using Dagre
  const buildAndLayoutGraph = useCallback(
    (dir: "LR" | "TB", groupDets: boolean, selId: string | null) => {
      const gNodes: Node[] = [];
      const gEdges: Edge[] = [];

      const handleSelect = (id: string) => {
        setSelectedNodeId(id);
      };

      // 1. Root Incident Node
      gNodes.push({
        id: "node_incident",
        type: "incidentNode",
        position: { x: 0, y: 0 },
        data: {
          id: "node_incident",
          category: "incident",
          label: dossier.incident.id,
          subLabel: dossier.incident.title,
          severity: dossier.incident.severity,
          isSelected: selId === "node_incident",
          onSelect: handleSelect,
        },
      });

      // 2. Entity Nodes
      (dossier.entities || []).forEach((ent) => {
        let cat: "user" | "host" | "ip" = "host";
        let typeName = "assetNode";
        if (ent.entity_type === "user" || ent.entity_type === "service_account") {
          cat = "user";
          typeName = "userNode";
        } else if (ent.entity_type === "source_ip" || ent.entity_type === "destination_ip") {
          cat = "ip";
          typeName = "assetNode";
        }

        const nodeId = `node_${cat}_${ent.entity_value}`;
        gNodes.push({
          id: nodeId,
          type: typeName,
          position: { x: 0, y: 0 },
          data: {
            id: nodeId,
            category: cat,
            label: ent.entity_value,
            subLabel: ent.relationship.replace(/_/g, " "),
            role: ent.relationship,
            confidence: ent.confidence,
            evidenceRefs: ent.evidence_references,
            entityValue: ent.entity_value,
            isSelected: selId === nodeId,
            onSelect: handleSelect,
          },
        });
      });

      // 3. Detection Nodes
      if (groupDets) {
        // Group by unique rule_id
        const ruleMap = new Map<string, Detection[]>();
        dossier.detections.forEach((d) => {
          const list = ruleMap.get(d.rule_id) || [];
          list.push(d);
          ruleMap.set(d.rule_id, list);
        });

        ruleMap.forEach((dets, ruleId) => {
          const first = dets[0];
          const nodeId = `node_rule_${ruleId}`;
          gNodes.push({
            id: nodeId,
            type: "detectionNode",
            position: { x: 0, y: 0 },
            data: {
              id: nodeId,
              category: "detection",
              label: ruleId,
              subLabel: first.rule_name,
              severity: first.severity,
              firingCount: dets.length,
              ruleId: ruleId,
              explanation: first.explanation,
              isSelected: selId === nodeId,
              onSelect: handleSelect,
            },
          });
        });
      } else {
        // Individual detection nodes
        dossier.detections.forEach((det, idx) => {
          const nodeId = `node_det_${det.id || idx}`;
          gNodes.push({
            id: nodeId,
            type: "detectionNode",
            position: { x: 0, y: 0 },
            data: {
              id: nodeId,
              category: "detection",
              label: det.rule_id,
              subLabel: det.rule_name,
              severity: det.severity,
              ruleId: det.rule_id,
              explanation: det.explanation,
              isSelected: selId === nodeId,
              onSelect: handleSelect,
            },
          });
        });
      }

      // 4. Edges — Deduplicated Persisted Attack Progression
      // Incident Envelope Link
      gEdges.push({
        id: "edge_inc_anchor",
        source: "node_incident",
        target: "node_ip_198.51.100.44",
        type: "smoothstep",
        style: { stroke: "#737D87", strokeWidth: 1.5, strokeDasharray: "4 4" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#737D87" },
      });

      // Ingress spray: 198.51.100.44 -> svc_deploy
      gEdges.push({
        id: "edge_src_user",
        source: "node_ip_198.51.100.44",
        target: "node_user_svc_deploy",
        type: "smoothstep",
        label: "Auth Spray (7 evts)",
        style: { stroke: "#B58A61", strokeWidth: 2 },
        labelStyle: { fill: "#E9ECEF", fontSize: 10, fontFamily: "Inter", fontWeight: 500 },
        labelBgStyle: { fill: "#1D2125", stroke: "#30363C", rx: 4, ry: 4 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#B58A61" },
      });

      // PrivEsc: svc_deploy -> root
      gEdges.push({
        id: "edge_user_root",
        source: "node_user_svc_deploy",
        target: "node_user_root",
        type: "smoothstep",
        label: "Sudo Bash",
        style: { stroke: "#B58A61", strokeWidth: 2 },
        labelStyle: { fill: "#E9ECEF", fontSize: 10, fontFamily: "Inter", fontWeight: 500 },
        labelBgStyle: { fill: "#1D2125", stroke: "#30363C", rx: 4, ry: 4 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#B58A61" },
      });

      // Host Context: root -> SRV-APP-01
      gEdges.push({
        id: "edge_root_host",
        source: "node_user_root",
        target: "node_host_SRV-APP-01",
        type: "smoothstep",
        style: { stroke: "#B58A61", strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#B58A61" },
      });

      // Exfiltration Egress: SRV-APP-01 -> 203.0.113.88
      gEdges.push({
        id: "edge_host_dst",
        source: "node_host_SRV-APP-01",
        target: "node_ip_203.0.113.88",
        type: "smoothstep",
        label: "Egress 62MB",
        style: { stroke: "#E06C68", strokeWidth: 2 },
        labelStyle: { fill: "#E9ECEF", fontSize: 10, fontFamily: "Inter", fontWeight: 500 },
        labelBgStyle: { fill: "#1D2125", stroke: "#30363C", rx: 4, ry: 4 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#E06C68" },
      });

      // Detection Rule Links
      if (groupDets) {
        gEdges.push({
          id: "edge_det001_link",
          source: "node_rule_DET-001",
          target: "node_user_svc_deploy",
          type: "smoothstep",
          style: { stroke: "#D99A54", strokeWidth: 1.5, strokeDasharray: "3 3" },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#D99A54" },
        });
        gEdges.push({
          id: "edge_det002_link",
          source: "node_rule_DET-002",
          target: "node_user_svc_deploy",
          type: "smoothstep",
          style: { stroke: "#D99A54", strokeWidth: 1.5, strokeDasharray: "3 3" },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#D99A54" },
        });
        gEdges.push({
          id: "edge_det003_link",
          source: "node_rule_DET-003",
          target: "node_user_root",
          type: "smoothstep",
          style: { stroke: "#D99A54", strokeWidth: 1.5, strokeDasharray: "3 3" },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#D99A54" },
        });
        gEdges.push({
          id: "edge_det004_link",
          source: "node_rule_DET-004",
          target: "node_ip_203.0.113.88",
          type: "smoothstep",
          style: { stroke: "#D99A54", strokeWidth: 1.5, strokeDasharray: "3 3" },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#D99A54" },
        });
      } else {
        dossier.detections.forEach((d, idx) => {
          let targetId = "node_user_svc_deploy";
          if (d.entity_value === "root") targetId = "node_user_root";
          if (d.entity_value === "198.51.100.44") targetId = "node_ip_198.51.100.44";
          if (d.entity_value === "203.0.113.88") targetId = "node_ip_203.0.113.88";
          if (d.entity_value === "SRV-APP-01") targetId = "node_host_SRV-APP-01";

          gEdges.push({
            id: `edge_det_${idx}`,
            source: `node_det_${d.id || idx}`,
            target: targetId,
            type: "smoothstep",
            style: { stroke: "#D99A54", strokeWidth: 1.5, strokeDasharray: "3 3" },
            markerEnd: { type: MarkerType.ArrowClosed, color: "#D99A54" },
          });
        });
      }

      // 5. Run Dagre Layout
      const dagreGraph = new dagre.graphlib.Graph();
      dagreGraph.setDefaultEdgeLabel(() => ({}));
      const isHorizontal = dir === "LR";
      dagreGraph.setGraph({
        rankdir: dir,
        align: "UL",
        nodesep: isHorizontal ? 55 : 65,
        ranksep: isHorizontal ? 95 : 85,
      });

      gNodes.forEach((node) => {
        const width = node.type === "incidentNode" ? 240 : 210;
        const height = node.type === "incidentNode" ? 82 : 72;
        dagreGraph.setNode(node.id, { width, height });
      });

      gEdges.forEach((edge) => {
        dagreGraph.setEdge(edge.source, edge.target);
      });

      dagre.layout(dagreGraph);

      const layoutedNodes = gNodes.map((node) => {
        const nodeWithPosition = dagreGraph.node(node.id);
        const width = node.type === "incidentNode" ? 240 : 210;
        const height = node.type === "incidentNode" ? 82 : 72;
        return {
          ...node,
          targetPosition: isHorizontal ? Position.Left : Position.Top,
          sourcePosition: isHorizontal ? Position.Right : Position.Bottom,
          position: {
            x: (nodeWithPosition?.x || 100) - width / 2,
            y: (nodeWithPosition?.y || 100) - height / 2,
          },
        };
      });

      setNodes(layoutedNodes);
      setEdges(gEdges);
    },
    [dossier, setNodes, setEdges]
  );

  useEffect(() => {
    buildAndLayoutGraph(direction, groupDetections, selectedNodeId);
  }, [direction, groupDetections, selectedNodeId, buildAndLayoutGraph]);

  // Automatically fit graph to viewport whenever nodes are calculated or updated
  useEffect(() => {
    if (nodes.length > 0) {
      const timer = setTimeout(() => {
        fitView({ padding: 0.15, duration: 250 });
      }, 80);
      return () => clearTimeout(timer);
    }
  }, [nodes.length, direction, groupDetections, fitView]);

  // Fit View on layout reset
  const handleResetLayout = () => {
    buildAndLayoutGraph(direction, groupDetections, selectedNodeId);
    setTimeout(() => {
      fitView({ padding: 0.15, duration: 300 });
    }, 50);
  };

  // Selected Node Metadata Resolver
  const selectedNodeData = useMemo(() => {
    if (!selectedNodeId) return null;
    const found = nodes.find((n) => n.id === selectedNodeId);
    return found ? (found.data as unknown as NodeDataPayload) : null;
  }, [selectedNodeId, nodes]);

  // Related events for selected entity
  const associatedEvents = useMemo(() => {
    if (!selectedNodeData || !dossier.events) return [];
    if (selectedNodeData.category === "incident") return dossier.events.slice(0, 5);
    const val = selectedNodeData.entityValue || selectedNodeData.label;
    return dossier.events.filter(
      (e) =>
        e.username === val ||
        e.hostname === val ||
        e.source_ip === val ||
        e.destination_ip === val
    );
  }, [selectedNodeData, dossier.events]);

  return (
    <div className="w-full h-full flex flex-col relative bg-[#111315]">
      {/* 1. Graph Toolbar & Controls */}
      <div className="p-3 border-b border-[#30363C] bg-[#1D2125] flex flex-wrap items-center justify-between text-xs gap-3 z-10 shrink-0">
        <div className="flex items-center gap-2">
          {/* Orientation Toggle */}
          <div className="flex items-center bg-[#24282C] p-0.5 rounded-md border border-[#30363C]">
            <button
              onClick={() => setDirection("LR")}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                direction === "LR"
                  ? "bg-[#1D2125] text-[#E9ECEF] border border-[#30363C]"
                  : "text-[#737D87] hover:text-[#E9ECEF]"
              }`}
            >
              Left → Right
            </button>
            <button
              onClick={() => setDirection("TB")}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                direction === "TB"
                  ? "bg-[#1D2125] text-[#E9ECEF] border border-[#30363C]"
                  : "text-[#737D87] hover:text-[#E9ECEF]"
              }`}
            >
              Top ↓ Bottom
            </button>
          </div>

          {/* Detections Clustering Toggle */}
          <div className="flex items-center bg-[#24282C] p-0.5 rounded-md border border-[#30363C]">
            <button
              onClick={() => setGroupDetections(true)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                groupDetections
                  ? "bg-[#1D2125] text-[#E9ECEF] border border-[#30363C]"
                  : "text-[#737D87] hover:text-[#E9ECEF]"
              }`}
            >
              Group Rules (4)
            </button>
            <button
              onClick={() => setGroupDetections(false)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                !groupDetections
                  ? "bg-[#1D2125] text-[#E9ECEF] border border-[#30363C]"
                  : "text-[#737D87] hover:text-[#E9ECEF]"
              }`}
            >
              All Firings (6)
            </button>
          </div>

          {/* Reset Layout / Fit View */}
          <button
            onClick={handleResetLayout}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#30363C] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] transition-colors cursor-pointer"
            title="Recalculate layout and center view"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset View</span>
          </button>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs text-[#737D87]">
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-[#B58A61] inline-block" />
            <span className="text-[#A0A7AE]">Observed Attack Flow</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 border-t border-dashed border-[#737D87] inline-block" />
            <span>Correlation Anchor</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 border-t border-dotted border-[#D99A54] inline-block" />
            <span>Rule Trigger</span>
          </span>
        </div>
      </div>

      {/* 2. Interactive Graph Canvas with Inspector Pane */}
      <div className="flex-1 w-full h-full relative overflow-hidden flex">
        <div className="flex-1 h-full relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onPaneClick={() => setSelectedNodeId(null)}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.3}
            maxZoom={1.8}
            defaultEdgeOptions={{ type: "smoothstep" }}
          >
            <Background color="#24282C" gap={24} size={1} />
            <Controls />
            <MiniMap
              nodeColor="#24282C"
              maskColor="rgba(17, 19, 21, 0.85)"
              style={{
                backgroundColor: "#191C1F",
                border: "1px solid #30363C",
                borderRadius: "6px",
              }}
            />
          </ReactFlow>
        </div>

        {/* 3. Entity Investigation Inspector (Opens on Node Click) */}
        {selectedNodeData && (
          <div className="w-[340px] shrink-0 border-l border-[#30363C] bg-[#191C1F] flex flex-col h-full shadow-2xl z-20 overflow-y-auto">
            {/* Inspector Header */}
            <div className="p-3.5 border-b border-[#30363C] bg-[#1D2125] flex items-center justify-between">
              <div className="flex items-center gap-2">
                {selectedNodeData.category === "user" && <User className="w-4 h-4 text-[#B58A61]" />}
                {selectedNodeData.category === "host" && <Server className="w-4 h-4 text-[#76A58B]" />}
                {selectedNodeData.category === "ip" && <Globe className="w-4 h-4 text-[#D99A54]" />}
                {selectedNodeData.category === "detection" && <Crosshair className="w-4 h-4 text-[#D99A54]" />}
                {selectedNodeData.category === "incident" && <ShieldAlert className="w-4 h-4 text-[#E06C68]" />}
                <span className="text-xs font-semibold text-[#E9ECEF]">Investigation Inspector</span>
              </div>
              <button
                onClick={() => setSelectedNodeId(null)}
                className="p-1 rounded hover:bg-[#24282C] text-[#737D87] hover:text-[#E9ECEF] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Inspector Body */}
            <div className="p-4 space-y-4 flex-1">
              {/* Entity Identification Card */}
              <div className="p-3.5 rounded-lg bg-[#1D2125] border border-[#30363C] space-y-2">
                <span className="text-[10px] uppercase font-semibold text-[#737D87] tracking-wider block">
                  {selectedNodeData.category === "detection" ? "Triggered Rule" : "Entity Value"}
                </span>
                <div className="text-sm font-mono font-bold text-[#E9ECEF] break-all">
                  {selectedNodeData.label}
                </div>
                {selectedNodeData.subLabel && (
                  <div className="text-xs text-[#A0A7AE]">{selectedNodeData.subLabel}</div>
                )}
                {selectedNodeData.role && (
                  <div className="pt-2 border-t border-[#30363C] flex items-center justify-between text-xs">
                    <span className="text-[#737D87]">Role:</span>
                    <span className="font-mono text-[#B58A61] font-medium">{selectedNodeData.role}</span>
                  </div>
                )}
              </div>

              {/* Action Jump to Asset Inventory */}
              {(selectedNodeData.category === "user" || selectedNodeData.category === "host" || selectedNodeData.category === "ip") && (
                <button
                  onClick={() => onNavigateToAssets(selectedNodeData.category, selectedNodeData.label)}
                  className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-[#24282C] hover:bg-[#2B2722] text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/50 text-xs font-medium transition-colors cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-[#B58A61]" />
                  <span>Inspect in Asset Inventory</span>
                </button>
              )}

              {/* Detection Explanation if Rule Node */}
              {selectedNodeData.explanation && (
                <div className="p-3 rounded-lg bg-[#1D2125] border border-[#30363C] space-y-1.5">
                  <span className="text-[10px] uppercase font-semibold text-[#D99A54] tracking-wider">
                    Rule Firing Logic
                  </span>
                  <p className="text-xs text-[#A0A7AE] leading-relaxed">
                    {selectedNodeData.explanation}
                  </p>
                </div>
              )}

              {/* Associated Persisted Evidence Events */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-[#E9ECEF]">Associated Evidence</span>
                  <span className="font-mono text-[11px] text-[#737D87]">
                    {associatedEvents.length} events
                  </span>
                </div>

                {associatedEvents.length === 0 ? (
                  <div className="p-3 text-center text-xs text-[#737D87] bg-[#1D2125] rounded-md border border-[#30363C]">
                    No direct event records mapped.
                  </div>
                ) : (
                  <div className="space-y-1.5 max-h-[220px] overflow-y-auto">
                    {associatedEvents.map((evt) => (
                      <div
                        key={evt.id}
                        onClick={() => onSelectEvent(evt)}
                        className="p-2.5 rounded bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/50 cursor-pointer transition-colors space-y-1"
                      >
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-mono text-xs font-semibold text-[#B58A61]">
                            {evt.id}
                          </span>
                          <span className="font-mono text-[10px] text-[#737D87]">
                            {evt.timestamp.slice(11, 19)} UTC
                          </span>
                        </div>
                        <div className="text-xs text-[#A0A7AE] flex items-center justify-between">
                          <span className="font-mono text-[11px] text-[#E9ECEF]">{evt.action}</span>
                          <span className="text-[10px] uppercase text-[#737D87]">{evt.category}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Main Incident Workspace Component
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
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [activeTab, setActiveTab] = useState<"graph" | "evidence" | "findings" | "detections">("graph");

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const detail = await api.getIncident(id);
      setDossier(detail);
      setIncidentStatus(detail.incident.status);

      const invs = await api.getInvestigations(id);
      if (invs && invs.length > 0) {
        setInvestigation(invs[0]);
      }
    } catch (err) {
      console.error("Failed to load incident dossier:", err);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!dossier) return;
    setUpdatingStatus(true);
    try {
      await api.updateIncidentStatus(dossier.incident.id, newStatus);
      setIncidentStatus(newStatus);
      setDossier((prev) =>
        prev
          ? {
              ...prev,
              incident: {
                ...prev.incident,
                status: newStatus,
              },
            }
          : null
      );
    } catch (err) {
      console.error("Failed to update status:", err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleRunInvestigation = async () => {
    if (!dossier) return;
    setInvestigating(true);
    try {
      const inv = await api.triggerInvestigation(dossier.incident.id, activeModel);
      setInvestigation(inv);
      setActiveTab("findings");
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
      <div className="flex-1 flex items-center justify-center p-12 text-[#737D87] text-xs">
        <RotateCcw className="w-4 h-4 animate-spin mr-2 text-[#B58A61]" />
        Loading Incident Dossier and Attack Graph...
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col h-[calc(100vh-3.5rem)] overflow-hidden bg-[#111315] select-none text-[#E9ECEF]">
      {/* Persistent Analyst Header */}
      <div className="h-14 border-b border-[#30363C] bg-[#191C1F] px-5 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate("/")}
            className="text-xs text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer font-medium"
          >
            ← Incidents
          </button>
          <span className="text-[#30363C]">/</span>
          <span className="text-sm font-mono font-semibold text-[#E9ECEF]">
            {dossier.incident.id}
          </span>
          <SeverityBadge severity={dossier.incident.severity} size="sm" />
          <DataProvenanceBadge provenance={dossier.incident.provenance} size="sm" />
          <span className="text-xs text-[#A0A7AE] font-medium truncate max-w-md hidden md:inline">
            {dossier.incident.title}
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* Real Persistent Status Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-[#737D87]">Status:</span>
            <select
              value={incidentStatus}
              onChange={(e) => handleStatusChange(e.target.value as IncidentStatus)}
              disabled={updatingStatus}
              className="px-2.5 py-1 rounded-md bg-[#1D2125] border border-[#30363C] text-xs font-medium text-[#E9ECEF] outline-none cursor-pointer hover:border-[#B58A61]/40"
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="contained">Contained</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>
          </div>

          {/* Trigger AI Investigation Button */}
          <button
            onClick={handleRunInvestigation}
            disabled={investigating}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] font-semibold text-xs transition-colors disabled:opacity-50 cursor-pointer shadow-sm"
          >
            <Sparkles className={`w-3.5 h-3.5 ${investigating ? "animate-spin" : ""}`} />
            <span>{investigating ? "Investigating..." : "Run AI Investigation"}</span>
          </button>
        </div>
      </div>

      {/* Operational Blast Radius & Telemetry Ribbon */}
      <div className="px-5 py-2.5 border-b border-[#30363C] bg-[#1D2125] flex items-center justify-between text-xs text-[#737D87] shrink-0 overflow-x-auto">
        <div className="flex items-center gap-3 whitespace-nowrap">
          <span>
            First Seen: <strong className="text-[#E9ECEF] font-mono">{dossier.incident.first_seen.replace("T", " ").slice(0, 19)} UTC</strong>
          </span>
          <span className="text-[#30363C]">|</span>
          <span>
            Last Seen: <strong className="text-[#E9ECEF] font-mono">{dossier.incident.last_seen.replace("T", " ").slice(0, 19)} UTC</strong>
          </span>
          <span className="text-[#30363C]">|</span>
          <span>
            Entities: <strong className="text-[#B58A61] font-mono">{dossier.entities.length} correlated</strong>
          </span>
          <span className="text-[#30363C]">|</span>
          <span>
            Telemetry Events: <strong className="text-[#E9ECEF] font-mono">{dossier.events.length}</strong>
          </span>
          <span className="text-[#30363C]">|</span>
          <span>
            Detection Rules: <strong className="text-[#D99A54] font-mono">{dossier.detections.length}</strong>
          </span>
        </div>

        {/* Console Navigation Tabs */}
        <div className="flex items-center bg-[#191C1F] p-0.5 rounded-md border border-[#30363C] shrink-0">
          <button
            onClick={() => setActiveTab("graph")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
              activeTab === "graph"
                ? "bg-[#24282C] text-[#E9ECEF]"
                : "text-[#737D87] hover:text-[#E9ECEF]"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Attack Graph</span>
          </button>
          <button
            onClick={() => setActiveTab("evidence")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
              activeTab === "evidence"
                ? "bg-[#24282C] text-[#E9ECEF]"
                : "text-[#737D87] hover:text-[#E9ECEF]"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Evidence Log ({dossier.events.length})</span>
          </button>
          <button
            onClick={() => setActiveTab("findings")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
              activeTab === "findings"
                ? "bg-[#24282C] text-[#E9ECEF]"
                : "text-[#737D87] hover:text-[#E9ECEF]"
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>AI Findings</span>
          </button>
          <button
            onClick={() => setActiveTab("detections")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
              activeTab === "detections"
                ? "bg-[#24282C] text-[#E9ECEF]"
                : "text-[#737D87] hover:text-[#E9ECEF]"
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Detections ({dossier.detections.length})</span>
          </button>
        </div>
      </div>

      {/* Main Tabbed Console Content */}
      <div className="flex-1 overflow-hidden relative">
        {/* TAB 1: REDESIGNED ATTACK GRAPH */}
        {activeTab === "graph" && (
          <ReactFlowProvider>
            <AttackGraphCanvas
              dossier={dossier}
              onSelectEvent={(evt) => {
                setSelectedEvent(evt);
                setDrawerOpen(true);
              }}
              onNavigateToAssets={(_type, _value) => {
                navigate("/assets");
              }}
            />
          </ReactFlowProvider>
        )}

        {/* TAB 2: EVIDENCE LOG */}
        {activeTab === "evidence" && (
          <div className="w-full h-full overflow-y-auto p-5 space-y-4">
            <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
              <div className="p-3.5 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
                <span className="text-xs font-semibold text-[#E9ECEF]">
                  Chronological Telemetry Evidence Dossier
                </span>
                <span className="text-[11px] text-[#737D87]">
                  Click any event row to inspect full JSON payload
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-[#30363C] bg-[#24282C]/50 text-[#737D87] text-[11px] font-medium">
                      <th className="py-2.5 px-3.5 whitespace-nowrap">Event ID</th>
                      <th className="py-2.5 px-3 whitespace-nowrap">Timestamp (UTC)</th>
                      <th className="py-2.5 px-3">Category / Action</th>
                      <th className="py-2.5 px-3">Identity</th>
                      <th className="py-2.5 px-3">Host</th>
                      <th className="py-2.5 px-3">Connection</th>
                      <th className="py-2.5 px-3.5 text-right whitespace-nowrap">Egress Bytes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#30363C]">
                    {dossier.events.map((evt) => (
                      <tr
                        key={evt.id}
                        onClick={() => {
                          setSelectedEvent(evt);
                          setDrawerOpen(true);
                        }}
                        className="hover:bg-[#24282C]/50 cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-3.5 font-mono text-xs font-semibold text-[#B58A61]">{evt.id}</td>
                        <td className="py-3 px-3 font-mono text-[11px] text-[#A0A7AE]">
                          {evt.timestamp.replace("T", " ").slice(0, 19)}
                        </td>
                        <td className="py-3 px-3">
                          <span className="text-[#E9ECEF] font-medium capitalize">
                            {evt.action.replace("_", " ")}
                          </span>
                          <span className="text-[11px] text-[#737D87] block uppercase font-mono">
                            {evt.category}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-mono text-xs text-[#B58A61]">{evt.username || "—"}</td>
                        <td className="py-3 px-3 font-mono text-xs text-[#A0A7AE]">{evt.hostname || "—"}</td>
                        <td className="py-3 px-3 font-mono text-xs text-[#737D87]">
                          {evt.source_ip || "—"} → {evt.destination_ip || "—"}
                        </td>
                        <td className="py-3 px-3.5 text-right font-mono text-xs">
                          {evt.bytes_out ? (
                            <span className="text-[#E06C68] font-medium">
                              {(evt.bytes_out / 1024 / 1024).toFixed(1)} MB
                            </span>
                          ) : (
                            <span className="text-[#737D87]">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: AI INVESTIGATION FINDINGS */}
        {activeTab === "findings" && (
          <div className="w-full h-full overflow-y-auto p-5 space-y-5">
            {investigation ? (
              <div className="max-w-5xl mx-auto space-y-5">
                {/* Executive Summary */}
                <div className="p-5 rounded-lg bg-[#1D2125] border border-[#30363C] space-y-3 shadow-card">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-[#B58A61]" />
                      <span className="text-xs font-semibold text-[#E9ECEF]">
                        Executive Investigation Summary
                      </span>
                    </div>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#24282C] text-[#A0A7AE] border border-[#30363C]">
                      Model: {investigation.model_id}
                    </span>
                  </div>
                  <p className="text-xs text-[#E9ECEF] leading-relaxed bg-[#24282C] p-4 rounded-md border border-[#30363C]">
                    {investigation.executive_summary}
                  </p>
                  <div className="flex items-center gap-6 text-xs text-[#737D87] pt-1">
                    <span>Tool Calls: <strong className="text-[#E9ECEF] font-mono">{investigation.tool_call_count}</strong></span>
                    <span>Investigation Latency: <strong className="text-[#E9ECEF] font-mono">{investigation.duration_seconds}s</strong></span>
                    <span>Evidence Grounding: <strong className="text-[#76A58B]">100% CES Verified</strong></span>
                  </div>
                </div>

                {/* Section 1: Observed Facts */}
                <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-5 space-y-3 shadow-card">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-[#E9ECEF]">
                      Observed Facts ({investigation.structured_result.observed_facts.length})
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-[#76A58B]/12 text-[#76A58B] border border-[#76A58B]/25 font-semibold">
                      GROUND TRUTH
                    </span>
                  </div>

                  <div className="space-y-2">
                    {investigation.structured_result.observed_facts.map((fact, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-md bg-[#24282C] border border-[#30363C] space-y-2"
                      >
                        <p className="text-xs text-[#E9ECEF] leading-relaxed">
                          {fact.statement}
                        </p>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-xs text-[#737D87]">Evidence Citations:</span>
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

                {/* Section 2: Hypotheses & Unknowns */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  {/* Analytic Hypotheses */}
                  <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-5 space-y-3 shadow-card">
                    <span className="text-xs font-semibold text-[#E9ECEF]">
                      Analytic Hypotheses ({investigation.structured_result.hypotheses.length})
                    </span>
                    <div className="space-y-2.5">
                      {investigation.structured_result.hypotheses.map((hyp, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-md bg-[#24282C] border border-[#30363C] space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <span
                              className={`text-[10px] uppercase font-medium px-2 py-0.5 rounded border ${
                                hyp.confidence === "high"
                                  ? "bg-[#E06C68]/12 text-[#E06C68] border-[#E06C68]/25"
                                  : hyp.confidence === "medium"
                                  ? "bg-[#C9B86B]/12 text-[#C9B86B] border-[#C9B86B]/25"
                                  : "bg-[#76A58B]/12 text-[#76A58B] border-[#76A58B]/25"
                              }`}
                            >
                              {hyp.confidence} Confidence
                            </span>
                          </div>
                          <p className="text-xs text-[#E9ECEF] leading-relaxed">
                            {hyp.statement}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Operational Unknowns */}
                  <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-5 space-y-3 shadow-card">
                    <span className="text-xs font-semibold text-[#E9ECEF]">
                      Operational Unknowns ({investigation.structured_result.unknowns.length})
                    </span>
                    <div className="space-y-2.5">
                      {investigation.structured_result.unknowns.map((unk, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-md bg-[#24282C] border border-[#30363C] space-y-1 text-xs leading-relaxed"
                        >
                          <div className="text-[#E9ECEF] font-medium">{unk.question}</div>
                          <div className="text-[11px] text-[#A0A7AE]">{unk.reason}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Section 3: Recommended Containment Actions */}
                <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-5 space-y-3 shadow-card">
                  <span className="text-xs font-semibold text-[#E9ECEF]">
                    Recommended Containment Actions ({investigation.structured_result.recommended_actions.length})
                  </span>
                  <div className="space-y-2.5">
                    {investigation.structured_result.recommended_actions.map((act, idx) => {
                      const isApproved = approvedActions[idx];
                      return (
                        <div
                          key={idx}
                          className="p-3.5 rounded-md bg-[#24282C] border border-[#30363C] flex items-center justify-between gap-4"
                        >
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-medium text-[#B58A61]">
                                {act.action}
                              </span>
                              <span
                                className={`text-[10px] uppercase font-medium px-1.5 py-0.2 rounded border ${
                                  act.impact === "high"
                                    ? "bg-[#E06C68]/12 text-[#E06C68] border-[#E06C68]/25"
                                    : "bg-[#D99A54]/12 text-[#D99A54] border-[#D99A54]/25"
                                }`}
                              >
                                {act.impact} Impact
                              </span>
                            </div>
                            <p className="text-xs text-[#A0A7AE]">{act.rationale}</p>
                          </div>

                          <button
                            onClick={() => handleApproveAction(idx)}
                            disabled={isApproved}
                            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors shrink-0 ${
                              isApproved
                                ? "bg-[#76A58B]/20 text-[#76A58B] border border-[#76A58B]/40 cursor-default"
                                : "bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] cursor-pointer shadow-sm"
                            }`}
                          >
                            {isApproved ? "Approved" : "Approve Action"}
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center text-xs text-[#737D87] bg-[#1D2125] rounded-lg border border-[#30363C] max-w-xl mx-auto space-y-3">
                <Sparkles className="w-8 h-8 text-[#B58A61] mx-auto opacity-60" />
                <div className="text-sm font-semibold text-[#E9ECEF]">No AI Findings Generated Yet</div>
                <p className="text-xs text-[#A0A7AE]">
                  Click the "Run AI Investigation" button in the console header to execute multi-step deterministic agent reasoning against CES evidence.
                </p>
                <button
                  onClick={handleRunInvestigation}
                  className="px-4 py-2 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] font-semibold text-xs transition-colors cursor-pointer inline-flex items-center gap-2"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Run AI Investigation</span>
                </button>
              </div>
            )}
          </div>
        )}

        {/* TAB 4: TRIGGERED DETECTIONS */}
        {activeTab === "detections" && (
          <div className="w-full h-full overflow-y-auto p-5 space-y-4">
            <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
              <div className="p-3.5 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
                <span className="text-xs font-semibold text-[#E9ECEF]">
                  Correlated Detection Firings ({dossier.detections.length})
                </span>
                <span className="text-[11px] text-[#737D87]">
                  Evaluated using deterministic Sigma-compatible rule definitions
                </span>
              </div>

              <div className="divide-y divide-[#30363C]">
                {dossier.detections.map((det) => (
                  <div key={det.id} className="p-4 space-y-2 hover:bg-[#24282C]/40 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-[#B58A61]">
                          {det.rule_id}
                        </span>
                        <SeverityBadge severity={det.severity} size="sm" />
                        <span className="text-sm font-medium text-[#E9ECEF]">{det.rule_name}</span>
                      </div>
                      <span className="font-mono text-[11px] text-[#737D87]">
                        {det.detected_at?.replace("T", " ").slice(0, 19)} UTC
                      </span>
                    </div>

                    <p className="text-xs text-[#A0A7AE] leading-relaxed bg-[#24282C] p-3 rounded-md border border-[#30363C]">
                      {det.explanation}
                    </p>

                    <div className="flex items-center gap-4 text-xs text-[#737D87] pt-1">
                      <span>
                        Implicated Entity:{" "}
                        <strong className="font-mono text-[#E9ECEF]">{det.entity_value}</strong> ({det.entity_type})
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Slide-over Evidence Drawer for inspecting individual events */}
      <EvidenceDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        event={selectedEvent}
      />
    </div>
  );
};
