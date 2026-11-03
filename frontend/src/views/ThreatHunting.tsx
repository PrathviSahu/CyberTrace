import React, { useState, useEffect, useCallback } from "react";
import {
  Play,
  Terminal,
  RefreshCw,
  Database,
  Plus,
  Trash2,
  Clock,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  AlertTriangle,
  Flame,
  Search,
  Filter,
  SlidersHorizontal,
  XCircle,
  Eye,
  Bookmark,
  BookmarkPlus,
} from "lucide-react";
import {
  FilterField,
  FilterOperator,
  FilterCondition,
  FilterGroup,
  HuntedEventItem,
  ThreatHuntQueryRequest,
  ThreatHuntQueryResponse,
  SavedHuntResponse,
  SavedHuntExecuteResponse,
  SavedHuntQueryDefinition,
} from "../types";
import { api } from "../services/api";
import { EvidenceDrawer } from "../components/common/EvidenceDrawer";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";
import { SaveHuntModal } from "../components/hunting/SaveHuntModal";
import { SavedHuntsDrawer } from "../components/hunting/SavedHuntsDrawer";
import { CreateRuleDraftModal } from "../components/rules/CreateRuleDraftModal";
import { DetectionRuleDraftResponse } from "../types";

// UI condition model with unique key for React lists
interface UICondition {
  id: string;
  field: FilterField;
  operator: FilterOperator;
  value: string;
}

// Field definitions with metadata
interface FieldMeta {
  field: FilterField;
  label: string;
  category: "identity" | "network" | "system" | "time";
  type: "string" | "number" | "port" | "timestamp" | "severity";
}

const FIELD_OPTIONS: FieldMeta[] = [
  { field: "username", label: "User (username)", category: "identity", type: "string" },
  { field: "hostname", label: "Host (hostname)", category: "system", type: "string" },
  { field: "category", label: "Category", category: "system", type: "string" },
  { field: "action", label: "Action", category: "system", type: "string" },
  { field: "severity", label: "Severity", category: "system", type: "severity" },
  { field: "process_name", label: "Process Name", category: "system", type: "string" },
  { field: "source_ip", label: "Source IP", category: "network", type: "string" },
  { field: "destination_ip", label: "Destination IP", category: "network", type: "string" },
  { field: "source_port", label: "Source Port", category: "network", type: "port" },
  { field: "destination_port", label: "Destination Port", category: "network", type: "port" },
  { field: "protocol", label: "Protocol", category: "network", type: "string" },
  { field: "bytes_out", label: "Bytes Out (Egress)", category: "network", type: "number" },
  { field: "bytes_in", label: "Bytes In (Ingress)", category: "network", type: "number" },
  { field: "timestamp", label: "Timestamp", category: "time", type: "timestamp" },
];

const STRING_OPERATORS: { op: FilterOperator; label: string }[] = [
  { op: "eq", label: "equals (=)" },
  { op: "neq", label: "not equals (!=)" },
  { op: "contains", label: "contains" },
  { op: "starts_with", label: "starts with" },
  { op: "in", label: "in list" },
];

const NUMERIC_OPERATORS: { op: FilterOperator; label: string }[] = [
  { op: "eq", label: "equals (=)" },
  { op: "neq", label: "not equals (!=)" },
  { op: "gt", label: "greater than (>)" },
  { op: "gte", label: "greater or equal (>=)" },
  { op: "lt", label: "less than (<)" },
  { op: "lte", label: "less or equal (<=)" },
  { op: "in", label: "in list" },
];

const SEVERITY_OPERATORS: { op: FilterOperator; label: string }[] = [
  { op: "eq", label: "equals (=)" },
  { op: "neq", label: "not equals (!=)" },
  { op: "in", label: "in list" },
];

const getOperatorsForField = (field: FilterField) => {
  const meta = FIELD_OPTIONS.find((f) => f.field === field);
  if (!meta) return STRING_OPERATORS;
  if (meta.type === "number" || meta.type === "port" || meta.type === "timestamp") {
    return NUMERIC_OPERATORS;
  }
  if (meta.type === "severity") {
    return SEVERITY_OPERATORS;
  }
  return STRING_OPERATORS;
};

// Preset hunting hypotheses
interface HuntPreset {
  name: string;
  description: string;
  conditions: UICondition[];
  logic: "AND" | "OR";
}

const PRESETS: HuntPreset[] = [
  {
    name: "Service Account Remote Access",
    description: "Audit automated account interactive sessions (e.g. svc_deploy)",
    logic: "AND",
    conditions: [
      { id: "p1", field: "username", operator: "eq", value: "svc_deploy" },
    ],
  },
  {
    name: "High-Volume Data Egress",
    description: "Detect outbound data transfers exceeding 10MB",
    logic: "AND",
    conditions: [
      { id: "p2", field: "bytes_out", operator: "gt", value: "10000000" },
    ],
  },
  {
    name: "Authentication Failures",
    description: "Detect brute-force or credential spraying attempts",
    logic: "AND",
    conditions: [
      { id: "p3", field: "action", operator: "contains", value: "logon_failure" },
    ],
  },
  {
    name: "Privilege Escalation Commands",
    description: "Spot privilege elevation or sudo activities across hosts",
    logic: "AND",
    conditions: [
      { id: "p4", field: "action", operator: "contains", value: "elevation" },
    ],
  },
  {
    name: "Critical & High Alerts",
    description: "Filter telemetry associated with critical or high severity events",
    logic: "AND",
    conditions: [
      { id: "p5", field: "severity", operator: "in", value: "critical, high" },
    ],
  },
];

export const ThreatHunting: React.FC = () => {
  // Query builder state
  const [conditions, setConditions] = useState<UICondition[]>([
    { id: "c1", field: "username", operator: "eq", value: "svc_deploy" },
  ]);
  const [logic, setLogic] = useState<"AND" | "OR">("AND");

  // Time range state
  const [timePreset, setTimePreset] = useState<"all" | "15m" | "1h" | "24h" | "7d" | "custom">("all");
  const [startTime, setStartTime] = useState<string>("");
  const [endTime, setEndTime] = useState<string>("");

  // Pagination & Sorting state
  const [sortBy, setSortBy] = useState<FilterField>("timestamp");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [limit, setLimit] = useState<number>(50);
  const [offset, setOffset] = useState<number>(0);

  // Execution result state
  const [queryResult, setQueryResult] = useState<ThreatHuntQueryResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Evidence Drawer state
  const [selectedEvent, setSelectedEvent] = useState<HuntedEventItem | null>(null);
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);

  // Saved Hunts UI state
  const [saveModalOpen, setSaveModalOpen] = useState<boolean>(false);
  const [savedHuntsDrawerOpen, setSavedHuntsDrawerOpen] = useState<boolean>(false);
  const [activeSavedHunt, setActiveSavedHunt] = useState<SavedHuntResponse | null>(null);
  const [executingSavedHuntBanner, setExecutingSavedHuntBanner] = useState<string | null>(null);
  const [savedHuntsCount, setSavedHuntsCount] = useState<number>(0);

  // Rule Draft Promotion state
  const [promoteModalHunt, setPromoteModalHunt] = useState<SavedHuntResponse | null>(null);
  const [createRuleModalOpen, setCreateRuleModalOpen] = useState<boolean>(false);
  const [ruleDraftSuccessBanner, setRuleDraftSuccessBanner] = useState<string | null>(null);

  const refreshSavedHuntsCount = useCallback(async () => {
    try {
      const data = await api.listSavedHunts({ limit: 1 });
      setSavedHuntsCount(data.total);
    } catch {
      // ignore in UI
    }
  }, []);

  useEffect(() => {
    refreshSavedHuntsCount();
  }, [refreshSavedHuntsCount]);

  // Convert UI conditions into typed FilterCondition AST
  const compileFilterConditions = (condList: UICondition[]): FilterCondition[] => {
    const valid: FilterCondition[] = [];
    for (const c of condList) {
      const valStr = c.value.trim();
      if (!valStr) continue;

      const meta = FIELD_OPTIONS.find((f) => f.field === c.field);
      const isNum = meta?.type === "number" || meta?.type === "port";

      if (c.operator === "in") {
        const items = valStr.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
        if (items.length === 0) continue;

        if (isNum) {
          const numList = items.map((i) => parseInt(i, 10)).filter((n) => !isNaN(n));
          if (numList.length > 0) {
            valid.push({ field: c.field, operator: c.operator, value: numList });
          }
        } else {
          valid.push({ field: c.field, operator: c.operator, value: items });
        }
      } else if (isNum) {
        const numVal = parseInt(valStr, 10);
        if (!isNaN(numVal)) {
          valid.push({ field: c.field, operator: c.operator, value: numVal });
        }
      } else {
        valid.push({ field: c.field, operator: c.operator, value: valStr });
      }
    }
    return valid;
  };

  // Compute ISO time range
  const computeTimeRange = () => {
    if (timePreset === "all") return undefined;

    const now = new Date();
    let startDt: Date | null = null;
    let endDt: Date | null = null;

    if (timePreset === "15m") {
      startDt = new Date(now.getTime() - 15 * 60 * 1000);
      endDt = now;
    } else if (timePreset === "1h") {
      startDt = new Date(now.getTime() - 60 * 60 * 1000);
      endDt = now;
    } else if (timePreset === "24h") {
      startDt = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      endDt = now;
    } else if (timePreset === "7d") {
      startDt = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      endDt = now;
    } else if (timePreset === "custom") {
      if (startTime) startDt = new Date(startTime);
      if (endTime) endDt = new Date(endTime);
    }

    if (!startDt && !endDt) return undefined;

    return {
      start: startDt ? startDt.toISOString() : undefined,
      end: endDt ? endDt.toISOString() : undefined,
    };
  };

  // Execute structured hunt query
  const executeQuery = useCallback(
    async (newOffset = offset, newSortBy = sortBy, newSortOrder = sortOrder, newLimit = limit) => {
      setLoading(true);
      setError(null);

      try {
        const compiled = compileFilterConditions(conditions);

        let filterGroup: FilterGroup | undefined = undefined;
        if (compiled.length > 0) {
          filterGroup = {
            logic: logic,
            conditions: compiled,
          };
        }

        const request: ThreatHuntQueryRequest = {
          time_range: computeTimeRange(),
          filter_group: filterGroup,
          sort_by: newSortBy,
          sort_order: newSortOrder,
          limit: newLimit,
          offset: newOffset,
        };

        const response = await api.executeThreatHunt(request);
        setQueryResult(response);
        setOffset(newOffset);
        setSortBy(newSortBy);
        setSortOrder(newSortOrder);
        setLimit(newLimit);
      } catch (err: any) {
        console.error("Threat hunt query failed:", err);
        setError(err.message || "Failed to execute threat hunting query. Please review filter syntax.");
      } finally {
        setLoading(false);
      }
    },
    [conditions, logic, timePreset, startTime, endTime, sortBy, sortOrder, limit, offset]
  );

  // Initial load
  useEffect(() => {
    executeQuery(0);
  }, []);

  // Condition manipulation
  const handleAddCondition = () => {
    const newCond: UICondition = {
      id: "c_" + Date.now(),
      field: "action",
      operator: "eq",
      value: "",
    };
    setConditions((prev) => [...prev, newCond]);
  };

  const handleRemoveCondition = (id: string) => {
    setConditions((prev) => prev.filter((c) => c.id !== id));
  };

  const handleUpdateCondition = (id: string, updates: Partial<UICondition>) => {
    setConditions((prev) =>
      prev.map((c) => {
        if (c.id !== id) return c;
        const updated = { ...c, ...updates };
        // If field changed, ensure operator is compatible
        if (updates.field && updates.field !== c.field) {
          const validOps = getOperatorsForField(updates.field);
          if (!validOps.some((o) => o.op === updated.operator)) {
            updated.operator = validOps[0].op;
          }
        }
        return updated;
      })
    );
  };

  const handleApplyPreset = (preset: HuntPreset) => {
    setLogic(preset.logic);
    setConditions(
      preset.conditions.map((c) => ({
        ...c,
        id: "p_" + Math.random().toString(36).substr(2, 9),
      }))
    );
  };

  const handleClearFilters = () => {
    setConditions([]);
  };

  // Sorting
  const handleToggleSort = (field: FilterField) => {
    let nextOrder: "asc" | "desc" = "desc";
    if (sortBy === field) {
      nextOrder = sortOrder === "desc" ? "asc" : "desc";
    }
    setSortBy(field);
    setSortOrder(nextOrder);
    executeQuery(0, field, nextOrder, limit);
  };

  // Pagination navigation
  const total = queryResult?.total ?? 0;
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const handleNextPage = () => {
    if (offset + limit < total) {
      executeQuery(offset + limit, sortBy, sortOrder, limit);
    }
  };

  const handlePrevPage = () => {
    if (offset - limit >= 0) {
      executeQuery(offset - limit, sortBy, sortOrder, limit);
    }
  };

  const handleLimitChange = (newLimit: number) => {
    setLimit(newLimit);
    executeQuery(0, sortBy, sortOrder, newLimit);
  };

  // Saved Hunts handlers
  const getQueryDefinitionForSave = (): SavedHuntQueryDefinition => {
    const compiled = compileFilterConditions(conditions);
    let filterGroup: FilterGroup | undefined = undefined;
    if (compiled.length > 0) {
      filterGroup = {
        logic: logic,
        conditions: compiled,
      };
    }
    return {
      time_range: computeTimeRange(),
      filter_group: filterGroup,
      sort_by: sortBy,
      sort_order: sortOrder,
      limit: limit,
      offset: 0,
    };
  };

  const handleSaveSuccess = (savedHunt: SavedHuntResponse) => {
    setActiveSavedHunt(savedHunt);
    refreshSavedHuntsCount();
    setExecutingSavedHuntBanner(`Saved Threat Hunt "${savedHunt.name}" (v${savedHunt.version}) persisted.`);
  };

  const handleLoadHuntIntoBuilder = (hunt: SavedHuntResponse) => {
    const qd = hunt.query_definition;
    if (!qd) return;

    if (qd.filter_group?.logic) {
      setLogic(qd.filter_group.logic);
    }

    if (qd.filter_group?.conditions && qd.filter_group.conditions.length > 0) {
      const loadedConditions: UICondition[] = qd.filter_group.conditions.map((c, idx) => ({
        id: `loaded_${hunt.id}_${idx}_${Date.now()}`,
        field: c.field,
        operator: c.operator,
        value: Array.isArray(c.value) ? c.value.join(", ") : String(c.value ?? ""),
      }));
      setConditions(loadedConditions);
    } else {
      setConditions([]);
    }

    if (qd.sort_by) setSortBy(qd.sort_by);
    if (qd.sort_order) setSortOrder(qd.sort_order);

    setActiveSavedHunt(hunt);
    setExecutingSavedHuntBanner(`Loaded Saved Hunt: "${hunt.name}" (v${hunt.version}) into Query Builder`);
  };

  const handleExecuteHuntDirectly = (execResult: SavedHuntExecuteResponse) => {
    setQueryResult({
      items: execResult.items,
      total: execResult.total,
      limit: execResult.limit,
      offset: execResult.offset,
      query_duration_ms: execResult.query_duration_ms,
      applied_filter_count: execResult.applied_filter_count,
      provenance: execResult.provenance as any,
    });
    setOffset(execResult.offset);
    setLimit(execResult.limit);
    setExecutingSavedHuntBanner(
      `Execution Results for Saved Hunt: "${execResult.hunt_name}" (v${execResult.executed_version}) • Run #${execResult.run_count} • ${execResult.total} matches in ${execResult.query_duration_ms}ms`
    );
    refreshSavedHuntsCount();
  };

  const handlePromoteToRule = (hunt: SavedHuntResponse) => {
    setPromoteModalHunt(hunt);
    setCreateRuleModalOpen(true);
  };

  const handleDraftCreated = (draft: DetectionRuleDraftResponse) => {
    setRuleDraftSuccessBanner(
      `Detection Rule Draft "${draft.name}" (ID: ${draft.id}, Severity: ${draft.severity}) created successfully! Access Detection Rules to run pre-flight simulation and review governance.`
    );
  };

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Structured Threat Hunting
            </h1>
            <span className="text-[11px] px-2 py-0.5 rounded-md bg-[#24282C] text-[#B58A61] border border-[#B58A61]/30 font-medium font-mono">
              Phase 6.2 Query Engine
            </span>
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            Parameterized, schema-validated threat hunting over persisted Common Event Schema (CES) telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <DataProvenanceBadge provenance={queryResult?.provenance || "unknown"} size="sm" />

          <button
            type="button"
            onClick={() => setSavedHuntsDrawerOpen(true)}
            title="Browse saved threat hunts library"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/40 text-[#A0A7AE] hover:text-[#E9ECEF] transition-colors cursor-pointer text-xs font-medium"
          >
            <Bookmark className="w-3.5 h-3.5 text-[#B58A61]" />
            <span>Saved Hunts</span>
            {savedHuntsCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-[#24282C] text-[10px] font-mono text-[#B58A61] border border-[#B58A61]/30">
                {savedHuntsCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setSaveModalOpen(true)}
            title="Save current query AST"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#24282C] border border-[#B58A61]/30 hover:border-[#B58A61] text-[#B58A61] hover:text-[#C69A70] transition-colors cursor-pointer text-xs font-semibold"
          >
            <BookmarkPlus className="w-3.5 h-3.5" />
            <span>Save Hunt</span>
          </button>

          <button
            onClick={() => executeQuery(offset)}
            title="Re-run active query"
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/40 text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer text-xs font-medium disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-[#B58A61]" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Rule Draft Promotion Success Banner */}
      {ruleDraftSuccessBanner && (
        <div className="p-3 rounded-lg bg-[#76A58B]/15 border border-[#76A58B]/30 flex items-center justify-between text-xs text-[#E9ECEF] animate-fadeIn">
          <div className="flex items-center gap-2">
            <Bookmark className="w-4 h-4 text-[#76A58B] shrink-0" />
            <span>{ruleDraftSuccessBanner}</span>
          </div>
          <button
            type="button"
            onClick={() => setRuleDraftSuccessBanner(null)}
            className="text-[11px] text-[#A0A7AE] hover:text-[#E9ECEF] underline cursor-pointer shrink-0 ml-3"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Active Saved Hunt Banner */}
      {executingSavedHuntBanner && (
        <div className="p-3 rounded-lg bg-[#B58A61]/10 border border-[#B58A61]/30 flex items-center justify-between text-xs text-[#E9ECEF] animate-fadeIn">
          <div className="flex items-center gap-2">
            <Bookmark className="w-4 h-4 text-[#B58A61] shrink-0" />
            <span>{executingSavedHuntBanner}</span>
          </div>
          <button
            type="button"
            onClick={() => {
              setExecutingSavedHuntBanner(null);
              setActiveSavedHunt(null);
            }}
            className="text-[11px] text-[#A0A7AE] hover:text-[#E9ECEF] underline cursor-pointer shrink-0 ml-3"
          >
            Clear Context
          </button>
        </div>
      )}

      {/* Query Builder Panel */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-4 space-y-4 shadow-card">
        {/* Active Hunt Context Indicator */}
        {activeSavedHunt && (
          <div className="flex items-center justify-between p-2 rounded bg-[#24282C] border border-[#B58A61]/30 text-xs text-[#E9ECEF]">
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-[#A0A7AE]">Active Saved Hunt:</span>
              <span className="font-semibold text-[#B58A61]">{activeSavedHunt.name}</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#1D2125] text-[#B58A61] border border-[#B58A61]/30">
                v{activeSavedHunt.version}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setActiveSavedHunt(null)}
              className="text-[11px] text-[#737D87] hover:text-[#E06C68] transition-colors cursor-pointer"
            >
              Unlink
            </button>
          </div>
        )}

        {/* Logic Toggle & Top Toolbar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-[#30363C]">
          <div className="flex items-center gap-2.5">
            <SlidersHorizontal className="w-4 h-4 text-[#B58A61]" />
            <span className="text-xs font-semibold text-[#E9ECEF]">Boolean Match Logic:</span>
            <div className="flex items-center rounded-md bg-[#24282C] border border-[#30363C] p-0.5">
              <button
                type="button"
                onClick={() => setLogic("AND")}
                className={`px-3 py-1 text-xs font-semibold rounded transition-colors cursor-pointer ${
                  logic === "AND"
                    ? "bg-[#B58A61] text-[#111315] shadow-sm"
                    : "text-[#A0A7AE] hover:text-[#E9ECEF]"
                }`}
              >
                AND (Match All)
              </button>
              <button
                type="button"
                onClick={() => setLogic("OR")}
                className={`px-3 py-1 text-xs font-semibold rounded transition-colors cursor-pointer ${
                  logic === "OR"
                    ? "bg-[#B58A61] text-[#111315] shadow-sm"
                    : "text-[#A0A7AE] hover:text-[#E9ECEF]"
                }`}
              >
                OR (Match Any)
              </button>
            </div>
            <span className="text-[11px] text-[#737D87]">
              {conditions.length} condition{conditions.length !== 1 ? "s" : ""} active
            </span>
          </div>

          {/* Time Range Quick Select */}
          <div className="flex items-center gap-2 flex-wrap">
            <Clock className="w-3.5 h-3.5 text-[#B58A61]" />
            <span className="text-xs text-[#737D87]">Time:</span>
            {(["all", "15m", "1h", "24h", "7d", "custom"] as const).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setTimePreset(p)}
                className={`px-2 py-0.5 rounded text-xs font-medium border transition-colors cursor-pointer ${
                  timePreset === p
                    ? "bg-[#2B2722] text-[#B58A61] border-[#B58A61]/40"
                    : "bg-[#24282C] text-[#A0A7AE] border-[#30363C] hover:text-[#E9ECEF]"
                }`}
              >
                {p === "all" ? "All Time" : p === "custom" ? "Custom" : `Last ${p}`}
              </button>
            ))}
          </div>
        </div>

        {/* Custom Datetime Range (if custom selected) */}
        {timePreset === "custom" && (
          <div className="flex flex-wrap items-center gap-3 p-3 rounded-md bg-[#24282C] border border-[#30363C] text-xs">
            <div className="flex items-center gap-2">
              <span className="text-[#A0A7AE]">Start (UTC):</span>
              <input
                type="datetime-local"
                value={startTime}
                onChange={(e) => setStartTime(e.target.value)}
                className="px-2.5 py-1 rounded bg-[#1D2125] border border-[#30363C] text-[#E9ECEF] text-xs font-mono outline-none"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[#A0A7AE]">End (UTC):</span>
              <input
                type="datetime-local"
                value={endTime}
                onChange={(e) => setEndTime(e.target.value)}
                className="px-2.5 py-1 rounded bg-[#1D2125] border border-[#30363C] text-[#E9ECEF] text-xs font-mono outline-none"
              />
            </div>
            <span className="text-[11px] text-[#737D87]">Boundaries are inclusive. Timezone-aware UTC evaluation.</span>
          </div>
        )}

        {/* Condition Rows */}
        <div className="space-y-2">
          {conditions.length === 0 ? (
            <div className="py-5 text-center text-xs text-[#737D87] bg-[#24282C]/30 rounded border border-dashed border-[#30363C]">
              No filter conditions added. Running the query will retrieve all telemetry within the specified time range.
            </div>
          ) : (
            conditions.map((cond, index) => {
              const meta = FIELD_OPTIONS.find((f) => f.field === cond.field);
              const operators = getOperatorsForField(cond.field);

              return (
                <div
                  key={cond.id}
                  className="flex flex-col sm:flex-row sm:items-center gap-2 p-2.5 rounded-md bg-[#24282C] border border-[#30363C]"
                >
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1D2125] text-[#737D87] border border-[#30363C] shrink-0 w-8 text-center">
                    {index === 0 ? "IF" : logic}
                  </span>

                  {/* Field Selector */}
                  <select
                    value={cond.field}
                    onChange={(e) =>
                      handleUpdateCondition(cond.id, { field: e.target.value as FilterField })
                    }
                    className="px-2.5 py-1.5 rounded bg-[#1D2125] border border-[#30363C] text-[#E9ECEF] text-xs font-medium outline-none shrink-0"
                  >
                    {FIELD_OPTIONS.map((f) => (
                      <option key={f.field} value={f.field}>
                        {f.label}
                      </option>
                    ))}
                  </select>

                  {/* Operator Selector */}
                  <select
                    value={cond.operator}
                    onChange={(e) =>
                      handleUpdateCondition(cond.id, { operator: e.target.value as FilterOperator })
                    }
                    className="px-2.5 py-1.5 rounded bg-[#1D2125] border border-[#30363C] text-[#B58A61] text-xs font-mono outline-none shrink-0"
                  >
                    {operators.map((op) => (
                      <option key={op.op} value={op.op}>
                        {op.label}
                      </option>
                    ))}
                  </select>

                  {/* Value Input */}
                  <div className="flex-1 flex items-center">
                    {meta?.type === "severity" && cond.operator !== "in" ? (
                      <select
                        value={cond.value}
                        onChange={(e) => handleUpdateCondition(cond.id, { value: e.target.value })}
                        className="w-full px-2.5 py-1.5 rounded bg-[#1D2125] border border-[#30363C] text-[#E9ECEF] text-xs outline-none"
                      >
                        <option value="">-- select severity --</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="informational">Informational</option>
                      </select>
                    ) : (
                      <input
                        type={meta?.type === "number" || meta?.type === "port" ? "text" : "text"}
                        value={cond.value}
                        onChange={(e) => handleUpdateCondition(cond.id, { value: e.target.value })}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            executeQuery(0);
                          }
                        }}
                        placeholder={
                          cond.operator === "in"
                            ? "comma-separated values (e.g. 80, 443 or svc_deploy, admin)"
                            : meta?.type === "port"
                            ? "e.g. 22 or 443 (0-65535)"
                            : meta?.type === "number"
                            ? "e.g. 10000000 (bytes)"
                            : `filter ${meta?.label.toLowerCase()}...`
                        }
                        className="w-full px-2.5 py-1.5 rounded bg-[#1D2125] border border-[#30363C] text-[#E9ECEF] text-xs font-mono placeholder-[#737D87] outline-none"
                      />
                    )}
                  </div>

                  {/* Remove Button */}
                  <button
                    type="button"
                    onClick={() => handleRemoveCondition(cond.id)}
                    title="Remove condition"
                    className="p-1.5 rounded hover:bg-[#1D2125] text-[#737D87] hover:text-[#E06C68] transition-colors cursor-pointer shrink-0"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })
          )}
        </div>

        {/* Action Buttons: Add Condition & Run Query */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleAddCondition}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#24282C] border border-[#30363C] hover:border-[#B58A61]/40 text-[#A0A7AE] hover:text-[#E9ECEF] text-xs font-medium transition-colors cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5 text-[#B58A61]" />
              <span>Add Condition</span>
            </button>

            {conditions.length > 0 && (
              <button
                type="button"
                onClick={handleClearFilters}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded text-xs text-[#737D87] hover:text-[#A0A7AE] transition-colors cursor-pointer"
              >
                <XCircle className="w-3.5 h-3.5" />
                <span>Clear All</span>
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setSaveModalOpen(true)}
              className="flex items-center justify-center gap-1.5 px-3.5 py-2 rounded-md bg-[#24282C] border border-[#B58A61]/30 hover:border-[#B58A61] text-[#B58A61] hover:text-[#C69A70] text-xs font-semibold transition-colors cursor-pointer shadow-sm"
            >
              <BookmarkPlus className="w-3.5 h-3.5" />
              <span>Save as Hunt</span>
            </button>

            <button
              type="button"
              onClick={() => executeQuery(0)}
              disabled={loading}
              className="flex items-center justify-center gap-2 px-5 py-2 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] text-xs font-semibold transition-colors cursor-pointer shadow-sm disabled:opacity-50"
            >
              {loading ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4 fill-current" />
              )}
              <span>{loading ? "Executing Query..." : "Execute Hunt"}</span>
            </button>
          </div>
        </div>

        {/* Presets Row */}
        <div className="flex items-center gap-2 flex-wrap pt-3 border-t border-[#30363C]">
          <span className="text-[11px] text-[#737D87] font-medium flex items-center gap-1">
            <Filter className="w-3 h-3" />
            Hypothesis Presets:
          </span>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleApplyPreset(p)}
              title={p.description}
              className="px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#2B2722] text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/30 transition-colors cursor-pointer"
            >
              {p.name}
            </button>
          ))}
        </div>
      </div>

      {/* Query Diagnostics & Status Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-lg bg-[#1D2125] border border-[#30363C] text-xs shadow-card">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <Database className="w-4 h-4 text-[#B58A61]" />
            <span className="font-semibold text-[#E9ECEF]">
              {loading ? "Executing..." : `${total.toLocaleString()} Matching Events`}
            </span>
          </div>

          {queryResult && (
            <>
              <span className="text-[#30363C]">•</span>
              <span className="text-[#A0A7AE] font-mono text-[11px]">
                Query Execution: <strong className="text-[#B58A61]">{queryResult.query_duration_ms}ms</strong>
              </span>
              <span className="text-[#30363C]">•</span>
              <span className="text-[#A0A7AE] text-[11px]">
                Applied Predicates: <strong className="text-[#E9ECEF]">{queryResult.applied_filter_count}</strong>
              </span>
            </>
          )}
        </div>

        <div className="flex items-center gap-2 text-[11px] text-[#737D87]">
          <span>SQLAlchemy AST • Zero N+1 • O(1) Batched Joins</span>
        </div>
      </div>

      {/* Visible Error Banner */}
      {error && (
        <div className="p-4 rounded-lg bg-[#E06C68]/10 border border-[#E06C68]/30 flex items-start gap-3 text-xs text-[#E9ECEF] shadow-card">
          <AlertCircle className="w-5 h-5 text-[#E06C68] shrink-0 mt-0.5" />
          <div className="space-y-1 flex-1">
            <div className="font-semibold text-[#E06C68]">Threat Hunting Query Rejected</div>
            <p className="text-xs text-[#A0A7AE] leading-relaxed font-mono">{error}</p>
          </div>
          <button
            type="button"
            onClick={() => setError(null)}
            className="text-xs text-[#A0A7AE] hover:text-[#E9ECEF] px-2 py-1 rounded bg-[#1D2125] border border-[#30363C]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Results Table Panel */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
        {/* Table Header Controls */}
        <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-[#B58A61]" />
            <span className="text-xs font-semibold text-[#E9ECEF]">
              Query Results
            </span>
            {queryResult && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[#1D2125] text-[#A0A7AE] border border-[#30363C]">
                Showing {total === 0 ? 0 : offset + 1}–{Math.min(offset + limit, total)} of {total}
              </span>
            )}
          </div>

          {/* Page size limit selector */}
          <div className="flex items-center gap-2 text-xs text-[#737D87]">
            <span>Page Size:</span>
            {[25, 50, 100].map((sz) => (
              <button
                key={sz}
                type="button"
                onClick={() => handleLimitChange(sz)}
                className={`px-2 py-0.5 rounded font-mono text-xs cursor-pointer border ${
                  limit === sz
                    ? "bg-[#2B2722] text-[#B58A61] border-[#B58A61]/30 font-semibold"
                    : "bg-[#1D2125] text-[#A0A7AE] border-[#30363C] hover:text-[#E9ECEF]"
                }`}
              >
                {sz}
              </button>
            ))}
          </div>
        </div>

        {/* Table Body / Loading / Empty State */}
        {loading ? (
          <div className="py-24 flex flex-col items-center justify-center text-xs text-[#737D87] space-y-2">
            <RefreshCw className="w-5 h-5 animate-spin text-[#B58A61]" />
            <span>Executing structured threat hunt query against telemetry store...</span>
          </div>
        ) : !queryResult || queryResult.items.length === 0 ? (
          <div className="py-20 flex flex-col items-center justify-center text-center text-xs text-[#737D87] space-y-2">
            <Terminal className="w-6 h-6 text-[#737D87]/60" />
            <span className="text-sm font-medium text-[#A0A7AE]">No telemetry records matched the query criteria</span>
            <span className="text-xs text-[#737D87] max-w-md leading-relaxed">
              Try adjusting the condition operators, expanding the time boundary, or running one of the hypothesis presets above.
            </span>
            <button
              type="button"
              onClick={handleClearFilters}
              className="mt-2 px-3 py-1.5 rounded-md bg-[#24282C] border border-[#30363C] text-xs text-[#B58A61] hover:text-[#C69A70]"
            >
              Reset All Filters
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#30363C] bg-[#24282C]/60 text-[#737D87] text-[11px] font-medium">
                  <th className="py-2.5 px-3 whitespace-nowrap">Event ID</th>
                  <th
                    onClick={() => handleToggleSort("timestamp")}
                    className="py-2.5 px-3 whitespace-nowrap cursor-pointer hover:text-[#E9ECEF] transition-colors"
                  >
                    <div className="flex items-center gap-1">
                      <span>Timestamp (UTC)</span>
                      {sortBy === "timestamp" ? (
                        sortOrder === "asc" ? <ArrowUp className="w-3 h-3 text-[#B58A61]" /> : <ArrowDown className="w-3 h-3 text-[#B58A61]" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 opacity-40" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleToggleSort("severity")}
                    className="py-2.5 px-3 whitespace-nowrap cursor-pointer hover:text-[#E9ECEF] transition-colors"
                  >
                    <div className="flex items-center gap-1">
                      <span>Severity</span>
                      {sortBy === "severity" ? (
                        sortOrder === "asc" ? <ArrowUp className="w-3 h-3 text-[#B58A61]" /> : <ArrowDown className="w-3 h-3 text-[#B58A61]" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 opacity-40" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleToggleSort("action")}
                    className="py-2.5 px-3 whitespace-nowrap cursor-pointer hover:text-[#E9ECEF] transition-colors"
                  >
                    <div className="flex items-center gap-1">
                      <span>Action / Category</span>
                      {sortBy === "action" ? (
                        sortOrder === "asc" ? <ArrowUp className="w-3 h-3 text-[#B58A61]" /> : <ArrowDown className="w-3 h-3 text-[#B58A61]" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 opacity-40" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleToggleSort("username")}
                    className="py-2.5 px-3 whitespace-nowrap cursor-pointer hover:text-[#E9ECEF] transition-colors"
                  >
                    <div className="flex items-center gap-1">
                      <span>User</span>
                      {sortBy === "username" ? (
                        sortOrder === "asc" ? <ArrowUp className="w-3 h-3 text-[#B58A61]" /> : <ArrowDown className="w-3 h-3 text-[#B58A61]" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 opacity-40" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleToggleSort("hostname")}
                    className="py-2.5 px-3 whitespace-nowrap cursor-pointer hover:text-[#E9ECEF] transition-colors"
                  >
                    <div className="flex items-center gap-1">
                      <span>Host</span>
                      {sortBy === "hostname" ? (
                        sortOrder === "asc" ? <ArrowUp className="w-3 h-3 text-[#B58A61]" /> : <ArrowDown className="w-3 h-3 text-[#B58A61]" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 opacity-40" />
                      )}
                    </div>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Network (Src → Dst)</th>
                  <th
                    onClick={() => handleToggleSort("bytes_out")}
                    className="py-2.5 px-3 whitespace-nowrap cursor-pointer hover:text-[#E9ECEF] transition-colors text-right"
                  >
                    <div className="flex items-center justify-end gap-1">
                      <span>Egress</span>
                      {sortBy === "bytes_out" ? (
                        sortOrder === "asc" ? <ArrowUp className="w-3 h-3 text-[#B58A61]" /> : <ArrowDown className="w-3 h-3 text-[#B58A61]" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 opacity-40" />
                      )}
                    </div>
                  </th>
                  <th className="py-2.5 px-3 whitespace-nowrap">Correlations</th>
                  <th className="py-2.5 px-3 text-right whitespace-nowrap">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#30363C]">
                {queryResult.items.map((evt) => {
                  const detCount = evt.related_detections?.length || 0;
                  const incCount = evt.related_incidents?.length || 0;

                  return (
                    <tr
                      key={evt.id}
                      onClick={() => {
                        setSelectedEvent(evt);
                        setDrawerOpen(true);
                      }}
                      className="hover:bg-[#24282C]/60 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-3 font-mono text-xs font-semibold text-[#B58A61] whitespace-nowrap">
                        {evt.id}
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#A0A7AE] whitespace-nowrap">
                        {evt.timestamp?.replace("T", " ").slice(0, 19)}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <SeverityBadge severity={evt.severity} size="sm" />
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="text-xs text-[#E9ECEF] font-medium capitalize">
                          {evt.action?.replace(/_/g, " ") || "—"}
                        </div>
                        <div className="text-[10px] text-[#737D87] font-mono">
                          {evt.category}
                        </div>
                      </td>
                      <td className="py-3 px-3 font-mono text-xs text-[#B58A61] whitespace-nowrap">
                        {evt.username || "—"}
                      </td>
                      <td className="py-3 px-3 font-mono text-xs text-[#A0A7AE] whitespace-nowrap">
                        {evt.hostname || "—"}
                      </td>
                      <td className="py-3 px-3 font-mono text-xs text-[#737D87] whitespace-nowrap">
                        {evt.source_ip ? `${evt.source_ip}${evt.source_port ? `:${evt.source_port}` : ""}` : "—"}
                        {" → "}
                        {evt.destination_ip ? `${evt.destination_ip}${evt.destination_port ? `:${evt.destination_port}` : ""}` : "—"}
                      </td>
                      <td className="py-3 px-3 text-right whitespace-nowrap font-mono text-xs">
                        {(evt.bytes_out || 0) > 0 ? (
                          <span className={(evt.bytes_out || 0) > 10000000 ? "text-[#E06C68] font-bold" : "text-[#A0A7AE]"}>
                            {(evt.bytes_out || 0) > 1048576
                              ? `${((evt.bytes_out || 0) / 1048576).toFixed(1)} MB`
                              : `${((evt.bytes_out || 0) / 1024).toFixed(0)} KB`}
                          </span>
                        ) : (
                          <span className="text-[#737D87]">0 B</span>
                        )}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          {detCount > 0 && (
                            <span
                              title={`${detCount} correlated detection rule(s) fired`}
                              className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-[#D99A54]/10 text-[#D99A54] border border-[#D99A54]/25"
                            >
                              <AlertTriangle className="w-2.5 h-2.5" />
                              {detCount} det
                            </span>
                          )}
                          {incCount > 0 && (
                            <span
                              title={`${incCount} associated security incident(s)`}
                              className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-[#E06C68]/10 text-[#E06C68] border border-[#E06C68]/25"
                            >
                              <Flame className="w-2.5 h-2.5" />
                              {incCount} inc
                            </span>
                          )}
                          {detCount === 0 && incCount === 0 && (
                            <span className="text-[#737D87] text-[11px]">—</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(evt);
                            setDrawerOpen(true);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#B58A61] border border-[#30363C] transition-colors text-xs cursor-pointer font-medium"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {queryResult && queryResult.items.length > 0 && (
          <div className="p-3 border-t border-[#30363C] bg-[#24282C] flex items-center justify-between text-xs">
            <span className="text-[#A0A7AE]">
              Page <strong className="text-[#E9ECEF]">{currentPage}</strong> of{" "}
              <strong className="text-[#E9ECEF]">{totalPages}</strong> ({total.toLocaleString()} total events)
            </span>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handlePrevPage}
                disabled={offset === 0 || loading}
                className="flex items-center gap-1 px-3 py-1.5 rounded bg-[#1D2125] border border-[#30363C] text-[#A0A7AE] hover:text-[#E9ECEF] disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Previous</span>
              </button>
              <button
                type="button"
                onClick={handleNextPage}
                disabled={offset + limit >= total || loading}
                className="flex items-center gap-1 px-3 py-1.5 rounded bg-[#1D2125] border border-[#30363C] text-[#A0A7AE] hover:text-[#E9ECEF] disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
              >
                <span>Next</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Evidence Drawer Component */}
      <EvidenceDrawer
        event={selectedEvent}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />

      {/* Save Threat Hunt Modal */}
      <SaveHuntModal
        isOpen={saveModalOpen}
        onClose={() => setSaveModalOpen(false)}
        onSaveSuccess={handleSaveSuccess}
        queryDefinition={getQueryDefinitionForSave()}
        activeConditionCount={conditions.filter((c) => c.value.trim().length > 0).length}
      />

      {/* Saved Threat Hunts Library Drawer */}
      <SavedHuntsDrawer
        isOpen={savedHuntsDrawerOpen}
        onClose={() => setSavedHuntsDrawerOpen(false)}
        onLoadHuntIntoBuilder={handleLoadHuntIntoBuilder}
        onExecuteHuntDirectly={handleExecuteHuntDirectly}
        onPromoteToRule={handlePromoteToRule}
      />

      {/* Promote to Rule Draft Modal */}
      <CreateRuleDraftModal
        isOpen={createRuleModalOpen}
        onClose={() => {
          setCreateRuleModalOpen(false);
          setPromoteModalHunt(null);
        }}
        onDraftCreated={handleDraftCreated}
        sourceHunt={
          promoteModalHunt
            ? {
                id: promoteModalHunt.id,
                name: promoteModalHunt.name,
                version: promoteModalHunt.version,
                queryDefinition: promoteModalHunt.query_definition,
              }
            : null
        }
      />
    </div>
  );
};
