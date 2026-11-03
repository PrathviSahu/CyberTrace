import React, { useState, useEffect, useCallback } from "react";
import {
  X,
  Bookmark,
  Play,
  SlidersHorizontal,
  Code2,
  Copy,
  Archive,
  Search,
  RefreshCw,
  AlertCircle,
  Clock,
  User,
  Tag,
  Check,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { api } from "../../services/api";
import {
  SavedHuntResponse,
  SavedHuntExecuteResponse,
} from "../../types";

interface SavedHuntsDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onLoadHuntIntoBuilder: (hunt: SavedHuntResponse) => void;
  onExecuteHuntDirectly: (execResult: SavedHuntExecuteResponse) => void;
}

export const SavedHuntsDrawer: React.FC<SavedHuntsDrawerProps> = ({
  isOpen,
  onClose,
  onLoadHuntIntoBuilder,
  onExecuteHuntDirectly,
}) => {
  const [hunts, setHunts] = useState<SavedHuntResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [includeArchived, setIncludeArchived] = useState(false);
  const [expandedAstId, setExpandedAstId] = useState<string | null>(null);
  const [executingHuntId, setExecutingHuntId] = useState<string | null>(null);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);

  const fetchHunts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listSavedHunts({
        query: searchTerm.trim() || undefined,
        tag: selectedTag || undefined,
        include_archived: includeArchived,
        limit: 100,
      });
      setHunts(data.items);
    } catch (err: any) {
      setError(err.message || "Failed to load saved threat hunts.");
    } finally {
      setLoading(false);
    }
  }, [searchTerm, selectedTag, includeArchived]);

  useEffect(() => {
    if (isOpen) {
      fetchHunts();
    }
  }, [isOpen, fetchHunts]);

  if (!isOpen) return null;

  const handleExecute = async (hunt: SavedHuntResponse) => {
    setExecutingHuntId(hunt.id);
    setError(null);
    try {
      const result = await api.executeSavedHunt(hunt.id, {
        executed_by: "analyst_alice",
      });
      onExecuteHuntDirectly(result);
      // Refresh list to update run_count and last_run_at
      await fetchHunts();
      onClose();
    } catch (err: any) {
      setError(err.message || `Execution of hunt '${hunt.name}' failed.`);
    } finally {
      setExecutingHuntId(null);
    }
  };

  const handleDuplicate = async (hunt: SavedHuntResponse) => {
    setError(null);
    try {
      const dup = await api.duplicateSavedHunt(hunt.id, {
        name: `Copy of ${hunt.name}`,
        created_by: "analyst_alice",
      });
      setActionSuccessMsg(`Duplicated as "${dup.name}"`);
      setTimeout(() => setActionSuccessMsg(null), 3000);
      await fetchHunts();
    } catch (err: any) {
      setError(err.message || `Failed to duplicate hunt '${hunt.name}'.`);
    }
  };

  const handleArchive = async (hunt: SavedHuntResponse) => {
    if (!window.confirm(`Archive saved hunt "${hunt.name}"? It will be excluded from default listings.`)) {
      return;
    }
    setError(null);
    try {
      await api.archiveSavedHunt(hunt.id);
      setActionSuccessMsg(`Archived hunt "${hunt.name}"`);
      setTimeout(() => setActionSuccessMsg(null), 3000);
      await fetchHunts();
    } catch (err: any) {
      setError(err.message || `Failed to archive hunt '${hunt.name}'.`);
    }
  };

  // Collect all unique tags for tag filter chips
  const allTags = Array.from(new Set(hunts.flatMap((h) => h.tags || [])));

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end animate-fadeIn">
      <div
        className="relative w-full max-w-2xl bg-[#1D2125] border-l border-[#30363C] h-full shadow-drawer flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363C] bg-[#24282C]">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-[#2B2722] border border-[#B58A61]/30 text-[#B58A61]">
              <Bookmark className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold text-[#E9ECEF]">Saved Threat Hunts</h2>
                <span className="px-2 py-0.5 rounded-full bg-[#111315] border border-[#30363C] text-[11px] font-mono text-[#A0A7AE]">
                  {hunts.length}
                </span>
              </div>
              <p className="text-xs text-[#A0A7AE] mt-0.5">
                Persisted AST hunting queries, execution metrics, and detection rule origins
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchHunts()}
              disabled={loading}
              title="Refresh saved hunts"
              className="p-1.5 rounded hover:bg-[#1D2125] text-[#737D87] hover:text-[#E9ECEF] transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-[#B58A61]" : ""}`} />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-[#1D2125] text-[#737D87] hover:text-[#E9ECEF] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Notifications Banner */}
        {error && (
          <div className="mx-6 mt-3 p-3 rounded-md bg-[#E06C68]/10 border border-[#E06C68]/30 flex items-start gap-2 text-xs text-[#E06C68]">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
        {actionSuccessMsg && (
          <div className="mx-6 mt-3 p-2.5 rounded-md bg-[#76A58B]/10 border border-[#76A58B]/30 flex items-center gap-2 text-xs text-[#76A58B]">
            <Check className="w-4 h-4 shrink-0" />
            <span>{actionSuccessMsg}</span>
          </div>
        )}

        {/* Search & Filter Toolbar */}
        <div className="px-6 py-3 border-b border-[#30363C] bg-[#1D2125] space-y-2.5">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search hunts by name or description..."
                className="w-full pl-8 pr-3 py-1.5 rounded-md bg-[#111315] border border-[#30363C] focus:border-[#B58A61] text-xs text-[#E9ECEF] placeholder-[#737D87] outline-none transition-colors"
              />
              <Search className="w-3.5 h-3.5 text-[#737D87] absolute left-2.5 top-2.5" />
            </div>

            <label className="flex items-center gap-1.5 text-[11px] text-[#A0A7AE] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includeArchived}
                onChange={(e) => setIncludeArchived(e.target.checked)}
                className="rounded border-[#30363C] text-[#B58A61] focus:ring-0"
              />
              <span>Archived</span>
            </label>
          </div>

          {/* Tags Filter Chips */}
          {allTags.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap pt-1">
              <span className="text-[10px] text-[#737D87] font-medium flex items-center gap-1">
                <Tag className="w-3 h-3" />
                Filter Tag:
              </span>
              {selectedTag && (
                <button
                  type="button"
                  onClick={() => setSelectedTag(null)}
                  className="px-2 py-0.5 rounded text-[10px] bg-[#E06C68]/20 text-[#E06C68] border border-[#E06C68]/30 hover:bg-[#E06C68]/30 transition-colors"
                >
                  Clear filter ({selectedTag}) ×
                </button>
              )}
              {allTags.slice(0, 8).map((tag) => (
                <button
                  key={tag}
                  type="button"
                  onClick={() => setSelectedTag(selectedTag === tag ? null : tag)}
                  className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                    selectedTag === tag
                      ? "bg-[#B58A61] text-[#111315] border-[#B58A61] font-semibold"
                      : "bg-[#24282C] text-[#A0A7AE] border-[#30363C] hover:text-[#E9ECEF]"
                  }`}
                >
                  {tag}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Saved Hunts List Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-3">
          {loading && hunts.length === 0 ? (
            <div className="py-20 flex flex-col items-center justify-center text-center text-xs text-[#737D87] space-y-2">
              <RefreshCw className="w-6 h-6 animate-spin text-[#B58A61]" />
              <span>Loading saved threat hunts...</span>
            </div>
          ) : hunts.length === 0 ? (
            <div className="py-20 flex flex-col items-center justify-center text-center text-xs text-[#737D87] space-y-2 border border-dashed border-[#30363C] rounded-lg">
              <Bookmark className="w-8 h-8 text-[#737D87]/40" />
              <span className="text-sm font-medium text-[#A0A7AE]">No saved threat hunts found</span>
              <p className="max-w-xs text-xs text-[#737D87] leading-relaxed">
                Build a query in the Threat Hunting view and click &quot;Save Hunt&quot; to persist your hypothesis.
              </p>
            </div>
          ) : (
            hunts.map((hunt) => {
              const condCount = hunt.query_definition?.filter_group?.conditions?.length || 0;
              const isExecuting = executingHuntId === hunt.id;
              const isAstExpanded = expandedAstId === hunt.id;

              return (
                <div
                  key={hunt.id}
                  className={`p-4 rounded-lg bg-[#24282C] border transition-colors space-y-3 ${
                    hunt.is_archived
                      ? "border-[#30363C]/60 opacity-60"
                      : "border-[#30363C] hover:border-[#B58A61]/40"
                  }`}
                >
                  {/* Card Header: Title & Badges */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-xs text-[#E9ECEF] hover:text-[#B58A61] transition-colors">
                          {hunt.name}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#1D2125] text-[#B58A61] border border-[#B58A61]/30">
                          v{hunt.version}
                        </span>
                        {hunt.is_archived && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-[#E06C68]/20 text-[#E06C68] border border-[#E06C68]/30">
                            ARCHIVED
                          </span>
                        )}
                      </div>
                      {hunt.description && (
                        <p className="text-[11px] text-[#A0A7AE] leading-relaxed line-clamp-2">
                          {hunt.description}
                        </p>
                      )}
                    </div>

                    {/* Quick Run Button */}
                    {!hunt.is_archived && (
                      <button
                        type="button"
                        onClick={() => handleExecute(hunt)}
                        disabled={isExecuting}
                        title="Execute saved hunt immediately"
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] font-semibold text-xs transition-colors shrink-0 disabled:opacity-50 cursor-pointer shadow-sm"
                      >
                        <Play className={`w-3.5 h-3.5 fill-current ${isExecuting ? "animate-spin" : ""}`} />
                        <span>{isExecuting ? "Running..." : "Run"}</span>
                      </button>
                    )}
                  </div>

                  {/* Metadata Row: Stats & Author */}
                  <div className="flex items-center justify-between gap-2 text-[11px] text-[#737D87] pt-1 border-t border-[#30363C]/40 flex-wrap">
                    <div className="flex items-center gap-3">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-[#B58A61]" />
                        <span>Runs: <strong className="text-[#E9ECEF] font-mono">{hunt.run_count}</strong></span>
                      </span>
                      <span>•</span>
                      <span>
                        Last:{" "}
                        <strong className="text-[#A0A7AE] font-mono">
                          {hunt.last_run_at ? hunt.last_run_at.replace("T", " ").slice(0, 19) : "Never"}
                        </strong>
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 text-[10px] text-[#737D87]">
                      <User className="w-3 h-3" />
                      <span>{hunt.created_by} (demo identity)</span>
                    </div>
                  </div>

                  {/* Tags */}
                  {hunt.tags && hunt.tags.length > 0 && (
                    <div className="flex items-center gap-1 flex-wrap">
                      {hunt.tags.map((t) => (
                        <span
                          key={t}
                          className="px-2 py-0.5 rounded text-[10px] bg-[#1D2125] text-[#A0A7AE] border border-[#30363C]"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* AST Definition Snippet */}
                  <div className="text-[11px] text-[#737D87] bg-[#1D2125] p-2 rounded border border-[#30363C] flex items-center justify-between">
                    <span>
                      AST: {condCount} conditions ({hunt.query_definition?.filter_group?.logic || "AND"}) • Sort:{" "}
                      {hunt.query_definition?.sort_by || "timestamp"}
                    </span>
                    <button
                      type="button"
                      onClick={() => setExpandedAstId(isAstExpanded ? null : hunt.id)}
                      className="text-[#B58A61] hover:underline flex items-center gap-0.5 text-[10px]"
                    >
                      <Code2 className="w-3 h-3" />
                      <span>{isAstExpanded ? "Hide AST" : "View AST"}</span>
                      {isAstExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>
                  </div>

                  {/* Collapsible AST JSON Viewer */}
                  {isAstExpanded && (
                    <div className="p-2.5 rounded bg-[#111315] border border-[#30363C] overflow-x-auto text-[10px] font-mono text-[#76A58B]">
                      <pre>{JSON.stringify(hunt.query_definition, null, 2)}</pre>
                    </div>
                  )}

                  {/* Card Actions Toolbar */}
                  <div className="flex items-center justify-between pt-1 text-xs">
                    <button
                      type="button"
                      onClick={() => {
                        onLoadHuntIntoBuilder(hunt);
                        onClose();
                      }}
                      className="flex items-center gap-1.5 text-xs text-[#B58A61] hover:text-[#C69A70] font-medium transition-colors cursor-pointer"
                    >
                      <SlidersHorizontal className="w-3.5 h-3.5" />
                      <span>Load into Query Builder</span>
                    </button>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleDuplicate(hunt)}
                        title="Duplicate hunt"
                        className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#1D2125] hover:bg-[#30363C] text-[11px] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] transition-colors"
                      >
                        <Copy className="w-3 h-3" />
                        <span>Duplicate</span>
                      </button>

                      {!hunt.is_archived && (
                        <button
                          type="button"
                          onClick={() => handleArchive(hunt)}
                          title="Archive hunt"
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#1D2125] hover:bg-[#E06C68]/20 text-[11px] text-[#737D87] hover:text-[#E06C68] border border-[#30363C] transition-colors"
                        >
                          <Archive className="w-3 h-3" />
                          <span>Archive</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
