import React, { useState } from "react";
import { X, BookmarkPlus, AlertCircle, Info, Tag, SlidersHorizontal, User } from "lucide-react";
import { api } from "../../services/api";
import { SavedHuntCreate, SavedHuntQueryDefinition, SavedHuntResponse } from "../../types";

interface SaveHuntModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSaveSuccess: (savedHunt: SavedHuntResponse) => void;
  queryDefinition: SavedHuntQueryDefinition;
  activeConditionCount: number;
}

export const SaveHuntModal: React.FC<SaveHuntModalProps> = ({
  isOpen,
  onClose,
  onSaveSuccess,
  queryDefinition,
  activeConditionCount,
}) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tagsInput, setTagsInput] = useState("");
  const [createdBy, setCreatedBy] = useState("analyst_alice");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) {
      setError("Hunt name cannot be blank or whitespace only.");
      return;
    }

    const tags = tagsInput
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    const payload: SavedHuntCreate = {
      name: trimmedName,
      description: description.trim() || undefined,
      tags: tags.length > 0 ? tags : undefined,
      query_definition: queryDefinition,
      created_by: createdBy.trim() || "analyst_alice",
    };

    setLoading(true);
    setError(null);

    try {
      const result = await api.createSavedHunt(payload);
      onSaveSuccess(result);
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to save threat hunt query definition.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div
        className="relative w-full max-w-lg bg-[#1D2125] border border-[#30363C] rounded-lg shadow-2xl flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363C] bg-[#24282C]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-[#2B2722] border border-[#B58A61]/30 text-[#B58A61]">
              <BookmarkPlus className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-[#E9ECEF]">Save Threat Hunt Query</h2>
              <p className="text-[11px] text-[#A0A7AE]">
                Persist current AST query definition for repeat execution and rule promotion
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded text-[#737D87] hover:text-[#E9ECEF] hover:bg-[#1D2125] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mx-6 mt-4 p-3 rounded-md bg-[#E06C68]/10 border border-[#E06C68]/30 flex items-start gap-2.5 text-xs text-[#E06C68]">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {/* Form Body */}
        <form onSubmit={handleSave} className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-medium text-[#E9ECEF] mb-1">
              Hunt Name <span className="text-[#E06C68]">*</span>
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Cobalt Strike C2 Egress on Port 4444"
              maxLength={128}
              className="w-full px-3 py-1.5 rounded-md bg-[#111315] border border-[#30363C] focus:border-[#B58A61] text-[#E9ECEF] text-xs placeholder-[#737D87] outline-none transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#E9ECEF] mb-1">
              Hypothesis / Description <span className="text-[11px] text-[#737D87]">(optional)</span>
            </label>
            <textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe adversary hypothesis or investigation notes..."
              maxLength={2000}
              className="w-full px-3 py-1.5 rounded-md bg-[#111315] border border-[#30363C] focus:border-[#B58A61] text-[#E9ECEF] text-xs placeholder-[#737D87] outline-none transition-colors resize-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#E9ECEF] mb-1">
              Categorization Tags <span className="text-[11px] text-[#737D87]">(comma-separated)</span>
            </label>
            <div className="relative">
              <input
                type="text"
                value={tagsInput}
                onChange={(e) => setTagsInput(e.target.value)}
                placeholder="e.g. c2, beaconing, mitre:t1071"
                className="w-full pl-8 pr-3 py-1.5 rounded-md bg-[#111315] border border-[#30363C] focus:border-[#B58A61] text-[#E9ECEF] text-xs placeholder-[#737D87] outline-none transition-colors"
              />
              <Tag className="w-3.5 h-3.5 text-[#737D87] absolute left-2.5 top-2.5" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#E9ECEF] mb-1">
              Author Demo Identity
            </label>
            <div className="relative">
              <input
                type="text"
                value={createdBy}
                onChange={(e) => setCreatedBy(e.target.value)}
                placeholder="analyst_alice"
                maxLength={128}
                className="w-full pl-8 pr-3 py-1.5 rounded-md bg-[#111315] border border-[#30363C] focus:border-[#B58A61] text-[#E9ECEF] text-xs placeholder-[#737D87] outline-none transition-colors"
              />
              <User className="w-3.5 h-3.5 text-[#737D87] absolute left-2.5 top-2.5" />
            </div>
            <p className="text-[10px] text-[#737D87] mt-1 flex items-center gap-1">
              <Info className="w-3 h-3 text-[#B58A61]" />
              Caller-supplied demo metadata. No cryptographic authentication or enterprise RBAC enforced.
            </p>
          </div>

          {/* AST Summary Preview */}
          <div className="p-3 rounded-md bg-[#24282C] border border-[#30363C] space-y-1 text-xs">
            <div className="flex items-center justify-between text-[#A0A7AE]">
              <span className="flex items-center gap-1.5 font-medium">
                <SlidersHorizontal className="w-3 h-3 text-[#B58A61]" />
                AST Definition Summary:
              </span>
              <span className="font-mono text-[#E9ECEF] font-semibold">
                {activeConditionCount} {activeConditionCount === 1 ? "Condition" : "Conditions"}
              </span>
            </div>
            <div className="flex items-center justify-between text-[11px] text-[#737D87]">
              <span>Boolean Logic: {queryDefinition.filter_group?.logic || "AND"}</span>
              <span>Sort: {queryDefinition.sort_by} ({queryDefinition.sort_order})</span>
            </div>
          </div>

          {/* Footer Controls */}
          <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#30363C]">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-3.5 py-1.5 rounded-md bg-[#24282C] hover:bg-[#30363C] border border-[#30363C] text-xs font-medium text-[#A0A7AE] hover:text-[#E9ECEF] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-md bg-[#B58A61] hover:bg-[#C69A70] text-[#111315] text-xs font-semibold transition-colors disabled:opacity-50 shadow-sm"
            >
              {loading ? "Saving..." : "Save Threat Hunt"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
