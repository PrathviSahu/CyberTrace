import React, { useState, useEffect } from "react";
import {
  Server,
  Search,
  Globe,
  User,
  RefreshCw,
  Layers,
  ChevronRight,
  X,
  ExternalLink,
} from "lucide-react";
import { api } from "../services/api";
import {
  AssetSummary,
  AssetDetail,
  IdentitySummary,
  IdentityDetail,
} from "../types";
import { DataProvenanceBadge } from "../components/common/DataProvenanceBadge";
import { useNavigate } from "react-router-dom";

export const AssetInventory: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<"assets" | "identities">("assets");
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [identities, setIdentities] = useState<IdentitySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | "hostname" | "ip">("all");

  // Detail Drawer State
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedAssetDetail, setSelectedAssetDetail] = useState<AssetDetail | null>(null);
  const [selectedIdentityDetail, setSelectedIdentityDetail] = useState<IdentityDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadData = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);

    try {
      const [assetsRes, identitiesRes] = await Promise.all([
        api.getAssets(),
        api.getIdentities(),
      ]);
      setAssets(assetsRes.assets || []);
      setIdentities(identitiesRes.identities || []);
    } catch (err) {
      console.error("Failed to load inventory:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleInspectAsset = async (asset: AssetSummary) => {
    setLoadingDetail(true);
    setSelectedIdentityDetail(null);
    setDrawerOpen(true);
    try {
      const detail = await api.getAssetDetail(asset.asset_type, asset.asset_value);
      setSelectedAssetDetail(detail);
    } catch (err) {
      console.error("Failed to load asset detail:", err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleInspectIdentity = async (identity: IdentitySummary) => {
    setLoadingDetail(true);
    setSelectedAssetDetail(null);
    setDrawerOpen(true);
    try {
      const detail = await api.getIdentityDetail(identity.username);
      setSelectedIdentityDetail(detail);
    } catch (err) {
      console.error("Failed to load identity detail:", err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const filteredAssets = assets.filter((a) => {
    if (typeFilter !== "all" && a.asset_type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return a.asset_value.toLowerCase().includes(q) || a.asset_type.toLowerCase().includes(q);
    }
    return true;
  });

  const filteredIdentities = identities.filter((i) => {
    if (search) {
      const q = search.toLowerCase();
      return i.username.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Asset & Identity Intelligence
            </h1>
            <DataProvenanceBadge provenance="observed_telemetry" size="sm" />
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            Discovered network hosts, observed IP addresses, and authenticated identities derived from live security telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Tab Selector */}
          <div className="flex items-center bg-[#1D2125] p-0.5 rounded-md border border-[#30363C] text-xs">
            <button
              onClick={() => setActiveTab("assets")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                activeTab === "assets"
                  ? "bg-[#24282C] text-[#E9ECEF]"
                  : "text-[#737D87] hover:text-[#E9ECEF]"
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              <span>Network Assets ({assets.length})</span>
            </button>
            <button
              onClick={() => setActiveTab("identities")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-colors cursor-pointer ${
                activeTab === "identities"
                  ? "bg-[#24282C] text-[#E9ECEF]"
                  : "text-[#737D87] hover:text-[#E9ECEF]"
              }`}
            >
              <User className="w-3.5 h-3.5" />
              <span>Identities ({identities.length})</span>
            </button>
          </div>

          {/* Search Box */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#1D2125] border border-[#30363C] text-xs">
            <Search className="w-3.5 h-3.5 text-[#737D87]" />
            <input
              type="text"
              placeholder="Search entity..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-transparent text-[#E9ECEF] placeholder-[#737D87] outline-none w-36 sm:w-44 text-xs font-sans"
            />
          </div>

          {/* Type Filter (for Assets) */}
          {activeTab === "assets" && (
            <div className="flex items-center bg-[#1D2125] p-0.5 rounded-md border border-[#30363C] text-xs">
              {(["all", "hostname", "ip"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`px-2 py-0.5 rounded uppercase text-[11px] font-medium transition-colors cursor-pointer ${
                    typeFilter === t
                      ? "bg-[#24282C] text-[#E9ECEF]"
                      : "text-[#737D87] hover:text-[#E9ECEF]"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          )}

          {/* Refresh */}
          <button
            onClick={() => loadData(true)}
            title="Refresh inventory"
            disabled={refreshing}
            className="p-1.5 rounded-md bg-[#1D2125] border border-[#30363C] hover:border-[#B58A61]/40 text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-[#B58A61]" : ""}`} />
          </button>
        </div>
      </div>

      {/* Main High-Density Inventory Table */}
      <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
        <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#B58A61]" />
            <span className="text-xs font-semibold text-[#E9ECEF]">
              {activeTab === "assets" ? "Observed Network Assets" : "Observed User Identities"}
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[#1D2125] text-[#A0A7AE] border border-[#30363C]">
              {activeTab === "assets" ? filteredAssets.length : filteredIdentities.length} entities
            </span>
          </div>
          <span className="text-[11px] text-[#737D87]">
            Click any row to inspect telemetry profile
          </span>
        </div>

        {loading ? (
          <div className="py-24 flex items-center justify-center text-xs text-[#737D87]">
            <RefreshCw className="w-4 h-4 animate-spin mr-2 text-[#B58A61]" />
            Loading observed telemetry inventory...
          </div>
        ) : activeTab === "assets" ? (
          filteredAssets.length === 0 ? (
            <div className="py-20 text-center text-xs text-[#737D87]">
              No network assets match the current filter.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#30363C] bg-[#24282C]/50 text-[#737D87] text-[11px] font-medium">
                    <th className="py-2.5 px-3.5 whitespace-nowrap">Asset Identifier</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">Type</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">First Observed (UTC)</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">Last Observed (UTC)</th>
                    <th className="py-2.5 px-3 text-center whitespace-nowrap">Event Volume</th>
                    <th className="py-2.5 px-3 text-center whitespace-nowrap">Detections</th>
                    <th className="py-2.5 px-3 text-center whitespace-nowrap">Incidents</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">Provenance</th>
                    <th className="py-2.5 px-3.5 text-right whitespace-nowrap">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#30363C]">
                  {filteredAssets.map((asset) => (
                    <tr
                      key={`${asset.asset_type}-${asset.asset_value}`}
                      onClick={() => handleInspectAsset(asset)}
                      className="hover:bg-[#24282C]/50 cursor-pointer transition-colors group"
                    >
                      <td className="py-3 px-3.5 font-mono text-xs font-semibold text-[#E9ECEF] group-hover:text-[#B58A61] transition-colors whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {asset.asset_type === "hostname" ? (
                            <Server className="w-4 h-4 text-[#A0A7AE] shrink-0" />
                          ) : (
                            <Globe className="w-4 h-4 text-[#737D87] shrink-0" />
                          )}
                          <span>{asset.asset_value}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-medium bg-[#24282C] text-[#737D87] border border-[#30363C]">
                          {asset.asset_type}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#737D87] whitespace-nowrap">
                        {asset.first_seen?.replace("T", " ").slice(0, 19)}
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#A0A7AE] whitespace-nowrap">
                        {asset.last_seen?.replace("T", " ").slice(0, 19)}
                      </td>
                      <td className="py-3 px-3 text-center font-mono text-xs">
                        <span className="text-[#E9ECEF] font-semibold">{asset.event_count}</span>
                      </td>
                      <td className="py-3 px-3 text-center font-mono text-xs">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                            asset.detection_count > 0
                              ? "bg-[#D99A54]/12 text-[#D99A54] border border-[#D99A54]/25"
                              : "text-[#737D87]"
                          }`}
                        >
                          {asset.detection_count}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center font-mono text-xs">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                            asset.incident_count > 0
                              ? "bg-[#E06C68]/12 text-[#E06C68] border border-[#E06C68]/25"
                              : "text-[#737D87]"
                          }`}
                        >
                          {asset.incident_count}
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <DataProvenanceBadge provenance={asset.provenance} size="sm" />
                      </td>
                      <td className="py-3 px-3.5 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspectAsset(asset);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-medium transition-colors cursor-pointer"
                        >
                          <span>Profile</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (
          filteredIdentities.length === 0 ? (
            <div className="py-20 text-center text-xs text-[#737D87]">
              No user identities match the current filter.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#30363C] bg-[#24282C]/50 text-[#737D87] text-[11px] font-medium">
                    <th className="py-2.5 px-3.5 whitespace-nowrap">Username</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">Type</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">First Observed (UTC)</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">Last Observed (UTC)</th>
                    <th className="py-2.5 px-3 text-center whitespace-nowrap">Event Volume</th>
                    <th className="py-2.5 px-3 text-center whitespace-nowrap">Detections</th>
                    <th className="py-2.5 px-3 text-center whitespace-nowrap">Incidents</th>
                    <th className="py-2.5 px-3 whitespace-nowrap">Provenance</th>
                    <th className="py-2.5 px-3.5 text-right whitespace-nowrap">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#30363C]">
                  {filteredIdentities.map((identity) => (
                    <tr
                      key={identity.username}
                      onClick={() => handleInspectIdentity(identity)}
                      className="hover:bg-[#24282C]/50 cursor-pointer transition-colors group"
                    >
                      <td className="py-3 px-3.5 font-mono text-xs font-semibold text-[#E9ECEF] group-hover:text-[#B58A61] transition-colors whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <User className="w-4 h-4 text-[#B58A61] shrink-0" />
                          <span>{identity.username}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-medium bg-[#24282C] text-[#737D87] border border-[#30363C]">
                          identity
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#737D87] whitespace-nowrap">
                        {identity.first_seen?.replace("T", " ").slice(0, 19)}
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#A0A7AE] whitespace-nowrap">
                        {identity.last_seen?.replace("T", " ").slice(0, 19)}
                      </td>
                      <td className="py-3 px-3 text-center font-mono text-xs">
                        <span className="text-[#E9ECEF] font-semibold">{identity.event_count}</span>
                      </td>
                      <td className="py-3 px-3 text-center font-mono text-xs">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                            identity.detection_count > 0
                              ? "bg-[#D99A54]/12 text-[#D99A54] border border-[#D99A54]/25"
                              : "text-[#737D87]"
                          }`}
                        >
                          {identity.detection_count}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center font-mono text-xs">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                            identity.incident_count > 0
                              ? "bg-[#E06C68]/12 text-[#E06C68] border border-[#E06C68]/25"
                              : "text-[#737D87]"
                          }`}
                        >
                          {identity.incident_count}
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <DataProvenanceBadge provenance={identity.provenance} size="sm" />
                      </td>
                      <td className="py-3 px-3.5 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleInspectIdentity(identity);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-medium transition-colors cursor-pointer"
                        >
                          <span>Profile</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}
      </div>

      {/* Slide-over Asset/Identity Telemetry Profile Drawer */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fadeIn select-none">
          <div className="w-full max-w-xl h-full bg-[#1D2125] border-l border-[#30363C] flex flex-col shadow-drawer p-6 space-y-5 overflow-y-auto">
            {/* Drawer Header */}
            <div className="flex items-center justify-between pb-4 border-b border-[#30363C]">
              <div className="flex items-center gap-3">
                {selectedAssetDetail ? (
                  selectedAssetDetail.asset_type === "hostname" ? (
                    <Server className="w-5 h-5 text-[#A0A7AE]" />
                  ) : (
                    <Globe className="w-5 h-5 text-[#737D87]" />
                  )
                ) : (
                  <User className="w-5 h-5 text-[#B58A61]" />
                )}
                <div>
                  <div className="text-base font-mono font-semibold text-[#E9ECEF]">
                    {selectedAssetDetail
                      ? selectedAssetDetail.asset_value
                      : selectedIdentityDetail?.username}
                  </div>
                  <div className="text-xs text-[#737D87]">
                    Telemetry Profile •{" "}
                    {selectedAssetDetail
                      ? selectedAssetDetail.asset_type
                      : "User Identity"}
                  </div>
                </div>
              </div>

              <button
                onClick={() => setDrawerOpen(false)}
                className="p-1.5 rounded-md bg-[#24282C] hover:bg-[#2B2722] text-[#737D87] hover:text-[#E9ECEF] transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {loadingDetail ? (
              <div className="py-24 flex items-center justify-center text-xs text-[#737D87]">
                <RefreshCw className="w-4 h-4 animate-spin mr-2 text-[#B58A61]" />
                Loading detailed telemetry profile...
              </div>
            ) : selectedAssetDetail ? (
              <div className="space-y-5">
                {/* Stats Overview */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 rounded-md bg-[#24282C] border border-[#30363C] text-center">
                    <div className="text-xs text-[#737D87]">Events</div>
                    <div className="text-lg font-mono font-semibold text-[#E9ECEF] mt-1">
                      {selectedAssetDetail.event_count}
                    </div>
                  </div>
                  <div className="p-3 rounded-md bg-[#24282C] border border-[#30363C] text-center">
                    <div className="text-xs text-[#737D87]">Detections</div>
                    <div className="text-lg font-mono font-semibold text-[#D99A54] mt-1">
                      {selectedAssetDetail.detection_count}
                    </div>
                  </div>
                  <div className="p-3 rounded-md bg-[#24282C] border border-[#30363C] text-center">
                    <div className="text-xs text-[#737D87]">Incidents</div>
                    <div className="text-lg font-mono font-semibold text-[#E06C68] mt-1">
                      {selectedAssetDetail.incident_count}
                    </div>
                  </div>
                </div>

                {/* Triggered Detection Rules */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-[#E9ECEF]">
                    Associated Detection Rules
                  </span>
                  {selectedAssetDetail.triggered_rules.length === 0 ? (
                    <div className="p-4 rounded-md bg-[#24282C] border border-[#30363C] text-xs text-[#737D87]">
                      No detection rules triggered against this asset.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {selectedAssetDetail.triggered_rules.map((rule, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-md bg-[#24282C] border border-[#30363C] flex items-center justify-between text-xs"
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-[#B58A61]">{rule.rule_id}</span>
                            <span className="text-[#A0A7AE]">{rule.rule_name}</span>
                          </div>
                          <button
                            onClick={() => {
                              setDrawerOpen(false);
                              navigate("/alerts");
                            }}
                            className="text-xs text-[#737D87] hover:text-[#E9ECEF] flex items-center gap-1 cursor-pointer font-medium"
                          >
                            <span>View Alert</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Associated Incident IDs */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-[#E9ECEF]">
                    Associated Incident IDs
                  </span>
                  {selectedAssetDetail.incident_ids.length === 0 ? (
                    <div className="p-4 rounded-md bg-[#24282C] border border-[#30363C] text-xs text-[#737D87]">
                      No active security incidents implicated.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {selectedAssetDetail.incident_ids.map((incId) => (
                        <div
                          key={incId}
                          className="p-3 rounded-md bg-[#E06C68]/10 border border-[#E06C68]/25 flex items-center justify-between text-xs font-mono"
                        >
                          <span className="font-semibold text-[#E06C68]">{incId}</span>
                          <button
                            onClick={() => {
                              setDrawerOpen(false);
                              navigate(`/incidents/${incId}`);
                            }}
                            className="text-xs text-[#B58A61] hover:text-[#C69A70] flex items-center gap-1 cursor-pointer font-sans font-medium"
                          >
                            <span>Open Incident</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : selectedIdentityDetail ? (
              <div className="space-y-5">
                {/* Stats Overview */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 rounded-md bg-[#24282C] border border-[#30363C] text-center">
                    <div className="text-xs text-[#737D87]">Events</div>
                    <div className="text-lg font-mono font-semibold text-[#E9ECEF] mt-1">
                      {selectedIdentityDetail.event_count}
                    </div>
                  </div>
                  <div className="p-3 rounded-md bg-[#24282C] border border-[#30363C] text-center">
                    <div className="text-xs text-[#737D87]">Detections</div>
                    <div className="text-lg font-mono font-semibold text-[#D99A54] mt-1">
                      {selectedIdentityDetail.detection_count}
                    </div>
                  </div>
                  <div className="p-3 rounded-md bg-[#24282C] border border-[#30363C] text-center">
                    <div className="text-xs text-[#737D87]">Incidents</div>
                    <div className="text-lg font-mono font-semibold text-[#E06C68] mt-1">
                      {selectedIdentityDetail.incident_count}
                    </div>
                  </div>
                </div>

                {/* Associated Rules */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-[#E9ECEF]">
                    Associated Detection Rules
                  </span>
                  {selectedIdentityDetail.triggered_rules.length === 0 ? (
                    <div className="p-4 rounded-md bg-[#24282C] border border-[#30363C] text-xs text-[#737D87]">
                      No detection rules triggered against this identity.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {selectedIdentityDetail.triggered_rules.map((rule, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-md bg-[#24282C] border border-[#30363C] flex items-center justify-between text-xs"
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-[#B58A61]">{rule.rule_id}</span>
                            <span className="text-[#A0A7AE]">{rule.rule_name}</span>
                          </div>
                          <button
                            onClick={() => {
                              setDrawerOpen(false);
                              navigate("/alerts");
                            }}
                            className="text-xs text-[#737D87] hover:text-[#E9ECEF] flex items-center gap-1 cursor-pointer font-medium"
                          >
                            <span>View Alert</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Associated Incidents */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-[#E9ECEF]">
                    Associated Incident IDs
                  </span>
                  {selectedIdentityDetail.incident_ids.length === 0 ? (
                    <div className="p-4 rounded-md bg-[#24282C] border border-[#30363C] text-xs text-[#737D87]">
                      No active security incidents implicated.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {selectedIdentityDetail.incident_ids.map((incId) => (
                        <div
                          key={incId}
                          className="p-3 rounded-md bg-[#E06C68]/10 border border-[#E06C68]/25 flex items-center justify-between text-xs font-mono"
                        >
                          <span className="font-semibold text-[#E06C68]">{incId}</span>
                          <button
                            onClick={() => {
                              setDrawerOpen(false);
                              navigate(`/incidents/${incId}`);
                            }}
                            className="text-xs text-[#B58A61] hover:text-[#C69A70] flex items-center gap-1 cursor-pointer font-sans font-medium"
                          >
                            <span>Open Incident</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
