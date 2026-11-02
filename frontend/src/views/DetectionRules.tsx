import React, { useState, useEffect } from "react";
import {
  Check,
  Copy,
  Search,
} from "lucide-react";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { api } from "../services/api";
import { Detection } from "../types";

export const DetectionRules: React.FC = () => {
  const [selectedRuleId, setSelectedRuleId] = useState<string>("DET-001");
  const [copied, setCopied] = useState(false);
  const [search, setSearch] = useState("");
  const [detections, setDetections] = useState<Detection[]>([]);

  useEffect(() => {
    api
      .getDetections()
      .then((dets) => setDetections(dets))
      .catch((err) => console.error("Failed to load detections for rule counts:", err));
  }, []);

  const rules = [
    {
      id: "DET-001",
      title: "Brute Force Authentication Burst",
      severity: "medium",
      tactic: "Credential Access",
      technique: "T1110.001 - Password Guessing",
      description:
        "Detects 5 or more failed authentication events for the same username within a 300-second temporal window.",
      yaml: `title: Brute Force Authentication Burst
id: 5a8e1f02-9c3b-4e12-b184-7a38e89f2101
status: production
description: Detects rapid consecutive failed logons targeting a single identity.
references:
  - https://attack.mitre.org/techniques/T1110/001/
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  category: authentication
  product: linux / windows
detection:
  selection:
    category: authentication
    action: logon_failure
  timeframe: 300s
  condition: selection | count(username) >= 5
severity: medium`,
    },
    {
      id: "DET-002",
      title: "Logon Success After Failed Attempts",
      severity: "high",
      tactic: "Initial Access",
      technique: "T1078.002 - Valid Accounts",
      description:
        "Detects a successful authentication event occurring within 300 seconds of a recognized brute-force failure cluster.",
      yaml: `title: Logon Success After Failed Attempts
id: 7b2d9e44-1f8a-4c23-9e12-88f1234abc02
status: production
description: Identifies valid account compromise immediately following password spray.
references:
  - https://attack.mitre.org/techniques/T1078/002/
tags:
  - attack.initial_access
  - attack.t1078.002
logsource:
  category: authentication
detection:
  condition: sequence(logon_failure >= 5, logon_success) by username within 300s
severity: high`,
    },
    {
      id: "DET-003",
      title: "Unauthorized Sudo Token Elevation",
      severity: "high",
      tactic: "Privilege Escalation",
      technique: "T1548.003 - Sudo and Sudo Caching",
      description:
        "Detects standard operator or deployment accounts executing sudo or token elevation to gain root privileges.",
      yaml: `title: Unauthorized Sudo Token Elevation
id: 8c3e0a15-4d7b-4819-a032-11e9876def03
status: production
description: Detects unexpected elevation to root or system privileges.
references:
  - https://attack.mitre.org/techniques/T1548/003/
tags:
  - attack.privilege_escalation
  - attack.t1548.003
logsource:
  category: authentication
  product: linux
detection:
  selection:
    action: privilege_elevation
    status: success
  condition: selection
severity: high`,
    },
    {
      id: "DET-004",
      title: "Anomalous Outbound Network Activity",
      severity: "critical",
      tactic: "Exfiltration",
      technique: "T1041 - Exfiltration Over C2 Channel",
      description:
        "Detects outbound network transmission exceeding 50,000,000 bytes (50 MB) to untrusted external destination IP addresses.",
      yaml: `title: Anomalous Outbound Network Activity
id: 9d4f1b26-5e8c-4920-b143-22f0987ghi04
status: production
description: Identifies anomalous large volume outbound egress.
references:
  - https://attack.mitre.org/techniques/T1041/
tags:
  - attack.exfiltration
  - attack.t1041
logsource:
  category: network_connection
detection:
  selection:
    category: network_connection
    bytes_out: > 50000000
  condition: selection
severity: critical`,
    },
  ];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const selectedRule = rules.find((r) => r.id === selectedRuleId) || rules[0];

  const filteredRules = rules.filter((r) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      r.id.toLowerCase().includes(q) ||
      r.title.toLowerCase().includes(q) ||
      r.tactic.toLowerCase().includes(q) ||
      r.technique.toLowerCase().includes(q)
    );
  });

  const getFiringCount = (ruleId: string) => {
    return detections.filter((d) => d.rule_id === ruleId).length;
  };

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 bg-[#111315] text-[#E9ECEF]">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-[#30363C]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[#E9ECEF] tracking-tight">
              Detection Engineering Catalog
            </h1>
            <span className="text-[11px] px-2 py-0.5 rounded-md bg-[#24282C] text-[#A0A7AE] border border-[#30363C] font-medium">
              Sigma-compatible subset
            </span>
          </div>
          <p className="text-xs text-[#A0A7AE] mt-1">
            Production detection logic mapped to MITRE ATT&CK enterprise tactics and evaluated against CES telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#1D2125] border border-[#30363C] text-xs">
            <Search className="w-3.5 h-3.5 text-[#737D87]" />
            <input
              type="text"
              placeholder="Search rule ID, technique..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-transparent text-[#E9ECEF] placeholder-[#737D87] outline-none w-48 text-xs font-sans"
            />
          </div>
        </div>
      </div>

      {/* Two-Column Catalog Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column (5 Cols): Rule List */}
        <div className="lg:col-span-5 space-y-3">
          <div className="rounded-lg bg-[#1D2125] border border-[#30363C] overflow-hidden shadow-card">
            <div className="p-3 border-b border-[#30363C] bg-[#24282C] flex items-center justify-between">
              <span className="text-xs font-semibold text-[#E9ECEF]">
                Active Rule Definitions ({filteredRules.length})
              </span>
              <span className="text-xs text-[#737D87]">
                Live Firing Counts
              </span>
            </div>

            <div className="divide-y divide-[#30363C]">
              {filteredRules.map((r) => {
                const count = getFiringCount(r.id);
                return (
                  <div
                    key={r.id}
                    onClick={() => setSelectedRuleId(r.id)}
                    className={`p-3.5 cursor-pointer transition-colors ${
                      r.id === selectedRuleId
                        ? "bg-[#2B2722] border-l-2 border-[#B58A61]"
                        : "hover:bg-[#24282C]/50"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-[#B58A61]">{r.id}</span>
                        <SeverityBadge severity={r.severity} size="sm" />
                      </div>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium ${
                          count > 0
                            ? "bg-[#D99A54]/12 text-[#D99A54] border border-[#D99A54]/25"
                            : "bg-[#24282C] text-[#737D87]"
                        }`}
                      >
                        {count} Active Firings
                      </span>
                    </div>

                    <div className="text-xs font-medium text-[#E9ECEF] mt-0.5">
                      {r.title}
                    </div>

                    <div className="text-[11px] text-[#737D87] mt-0.5 truncate">
                      {r.technique}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column (7 Cols): Rule Detail & Sigma YAML Specification */}
        <div className="lg:col-span-7 space-y-4">
          <div className="rounded-lg bg-[#1D2125] border border-[#30363C] p-5 space-y-4 shadow-card">
            <div className="flex items-start justify-between gap-4 pb-3 border-b border-[#30363C]">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-semibold text-[#B58A61]">
                    {selectedRule.id}
                  </span>
                  <SeverityBadge severity={selectedRule.severity} size="sm" />
                  <span className="text-[11px] px-2 py-0.5 rounded bg-[#24282C] text-[#A0A7AE] border border-[#30363C]">
                    {selectedRule.tactic}
                  </span>
                </div>
                <h2 className="text-base font-semibold text-[#E9ECEF]">
                  {selectedRule.title}
                </h2>
                <div className="text-xs text-[#737D87] mt-0.5">
                  MITRE ATT&CK: <span className="text-[#A0A7AE] font-mono text-xs">{selectedRule.technique}</span>
                </div>
              </div>

              <button
                onClick={() => handleCopy(selectedRule.yaml)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#24282C] hover:bg-[#2B2722] text-[#A0A7AE] hover:text-[#E9ECEF] border border-[#30363C] hover:border-[#B58A61]/40 text-xs font-medium transition-colors shrink-0 cursor-pointer"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-[#76A58B]" />
                    <span className="text-[#76A58B]">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-[#737D87]" />
                    <span>Copy Rule YAML</span>
                  </>
                )}
              </button>
            </div>

            <p className="text-xs text-[#A0A7AE] leading-relaxed bg-[#24282C] p-3.5 rounded-md border border-[#30363C]">
              {selectedRule.description}
            </p>

            {/* Sigma YAML Code Block */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-[#737D87]">
                <span className="font-semibold text-[#E9ECEF]">
                  Sigma-Compatible Rule Specification
                </span>
                <span className="text-[11px] text-[#737D87] font-mono">Format: YAML / Sigma-compatible subset</span>
              </div>
              <pre className="p-4 rounded-lg bg-[#191C1F] border border-[#30363C] text-xs font-mono text-[#A0A7AE] leading-relaxed overflow-x-auto">
                {selectedRule.yaml}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
