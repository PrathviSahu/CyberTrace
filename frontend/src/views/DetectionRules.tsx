import React, { useState } from "react";
import { SeverityBadge } from "../components/common/SeverityBadge";

export const DetectionRules: React.FC = () => {
  const [selectedRuleId, setSelectedRuleId] = useState<string>("DET-001");

  const rules = [
    {
      id: "DET-001",
      title: "Brute Force Authentication Burst",
      severity: "medium",
      tactic: "Credential Access",
      technique: "T1110.001 - Password Guessing",
      description: "Detects 5 or more failed authentication events for the same username within a 60-second sliding temporal window.",
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
  timeframe: 60s
  condition: selection | count(username) >= 5
severity: medium`,
    },
    {
      id: "DET-002",
      title: "Logon Success After Failed Attempts",
      severity: "high",
      tactic: "Initial Access",
      technique: "T1078.002 - Valid Accounts",
      description: "Detects a successful authentication event occurring within 120 seconds of a recognized brute-force failure cluster.",
      yaml: `title: Logon Success After Failed Attempts
id: 7b2d9e44-1f8a-4c23-9e12-88f1234abc02
status: production
description: Identifies valid account compromised immediately following password spray.
references:
  - https://attack.mitre.org/techniques/T1078/002/
tags:
  - attack.initial_access
  - attack.t1078.002
logsource:
  category: authentication
detection:
  condition: sequence(logon_failure >= 5, logon_success) by username within 120s
severity: high`,
    },
    {
      id: "DET-003",
      title: "Unauthorized Sudo Token Elevation",
      severity: "high",
      tactic: "Privilege Escalation",
      technique: "T1548.003 - Sudo and Sudo Caching",
      description: "Detects standard operator accounts executing sudo or token elevation outside approved maintenance windows.",
      yaml: `title: Unauthorized Sudo Token Elevation
id: 8c3e0a15-4d7b-4819-a032-11e9876def03
status: production
description: Detects unexpected elevation to root or system privileges.
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
  condition: selection AND NOT maintenance_window
severity: high`,
    },
    {
      id: "DET-004",
      title: "High-Volume Data Exfiltration",
      severity: "critical",
      tactic: "Exfiltration",
      technique: "T1041 - Exfiltration Over C2 Channel",
      description: "Detects outbound network transmission exceeding 100,000,000 bytes (100 MB) to untrusted external destination IP addresses.",
      yaml: `title: High-Volume Data Exfiltration
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
    bytes_out > 100000000
    destination_ip != private_rfc1918
  condition: selection
severity: critical`,
    },
  ];

  const currentRule = rules.find((r) => r.id === selectedRuleId) || rules[0];

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border-subtle">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-mono font-bold text-white tracking-wide">
              DETECTION-AS-CODE RULE CATALOG
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
              SIGMA COMPATIBLE
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Declarative deterministic detection rules mapped to the MITRE ATT&CK enterprise matrix.
          </p>
        </div>
      </div>

      {/* Rules Grid & Detail Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Rule List (5 cols) */}
        <div className="lg:col-span-5 space-y-3">
          {rules.map((rule) => (
            <div
              key={rule.id}
              onClick={() => setSelectedRuleId(rule.id)}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                rule.id === selectedRuleId
                  ? "bg-bg-surface1 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]"
                  : "bg-bg-surface1/60 border-border-subtle hover:border-slate-600 hover:bg-bg-surface1"
              } space-y-2`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-cyan-400">{rule.id}</span>
                  <SeverityBadge severity={rule.severity} size="sm" />
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/30">
                  {rule.tactic}
                </span>
              </div>
              <div className="text-xs font-mono font-bold text-white">{rule.title}</div>
              <p className="text-[11px] font-mono text-slate-400 line-clamp-2">
                {rule.description}
              </p>
            </div>
          ))}
        </div>

        {/* Right YAML Rule Inspector (7 cols) */}
        <div className="lg:col-span-7 rounded-xl bg-bg-surface1 border border-border-subtle p-5 space-y-4 shadow-card">
          <div className="flex items-start justify-between pb-3 border-b border-border-subtle">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-mono font-bold text-white">{currentRule.title}</span>
                <SeverityBadge severity={currentRule.severity} size="sm" />
              </div>
              <div className="text-xs font-mono text-slate-400 mt-1">
                ATT&CK: <strong className="text-indigo-400">{currentRule.technique}</strong>
              </div>
            </div>
            <span className="text-[10px] font-mono px-2 py-1 rounded bg-bg-surface2 text-emerald-400 border border-emerald-500/30 font-bold">
              STATUS: PRODUCTION
            </span>
          </div>

          <p className="text-xs font-mono text-slate-300 leading-relaxed">
            {currentRule.description}
          </p>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Declarative Sigma Rule Definition:</span>
              <span className="text-cyan-400 font-mono">YAML</span>
            </div>
            <pre className="p-4 rounded-xl bg-black/60 border border-border-subtle font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
              {currentRule.yaml}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
