export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type IncidentStatus = "open" | "in_progress" | "contained" | "resolved" | "closed";
export type DataProvenance = "live_telemetry" | "synthetic_benchmark" | "calculated_evaluation";

export interface CommonEvent {
  id: string;
  timestamp: string;
  source_type: string;
  category: string;
  action: string;
  severity: Severity;
  username?: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  hostname?: string;
  bytes_out?: number;
  process_name?: string;
  process_command_line?: string;
  source_file_hash?: string;
}

export interface Detection {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  entity_type: string;
  entity_value: string;
  detected_at: string;
  explanation: string;
  triggering_event_ids?: string[];
  mitre_tactic?: string;
  mitre_technique?: string;
}

export interface IncidentEntity {
  entity_type: "user" | "hostname" | "source_ip" | "destination_ip" | "service_account";
  entity_value: string;
  relationship: string;
  confidence: number;
  evidence_references: string[];
}

export interface IncidentSummary {
  id: string;
  correlation_key: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  first_seen: string;
  last_seen: string;
  entities: IncidentEntity[];
  owner?: string;
  detections_count?: number;
  events_count?: number;
  provenance: DataProvenance;
}

export interface IncidentDetail {
  incident: IncidentSummary;
  detections: Detection[];
  events: CommonEvent[];
  entities: IncidentEntity[];
}

export interface ObservedFact {
  statement: string;
  event_ids: string[];
}

export interface Hypothesis {
  statement: string;
  supporting_event_ids: string[];
  contradicting_event_ids: string[];
  confidence: "low" | "medium" | "high";
  caveats: string[];
}

export interface UnknownGap {
  question: string;
  reason: string;
}

export interface RecommendedAction {
  action: string;
  rationale: string;
  supporting_event_ids: string[];
  impact: "low" | "medium" | "high";
  requires_human_approval: boolean;
  is_generic_guidance?: boolean;
}

export interface StructuredInvestigation {
  executive_summary: string;
  observed_facts: ObservedFact[];
  hypotheses: Hypothesis[];
  unknowns: UnknownGap[];
  recommended_actions: RecommendedAction[];
  limitations: string[];
}

export interface InvestigationResponse {
  id: string;
  incident_id: string;
  model_id: string;
  status: "completed" | "fallback" | "in_progress" | "failed";
  executive_summary: string;
  structured_result: StructuredInvestigation;
  event_citations: string[];
  tool_call_count: number;
  duration_seconds: number;
  request_id?: string;
  error_message?: string;
  created_at: string;
  completed_at?: string;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: "user" | "host" | "ip" | "detection" | "incident";
  subLabel?: string;
  severity?: Severity;
  criticality?: "tier_1" | "tier_2" | "tier_3" | "tier_4";
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  edgeType: "observed" | "correlated" | "inferred";
  evidenceEventId?: string;
}

export interface OverviewMetrics {
  openIncidents: number;
  criticalAlerts: number;
  monitoredAssets: number;
  detectionCoveragePercent: number;
  eventsIngested24h: number;
  meanTimeToTriageMin: number;
  aiInvestigationsCount: number;
  providerStatus: "healthy" | "degraded" | "fallback";
  provenance: DataProvenance;
}

export interface AssetRecord {
  id: string;
  name: string;
  type: "server" | "workstation" | "domain_controller" | "gateway";
  criticality: "tier_1" | "tier_2" | "tier_3" | "tier_4";
  ip_address: string;
  owner?: string;
  last_seen: string;
  active_incident_count: number;
  risk_score: number;
}

export interface ConfusionMatrix {
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  true_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
}

export interface ThreatLabScenario {
  scenario_id: string;
  name: string;
  description: string;
  event_count: number;
  expected_detection_count: number;
  category: string;
  mitre_techniques: string[];
}

export interface ScenarioReplayResult {
  scenario_id: string;
  scenario_name: string;
  events_processed: number;
  detections_fired_count: number;
  detections: Array<{
    rule_id: string;
    rule_name: string;
    severity: string;
    entity_value: string;
    detected_at: string;
    explanation: string;
    triggering_event_ids: string[];
  }>;
  confusion_matrix: ConfusionMatrix;
  duration_ms: number;
  status: string;
  evaluation_notes: string[];
}
