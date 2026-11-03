import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DetectionRules } from "../DetectionRules";
import { api } from "../../services/api";
import {
  DetectionRuleDraftResponse,
  DetectionRuleDraftListResponse,
  RuleValidationReportResponse,
} from "../../types";

vi.mock("../../services/api", () => ({
  api: {
    getDetections: vi.fn(),
    listActiveRules: vi.fn(),
    listRuleDrafts: vi.fn(),
    createRuleDraft: vi.fn(),
    validateRuleDraft: vi.fn(),
    archiveRuleDraft: vi.fn(),
    approveRuleDraft: vi.fn(),
    rejectRuleDraft: vi.fn(),
    updateActiveRuleStatus: vi.fn(),
    listRuleAuditEntries: vi.fn(),
  },
}));

const mockDraft: DetectionRuleDraftResponse = {
  id: "draft_001",
  name: "PowerShell Encoded Command Execution",
  description: "Detects base64 encoded powershell payloads",
  severity: "high",
  mitre_attack_id: "T1059.001",
  mitre_tactic: "execution",
  source_hunt_id: "hunt_001",
  source_hunt_version: 1,
  query_definition: {
    filter_group: {
      logic: "AND",
      conditions: [{ field: "process_name", operator: "contains", value: "powershell" }],
    },
    sort_by: "timestamp",
    sort_order: "desc",
  },
  status: "DRAFT",
  version: 1,
  created_by: "analyst_alice",
  is_archived: false,
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
  latest_validation: null,
  author_attribution_note: "Caller-supplied demo identity.",
};

const mockDraftList: DetectionRuleDraftListResponse = {
  items: [mockDraft],
  total: 1,
  limit: 100,
  offset: 0,
};

const mockValidationReport: RuleValidationReportResponse = {
  validation_id: "val_001",
  draft_id: "draft_001",
  draft_version: 1,
  run_at: "2026-11-01T11:00:00Z",
  target_scope: "all",
  duration_ms: 18.5,
  status: "VALIDATED",
  error_message: null,
  is_stale: false,
  draft_status_updated: true,
  provenance_disclaimer: "Synthetic benchmark matches are evaluated separately.",
  historical_metrics: {
    events_scanned: 1500,
    matches_found: 4,
    observation_start: "2026-11-01T00:00:00Z",
    observation_end: "2026-11-02T00:00:00Z",
    observation_duration_days: 1.0,
    estimated_daily_alert_volume: 4.0,
    daily_volume_formula: "matches / duration_days",
    insufficient_history_warning: false,
    provenance_breakdown: {
      synthetic_benchmark: 4,
      observed_telemetry: 0,
      unknown: 0,
    },
    sample_matched_event_ids: ["evt_01", "evt_02"],
  },
  threatlab_metrics: {
    scenarios_evaluated: 4,
    total_benchmark_events: 100,
    total_matches: 4,
    benign_baseline_matches: 0,
    has_benign_baseline_warning: false,
    scenario_results: [
      {
        scenario_id: "SCN-001",
        name: "Cobalt Strike Infiltration",
        category: "c2",
        total_events: 25,
        matches_found: 4,
        classification: "true_positive",
        is_benign_baseline_warning: false,
        matched_event_ids: ["evt_01"],
      },
      {
        scenario_id: "SCN-004",
        name: "Benign Admin Baseline",
        category: "benign",
        total_events: 50,
        matches_found: 0,
        classification: "true_negative",
        is_benign_baseline_warning: false,
        matched_event_ids: [],
      },
    ],
  },
};

describe("DetectionRules View - Rule Drafts & Simulation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getDetections as any).mockResolvedValue([]);
    (api.listActiveRules as any).mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 });
    (api.listRuleDrafts as any).mockResolvedValue(mockDraftList);
    (api.createRuleDraft as any).mockResolvedValue({
      ...mockDraft,
      id: "draft_002",
      name: "Scratch Mimikatz Rule",
      status: "DRAFT",
    });
    (api.validateRuleDraft as any).mockResolvedValue(mockValidationReport);
    (api.archiveRuleDraft as any).mockResolvedValue({ ...mockDraft, is_archived: true });
  });

  it("navigates to Rule Drafts tab and displays draft cards with status and attribution", async () => {
    render(<DetectionRules />);

    // Click Rule Drafts tab
    const draftsTab = screen.getByText("Rule Drafts & Pre-flight");
    fireEvent.click(draftsTab);

    await waitFor(() => {
      expect(api.listRuleDrafts).toHaveBeenCalled();
    });

    // Verify draft details
    expect(screen.getByText("PowerShell Encoded Command Execution")).toBeDefined();
    expect(screen.getByText("draft_001")).toBeDefined();
    expect(screen.getByText("v1")).toBeDefined();
    expect(screen.getByText("analyst_alice")).toBeDefined();
  });

  it("creates a new rule draft from scratch with demo author identity", async () => {
    render(<DetectionRules />);

    const draftsTab = screen.getByText("Rule Drafts & Pre-flight");
    fireEvent.click(draftsTab);

    await waitFor(() => {
      expect(api.listRuleDrafts).toHaveBeenCalled();
    });

    // Click New Rule Draft button in header
    const newDraftBtn = screen.getByText("New Rule Draft");
    fireEvent.click(newDraftBtn);

    // Modal opens
    expect(screen.getByText("Create Detection Rule Draft")).toBeDefined();
    expect(screen.getByText(/Security Governance Notice/i)).toBeDefined();

    // Fill title
    const titleInput = screen.getByPlaceholderText(/e\.g\. Cobalt Strike Beacon Spawning Powershell/i);
    fireEvent.change(titleInput, { target: { value: "Scratch Mimikatz Rule" } });

    // Submit modal form
    const submitBtns = screen.getAllByRole("button", { name: /Create Rule Draft/i });
    fireEvent.click(submitBtns[submitBtns.length - 1]);

    await waitFor(() => {
      expect(api.createRuleDraft).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Scratch Mimikatz Rule",
          severity: "medium",
          created_by: "analyst_alice",
        })
      );
    });
  });

  it("opens validation modal and executes pre-flight simulation against historical telemetry", async () => {
    render(<DetectionRules />);

    const draftsTab = screen.getByText("Rule Drafts & Pre-flight");
    fireEvent.click(draftsTab);

    await waitFor(() => {
      expect(screen.getByText("Run Pre-flight")).toBeDefined();
    });

    // Open simulation modal
    fireEvent.click(screen.getByText("Run Pre-flight"));

    expect(screen.getByText("Pre-flight Rule Simulation & Benchmark Validation")).toBeDefined();

    // Trigger simulation
    const simulateBtn = screen.getByText("Run Pre-flight Simulation");
    fireEvent.click(simulateBtn);

    await waitFor(() => {
      expect(api.validateRuleDraft).toHaveBeenCalledWith("draft_001", { target_scope: "all" });
    });

    // Verify simulation report metrics
    await waitFor(() => {
      expect(screen.getByText("Historical Database Telemetry Simulation")).toBeDefined();
      expect(screen.getByText("ThreatLab Attack Scenario Ground-Truth Benchmark")).toBeDefined();
      expect(screen.getByText("4.0 / day")).toBeDefined();
      expect(screen.getByText("4 / 1500")).toBeDefined();
    });
  });

  it("flags benign baseline warning if rule matches benign administrative baseline", async () => {
    const warningReport: RuleValidationReportResponse = {
      ...mockValidationReport,
      threatlab_metrics: {
        ...mockValidationReport.threatlab_metrics!,
        benign_baseline_matches: 12,
        has_benign_baseline_warning: true,
        scenario_results: [
          {
            scenario_id: "SCN-004",
            name: "Benign Admin Baseline",
            category: "benign",
            total_events: 50,
            matches_found: 12,
            classification: "benign_baseline_warning",
            is_benign_baseline_warning: true,
            matched_event_ids: ["b1", "b2"],
          },
        ],
      },
    };
    (api.validateRuleDraft as any).mockResolvedValue(warningReport);

    render(<DetectionRules />);

    const draftsTab = screen.getByText("Rule Drafts & Pre-flight");
    fireEvent.click(draftsTab);

    await waitFor(() => {
      expect(screen.getByText("Run Pre-flight")).toBeDefined();
    });

    fireEvent.click(screen.getByText("Run Pre-flight"));
    fireEvent.click(screen.getByText("Run Pre-flight Simulation"));

    await waitFor(() => {
      expect(screen.getByText(/Benign Baseline False Alarm Warning/i)).toBeDefined();
    });
  });
});
