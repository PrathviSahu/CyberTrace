import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { DetectionRules } from "../DetectionRules";
import { api } from "../../services/api";
import {
  ActiveDetectionRuleResponse,
  DetectionRuleDraftResponse,
  RuleAuditListResponse,
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

const mockActiveRule: ActiveDetectionRuleResponse = {
  id: "act_001",
  rule_code: "CUST-001",
  name: "Custom Cobalt Strike Beacon Detection",
  description: "Detects beacons communicating on port 8088",
  severity: "critical",
  mitre_attack_id: "T1071.001",
  mitre_tactic: "command_and_control",
  source_draft_id: "draft_001",
  source_draft_version: 1,
  validation_run_id: "val_001",
  status: "ACTIVE",
  version: 1,
  approved_by: "lead_bob",
  approved_at: "2026-11-01T12:00:00Z",
  activated_at: "2026-11-01T12:00:00Z",
  deactivated_at: null,
  created_at: "2026-11-01T12:00:00Z",
  updated_at: "2026-11-01T12:00:00Z",
  governance_classification: "demonstration_level_approval_gate",
  author_attribution_note: "Caller-supplied demo identity.",
};

const mockValidatedDraft: DetectionRuleDraftResponse = {
  id: "draft_001",
  name: "Custom Cobalt Strike Beacon Detection",
  description: "Detects beacons communicating on port 8088",
  severity: "critical",
  mitre_attack_id: "T1071.001",
  mitre_tactic: "command_and_control",
  source_hunt_id: "hunt_001",
  source_hunt_version: 1,
  query_definition: {
    filter_group: {
      logic: "AND",
      conditions: [{ field: "destination_port", operator: "eq", value: 8088 }],
    },
    sort_by: "timestamp",
    sort_order: "desc",
  },
  status: "VALIDATED",
  version: 1,
  created_by: "analyst_alice",
  is_archived: false,
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
  latest_validation: {
    validation_id: "val_001",
    draft_version: 1,
    run_at: "2026-11-01T11:00:00Z",
    target_scope: "all",
    matches_found: 4,
    estimated_daily_alert_volume: 4.0,
    status: "VALIDATED",
    is_stale: false,
    has_benign_baseline_warning: false,
  },
  author_attribution_note: "Caller-supplied demo identity.",
};

const mockAuditList: RuleAuditListResponse = {
  items: [
    {
      id: "aud_001",
      target_type: "ACTIVE_RULE",
      target_id: "act_001",
      action: "ACTIVATE_RULE",
      actor: "lead_bob",
      timestamp: "2026-11-01T12:00:00Z",
      justification: "Validated zero false positives across historical baseline telemetry.",
      state_before: {},
      state_after: { status: "ACTIVE", rule_code: "CUST-001" },
      demo_override_flag: false,
      security_warning: null,
      storage_classification: "application_level_append_only",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

describe("DetectionRules View - Governance & Active Rules", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getDetections as any).mockResolvedValue([]);
    (api.listActiveRules as any).mockResolvedValue({
      items: [mockActiveRule],
      total: 1,
      limit: 100,
      offset: 0,
    });
    (api.listRuleDrafts as any).mockResolvedValue({
      items: [mockValidatedDraft],
      total: 1,
      limit: 100,
      offset: 0,
    });
    (api.approveRuleDraft as any).mockResolvedValue(mockActiveRule);
    (api.rejectRuleDraft as any).mockResolvedValue({
      ...mockValidatedDraft,
      status: "DRAFT",
    });
    (api.updateActiveRuleStatus as any).mockResolvedValue({
      ...mockActiveRule,
      status: "DISABLED",
      version: 2,
    });
    (api.listRuleAuditEntries as any).mockResolvedValue(mockAuditList);
  });

  it("renders active custom rules table with CUST-001, status badge, and reviewer metadata", async () => {
    render(<DetectionRules />);

    await waitFor(() => {
      expect(api.listActiveRules).toHaveBeenCalled();
    });

    expect(screen.getByText("CUST-001")).toBeDefined();
    expect(screen.getByText("Custom Cobalt Strike Beacon Detection")).toBeDefined();
    expect(screen.getByText("ACTIVE")).toBeDefined();
    expect(screen.getByText(/Approved by:/i)).toBeDefined();
    expect(screen.getByText("lead_bob")).toBeDefined();
  });

  it("enforces four-eyes separation in approval modal when reviewer matches creator", async () => {
    render(<DetectionRules />);

    // Switch to Rule Drafts tab
    fireEvent.click(screen.getByText("Rule Drafts & Pre-flight"));

    await waitFor(() => {
      expect(screen.getByText("Four-Eyes Approve")).toBeDefined();
    });

    // Open Approval Modal
    fireEvent.click(screen.getByText("Four-Eyes Approve"));

    expect(screen.getByText(/Four-Eyes Governance: Approve Rule Draft/i)).toBeDefined();

    // Set reviewer identity to same as creator ('analyst_alice')
    const reviewerInput = screen.getByPlaceholderText("e.g. lead_bob");
    fireEvent.change(reviewerInput, { target: { value: "analyst_alice" } });

    // Verify Four-Eyes violation banner appears
    expect(screen.getByText(/Four-Eyes Separation Violation/i)).toBeDefined();
    expect(screen.getByText(/cannot approve their own rule/i)).toBeDefined();

    // Verify approve button is disabled
    const approveBtn = screen.getByRole("button", { name: /Approve & Activate Rule/i });
    expect((approveBtn as HTMLButtonElement).disabled).toBeTruthy();

    // Switch back to different reviewer ('lead_bob') and provide valid justification (>= 10 chars)
    fireEvent.change(reviewerInput, { target: { value: "lead_bob" } });
    const justInput = screen.getByPlaceholderText(/Detail validation review findings/i);
    fireEvent.change(justInput, { target: { value: "Verified against baseline noise and empirical confusion matrix." } });

    // Now can submit
    expect((approveBtn as HTMLButtonElement).disabled).toBeFalsy();
    fireEvent.click(approveBtn);

    await waitFor(() => {
      expect(api.approveRuleDraft).toHaveBeenCalledWith(
        "draft_001",
        expect.objectContaining({
          draft_version: 1,
          approver_id: "lead_bob",
          justification: "Verified against baseline noise and empirical confusion matrix.",
          activate_immediately: true,
        })
      );
    });
  });

  it("allows updating active rule status to DISABLED with mandatory operational rationale", async () => {
    render(<DetectionRules />);

    await waitFor(() => {
      expect(screen.getByText("Update Status")).toBeDefined();
    });

    fireEvent.click(screen.getByText("Update Status"));

    expect(screen.getByText(/Update Rule Status & Lifecycle State/i)).toBeDefined();

    // Provide rationale (>= 10 chars)
    const justInput = screen.getByPlaceholderText(/State the reason for this status transition/i);
    fireEvent.change(justInput, { target: { value: "Temporary deactivation for telemetry maintenance." } });

    // Click submit
    const commitBtn = screen.getByText("Commit Status Change");
    fireEvent.click(commitBtn);

    await waitFor(() => {
      expect(api.updateActiveRuleStatus).toHaveBeenCalledWith(
        "act_001",
        expect.objectContaining({
          version: 1,
          status: "DISABLED",
          justification: "Temporary deactivation for telemetry maintenance.",
          actor: "soc_operator",
        })
      );
    });
  });

  it("navigates to Governance Audit Ledger and displays immutable lifecycle events with state diff", async () => {
    render(<DetectionRules />);

    // Click Audit Ledger tab
    fireEvent.click(screen.getByText("Governance Audit Ledger"));

    await waitFor(() => {
      expect(api.listRuleAuditEntries).toHaveBeenCalled();
    });

    // Check entry rendered
    expect(screen.getAllByText("ACTIVATE_RULE").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/ACTIVE_RULE: act_001/i)).toBeDefined();
    expect(screen.getByText("lead_bob")).toBeDefined();
    expect(screen.getByText(/Validated zero false positives across historical baseline telemetry/i)).toBeDefined();

    // Expand state diff
    const diffBtn = screen.getByText("Inspect State Diff");
    fireEvent.click(diffBtn);

    expect(screen.getByText("State Before")).toBeDefined();
    expect(screen.getByText("State After")).toBeDefined();
  });
});
