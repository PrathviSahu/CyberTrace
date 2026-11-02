import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ThreatHunting } from "../ThreatHunting";
import { api } from "../../services/api";
import { ThreatHuntQueryResponse } from "../../types";

vi.mock("../../services/api", () => ({
  api: {
    executeThreatHunt: vi.fn(),
  },
}));

const mockSuccessResponse: ThreatHuntQueryResponse = {
  items: [
    {
      id: "evt_test_01",
      timestamp: "2026-11-01T12:00:00Z",
      source_type: "syslog",
      category: "authentication",
      action: "logon_failure",
      severity: "high",
      username: "svc_deploy",
      hostname: "SRV-APP-01",
      source_ip: "10.0.0.5",
      destination_ip: "10.0.0.1",
      source_port: 54321,
      destination_port: 22,
      bytes_out: 15000000,
      bytes_in: 200,
      protocol: "SSH",
      process_name: "/usr/sbin/sshd",
      raw_payload: { test: true },
      provenance: "observed_telemetry",
      related_detections: [
        {
          id: "det_01",
          rule_id: "RULE-01",
          rule_name: "SSH Brute Force",
          severity: "high",
          explanation: "Multiple rapid failed logins",
        },
      ],
      related_incidents: [
        {
          id: "INC-001",
          title: "Service Account Spray",
          severity: "high",
          status: "open",
        },
      ],
    },
    {
      id: "evt_test_02",
      timestamp: "2026-11-01T11:00:00Z",
      source_type: "syslog",
      category: "network",
      action: "egress_transfer",
      severity: "medium",
      username: "admin_alice",
      hostname: "WS-01",
      source_ip: "192.168.1.50",
      destination_ip: "1.2.3.4",
      source_port: 44321,
      destination_port: 443,
      bytes_out: 5000,
      bytes_in: 1000,
      protocol: "TCP",
      provenance: "observed_telemetry",
      related_detections: [],
      related_incidents: [],
    },
  ],
  total: 2,
  limit: 50,
  offset: 0,
  query_duration_ms: 2.45,
  applied_filter_count: 1,
  provenance: "observed_telemetry",
};

describe("ThreatHunting View Component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders page header and executes initial structured query", async () => {
    (api.executeThreatHunt as any).mockResolvedValue(mockSuccessResponse);

    render(<ThreatHunting />);

    expect(screen.getByText("Structured Threat Hunting")).toBeDefined();
    expect(screen.getByText("Phase 6.2 Query Engine")).toBeDefined();

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(1);
    });

    // Check query call arguments
    const callArg = (api.executeThreatHunt as any).mock.calls[0][0];
    expect(callArg.limit).toBe(50);
    expect(callArg.offset).toBe(0);
    expect(callArg.sort_by).toBe("timestamp");
    expect(callArg.sort_order).toBe("desc");

    // Check rendered results and button state after query completes
    await waitFor(() => {
      expect(screen.getByText("Execute Hunt")).toBeDefined();
      expect(screen.getByText("evt_test_01")).toBeDefined();
      expect(screen.getByText("evt_test_02")).toBeDefined();
      expect(screen.getByText("2 Matching Events")).toBeDefined();
    });
  });

  it("supports adding and removing filter conditions", async () => {
    (api.executeThreatHunt as any).mockResolvedValue(mockSuccessResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(1);
    });

    // Initial has 1 condition
    expect(screen.getAllByRole("combobox").length).toBeGreaterThan(0);

    // Click Add Condition
    const addBtn = screen.getByText("Add Condition");
    fireEvent.click(addBtn);

    // Now there are 2 conditions
    const removeBtns = screen.getAllByTitle("Remove condition");
    expect(removeBtns.length).toBe(2);

    // Remove one condition
    fireEvent.click(removeBtns[0]);
    expect(screen.getAllByTitle("Remove condition").length).toBe(1);
  });

  it("supports changing boolean logic between AND and OR", async () => {
    (api.executeThreatHunt as any).mockResolvedValue(mockSuccessResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(1);
    });

    const orBtn = screen.getByText("OR (Match Any)");
    fireEvent.click(orBtn);

    // Execute hunt with OR
    const execBtn = screen.getByText("Execute Hunt");
    fireEvent.click(execBtn);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(2);
    });

    const secondCall = (api.executeThreatHunt as any).mock.calls[1][0];
    expect(secondCall.filter_group.logic).toBe("OR");
  });

  it("handles empty query results cleanly", async () => {
    const emptyResponse: ThreatHuntQueryResponse = {
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
      query_duration_ms: 1.12,
      applied_filter_count: 2,
      provenance: "observed_telemetry",
    };
    (api.executeThreatHunt as any).mockResolvedValue(emptyResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(screen.getByText("No telemetry records matched the query criteria")).toBeDefined();
      expect(screen.getByText("0 Matching Events")).toBeDefined();
    });
  });

  it("visibly displays API errors without crashing", async () => {
    (api.executeThreatHunt as any).mockRejectedValue(
      new Error("Value for integer field 'source_port' must be an integer, got 'invalid'")
    );

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(screen.getByText("Threat Hunting Query Rejected")).toBeDefined();
      expect(
        screen.getByText(/Value for integer field 'source_port' must be an integer/)
      ).toBeDefined();
    });
  });

  it("toggles sorting when column header is clicked", async () => {
    (api.executeThreatHunt as any).mockResolvedValue(mockSuccessResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(1);
    });

    // Click on Action column header to sort
    const actionHeader = screen.getByText("Action / Category");
    fireEvent.click(actionHeader);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(2);
    });

    const sortCall = (api.executeThreatHunt as any).mock.calls[1][0];
    expect(sortCall.sort_by).toBe("action");
    expect(sortCall.sort_order).toBe("desc");
  });

  it("opens EvidenceDrawer when Inspect button is clicked", async () => {
    (api.executeThreatHunt as any).mockResolvedValue(mockSuccessResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(screen.getByText("evt_test_01")).toBeDefined();
    });

    // Click Inspect on first event
    const inspectBtns = screen.getAllByText("Inspect");
    fireEvent.click(inspectBtns[0]);

    // Drawer should show event details, related detections, related incidents
    await waitFor(() => {
      expect(screen.getByText("Triggered Detections (1)")).toBeDefined();
      expect(screen.getByText("Associated Incidents (1)")).toBeDefined();
      expect(screen.getByText("SSH Brute Force")).toBeDefined();
      expect(screen.getByText("Service Account Spray")).toBeDefined();
    });
  });

  it("supports applying presets", async () => {
    (api.executeThreatHunt as any).mockResolvedValue(mockSuccessResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(1);
    });

    const egressPreset = screen.getByText("High-Volume Data Egress");
    fireEvent.click(egressPreset);

    // The condition should be updated to bytes_out > 10000000
    const valueInputs = screen.getAllByPlaceholderText(/bytes/);
    expect(valueInputs.length).toBeGreaterThan(0);
    expect((valueInputs[0] as HTMLInputElement).value).toBe("10000000");
  });

  it("supports pagination navigation and limit changes", async () => {
    const multiPageResponse: ThreatHuntQueryResponse = {
      ...mockSuccessResponse,
      total: 120,
      limit: 50,
      offset: 0,
    };
    (api.executeThreatHunt as any).mockResolvedValue(multiPageResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(screen.getByText("Next")).toBeDefined();
    });

    // Click Next
    const nextBtn = screen.getByText("Next");
    fireEvent.click(nextBtn);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(2);
    });

    const nextCall = (api.executeThreatHunt as any).mock.calls[1][0];
    expect(nextCall.offset).toBe(50);
    expect(nextCall.limit).toBe(50);

    // Change page size to 25
    const limit25Btn = screen.getByText("25");
    fireEvent.click(limit25Btn);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(3);
    });

    const limitCall = (api.executeThreatHunt as any).mock.calls[2][0];
    expect(limitCall.offset).toBe(0);
    expect(limitCall.limit).toBe(25);
  });

  it("applies time range presets when selected", async () => {
    (api.executeThreatHunt as any).mockResolvedValue(mockSuccessResponse);

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(1);
    });

    // Click 'Last 24h'
    const last24hBtn = screen.getByText("Last 24h");
    fireEvent.click(last24hBtn);

    // Run query
    const runBtn = screen.getByText("Execute Hunt");
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(api.executeThreatHunt).toHaveBeenCalledTimes(2);
    });

    const timeCall = (api.executeThreatHunt as any).mock.calls[1][0];
    expect(timeCall.time_range).toBeDefined();
    expect(timeCall.time_range.start).toBeDefined();
    expect(timeCall.time_range.end).toBeDefined();
  });

  it("renders Unknown Provenance badge when API returns unknown provenance", async () => {
    (api.executeThreatHunt as any).mockResolvedValue({
      ...mockSuccessResponse,
      provenance: "unknown",
    });

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(screen.getByText("Unknown Provenance")).toBeDefined();
    });
  });

  it("renders Mixed Provenance badge when API returns mixed provenance", async () => {
    (api.executeThreatHunt as any).mockResolvedValue({
      ...mockSuccessResponse,
      provenance: "mixed",
    });

    render(<ThreatHunting />);

    await waitFor(() => {
      expect(screen.getByText("Mixed Provenance")).toBeDefined();
    });
  });
});
