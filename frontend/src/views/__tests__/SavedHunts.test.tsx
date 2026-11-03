import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ThreatHunting } from "../ThreatHunting";
import { api } from "../../services/api";
import {
  ThreatHuntQueryResponse,
  SavedHuntListResponse,
  SavedHuntResponse,
  SavedHuntExecuteResponse,
} from "../../types";

vi.mock("../../services/api", () => ({
  api: {
    executeThreatHunt: vi.fn(),
    listSavedHunts: vi.fn(),
    createSavedHunt: vi.fn(),
    executeSavedHunt: vi.fn(),
    duplicateSavedHunt: vi.fn(),
    archiveSavedHunt: vi.fn(),
  },
}));

const mockQueryResponse: ThreatHuntQueryResponse = {
  items: [
    {
      id: "evt_hunt_01",
      timestamp: "2026-11-01T12:00:00Z",
      source_type: "json",
      category: "authentication",
      action: "logon_failure",
      severity: "high",
      username: "svc_deploy",
      hostname: "SRV-APP-01",
      source_ip: "10.0.0.5",
      destination_ip: "10.0.0.1",
      source_port: 54321,
      destination_port: 22,
      bytes_out: 1500,
      bytes_in: 200,
      protocol: "SSH",
      process_name: "/usr/sbin/sshd",
      raw_payload: { test: true },
      provenance: "unknown",
      related_detections: [],
      related_incidents: [],
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
  query_duration_ms: 12.5,
  applied_filter_count: 1,
  provenance: "unknown",
};

const mockSavedHunt: SavedHuntResponse = {
  id: "hunt_001",
  name: "Service Account Spray Investigation",
  description: "Track repeated logon failures on svc_deploy",
  tags: ["brute_force", "mitre:t1078"],
  query_definition: {
    time_range: undefined,
    filter_group: {
      logic: "AND",
      conditions: [{ field: "username", operator: "eq", value: "svc_deploy" }],
    },
    sort_by: "timestamp",
    sort_order: "desc",
    limit: 50,
    offset: 0,
  },
  created_by: "analyst_alice",
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
  version: 1,
  last_run_at: "2026-11-01T11:00:00Z",
  run_count: 3,
  is_archived: false,
  author_attribution_note: "Caller-supplied demo identity. No cryptographic auth or RBAC enforced.",
};

const mockListResponse: SavedHuntListResponse = {
  items: [mockSavedHunt],
  total: 1,
  limit: 100,
  offset: 0,
};

const mockExecuteResponse: SavedHuntExecuteResponse = {
  hunt_id: "hunt_001",
  hunt_name: "Service Account Spray Investigation",
  executed_version: 1,
  executed_at: "2026-11-01T12:30:00Z",
  run_count: 4,
  items: mockQueryResponse.items,
  total: 1,
  limit: 50,
  offset: 0,
  query_duration_ms: 8.2,
  applied_filter_count: 1,
  provenance: "unknown",
};

describe("Stage 1 — Saved Threat Hunts Workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.executeThreatHunt as any).mockResolvedValue(mockQueryResponse);
    (api.listSavedHunts as any).mockResolvedValue(mockListResponse);
    (api.createSavedHunt as any).mockResolvedValue({
      ...mockSavedHunt,
      id: "hunt_002",
      name: "New Saved Hunt",
    });
    (api.executeSavedHunt as any).mockResolvedValue(mockExecuteResponse);
    (api.duplicateSavedHunt as any).mockResolvedValue({
      ...mockSavedHunt,
      id: "hunt_001_copy",
      name: "Copy of Service Account Spray Investigation",
      run_count: 0,
      last_run_at: null,
    });
    (api.archiveSavedHunt as any).mockResolvedValue({
      ...mockSavedHunt,
      is_archived: true,
    });
  });

  it("renders Saved Hunts button and count in the ThreatHunting header", async () => {
    render(<ThreatHunting />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Saved Hunts/i })).toBeDefined();
    });

    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
  });

  it("opens the SaveHuntModal and creates a saved hunt with author disclaimer", async () => {
    render(<ThreatHunting />);

    // Click "Save Hunt" in header
    const saveButtons = screen.getAllByText("Save Hunt");
    fireEvent.click(saveButtons[0]);

    // Modal should be open
    await waitFor(() => {
      expect(screen.getByText("Save Threat Hunt Query")).toBeDefined();
      expect(screen.getByText(/Caller-supplied demo metadata/i)).toBeDefined();
    });

    // Fill in name
    const nameInput = screen.getByPlaceholderText(/e\.g\. Cobalt Strike C2 Egress/i);
    fireEvent.change(nameInput, { target: { value: "New Saved Hunt" } });

    // Submit form
    const submitBtn = screen.getByRole("button", { name: "Save Threat Hunt" });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(api.createSavedHunt).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "New Saved Hunt",
          created_by: "analyst_alice",
        })
      );
    });
  });

  it("opens SavedHuntsDrawer, displays hunt cards, version badge, and execution stats", async () => {
    render(<ThreatHunting />);

    // Open drawer
    const savedHuntsBtn = screen.getByText("Saved Hunts");
    fireEvent.click(savedHuntsBtn);

    await waitFor(() => {
      expect(screen.getByText("Service Account Spray Investigation")).toBeDefined();
      expect(screen.getByText("v1")).toBeDefined();
      expect(screen.getByText("Runs:")).toBeDefined();
      expect(screen.getByText("3")).toBeDefined();
      expect(screen.getByText(/analyst_alice \(demo identity\)/i)).toBeDefined();
    });
  });

  it("loads a saved hunt AST into the Query Builder when 'Load into Query Builder' is clicked", async () => {
    render(<ThreatHunting />);

    // Open drawer
    fireEvent.click(screen.getByText("Saved Hunts"));

    await waitFor(() => {
      expect(screen.getByText("Load into Query Builder")).toBeDefined();
    });

    // Click load
    fireEvent.click(screen.getByText("Load into Query Builder"));

    // Query builder should show active hunt banner
    await waitFor(() => {
      expect(screen.getByText("Active Saved Hunt:")).toBeDefined();
      expect(screen.getAllByText("Service Account Spray Investigation")[0]).toBeDefined();
    });
  });

  it("executes a saved hunt directly from the drawer and displays execution banner", async () => {
    render(<ThreatHunting />);

    // Open drawer
    fireEvent.click(screen.getByText("Saved Hunts"));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Run" })).toBeDefined();
    });

    // Click Run
    fireEvent.click(screen.getByRole("button", { name: "Run" }));

    await waitFor(() => {
      expect(api.executeSavedHunt).toHaveBeenCalledWith("hunt_001", {
        executed_by: "analyst_alice",
      });
      expect(
        screen.getByText(/Execution Results for Saved Hunt: "Service Account Spray Investigation"/i)
      ).toBeDefined();
    });
  });

  it("duplicates a saved hunt via duplicateSavedHunt API", async () => {
    render(<ThreatHunting />);

    // Open drawer
    fireEvent.click(screen.getByText("Saved Hunts"));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Duplicate" })).toBeDefined();
    });

    // Click Duplicate
    fireEvent.click(screen.getByRole("button", { name: "Duplicate" }));

    await waitFor(() => {
      expect(api.duplicateSavedHunt).toHaveBeenCalledWith("hunt_001", {
        name: "Copy of Service Account Spray Investigation",
        created_by: "analyst_alice",
      });
    });
  });
});
