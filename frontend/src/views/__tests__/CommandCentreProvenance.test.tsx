import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { CommandCentre } from "../CommandCentre";
import { api } from "../../services/api";

vi.mock("../../services/api", () => ({
  api: {
    getOverviewMetrics: vi.fn(),
    getIncidents: vi.fn(),
    getDetections: vi.fn(),
    getEvents: vi.fn(),
    getIdentities: vi.fn(),
    getAssets: vi.fn(),
  },
}));

describe("CommandCentre - Truthful Provenance Badge Rendering", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getIncidents as any).mockResolvedValue([]);
    (api.getDetections as any).mockResolvedValue([]);
    (api.getEvents as any).mockResolvedValue([]);
    (api.getIdentities as any).mockResolvedValue({ items: [], total: 0 });
    (api.getAssets as any).mockResolvedValue({ items: [], total: 0 });
  });

  it("renders 'Unknown Provenance' badge when metrics indicate unknown", async () => {
    (api.getOverviewMetrics as any).mockResolvedValue({
      openIncidents: 0,
      criticalAlerts: 0,
      monitoredAssets: 0,
      detectionCoveragePercent: null,
      eventsIngestedSample: 0,
      totalDetectionsFired: 0,
      meanTimeToTriageMin: null,
      aiInvestigationsCount: 0,
      providerStatus: "healthy",
      provenance: "unknown",
    });

    render(
      <MemoryRouter>
        <CommandCentre onOpenUpload={() => {}} />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Unknown Provenance")).toBeDefined();
    });
  });

  it("renders 'Observed Telemetry' badge when metrics indicate observed_telemetry", async () => {
    (api.getOverviewMetrics as any).mockResolvedValue({
      openIncidents: 1,
      criticalAlerts: 0,
      monitoredAssets: 5,
      detectionCoveragePercent: 50,
      eventsIngestedSample: 100,
      totalDetectionsFired: 2,
      meanTimeToTriageMin: null,
      aiInvestigationsCount: 0,
      providerStatus: "healthy",
      provenance: "observed_telemetry",
    });

    render(
      <MemoryRouter>
        <CommandCentre onOpenUpload={() => {}} />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Observed Telemetry")).toBeDefined();
    });
  });

  it("renders 'Synthetic Benchmark' badge when metrics indicate synthetic_benchmark", async () => {
    (api.getOverviewMetrics as any).mockResolvedValue({
      openIncidents: 1,
      criticalAlerts: 1,
      monitoredAssets: 2,
      detectionCoveragePercent: 100,
      eventsIngestedSample: 9,
      totalDetectionsFired: 6,
      meanTimeToTriageMin: null,
      aiInvestigationsCount: 1,
      providerStatus: "healthy",
      provenance: "synthetic_benchmark",
    });

    render(
      <MemoryRouter>
        <CommandCentre onOpenUpload={() => {}} />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Synthetic Benchmark")).toBeDefined();
    });
  });

  it("renders 'Mixed Provenance' badge when metrics indicate mixed", async () => {
    (api.getOverviewMetrics as any).mockResolvedValue({
      openIncidents: 2,
      criticalAlerts: 1,
      monitoredAssets: 4,
      detectionCoveragePercent: 75,
      eventsIngestedSample: 50,
      totalDetectionsFired: 3,
      meanTimeToTriageMin: null,
      aiInvestigationsCount: 1,
      providerStatus: "healthy",
      provenance: "mixed",
    });

    render(
      <MemoryRouter>
        <CommandCentre onOpenUpload={() => {}} />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Mixed Provenance")).toBeDefined();
    });
  });
});
