import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "../api";

describe("Frontend Provenance Classification & Aggregation", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("api.getOverviewMetrics()", () => {
    it("reports 'observed_telemetry' when all telemetry is verified observed", async () => {
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes("/health")) return Promise.resolve(new Response(JSON.stringify({ status: "healthy" }), { status: 200 }));
        if (url.includes("/incidents")) return Promise.resolve(new Response(JSON.stringify([{ id: "inc_1", provenance: "observed_telemetry", severity: "high", status: "open" }]), { status: 200 }));
        if (url.includes("/detections")) return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
        if (url.includes("/events")) return Promise.resolve(new Response(JSON.stringify([{ id: "e1", provenance: "observed_telemetry" }]), { status: 200 }));
        if (url.includes("/assets")) return Promise.resolve(new Response(JSON.stringify({ total: 1 }), { status: 200 }));
        return Promise.reject(new Error("Unknown route"));
      });

      const metrics = await api.getOverviewMetrics();
      expect(metrics.provenance).toBe("observed_telemetry");
    });

    it("reports 'synthetic_benchmark' when all telemetry is synthetic", async () => {
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes("/health")) return Promise.resolve(new Response(JSON.stringify({ status: "healthy" }), { status: 200 }));
        if (url.includes("/incidents")) return Promise.resolve(new Response(JSON.stringify([{ id: "inc_1", provenance: "synthetic_benchmark", severity: "medium", status: "open" }]), { status: 200 }));
        if (url.includes("/detections")) return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
        if (url.includes("/events")) return Promise.resolve(new Response(JSON.stringify([{ id: "e1", provenance: "synthetic_benchmark" }]), { status: 200 }));
        if (url.includes("/assets")) return Promise.resolve(new Response(JSON.stringify({ total: 0 }), { status: 200 }));
        return Promise.reject(new Error("Unknown route"));
      });

      const metrics = await api.getOverviewMetrics();
      expect(metrics.provenance).toBe("synthetic_benchmark");
    });

    it("reports 'unknown' when telemetry lacks verified attribution", async () => {
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes("/health")) return Promise.resolve(new Response(JSON.stringify({ status: "healthy" }), { status: 200 }));
        if (url.includes("/incidents")) return Promise.resolve(new Response(JSON.stringify([{ id: "inc_1", provenance: "unknown", severity: "low", status: "open" }]), { status: 200 }));
        if (url.includes("/detections")) return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
        if (url.includes("/events")) return Promise.resolve(new Response(JSON.stringify([{ id: "e1", provenance: "unknown" }]), { status: 200 }));
        if (url.includes("/assets")) return Promise.resolve(new Response(JSON.stringify({ total: 0 }), { status: 200 }));
        return Promise.reject(new Error("Unknown route"));
      });

      const metrics = await api.getOverviewMetrics();
      expect(metrics.provenance).toBe("unknown");
    });

    it("reports 'mixed' when dataset contains multiple distinct provenance classes", async () => {
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes("/health")) return Promise.resolve(new Response(JSON.stringify({ status: "healthy" }), { status: 200 }));
        if (url.includes("/incidents")) return Promise.resolve(new Response(JSON.stringify([{ id: "inc_1", provenance: "synthetic_benchmark", severity: "high", status: "open" }]), { status: 200 }));
        if (url.includes("/detections")) return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
        if (url.includes("/events")) return Promise.resolve(new Response(JSON.stringify([{ id: "e1", provenance: "observed_telemetry" }]), { status: 200 }));
        if (url.includes("/assets")) return Promise.resolve(new Response(JSON.stringify({ total: 0 }), { status: 200 }));
        return Promise.reject(new Error("Unknown route"));
      });

      const metrics = await api.getOverviewMetrics();
      expect(metrics.provenance).toBe("mixed");
    });

    it("defaults to 'unknown' when dataset is empty", async () => {
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes("/health")) return Promise.resolve(new Response(JSON.stringify({ status: "healthy" }), { status: 200 }));
        if (url.includes("/incidents")) return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
        if (url.includes("/detections")) return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
        if (url.includes("/events")) return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
        if (url.includes("/assets")) return Promise.resolve(new Response(JSON.stringify({ total: 0 }), { status: 200 }));
        return Promise.reject(new Error("Unknown route"));
      });

      const metrics = await api.getOverviewMetrics();
      expect(metrics.provenance).toBe("unknown");
    });
  });

  describe("api.getIncidents() and api.getIncident()", () => {
    it("resolves to 'unknown' when backend omits provenance field", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify([
        { id: "inc_x", title: "Unclassified Incident", severity: "medium", status: "open" }
      ]), { status: 200 }));

      const list = await api.getIncidents();
      expect(list[0].provenance).toBe("unknown");
    });

    it("preserves explicit provenance provided by backend", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify([
        { id: "inc_obs", title: "Observed", provenance: "observed_telemetry", severity: "high", status: "open" },
        { id: "inc_synth", title: "Synthetic", provenance: "synthetic_benchmark", severity: "low", status: "open" }
      ]), { status: 200 }));

      const list = await api.getIncidents();
      expect(list[0].provenance).toBe("observed_telemetry");
      expect(list[1].provenance).toBe("synthetic_benchmark");
    });

    it("getIncident defaults to 'unknown' when missing from response", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
        incident: { id: "inc_detail", title: "Detail Test", severity: "high", status: "open" },
        detections: [],
        events: [],
        entities: []
      }), { status: 200 }));

      const detail = await api.getIncident("inc_detail");
      expect(detail.incident.provenance).toBe("unknown");
    });
  });

  describe("api.uploadLog()", () => {
    it("preserves backend returned provenance and defaults to 'unknown'", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
        filename: "test.log",
        detected_format: "generic_json",
        source_file_hash: "abcdef",
        parsed_events_count: 5,
        persisted_events_count: 5,
        detections_count: 0,
        incidents_count: 0,
        status: "success",
        provenance: "observed_telemetry"
      }), { status: 200 }));

      const dummyFile = new File(["test"], "test.log", { type: "application/json" });
      const res = await api.uploadLog(dummyFile);
      expect(res.provenance).toBe("observed_telemetry");
    });

    it("resolves to 'unknown' if backend upload response has no provenance", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
        filename: "test.log",
        detected_format: "generic_json",
        source_file_hash: "abcdef",
        parsed_events_count: 5,
        persisted_events_count: 5,
        detections_count: 0,
        incidents_count: 0,
        status: "success"
      }), { status: 200 }));

      const dummyFile = new File(["test"], "test.log", { type: "application/json" });
      const res = await api.uploadLog(dummyFile);
      expect(res.provenance).toBe("unknown");
    });
  });
});
