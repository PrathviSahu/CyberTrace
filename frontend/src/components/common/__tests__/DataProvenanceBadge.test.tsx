import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DataProvenanceBadge } from "../DataProvenanceBadge";
import { EvidenceDrawer } from "../EvidenceDrawer";
import { CommonEvent } from "../../../types";

describe("DataProvenanceBadge Component", () => {
  it("renders Observed Telemetry with warm bronze styling for observed_telemetry", () => {
    const { container } = render(<DataProvenanceBadge provenance="observed_telemetry" />);
    expect(screen.getByText("Observed Telemetry")).toBeDefined();
    expect((container.firstChild as HTMLElement).className).toContain("text-[#B58A61]");
  });

  it("renders Synthetic Benchmark with purple styling for synthetic_benchmark", () => {
    const { container } = render(<DataProvenanceBadge provenance="synthetic_benchmark" />);
    expect(screen.getByText("Synthetic Benchmark")).toBeDefined();
    expect((container.firstChild as HTMLElement).className).toContain("text-[#9B8FA8]");
  });

  it("renders Calculated Evaluation with teal styling for calculated_evaluation", () => {
    const { container } = render(<DataProvenanceBadge provenance="calculated_evaluation" />);
    expect(screen.getByText("Calculated Evaluation")).toBeDefined();
    expect((container.firstChild as HTMLElement).className).toContain("text-[#6EA59A]");
  });

  it("renders Mixed Provenance with amber styling for mixed", () => {
    const { container } = render(<DataProvenanceBadge provenance="mixed" />);
    expect(screen.getByText("Mixed Provenance")).toBeDefined();
    expect((container.firstChild as HTMLElement).className).toContain("text-[#D99A54]");
  });

  it("renders Unknown Provenance with muted styling for unknown", () => {
    const { container } = render(<DataProvenanceBadge provenance="unknown" />);
    expect(screen.getByText("Unknown Provenance")).toBeDefined();
    expect((container.firstChild as HTMLElement).className).toContain("text-[#A0A7AE]");
  });

  it("safely falls back to Unknown Provenance instead of defaulting to Observed Telemetry", () => {
    render(<DataProvenanceBadge provenance="" />);
    expect(screen.getByText("Unknown Provenance")).toBeDefined();
    expect(screen.queryByText("Observed Telemetry")).toBeNull();
  });
});

describe("EvidenceDrawer Provenance Integrity", () => {
  it("displays Unknown Provenance even when SHA-256 hash is present if event has no verified attribution", () => {
    const eventWithHashOnly: CommonEvent = {
      id: "evt_unverified",
      timestamp: "2026-11-01T12:00:00Z",
      source_type: "csv",
      category: "authentication",
      action: "logon_success",
      severity: "low",
      source_file_hash: "6ec34a29fdac36ef58e6aa712a724b6dfe8d724a85430ed2ede5151e9fac078d",
      provenance: "unknown",
      raw_payload: {},
    };

    render(
      <EvidenceDrawer
        isOpen={true}
        onClose={() => {}}
        event={eventWithHashOnly}
      />
    );

    // Provenance badge MUST display Unknown Provenance, NOT Observed Telemetry!
    expect(screen.getByText("Unknown Provenance")).toBeDefined();
    expect(screen.queryByText("Observed Telemetry")).toBeNull();

    // Checksum must be explicitly labeled as checksum only
    expect(screen.getByText("File Checksum (SHA-256):")).toBeDefined();
    expect(
      screen.getByText(
        "Integrity verification only; does not establish source authenticity"
      )
    ).toBeDefined();
  });

  it("displays Observed Telemetry when event has verified observed_telemetry provenance", () => {
    const observedEvent: CommonEvent = {
      id: "evt_verified",
      timestamp: "2026-11-01T12:00:00Z",
      source_type: "syslog",
      category: "authentication",
      action: "logon_success",
      severity: "informational",
      source_file_hash: "15def78315f04d2b6925461abb45a05fdc7a8c5c0c6472f980e0350a4b37d400",
      provenance: "observed_telemetry",
      raw_payload: { source_attribution: "corporate_edr_sensor" },
    };

    render(
      <EvidenceDrawer
        isOpen={true}
        onClose={() => {}}
        event={observedEvent}
      />
    );

    expect(screen.getByText("Observed Telemetry")).toBeDefined();
  });
});
