# CyberTrace — Provenance Integrity & Telemetry Authenticity Audit

> **Phase:** 6.2 (Structured Threat Hunting & Evidence Provenance)  
> **Status:** Accepted & Verified  
> **Audited By:** CyberTrace Engineering Team  
> **Classification:** Security Architecture & Evidence Grounding Policy  

---

## 1. Executive Summary

In enterprise Security Operations Centers (SOCs) and digital forensics platforms, **evidence integrity** and **source authenticity** are distinct cryptographic concepts:

- **Content Integrity (Checksum):** A cryptographic SHA-256 hash verifies that file bytes have not been altered, truncated, or corrupted in transit or storage.
- **Source Authenticity (Provenance):** Authenticity establishes *who* originated the telemetry, *which* authorized sensor or collector forwarded it, and whether it represents genuine organizational traffic or synthetic benchmark simulation.

### The Vulnerability Identified
Prior to Phase 6.2, telemetry records possessing an ingested `source_file_hash` were categorized by default as `observed_telemetry`. This assumption was technically flawed: any user or automated test script uploading a synthetic CSV, benchmark scenario, or mock dataset produces a valid 64-character SHA-256 hash. Inferring telemetry authenticity solely from hash presence resulted in an unsupported security claim.

### The Resolution
CyberTrace enforces explicit, verifiable provenance classification backed by attribution metadata, strict precedence rules, and truthful UI presentation.

---

## 2. Ingestion Pipeline & Hash Lifecycle

```
[Raw Log File] ──> [Upload / API Intake] ──> SHA-256 Hash Computed (File Checksum)
                           │
                           ▼
                 [LogIngestionPipeline]
                 (Format Auto-Detection: Windows, Linux, Zeek, CSV, JSON)
                           │
                           ▼
                 [Normalized CommonEvent (CES)]
                 (Preserves raw_payload & attribution metadata)
                           │
                           ▼
                 [EventRepository.upsert_events]
                 (Persists to SQLite: security_events table)
                           │
                           ▼
                 [Threat Hunting Query Engine]
                 (classify_event_provenance() evaluated dynamically per event)
```

1. **Ingestion Intake (`POST /api/v1/logs/upload`):**  
   File bytes are read into buffer and hashed via `hashlib.sha256(buffer).hexdigest()`. This value is persisted as `source_file_hash` in the database.
2. **ThreatLab Scenario Replays (`app/threatlab/service.py`):**  
   Executes in memory without mutating production database tables. In the event synthetic events are ingested, their scenario prefix (`scn`, `synth_`) or `source_type="synthetic"` ensures they cannot be elevated to observed telemetry.

---

## 3. Provenance Taxonomy & Decision Matrix

| Provenance Category | Grounding Criteria | Precedence & Fallback Rules | UI Rendering |
| :--- | :--- | :--- | :--- |
| **`synthetic_benchmark`** | Record possesses `synthetic=true`, `benchmark=true`, `simulation=true`, `source_type in ('synthetic', 'benchmark', 'threatlab')`, or ThreatLab ID prefixes (`scn`, `synth_`). | **Strict High Precedence:** If any synthetic marker is present, the event is immediately classified as synthetic. Contradictory claims of observed status are rejected. | Muted Purple Badge (`#9B8FA8`) |
| **`observed_telemetry`** | Record contains **explicit verified source attribution** (`source_attribution`, `collector_id`, `sensor_id`, or `source_authority`) linking it to an authorized enterprise source. | **Never inferred from SHA-256 checksum.** Requires non-synthetic source attribution metadata. | Warm Bronze Badge (`#B58A61`) |
| **`unknown`** | Provenance cannot be verified from available attribution metadata. | **Truthful Grounding:** Existing records in `cybertrace.db` lacking recorded attribution metadata are classified as `unknown` rather than making unsupported authenticity claims. | Neutral Slate Badge (`#A0A7AE`) |
| **`mixed`** | Response-level aggregation when query results span multiple distinct provenance categories. | Reflects heterogeneous result sets without masking item-level variations. | Warm Amber Badge (`#D99A54`) |

---

## 4. UI Evidence Grounding & Checksum Transparency

In [`frontend/src/components/common/EvidenceDrawer.tsx`](../frontend/src/components/common/EvidenceDrawer.tsx):

1. **Per-Event Provenance Badge:**  
   The drawer dynamically renders `<DataProvenanceBadge provenance={event.provenance || "unknown"} />`. It never performs client-side hash-to-observed fallbacks.
2. **Disclaimed Checksum Label:**  
   The SHA-256 hash is explicitly labeled:
   > **File Checksum (SHA-256):**  
   > `15def78315f04d2b6925461abb45a05fdc7a8c5c0c6472f980e0...`  
   > *Integrity verification only; does not establish source authenticity*

In [`frontend/src/views/ThreatHunting.tsx`](../frontend/src/views/ThreatHunting.tsx):
- Header badge displays `queryResult?.provenance || "unknown"`.
- Empty queries (`total === 0`) and unverified result sets honestly render `Unknown Provenance`.

---

## 5. Automated Verification & Regression Testing

The provenance architecture is validated across 144 backend tests and 20 frontend tests:

### Backend Pytest Suite (`backend/tests/test_hunting.py`)
- `test_synthetic_event_with_valid_sha256_hash_is_not_observed`: A synthetic event with a valid SHA-256 hash returns `synthetic_benchmark`, never `observed_telemetry`.
- `test_observed_event_with_verified_source_attribution`: An event with `source_attribution="corporate_edr_sensor_prod_01"` returns `observed_telemetry`.
- `test_event_with_missing_provenance_is_classified_unknown`: An event lacking attribution returns `unknown`.
- `test_event_with_conflicting_synthetic_and_observed_metadata`: Contradictory flags (`provenance="observed_telemetry"` + `synthetic=true`) resolve strictly to `synthetic_benchmark`.
- `test_provenance_database_persistence_and_api_serialization`: Validates end-to-end database persistence and API JSON serialization across observed, synthetic, and unknown events, plus response-level `"mixed"` aggregation.
- `test_classify_event_provenance_unit_rules`: Full matrix testing of classification helper rules.
- `test_determine_response_provenance_aggregation`: Validates aggregate responses for single, empty, and mixed batches.

### Frontend Vitest Suite (`frontend/src/components/common/__tests__/DataProvenanceBadge.test.tsx`)
- Verified badge text, colors, and titles across `observed_telemetry`, `synthetic_benchmark`, `calculated_evaluation`, `mixed`, and `unknown`.
- Verified that empty or invalid provenance safely renders `Unknown Provenance` rather than defaulting to observed.
- Verified Evidence Drawer displays `Unknown Provenance` and the integrity disclaimer when inspecting unverified events with hashes.
- Verified Threat Hunting header displays `Unknown Provenance` or `Mixed Provenance` matching API response payloads.

---

## 6. Architecture Limitations & Future Roadmap

1. **Storage Representation:**  
   In the current prototype, attribution metadata is preserved within `SecurityEventModel.raw_payload` (JSON). Future iterations will introduce dedicated indexed database columns (`collector_id`, `provenance_tier`).
2. **Cryptographic Sensor Authentication:**  
   Logs ingested via `POST /api/v1/logs/upload` without signed collector certificates or explicit `source_attribution` headers remain classified as `unknown`. Future production iterations will support mutual TLS (mTLS) with signed sensor certificates for end-to-end hardware-rooted telemetry provenance.
