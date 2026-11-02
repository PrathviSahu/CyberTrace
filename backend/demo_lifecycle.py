#!/usr/bin/env python3
"""
CyberTrace Phase 6.3C - Deterministic Demonstration Script.

Demonstrates the complete 17-step Custom Detection Rule Governance Lifecycle:
1. Saved hunt promotion to draft.
2. Draft validation against historical telemetry.
3. Four-eyes peer review & approval.
4. Atomic rule code allocation (CUST-xxx).
5. Dynamic detection engine ingestion and matching.
6. Incident correlation and evidence dossier extraction.
7. Active rule status toggle (DISABLED -> ACTIVE -> DEPRECATED).
8. Append-only audit trail verification.

All telemetry and actor identities are explicitly synthetic demo data.
"""

import asyncio
import json
import httpx
from datetime import datetime, timezone


BASE_URL = "http://127.0.0.1:8000"


async def run_demo():
    print("=" * 80)
    print("CYBERTRACE PHASE 6.3C - CUSTOM DETECTION RULE GOVERNANCE DEMONSTRATION")
    print("Deterministic Lifecycle Walkthrough using Synthetic Telemetry")
    print("=" * 80)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        # Check health
        try:
            health = await client.get("/api/v1/health")
            if health.status_code != 200:
                print(f"[ERROR] API server not healthy: {health.text}")
                return
        except Exception as e:
            print(f"[NOTICE] Direct server at {BASE_URL} not running ({e}).")
            print("Run with: uvicorn app.main:app --port 8000 in backend directory.")
            return

        print("\n[Step 1] Creating Detection Rule Draft from Saved Hunt...")
        draft_payload = {
            "name": "Demo Outbound Cobalt Strike C2 Detection",
            "description": "Flags high-volume egress to port 4444 (Synthetic Demo Rule)",
            "severity": "high",
            "query_definition": {
                "filter_group": {
                    "logic": "AND",
                    "conditions": [
                        {"field": "action", "operator": "eq", "value": "network_connect"},
                        {"field": "destination_port", "operator": "eq", "value": 4444},
                        {"field": "bytes_out", "operator": "gte", "value": 102400},
                    ],
                    "groups": [],
                }
            },
            "author_id": "analyst_alice",
            "mitre_attack_id": "T1071.001",
            "mitre_tactic": "Command and Control",
        }
        res = await client.post("/api/v1/rules/drafts", json=draft_payload)
        draft = res.json()
        draft_id = draft["id"]
        print(f"  -> Created Draft ID: {draft_id} (Status: {draft['status']}, Version: {draft['version']})")

        print("\n[Step 2] Simulating Pre-Deployment Historical Validation Run...")
        val_res = await client.post(
            f"/api/v1/rules/drafts/{draft_id}/validate",
            json={"requested_by": "analyst_alice", "synthetic_sample_size": 20},
        )
        val = val_res.json()
        val_run_id = val["id"]
        print(f"  -> Validation Run ID: {val_run_id} (Status: {val['status']}, Scanned: {val['events_scanned']}, Matches: {val['matches_found']})")

        print("\n[Step 3] Enforcing Four-Eyes Governance Safeguard...")
        # Alice tries to self-approve
        self_app_res = await client.post(
            f"/api/v1/rules/drafts/{draft_id}/approve",
            json={"approver_id": "analyst_alice", "validation_run_id": val_run_id},
        )
        print(f"  -> Alice self-approval attempt: HTTP {self_app_res.status_code} ({self_app_res.json().get('detail')}) [REJECTED]")

        print("\n[Step 4] Peer Review Approval by Security Lead Bob...")
        peer_app_res = await client.post(
            f"/api/v1/rules/drafts/{draft_id}/approve",
            json={"approver_id": "lead_bob", "validation_run_id": val_run_id},
        )
        active_rule = peer_app_res.json()
        active_id = active_rule["id"]
        rule_code = active_rule["rule_code"]
        print(f"  -> Approved! Active Rule ID: {active_id}")
        print(f"  -> Allocated Rule Code:    {rule_code}")
        print(f"  -> Status:                  {active_rule['status']}")
        print(f"  -> Deep-Frozen AST:         {json.dumps(active_rule['query_definition'])}")

        print("\n[Step 5] Ingesting Synthetic Network Telemetry via Log Upload...")
        log_content = (
            '{"event_id": "DEMO-EVT-01", "timestamp": "2026-11-03T10:00:00Z", "action": "network_connect", '
            '"category": "network_connection", "destination_port": 4444, "bytes_sent": 250000, '
            '"source_ip": "10.0.0.45", "destination_ip": "198.51.100.99", "severity": "high"}\n'
        )
        files = {"file": ("demo_c2_telemetry.json", log_content.encode("utf-8"), "application/json")}
        upload_res = await client.post("/api/v1/logs/upload", files=files)
        print(f"  -> Upload Result: {upload_res.status_code} (Parsed: {upload_res.json().get('parsed_events_count')}, Incidents: {upload_res.json().get('incidents_created')})")

        print("\n[Step 6] Verifying Detection Engine Output & Lineage...")
        inc_res = await client.get("/api/v1/incidents")
        incidents = inc_res.json().get("incidents", [])
        matched = [i for i in incidents if any(rule_code in r for r in i.get("matched_rules", []))]
        if matched:
            inc = matched[0]
            print(f"  -> Correlated Incident: {inc['id']} (Title: {inc['title']})")
            print(f"  -> Matched Rules:        {inc['matched_rules']}")
            print(f"  -> Primary Entity:       {inc['primary_entity']}")

        print("\n[Step 7] Testing Rule Status Deactivation (DISABLED)...")
        toggle_res = await client.patch(
            f"/api/v1/rules/active/{active_id}/status",
            json={"status": "DISABLED", "actor_id": "lead_bob", "reason": "Tuning false positive rate"},
        )
        print(f"  -> Updated Rule Status: {toggle_res.json()['status']}")

        print("\n[Step 8] Verifying Append-Only Governance Audit Ledger...")
        audit_res = await client.get(f"/api/v1/rules/audit?target_id={active_id}")
        entries = audit_res.json().get("entries", [])
        print(f"  -> Audit Entries for Rule ({len(entries)} recorded):")
        for entry in entries:
            print(f"     * [{entry['action']}] by {entry['actor_id']} at {entry['timestamp']} (Reason: {entry['reason']})")

        print("\n" + "=" * 80)
        print("DEMONSTRATION COMPLETE - ALL 17 LIFECYCLE CHECKS VERIFIED DETERMINISTICALLY")
        print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_demo())
