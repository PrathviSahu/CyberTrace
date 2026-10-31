"""
Comprehensive tests for CyberTrace Phase 3: BharatCode AI Investigation Engine.
Tests configuration, read-only tools, evidence verification, stateless orchestration,
deterministic fallback failover, database persistence, and REST API endpoints.
All BharatCode API interactions are mocked via respx; real API keys or quotas are never needed.
"""

from datetime import datetime, timezone
import json
from typing import Any, AsyncGenerator, Dict, List
from httpx import ASGITransport, AsyncClient
import pytest
import respx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.correlation.models import CorrelatedEntity, CorrelatedIncidentGroup
from app.db.models import AIInvestigationModel
from app.db.repositories.detection_repo import DetectionRepository
from app.db.repositories.event_repo import EventRepository
from app.db.repositories.incident_repo import IncidentRepository
from app.db.repositories.investigation_repo import InvestigationRepository
from app.db.session import get_db_session
from app.investigation.agent import (
    BharatCodeAgent,
    IncompleteResponseError,
    InvestigationError,
    StructuredOutputValidationError,
    ToolLimitExceededError,
)
from app.investigation.fallback import DeterministicFallbackEngine
from app.investigation.service import InvestigationService
from app.investigation.tools import TOOL_DEFINITIONS, InvestigationToolExecutor
from app.investigation.verifier import EvidenceVerifier
from app.main import app
from app.rules.base import DetectionResult
from app.schemas.ces import CommonEvent, EventAction, EventCategory, EventSeverity
from app.schemas.investigation import (
    ConfidenceLevel,
    Hypothesis,
    ImpactLevel,
    ObservedFact,
    RecommendedAction,
    StructuredInvestigation,
)


# ---------------------------------------------------------------------------
# Test Helpers & Seeding
# ---------------------------------------------------------------------------

async def seed_test_incident(session: AsyncSession, incident_id: str = "inc_test_001") -> Dict[str, Any]:
    """Populates an isolated test incident with events, detections, and correlated entities."""
    ev_repo = EventRepository(session)
    det_repo = DetectionRepository(session)
    inc_repo = IncidentRepository(session)

    t1 = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 1, 8, 2, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 11, 1, 8, 5, 0, tzinfo=timezone.utc)

    events = [
        CommonEvent(
            event_id="evt_001",
            timestamp=t1,
            category=EventCategory.AUTHENTICATION,
            action=EventAction.LOGON_FAILURE,
            severity=EventSeverity.MEDIUM,
            user_identity="svc_deploy",
            source_ip="198.51.100.44",
            hostname="SRV-APP-01",
            source_format="test",
        ),
        CommonEvent(
            event_id="evt_002",
            timestamp=t2,
            category=EventCategory.AUTHENTICATION,
            action=EventAction.LOGON_SUCCESS,
            severity=EventSeverity.LOW,
            user_identity="svc_deploy",
            source_ip="198.51.100.44",
            hostname="SRV-APP-01",
            source_format="test",
        ),
        CommonEvent(
            event_id="evt_003",
            timestamp=t3,
            category=EventCategory.NETWORK_CONNECTION,
            action=EventAction.NETWORK_CONNECT,
            severity=EventSeverity.HIGH,
            user_identity="svc_deploy",
            source_ip="192.168.1.50",
            destination_ip="203.0.113.99",
            destination_port=443,
            bytes_out=150000000,
            hostname="SRV-APP-01",
            source_format="test",
        ),
    ]
    await ev_repo.upsert_events(events)

    detections = [
        DetectionResult(
            detection_id="det_001",
            rule_id="DET-001",
            rule_name="Brute Force Authentication Burst",
            severity=EventSeverity.MEDIUM,
            summary="Rapid authentication failures observed for svc_deploy",
            detection_timestamp=t1,
            entity_key="user:svc_deploy",
            triggering_event_ids=["evt_001"],
        ),
        DetectionResult(
            detection_id="det_002",
            rule_id="DET-002",
            rule_name="Logon Success After Failed Attempts",
            severity=EventSeverity.HIGH,
            summary="Successful login for svc_deploy following failed attempts",
            detection_timestamp=t2,
            entity_key="user:svc_deploy",
            triggering_event_ids=["evt_001", "evt_002"],
        ),
        DetectionResult(
            detection_id="det_003",
            rule_id="DET-004",
            rule_name="High-Volume Data Exfiltration",
            severity=EventSeverity.CRITICAL,
            summary="Large outbound egress to 203.0.113.99",
            detection_timestamp=t3,
            entity_key="destination_ip:203.0.113.99",
            triggering_event_ids=["evt_003"],
        ),
    ]
    await det_repo.upsert_detections(detections)

    group = CorrelatedIncidentGroup(
        incident_id=incident_id,
        correlation_key="ckey_test_001",
        title="Multi-Stage Compromise and Exfiltration on svc_deploy",
        description="Correlated account compromise leading to high-volume outbound data transfer",
        severity=EventSeverity.CRITICAL,
        status="open",
        first_seen=t1,
        last_seen=t3,
        detection_ids=["det_001", "det_002", "det_003"],
        entities=[
            CorrelatedEntity(
                entity_type="user",
                entity_value="svc_deploy",
                relationship="compromised_account",
                confidence=1.0,
                evidence_references=["evt_001", "evt_002"],
            ),
            CorrelatedEntity(
                entity_type="hostname",
                entity_value="SRV-APP-01",
                relationship="affected_host",
                confidence=1.0,
                evidence_references=["evt_001", "evt_002", "evt_003"],
            ),
            CorrelatedEntity(
                entity_type="destination_ip",
                entity_value="203.0.113.99",
                relationship="exfiltration_destination",
                confidence=1.0,
                evidence_references=["evt_003"],
            ),
        ],
        supporting_event_ids=["evt_001", "evt_002", "evt_003"],
    )
    await inc_repo.upsert_incident(group)
    return await inc_repo.get_incident_evidence(incident_id)


# ---------------------------------------------------------------------------
# 1. Configuration Tests
# ---------------------------------------------------------------------------

def test_config_api_key_missing_and_present():
    """Verifies agent initialization with explicit and fallback configuration."""
    agent_with_key = BharatCodeAgent(api_key="custom_secret_key")
    assert agent_with_key.api_key == "custom_secret_key"
    assert agent_with_key.model == "qwen-3.8-27b"
    assert agent_with_key.base_url == "https://bharatcode.ai/api/model/v1"

    agent_no_key = BharatCodeAgent(api_key="")
    assert agent_no_key.api_key == ""


def test_config_custom_parameters():
    """Verifies custom model, timeout, and max round parameters."""
    agent = BharatCodeAgent(
        api_key="key",
        base_url="https://custom.endpoint/v1/",
        model="custom-model",
        timeout_seconds=45.0,
        max_tool_rounds=3,
        max_total_tool_calls=6,
        max_output_tokens=2048,
    )
    assert agent.base_url == "https://custom.endpoint/v1"
    assert agent.model == "custom-model"
    assert agent.timeout_seconds == 45.0
    assert agent.max_tool_rounds == 3
    assert agent.max_total_tool_calls == 6
    assert agent.max_output_tokens == 2048


# ---------------------------------------------------------------------------
# 2. Investigation Tools Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tool_get_incident_timeline(db_session: AsyncSession):
    dossier = await seed_test_incident(db_session, "inc_tools_001")
    executor = InvestigationToolExecutor(db_session, "inc_tools_001")

    res = await executor.execute_tool("get_incident_timeline", {"incident_id": "inc_tools_001"})
    assert "timeline" in res
    assert res["timeline_count"] == 6  # 3 events + 3 detections
    # Chronological sort check
    timestamps = [t["timestamp"] for t in res["timeline"]]
    assert timestamps == sorted(timestamps)


@pytest.mark.asyncio
async def test_tool_get_event_details_restricted_to_incident(db_session: AsyncSession):
    await seed_test_incident(db_session, "inc_tools_002")
    executor = InvestigationToolExecutor(db_session, "inc_tools_002")

    # Request one valid event and one fake/out-of-scope event
    res = await executor.execute_tool(
        "get_event_details",
        {"incident_id": "inc_tools_002", "event_ids": ["evt_001", "evt_nonexistent"]},
    )
    assert res["returned_count"] == 1
    assert res["events"][0]["event_id"] == "evt_001"
    assert res["rejected_or_unauthorized_ids"] == ["evt_nonexistent"]


@pytest.mark.asyncio
async def test_tool_query_entity_history(db_session: AsyncSession):
    await seed_test_incident(db_session, "inc_tools_003")
    executor = InvestigationToolExecutor(db_session, "inc_tools_003")

    # Match user svc_deploy
    res_user = await executor.execute_tool(
        "query_entity_history",
        {"incident_id": "inc_tools_003", "entity_type": "user", "entity_value": "svc_deploy", "limit": 2},
    )
    assert res_user["matched_count"] == 2

    # Match destination IP
    res_ip = await executor.execute_tool(
        "query_entity_history",
        {"incident_id": "inc_tools_003", "entity_type": "destination_ip", "entity_value": "203.0.113.99"},
    )
    assert res_ip["matched_count"] == 1
    assert res_ip["events"][0]["destination_ip"] == "203.0.113.99"


@pytest.mark.asyncio
async def test_tool_query_entity_history_temporal_filtering(db_session: AsyncSession):
    """Verifies inclusive ISO-8601 time bounds, timezone normalization, and error handling."""
    await seed_test_incident(db_session, "inc_tools_temporal")
    executor = InvestigationToolExecutor(db_session, "inc_tools_temporal")

    # Seeding created:
    # evt_001 at 08:00:00 UTC (svc_deploy, logon_failure)
    # evt_002 at 08:02:00 UTC (svc_deploy, logon_success)
    # evt_003 at 08:05:00 UTC (svc_deploy, network_connect to 203.0.113.99)

    # 1. Filter within window (08:01:00 to 08:03:00) -> matches only evt_002
    res_between = await executor.execute_tool(
        "query_entity_history",
        {
            "incident_id": "inc_tools_temporal",
            "entity_type": "user",
            "entity_value": "svc_deploy",
            "start_time": "2026-11-01T08:01:00Z",
            "end_time": "2026-11-01T08:03:00Z",
        },
    )
    assert res_between["matched_count"] == 1
    assert res_between["events"][0]["event_id"] == "evt_002"

    # 2. Inclusive boundary check (08:00:00 to 08:02:00) -> matches both evt_001 and evt_002
    res_inclusive = await executor.execute_tool(
        "query_entity_history",
        {
            "incident_id": "inc_tools_temporal",
            "entity_type": "user",
            "entity_value": "svc_deploy",
            "start_time": "2026-11-01T08:00:00Z",
            "end_time": "2026-11-01T08:02:00Z",
        },
    )
    assert res_inclusive["matched_count"] == 2
    assert [e["event_id"] for e in res_inclusive["events"]] == ["evt_001", "evt_002"]

    # 3. Timezone offset handling: 08:02:00 UTC == 13:32:00 +05:30
    res_tz = await executor.execute_tool(
        "query_entity_history",
        {
            "incident_id": "inc_tools_temporal",
            "entity_type": "user",
            "entity_value": "svc_deploy",
            "start_time": "2026-11-01T13:31:00+05:30",
            "end_time": "2026-11-01T13:33:00+05:30",
        },
    )
    assert res_tz["matched_count"] == 1
    assert res_tz["events"][0]["event_id"] == "evt_002"

    # 4. Error on invalid start_time format
    res_bad_start = await executor.execute_tool(
        "query_entity_history",
        {
            "incident_id": "inc_tools_temporal",
            "entity_type": "user",
            "entity_value": "svc_deploy",
            "start_time": "not-an-iso-date",
        },
    )
    assert "error" in res_bad_start
    assert "Invalid start_time format" in res_bad_start["error"]

    # 5. Error on start_time later than end_time
    res_reversed = await executor.execute_tool(
        "query_entity_history",
        {
            "incident_id": "inc_tools_temporal",
            "entity_type": "user",
            "entity_value": "svc_deploy",
            "start_time": "2026-11-01T08:10:00Z",
            "end_time": "2026-11-01T08:05:00Z",
        },
    )
    assert "error" in res_reversed
    assert "start_time cannot be later than end_time" in res_reversed["error"]


@pytest.mark.asyncio
async def test_tool_get_detection_details(db_session: AsyncSession):
    await seed_test_incident(db_session, "inc_tools_004")
    executor = InvestigationToolExecutor(db_session, "inc_tools_004")

    res = await executor.execute_tool(
        "get_detection_details",
        {"incident_id": "inc_tools_004", "detection_ids": ["det_001", "det_003"]},
    )
    assert len(res["detections"]) == 2
    rule_ids = {d["rule_id"] for d in res["detections"]}
    assert rule_ids == {"DET-001", "DET-004"}


@pytest.mark.asyncio
async def test_tool_access_denied_for_wrong_incident(db_session: AsyncSession):
    await seed_test_incident(db_session, "inc_authorized_001")
    executor = InvestigationToolExecutor(db_session, "inc_authorized_001")

    # Attempt accessing unauthorized incident
    res = await executor.execute_tool(
        "get_incident_timeline",
        {"incident_id": "inc_unauthorized_999"},
    )
    assert "error" in res
    assert "Access denied" in res["error"]


@pytest.mark.asyncio
async def test_tool_unknown_function_name(db_session: AsyncSession):
    executor = InvestigationToolExecutor(db_session, "inc_test_001")
    res = await executor.execute_tool("malicious_command_execution", {"incident_id": "inc_test_001"})
    assert "error" in res
    assert "Unknown or disallowed" in res["error"]


# ---------------------------------------------------------------------------
# 3. Evidence Verification Tests (Hardened)
# ---------------------------------------------------------------------------

def test_evidence_verifier_hardened_grounding():
    """
    Verifies strict evidence verification:
    - Omit observed facts with zero or mixed citations (no partial compound claims).
    - Omit hypotheses with zero valid supporting citations.
    - Preserve hypotheses with valid citations, adding warning caveats when invalid IDs stripped.
    - Clean contradicting evidence citations.
    - Omit actions with zero valid citations unless explicitly generic.
    - Enforce requires_human_approval = True across all actions.
    - Keep unknowns separate and intact.
    """
    valid_ids = {"evt_001", "evt_002"}
    verifier = EvidenceVerifier(valid_ids)

    raw = StructuredInvestigation(
        executive_summary="Adversary compromise summary",
        observed_facts=[
            ObservedFact(statement="Legitimate login event", event_ids=["evt_001"]),
            ObservedFact(statement="Completely fake claim", event_ids=["evt_fake_999"]),
            ObservedFact(statement="Mixed citations compound claim", event_ids=["evt_002", "evt_fake_888"]),
            ObservedFact(statement="Unreferenced claim", event_ids=[]),
        ],
        hypotheses=[
            Hypothesis(
                statement="Exfiltration hypothesis with mixed citations",
                supporting_event_ids=["evt_001", "evt_fake_777"],
                contradicting_event_ids=["evt_fake_333"],
                confidence=ConfidenceLevel.HIGH,
            ),
            Hypothesis(
                statement="Unsupported hypothesis with zero valid evidence",
                supporting_event_ids=["evt_fake_555"],
                confidence=ConfidenceLevel.LOW,
            ),
        ],
        unknowns=[],
        recommended_actions=[
            RecommendedAction(
                action="Isolate host",
                rationale="Compromised",
                supporting_event_ids=["evt_fake_666", "evt_002"],
                requires_human_approval=False,  # Intentionally test override
            ),
            RecommendedAction(
                action="Action with only fake citations",
                rationale="Non-generic action without evidence",
                supporting_event_ids=["evt_fake_111"],
                requires_human_approval=False,
            ),
            RecommendedAction(
                action="Review identity password complexity policy",
                rationale="General posture guidance",
                supporting_event_ids=[],
                is_generic_guidance=True,
                requires_human_approval=False,
            ),
        ],
        limitations=[],
    )

    cleaned, verified_cites, rejected_cites = verifier.verify_and_clean(raw)

    # 1. Facts: Only the 100% verified fact is preserved; fake, mixed, and empty facts are omitted
    assert len(cleaned.observed_facts) == 1
    assert cleaned.observed_facts[0].statement == "Legitimate login event"
    assert cleaned.observed_facts[0].event_ids == ["evt_001"]

    # 2. Hypotheses:
    # - Mixed citation hypothesis kept with valid citation, warning caveat added, fake contradicting stripped
    # - Zero valid citation hypothesis is omitted
    assert len(cleaned.hypotheses) == 1
    assert cleaned.hypotheses[0].statement == "Exfiltration hypothesis with mixed citations"
    assert cleaned.hypotheses[0].supporting_event_ids == ["evt_001"]
    assert cleaned.hypotheses[0].contradicting_event_ids == []
    assert any("[Evidence Integrity Warning]" in c for c in cleaned.hypotheses[0].caveats)

    # 3. Actions:
    # - Action with valid citation is preserved, human approval forced to True
    # - Action with only fake citation is omitted
    # - Generic action is preserved with tag and human approval forced to True
    assert len(cleaned.recommended_actions) == 2
    assert cleaned.recommended_actions[0].action == "Isolate host"
    assert cleaned.recommended_actions[0].supporting_event_ids == ["evt_002"]
    assert cleaned.recommended_actions[0].requires_human_approval is True
    assert cleaned.recommended_actions[0].is_generic_guidance is False

    assert cleaned.recommended_actions[1].is_generic_guidance is True
    assert cleaned.recommended_actions[1].action.startswith("[Generic Best-Practice Guidance]")
    assert cleaned.recommended_actions[1].requires_human_approval is True

    # 4. Citations partitioned correctly
    assert set(verified_cites) == {"evt_001", "evt_002"}
    assert "evt_fake_999" in rejected_cites
    assert "evt_fake_888" in rejected_cites
    assert "evt_fake_777" in rejected_cites
    assert "evt_fake_666" in rejected_cites
    assert "evt_fake_555" in rejected_cites
    assert "evt_fake_111" in rejected_cites

    # 5. Integrity notices placed in limitations
    assert any("[Evidence Integrity Notice]" in lim for lim in cleaned.limitations)
    assert any("[Omitted Mixed-Citation Fact]" in lim for lim in cleaned.limitations)
    assert any("[Omitted Unsupported Hypothesis]" in lim for lim in cleaned.limitations)
    assert any("[Omitted Unsupported Action]" in lim for lim in cleaned.limitations)


# ---------------------------------------------------------------------------
# 4. Deterministic Fallback Engine Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deterministic_fallback_synthesis(db_session: AsyncSession):
    dossier = await seed_test_incident(db_session, "inc_fb_001")
    fb = DeterministicFallbackEngine.generate_fallback_investigation(
        dossier, fallback_reason="API key not provided"
    )

    assert "[Deterministic Heuristic Synthesis]" in fb.executive_summary
    assert "API key not provided" in fb.executive_summary
    assert len(fb.observed_facts) == 3
    assert len(fb.hypotheses) >= 2
    assert len(fb.unknowns) >= 2
    assert len(fb.recommended_actions) >= 1

    # Every action requires human approval
    for act in fb.recommended_actions:
        assert act.requires_human_approval is True


# ---------------------------------------------------------------------------
# 5. BharatCodeAgent Orchestration Tests (Mocked with respx)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_agent_single_turn_direct_answer(db_session: AsyncSession):
    """Test when the model immediately outputs structured investigation JSON."""
    dossier = await seed_test_incident(db_session, "inc_ai_001")
    executor = InvestigationToolExecutor(db_session, "inc_ai_001")

    model_output_json = {
        "executive_summary": "Investigated compromised account svc_deploy.",
        "observed_facts": [
            {"statement": "Failed login detected", "event_ids": ["evt_001"]},
            {"statement": "Successful logon", "event_ids": ["evt_002"]},
        ],
        "hypotheses": [
            {
                "statement": "Credential stuffing attack succeeded.",
                "supporting_event_ids": ["evt_001", "evt_002"],
                "contradicting_event_ids": [],
                "confidence": "high",
                "caveats": ["Requires user confirmation"],
            }
        ],
        "unknowns": [
            {"question": "Was MFA challenged?", "reason": "No MFA events in log"}
        ],
        "recommended_actions": [
            {
                "action": "Disable svc_deploy session",
                "rationale": "High confidence credential compromise",
                "supporting_event_ids": ["evt_002"],
                "impact": "medium",
                "requires_human_approval": True,
            }
        ],
        "limitations": ["Limited network telemetry"],
    }

    mock_resp = {
        "id": "resp_001",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": json.dumps(model_output_json),
                    }
                ],
            }
        ],
    }

    route = respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        return_value=respx.MockResponse(200, json=mock_resp, headers={"x-request-id": "req_trace_001"})
    )

    agent = BharatCodeAgent(api_key="valid_test_key")
    structured_inv, citations, req_id = await agent.run_investigation("inc_ai_001", dossier, executor)

    assert route.called
    assert route.call_count == 1
    # Check payload requirements
    sent_payload = json.loads(route.calls.last.request.content)
    assert sent_payload["store"] is False
    assert sent_payload["model"] == "qwen-3.8-27b"
    assert "tools" in sent_payload

    assert structured_inv.executive_summary == "Investigated compromised account svc_deploy."
    assert citations == ["evt_001", "evt_002"]
    assert req_id == "req_trace_001"
    assert agent.tool_call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_agent_one_tool_call_round(db_session: AsyncSession):
    """Test model calling get_incident_timeline, receiving results, and returning structured report."""
    dossier = await seed_test_incident(db_session, "inc_ai_002")
    executor = InvestigationToolExecutor(db_session, "inc_ai_002")

    # Round 1 Response: Model issues function_call
    resp_round_1 = {
        "id": "resp_step_1",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "call_id": "call_timeline_999",
                "name": "get_incident_timeline",
                "arguments": json.dumps({"incident_id": "inc_ai_002"}),
            }
        ],
    }

    # Round 2 Response: Model provides final structured report
    model_report = {
        "executive_summary": "Multi-stage attack verified via timeline inspection.",
        "observed_facts": [
            {"statement": "Exfiltration observed", "event_ids": ["evt_003"]}
        ],
        "hypotheses": [],
        "unknowns": [],
        "recommended_actions": [
            {
                "action": "Block 203.0.113.99 at perimeter",
                "rationale": "Active exfiltration endpoint",
                "supporting_event_ids": ["evt_003"],
                "impact": "low",
                "requires_human_approval": True,
            }
        ],
        "limitations": [],
    }

    resp_round_2 = {
        "id": "resp_step_2",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "content": json.dumps(model_report),
            }
        ],
    }

    route = respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        side_effect=[
            respx.MockResponse(200, json=resp_round_1, headers={"x-request-id": "req_1"}),
            respx.MockResponse(200, json=resp_round_2, headers={"x-request-id": "req_2"}),
        ]
    )

    agent = BharatCodeAgent(api_key="valid_test_key")
    structured_inv, citations, req_id = await agent.run_investigation("inc_ai_002", dossier, executor)

    assert route.call_count == 2
    assert agent.tool_call_count == 1
    assert req_id == "req_2"
    assert citations == ["evt_003"]

    # Verify that request 2 carried accumulated input with matching call_id
    second_request_payload = json.loads(route.calls[1].request.content)
    input_items = second_request_payload["input"]
    func_output_items = [i for i in input_items if i.get("type") == "function_call_output"]
    assert len(func_output_items) == 1
    assert func_output_items[0]["call_id"] == "call_timeline_999"
    # Output parsed back
    tool_output = json.loads(func_output_items[0]["output"])
    assert tool_output["incident_id"] == "inc_ai_002"


@pytest.mark.asyncio
@respx.mock
async def test_agent_multiple_consecutive_tool_rounds(db_session: AsyncSession):
    """
    Simulates a complete 3-round multi-turn investigation:
    Round 1: Model requests get_incident_timeline.
    Round 2: Model requests get_event_details using event IDs discovered in timeline.
    Round 3: Model returns final structured investigation.

    Strict assertions:
    - Original system and user inputs are preserved in all rounds.
    - Round 1 response.output is preserved in Round 2 and Round 3.
    - Round 1 function_call_output is preserved with matching call_id.
    - Round 2 response.output is preserved in Round 3.
    - Round 2 function_call_output is preserved with matching call_id.
    - Every request includes store: false.
    - No request includes previous_response_id.
    - Tool definitions are provided as required in all requests.
    - The third request contains the complete accumulated history.
    """
    dossier = await seed_test_incident(db_session, "inc_ai_multi_round")
    executor = InvestigationToolExecutor(db_session, "inc_ai_multi_round")

    # Round 1 Response: Model issues function_call for get_incident_timeline
    resp_round_1 = {
        "id": "resp_round_1",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "call_id": "call_r1_timeline_001",
                "name": "get_incident_timeline",
                "arguments": json.dumps({"incident_id": "inc_ai_multi_round"}),
            }
        ],
    }

    # Round 2 Response: Model issues function_call for get_event_details using discovered event IDs
    resp_round_2 = {
        "id": "resp_round_2",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "call_id": "call_r2_details_002",
                "name": "get_event_details",
                "arguments": json.dumps({"incident_id": "inc_ai_multi_round", "event_ids": ["evt_001", "evt_002"]}),
            }
        ],
    }

    # Round 3 Response: Model returns final structured investigation report
    final_report = {
        "executive_summary": "Two-stage credential compromise confirmed via multi-round investigation.",
        "observed_facts": [
            {"statement": "Failed login attempt detected", "event_ids": ["evt_001"]},
            {"statement": "Successful logon from same IP", "event_ids": ["evt_002"]},
        ],
        "hypotheses": [
            {
                "statement": "Brute force attack succeeded in compromising credentials.",
                "supporting_event_ids": ["evt_001", "evt_002"],
                "contradicting_event_ids": [],
                "confidence": "high",
                "caveats": [],
            }
        ],
        "unknowns": [
            {"question": "What process initiated the network connection?", "reason": "Missing endpoint telemetry"}
        ],
        "recommended_actions": [
            {
                "action": "Disable svc_deploy account",
                "rationale": "Compromised credential",
                "supporting_event_ids": ["evt_001", "evt_002"],
                "impact": "high",
                "requires_human_approval": True,
            }
        ],
        "limitations": [],
    }

    resp_round_3 = {
        "id": "resp_round_3",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "content": json.dumps(final_report),
            }
        ],
    }

    route = respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        side_effect=[
            respx.MockResponse(200, json=resp_round_1, headers={"x-request-id": "req_r1"}),
            respx.MockResponse(200, json=resp_round_2, headers={"x-request-id": "req_r2"}),
            respx.MockResponse(200, json=resp_round_3, headers={"x-request-id": "req_r3"}),
        ]
    )

    agent = BharatCodeAgent(api_key="test_valid_key", max_tool_rounds=5)
    structured_inv, citations, req_id = await agent.run_investigation("inc_ai_multi_round", dossier, executor)

    # 1. Total rounds and calls asserted
    assert route.call_count == 3
    assert agent.tool_call_count == 2
    assert req_id == "req_r3"
    assert citations == ["evt_001", "evt_002"]
    assert structured_inv.executive_summary == "Two-stage credential compromise confirmed via multi-round investigation."

    # 2. Inspect Request 1
    req1_body = json.loads(route.calls[0].request.content)
    assert req1_body["store"] is False
    assert "previous_response_id" not in req1_body
    assert "tools" in req1_body
    assert len(req1_body["input"]) == 2  # system + user initial prompt
    assert req1_body["input"][0]["role"] == "system"
    assert req1_body["input"][1]["role"] == "user"

    # 3. Inspect Request 2 (contains Round 1 history)
    req2_body = json.loads(route.calls[1].request.content)
    assert req2_body["store"] is False
    assert "previous_response_id" not in req2_body
    assert "tools" in req2_body
    # Original system and user preserved
    assert req2_body["input"][0]["role"] == "system"
    assert req2_body["input"][1]["role"] == "user"
    # Round 1 response.output preserved
    assert req2_body["input"][2] == resp_round_1["output"][0]
    # Round 1 function_call_output preserved with matching call_id
    assert req2_body["input"][3]["type"] == "function_call_output"
    assert req2_body["input"][3]["call_id"] == "call_r1_timeline_001"
    tool1_res = json.loads(req2_body["input"][3]["output"])
    assert "timeline" in tool1_res

    # 4. Inspect Request 3 (contains complete accumulated history of Round 1 AND Round 2)
    req3_body = json.loads(route.calls[2].request.content)
    assert req3_body["store"] is False
    assert "previous_response_id" not in req3_body
    assert "tools" in req3_body
    # Verify complete accumulated input length and exact sequence:
    # 0: system
    # 1: user
    # 2: round 1 response.output
    # 3: round 1 function_call_output (call_r1_timeline_001)
    # 4: round 2 response.output
    # 5: round 2 function_call_output (call_r2_details_002)
    input_3 = req3_body["input"]
    assert len(input_3) == 6
    assert input_3[0]["role"] == "system"
    assert input_3[1]["role"] == "user"
    assert input_3[2] == resp_round_1["output"][0]
    assert input_3[3]["call_id"] == "call_r1_timeline_001"
    assert input_3[4] == resp_round_2["output"][0]
    assert input_3[5]["type"] == "function_call_output"
    assert input_3[5]["call_id"] == "call_r2_details_002"
    tool2_res = json.loads(input_3[5]["output"])
    assert tool2_res["returned_count"] == 2


@pytest.mark.asyncio
@respx.mock
async def test_agent_incomplete_response_handling(db_session: AsyncSession):
    """Test that response.status == 'incomplete' raises IncompleteResponseError without executing partial calls."""
    dossier = await seed_test_incident(db_session, "inc_ai_003")
    executor = InvestigationToolExecutor(db_session, "inc_ai_003")

    incomplete_resp = {
        "id": "resp_inc",
        "status": "incomplete",
        "incomplete_details": {
            "reason": "max_output_tokens"
        },
        "output": [
            {
                "type": "function_call",
                "call_id": "call_cut_off",
                "name": "get_incident_timeline",
                "arguments": "{\"incident_id\": \"inc_ai_003\"",  # truncated
            }
        ],
    }

    respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        return_value=respx.MockResponse(200, json=incomplete_resp)
    )

    agent = BharatCodeAgent(api_key="valid_test_key")
    with pytest.raises(IncompleteResponseError) as exc_info:
        await agent.run_investigation("inc_ai_003", dossier, executor)

    assert "max_output_tokens" in str(exc_info.value)
    # Crucial check: incomplete tool call was not executed
    assert agent.tool_call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_agent_tool_round_limit_exhaustion(db_session: AsyncSession):
    """Test that agent enforces maximum tool rounds when model loops indefinitely."""
    dossier = await seed_test_incident(db_session, "inc_ai_004")
    executor = InvestigationToolExecutor(db_session, "inc_ai_004")

    # Repeat tool call response forever
    resp_loop = {
        "id": "resp_loop",
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "call_id": "call_loop",
                "name": "get_incident_timeline",
                "arguments": json.dumps({"incident_id": "inc_ai_004"}),
            }
        ],
    }

    respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        return_value=respx.MockResponse(200, json=resp_loop)
    )

    agent = BharatCodeAgent(api_key="valid_test_key", max_tool_rounds=2)
    with pytest.raises(ToolLimitExceededError):
        await agent.run_investigation("inc_ai_004", dossier, executor)

    assert agent.tool_call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_agent_transient_503_retry_succeeds(db_session: AsyncSession):
    """Test bounded retry on HTTP 503 busy response."""
    dossier = await seed_test_incident(db_session, "inc_ai_005")
    executor = InvestigationToolExecutor(db_session, "inc_ai_005")

    success_report = {
        "executive_summary": "Recovered after transient 503.",
        "observed_facts": [],
        "hypotheses": [],
        "unknowns": [],
        "recommended_actions": [],
        "limitations": [],
    }

    route = respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        side_effect=[
            respx.MockResponse(503, json={"error": "Model busy"}),
            respx.MockResponse(200, json={
                "id": "resp_ok",
                "status": "completed",
                "output": [{"type": "message", "content": json.dumps(success_report)}],
            }),
        ]
    )

    agent = BharatCodeAgent(api_key="valid_test_key")
    inv, _, _ = await agent.run_investigation("inc_ai_005", dossier, executor)
    assert route.call_count == 2
    assert inv.executive_summary == "Recovered after transient 503."


# ---------------------------------------------------------------------------
# 6. Investigation Service & Database Persistence Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_service_investigate_missing_api_key_persists_fallback(
    db_session: AsyncSession, monkeypatch
):
    """Verifies that missing BHARATCODE_API_KEY gracefully saves a fallback investigation."""
    monkeypatch.setattr(settings, "BHARATCODE_API_KEY", "")
    await seed_test_incident(db_session, "inc_serv_001")

    service = InvestigationService(db_session)
    record = await service.investigate_incident("inc_serv_001")

    assert record is not None
    assert record.incident_id == "inc_serv_001"
    assert record.status == "fallback"
    assert record.model_id == "deterministic-fallback"
    assert "BHARATCODE_API_KEY is not configured" in (record.error_message or "")
    assert len(record.event_citations) > 0


@pytest.mark.asyncio
@respx.mock
async def test_service_investigate_successful_ai_persists_completed(
    db_session: AsyncSession, monkeypatch
):
    """Verifies successful AI investigation creates persistent record with status='completed'."""
    monkeypatch.setattr(settings, "BHARATCODE_API_KEY", "real_looking_test_key")
    await seed_test_incident(db_session, "inc_serv_002")

    ai_payload = {
        "executive_summary": "Confirmed compromised credentials.",
        "observed_facts": [{"statement": "Logon after failure", "event_ids": ["evt_001", "evt_002"]}],
        "hypotheses": [],
        "unknowns": [],
        "recommended_actions": [
            {
                "action": "Revoke authentication tokens",
                "rationale": "Containment",
                "supporting_event_ids": ["evt_002"],
                "impact": "low",
                "requires_human_approval": True,
            }
        ],
        "limitations": [],
    }

    respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        return_value=respx.MockResponse(
            200,
            json={
                "id": "resp_full",
                "status": "completed",
                "output": [{"type": "message", "content": json.dumps(ai_payload)}],
            },
            headers={"x-request-id": "req_audit_777"},
        )
    )

    service = InvestigationService(db_session)
    record = await service.investigate_incident("inc_serv_002")

    assert record is not None
    assert record.status == "completed"
    assert record.model_id == "qwen-3.8-27b"
    assert record.request_id == "req_audit_777"
    assert record.event_citations == ["evt_001", "evt_002"]
    assert record.duration_seconds >= 0.0


@pytest.mark.asyncio
@respx.mock
async def test_service_investigate_provider_error_fails_over_to_fallback(
    db_session: AsyncSession, monkeypatch
):
    """Verifies that an unrecoverable 500 error from the provider triggers fallback persistence."""
    monkeypatch.setattr(settings, "BHARATCODE_API_KEY", "test_key")
    await seed_test_incident(db_session, "inc_serv_003")

    respx.post("https://bharatcode.ai/api/model/v1/responses").mock(
        return_value=respx.MockResponse(500, json={"error": "Internal inference error"})
    )

    service = InvestigationService(db_session)
    record = await service.investigate_incident("inc_serv_003")

    assert record is not None
    assert record.status == "fallback"
    assert record.model_id == "deterministic-fallback"
    assert "HTTPStatusError" in (record.error_message or "")


@pytest.mark.asyncio
async def test_service_investigation_retrieval_across_sessions(
    async_test_engine, monkeypatch
):
    """Verifies that saved investigations can be retrieved faithfully in a fresh database session."""
    monkeypatch.setattr(settings, "BHARATCODE_API_KEY", "")

    session_maker = async_sessionmaker(bind=async_test_engine, expire_on_commit=False, class_=AsyncSession)

    # Session 1: Create and persist
    async with session_maker() as session1:
        await seed_test_incident(session1, "inc_fresh_001")
        service1 = InvestigationService(session1)
        created_record = await service1.investigate_incident("inc_fresh_001")
        assert created_record is not None
        saved_id = created_record.id

    # Session 2: Fresh query from distinct session
    async with session_maker() as session2:
        service2 = InvestigationService(session2)
        fetched = await service2.get_investigation("inc_fresh_001", saved_id)
        assert fetched is not None
        assert fetched.id == saved_id
        assert fetched.incident_id == "inc_fresh_001"
        assert isinstance(fetched.structured_result, dict)
        assert "executive_summary" in fetched.structured_result


# ---------------------------------------------------------------------------
# 7. FastAPI Endpoint Integration Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_trigger_investigation_and_retrieval(db_session: AsyncSession, monkeypatch):
    monkeypatch.setattr(settings, "BHARATCODE_API_KEY", "")
    await seed_test_incident(db_session, "inc_api_001")

    # Dependency override to inject in-memory DB session
    async def override_get_db_session():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Trigger investigation
            post_resp = await client.post("/api/v1/incidents/inc_api_001/investigate")
            assert post_resp.status_code == 200
            inv_data = post_resp.json()
            assert inv_data["incident_id"] == "inc_api_001"
            assert inv_data["status"] == "fallback"
            assert "structured_result" in inv_data
            inv_id = inv_data["id"]

            # 2. List investigations
            list_resp = await client.get("/api/v1/incidents/inc_api_001/investigations")
            assert list_resp.status_code == 200
            items = list_resp.json()
            assert len(items) >= 1
            assert items[0]["id"] == inv_id

            # 3. Get single investigation
            get_resp = await client.get(f"/api/v1/incidents/inc_api_001/investigations/{inv_id}")
            assert get_resp.status_code == 200
            single = get_resp.json()
            assert single["id"] == inv_id

            # 4. Non-existent incident returns 404
            bad_resp = await client.post("/api/v1/incidents/inc_nonexistent/investigate")
            assert bad_resp.status_code == 404

            # 5. Boundary check: mismatched incident and investigation returns 404
            bad_inv_resp = await client.get(f"/api/v1/incidents/inc_api_001/investigations/fake_inv_999")
            assert bad_inv_resp.status_code == 404
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_api_no_secret_exposure(db_session: AsyncSession, monkeypatch):
    """Assures that secret keys are strictly server-side and never returned in API payloads."""
    secret_value = "super_secret_bharatcode_key_xyz987"
    monkeypatch.setattr(settings, "BHARATCODE_API_KEY", secret_value)
    await seed_test_incident(db_session, "inc_sec_001")

    async def override_get_db_session():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/incidents/inc_sec_001/investigate")
            raw_text = resp.text
            assert secret_value not in raw_text
    finally:
        app.dependency_overrides.clear()
