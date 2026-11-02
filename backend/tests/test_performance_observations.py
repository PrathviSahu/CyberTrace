"""
Phase 6.3C Stage 5 - Performance and Operational Observations Benchmark.

Measures:
1. Active rule query count per ingestion batch (verifying O(1) query count, no N+1).
2. Detection engine execution latency across varying rule counts (0, 1, 5, 10 custom rules).
3. Throughput across 100 and 500 synthetic event batches.
4. Memory footprint and instantiation overhead of immutable DynamicCustomRule snapshots.
"""

import gc
import sys
import time
import tracemalloc
import pytest
from datetime import datetime, timezone
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.db.models import (
    Base,
    DetectionRuleDraftModel,
    RuleValidationRunModel,
    ActiveDetectionRuleModel,
)
from app.rules.rule_engine import DetectionEngine
from app.rules.dynamic_rule import DynamicCustomRule
from app.correlation.service import IncidentService
from app.schemas.ces import CommonEvent, EventCategory, EventAction, EventSeverity


@pytest.fixture
async def perf_db():
    """Isolated SQLite in-memory database for performance measurements."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session, engine
    await engine.dispose()


def _generate_synthetic_events(count: int) -> list[CommonEvent]:
    """Generate deterministic synthetic network and auth events."""
    events = []
    base_time = datetime(2026, 11, 3, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(count):
        port = 4444 if i % 10 == 0 else 80
        action = EventAction.NETWORK_CONNECT if i % 2 == 0 else EventAction.LOGON_FAILURE
        category = EventCategory.NETWORK_CONNECTION if i % 2 == 0 else EventCategory.AUTHENTICATION
        evt = CommonEvent(
            event_id=f"SYNTH-EVT-{i:05d}",
            timestamp=base_time,
            category=category,
            action=action,
            source_ip=f"10.0.0.{i % 250 + 1}",
            destination_ip="198.51.100.5",
            destination_port=port,
            bytes_sent=150000 if port == 4444 else 500,
            severity=EventSeverity.MEDIUM,
            source_format="synthetic",
            raw_payload={"index": i},
        )
        events.append(evt)
    return events


async def _seed_active_rules(session: AsyncSession, count: int) -> list[ActiveDetectionRuleModel]:
    """Seed `count` active detection rules with valid AST filters."""
    rules = []
    now = datetime.now(timezone.utc)

    for i in range(count):
        rule_code = f"CUST-{i+1:03d}"
        draft_id = f"draft_perf_{i+1:03d}"
        val_id = f"val_perf_{i+1:03d}"

        draft = DetectionRuleDraftModel(
            id=draft_id,
            name=f"Perf Rule {i+1}",
            query_definition={},
            status="APPROVED",
            version=1,
            created_by="perf_runner",
        )
        val = RuleValidationRunModel(
            id=val_id,
            draft_id=draft_id,
            draft_version=1,
            query_definition_snapshot={},
            events_scanned=10,
            matches_found=1,
            status="COMPLETED",
        )
        session.add(draft)
        session.add(val)
        await session.flush()

        query_def = {
            "filter_group": {
                "logic": "AND",
                "conditions": [
                    {"field": "destination_port", "operator": "eq", "value": 4444},
                    {"field": "bytes_out", "operator": "gte", "value": 102400},
                ],
                "groups": [],
            }
        }

        active_rule = ActiveDetectionRuleModel(
            id=f"act_perf_{i+1:03d}",
            rule_code=rule_code,
            name=f"Active Perf Rule {i+1}",
            description=f"Active performance test rule {i+1}",
            severity="high",
            status="ACTIVE",
            source_draft_id=draft_id,
            source_draft_version=1,
            validation_run_id=val_id,
            query_definition=query_def,
            version=1,
            approved_by="perf_peer",
            approved_at=now,
            activated_at=now,
        )
        session.add(active_rule)
        rules.append(active_rule)

    await session.commit()
    return rules


@pytest.mark.asyncio
async def test_active_rule_query_count_is_strictly_o1(perf_db):
    """Verify exactly 1 SQL query is executed to load active rules for an entire batch."""
    session, engine = perf_db
    await _seed_active_rules(session, 5)

    events = _generate_synthetic_events(50)
    service = IncidentService(session=session)

    query_count = 0

    def query_listener(conn, cursor, statement, parameters, context, executemany):
        nonlocal query_count
        if "active_detection_rules" in statement.lower():
            query_count += 1

    event.listen(engine.sync_engine, "before_cursor_execute", query_listener)
    try:
        results = await service.process_and_correlate_events(events)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", query_listener)

    # Must be exactly 1 query to fetch active rules regardless of batch size (50 events)
    assert query_count == 1
    assert isinstance(results, list)
    assert len(results) > 0


@pytest.mark.asyncio
async def test_detection_latency_scaling(perf_db):
    """
    Measure detection execution latency across different rule counts and event batch sizes:
    - 0 custom rules (4 foundational)
    - 1 custom rule (5 total)
    - 5 custom rules (9 total)
    - 10 custom rules (14 total)
    Batch sizes: 100 events, 500 events.
    """
    session, engine = perf_db
    events_100 = _generate_synthetic_events(100)
    events_500 = _generate_synthetic_events(500)

    # 1. Baseline: Pure engine with 0 custom rules
    engine_0 = DetectionEngine()
    t0 = time.perf_counter()
    res_0_100 = engine_0.evaluate_all(events_100)
    t_0_100 = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    res_0_500 = engine_0.evaluate_all(events_500)
    t_0_500 = (time.perf_counter() - t0) * 1000.0

    # 2. Seed 10 rules
    rule_models = await _seed_active_rules(session, 10)
    dynamic_rules = [DynamicCustomRule.from_active_model(m) for m in rule_models]

    # Evaluate with 1 custom rule
    engine_1 = DetectionEngine(custom_rules=[dynamic_rules[0]])
    t0 = time.perf_counter()
    res_1_100 = engine_1.evaluate_all(events_100)
    t_1_100 = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    res_1_500 = engine_1.evaluate_all(events_500)
    t_1_500 = (time.perf_counter() - t0) * 1000.0

    # Evaluate with 5 custom rules
    engine_5 = DetectionEngine(custom_rules=dynamic_rules[:5])
    t0 = time.perf_counter()
    res_5_100 = engine_5.evaluate_all(events_100)
    t_5_100 = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    res_5_500 = engine_5.evaluate_all(events_500)
    t_5_500 = (time.perf_counter() - t0) * 1000.0

    # Evaluate with 10 custom rules
    engine_10 = DetectionEngine(custom_rules=dynamic_rules[:10])
    t0 = time.perf_counter()
    res_10_100 = engine_10.evaluate_all(events_100)
    t_10_100 = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    res_10_500 = engine_10.evaluate_all(events_500)
    t_10_500 = (time.perf_counter() - t0) * 1000.0

    print("\n--- Detection Latency Benchmark Results ---")
    print(f"| Rules Count           | 100 Events Latency | 500 Events Latency | Per-Event Avg (500) |")
    print(f"|-----------------------|--------------------|--------------------|---------------------|")
    print(f"| 0 Custom (4 Found.)   | {t_0_100:8.2f} ms   | {t_0_500:8.2f} ms   | {t_0_500/500*1000:6.1f} µs/evt  |")
    print(f"| 1 Custom (5 Total)    | {t_1_100:8.2f} ms   | {t_1_500:8.2f} ms   | {t_1_500/500*1000:6.1f} µs/evt  |")
    print(f"| 5 Custom (9 Total)    | {t_5_100:8.2f} ms   | {t_5_500:8.2f} ms   | {t_5_500/500*1000:6.1f} µs/evt  |")
    print(f"| 10 Custom (14 Total)  | {t_10_100:8.2f} ms  | {t_10_500:8.2f} ms  | {t_10_500/500*1000:6.1f} µs/evt  |")

    # Latency assertions (should process 500 events across 14 rules in well under 100ms)
    assert t_10_500 < 200.0  # Safe threshold for CI / local runs
    assert len(res_10_500) > 0


@pytest.mark.asyncio
async def test_dynamic_rule_memory_and_instantiation_overhead(perf_db):
    """Measure memory footprint and instantiation time of DynamicCustomRule objects."""
    session, _ = perf_db
    rules = await _seed_active_rules(session, 10)

    # 1. Instantiation time for 10 rules
    t0 = time.perf_counter()
    for _ in range(100):
        snapshots = [DynamicCustomRule.from_active_model(m) for m in rules]
    instantiation_time_avg_us = ((time.perf_counter() - t0) / 100 / len(rules)) * 1_000_000.0

    # 2. Memory measurement with tracemalloc
    gc.collect()
    tracemalloc.start()
    sample_rules = [DynamicCustomRule.from_active_model(m) for m in rules]
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    bytes_per_rule = current / len(sample_rules)

    print("\n--- DynamicCustomRule Overhead Results ---")
    print(f"Instantiation latency: {instantiation_time_avg_us:.2f} µs per rule")
    print(f"Memory footprint:      {bytes_per_rule:.1f} bytes per active rule snapshot")
    print(f"Total for 10 rules:    {current} bytes (peak {peak} bytes)")

    # Assertions
    assert instantiation_time_avg_us < 500.0  # < 0.5 ms per rule
    assert bytes_per_rule < 20000  # < 20 KB per rule
