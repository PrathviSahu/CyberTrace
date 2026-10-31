"""
Unit and integration tests for CyberTrace log parsers and ingestion pipeline.
"""

from pathlib import Path
from app.parsers.csv_parser import GenericCsvParser
from app.parsers.json_parser import GenericJsonParser
from app.parsers.linux_parser import LinuxAuthParser
from app.parsers.network_parser import ZeekConnParser
from app.parsers.pipeline import LogIngestionPipeline
from app.parsers.windows_parser import WindowsEventParser
from app.schemas.ces import EventAction, EventCategory


SAMPLE_DIR = Path(__file__).resolve().parent.parent / "app" / "data" / "sample_logs"


def test_generic_json_parser():
    json_path = SAMPLE_DIR / "enterprise_combined_logs.json"
    with open(json_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = GenericJsonParser()
    assert parser.can_parse(content) is True

    events = parser.parse(content)
    assert len(events) == 15
    assert events[0].event_id == "evt_ben_001"
    assert events[1].event_id == "evt_ben_002"
    assert any(e.user_identity == "svc_deploy" for e in events)


def test_generic_csv_parser():
    csv_path = SAMPLE_DIR / "enterprise_combined_logs.csv"
    with open(csv_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = GenericCsvParser()
    assert parser.can_parse(content) is True

    events = parser.parse(content)
    assert len(events) == 15
    first_ev = events[0]
    assert first_ev.source_format == "csv"
    assert first_ev.action in (EventAction.LOGON_SUCCESS, EventAction.PROCESS_START)


def test_linux_auth_parser_text():
    raw_linux_logs = """
    Nov 01 08:01:05 SRV-APP-01 sshd[1234]: Failed password for invalid user svc_deploy from 198.51.100.44 port 41201 ssh2
    Nov 01 08:05:40 SRV-APP-01 sshd[1240]: Accepted password for svc_deploy from 198.51.100.44 port 41230 ssh2
    Nov 01 08:08:12 SRV-APP-01 sudo: svc_deploy : TTY=pts/2 ; PWD=/home/svc_deploy ; USER=root ; COMMAND=/bin/bash
    """
    parser = LinuxAuthParser()
    assert parser.can_parse(raw_linux_logs) is True

    events = parser.parse(raw_linux_logs)
    assert len(events) == 3

    assert events[0].action == EventAction.LOGON_FAILURE
    assert events[0].user_identity == "svc_deploy"
    assert events[0].source_ip == "198.51.100.44"

    assert events[1].action == EventAction.LOGON_SUCCESS
    assert events[1].user_identity == "svc_deploy"

    assert events[2].action == EventAction.ELEVATION_SUCCESS
    assert events[2].process_command_line == "/bin/bash"


def test_windows_parser():
    raw_windows_json = """
    [
      {
        "EventID": 4625,
        "TimeCreated": "2026-11-01T08:01:05Z",
        "TargetUserName": "svc_deploy",
        "IpAddress": "198.51.100.44",
        "ComputerName": "DC-01"
      },
      {
        "EventID": 4624,
        "TimeCreated": "2026-11-01T08:05:40Z",
        "TargetUserName": "svc_deploy",
        "IpAddress": "198.51.100.44",
        "ComputerName": "DC-01"
      }
    ]
    """
    parser = WindowsEventParser()
    assert parser.can_parse(raw_windows_json) is True

    events = parser.parse(raw_windows_json)
    assert len(events) == 2
    assert events[0].action == EventAction.LOGON_FAILURE
    assert events[1].action == EventAction.LOGON_SUCCESS


def test_zeek_parser():
    raw_zeek = """
    {"ts": "2026-11-01T08:12:05Z", "id.orig_h": "192.168.1.105", "id.orig_p": 49152, "id.resp_h": "203.0.113.88", "id.resp_p": 443, "orig_bytes": 65011712, "resp_bytes": 14200, "proto": "tcp"}
    """
    parser = ZeekConnParser()
    assert parser.can_parse(raw_zeek) is True

    events = parser.parse(raw_zeek)
    assert len(events) == 1
    assert events[0].category == EventCategory.NETWORK_CONNECTION
    assert events[0].source_ip == "192.168.1.105"
    assert events[0].destination_ip == "203.0.113.88"
    assert events[0].bytes_sent == 65011712


def test_log_ingestion_pipeline_auto_detection():
    pipeline = LogIngestionPipeline()
    json_path = SAMPLE_DIR / "enterprise_combined_logs.json"
    with open(json_path, "r", encoding="utf-8") as f:
        content = f.read()

    events, detected_format = pipeline.ingest(content, filename="logs.json")
    assert len(events) == 15
    assert detected_format in ("generic_json", "windows_event_log")
    # Verify sorted chronologically
    for i in range(len(events) - 1):
        assert events[i].timestamp <= events[i+1].timestamp
