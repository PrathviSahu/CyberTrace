"""
CyberTrace Log Ingestion Pipeline.
Orchestrates format auto-detection, schema normalization, sorting, and deduplication.
"""

from typing import List, Tuple
from app.parsers.base import BaseLogParser
from app.parsers.csv_parser import GenericCsvParser
from app.parsers.json_parser import GenericJsonParser
from app.parsers.linux_parser import LinuxAuthParser
from app.parsers.network_parser import ZeekConnParser
from app.parsers.windows_parser import WindowsEventParser
from app.schemas.ces import CommonEvent


class LogIngestionPipeline:
    def __init__(self):
        # Order of precedence: specialized parsers first, generic fallbacks last
        self.parsers: List[BaseLogParser] = [
            WindowsEventParser(),
            LinuxAuthParser(),
            ZeekConnParser(),
            GenericJsonParser(),
            GenericCsvParser(),
        ]

    def ingest(self, raw_content: str, filename: str = "") -> Tuple[List[CommonEvent], str]:
        """
        Ingest and normalize raw log text.
        Returns: (normalized_events_list, detected_format_name)
        """
        stripped = raw_content.strip()
        if not stripped:
            return [], "empty"

        sample = "\n".join(stripped.splitlines()[:20])

        # Match parser by filename hint or heuristic inspection
        chosen_parser: BaseLogParser = self.parsers[-1]  # default fallback
        
        # Check by content heuristics
        for parser in self.parsers:
            if parser.can_parse(sample):
                chosen_parser = parser
                break

        # If extension provides explicit hint
        fn_lower = filename.lower()
        if fn_lower.endswith(".csv"):
            chosen_parser = GenericCsvParser()
        elif fn_lower.endswith(".json") or fn_lower.endswith(".jsonl"):
            chosen_parser = GenericJsonParser()

        # Parse events
        events = chosen_parser.parse(stripped)

        # Sort chronologically by timestamp
        events.sort(key=lambda x: x.timestamp)

        return events, chosen_parser.format_name
