"""
Base parser interface for CyberTrace log ingestion.
"""

from abc import ABC, abstractmethod
from typing import List
from app.schemas.ces import CommonEvent


class BaseLogParser(ABC):
    """Abstract Base Class for all format-specific log parsers."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the format handled by this parser."""
        pass

    @abstractmethod
    def can_parse(self, sample_text: str) -> bool:
        """Heuristic check to determine if this parser can handle the provided log content."""
        pass

    @abstractmethod
    def parse(self, text_content: str) -> List[CommonEvent]:
        """Parse raw content into normalized CommonEvent instances."""
        pass
