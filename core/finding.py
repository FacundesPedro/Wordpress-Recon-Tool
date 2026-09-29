# recon_wp/core/finding.py
"""Finding dataclass - the core atom for all results."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

SARIF_LEVEL_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

# Confidence expresses certainty of the detection, not impact. A confirmed
# exploitation should be `high`; a syntactic/heuristic match should be `low`.
Confidence = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class Finding:
    """
    Immutable record of a discovered issue or information.
    """

    module: str
    step: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    evidence: str
    recommendation: str
    confidence: Confidence = "high"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw: dict[str, Any] = field(default_factory=dict)

    # `confidence` is intentionally excluded: two otherwise-identical findings
    # should dedupe regardless of how certain each detection was.
    _DEDUP_FIELDS = (
        "module", "step", "severity", "title", "description", "evidence", "recommendation",
    )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return tuple(getattr(self, f) for f in self._DEDUP_FIELDS) == tuple(
            getattr(other, f) for f in self._DEDUP_FIELDS
        )

    def __hash__(self) -> int:
        return hash(tuple(getattr(self, f) for f in self._DEDUP_FIELDS))

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary for reports."""
        return {
            "module": self.module,
            "step": self.step,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp.isoformat(),
            "raw": self.raw,
        }

    def to_sarif(self) -> dict[str, Any]:
        """Serialize finding to SARIF result object."""
        sarif_severity = SARIF_LEVEL_MAP.get(self.severity, "none")

        return {
            "ruleId": f"{self.module}/{self.step}",
            "level": sarif_severity,
            "message": {"text": f"{self.title}: {self.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.evidence or ""},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "module": self.module,
                "step": self.step,
                "severity": self.severity,
                "confidence": self.confidence,
                "recommendation": self.recommendation,
                "raw": self.raw,
            },
        }
