# recon_wp/core/finding.py
"""Finding dataclass - the core atom for all results."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


@dataclass
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
    timestamp: datetime = field(default_factory=datetime.utcnow)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary for reports."""
        return {
            "module": self.module,
            "step": self.step,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp.isoformat(),
            "raw": self.raw,
        }

    def to_sarif(self) -> dict[str, Any]:
        """Serialize finding to SARIF result object."""
        sarif_severity = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }.get(self.severity, "none")

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
                "recommendation": self.recommendation,
                "raw": self.raw,
            },
        }
