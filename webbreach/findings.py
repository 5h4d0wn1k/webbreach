"""Finding data model and severity definitions."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    engine: str
    severity: Severity
    title: str
    url: str = ""
    param: str = ""
    method: str = ""
    evidence: str = ""
    payload: str = ""
    timestamp: float = field(default_factory=time.time)
    false_positive_risk: str = "low"

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def __str__(self):
        return f"[{self.severity.value.upper()}] {self.engine}: {self.title} @ {self.url}"


@dataclass
class ScanResult:
    target: str
    engine: str
    findings: list[Finding] = field(default_factory=list)
    duration: float = 0.0
    error: str = ""

    def to_dict(self):
        return {
            "target": self.target,
            "engine": self.engine,
            "findings": [f.to_dict() for f in self.findings],
            "duration": self.duration,
            "error": self.error,
        }
