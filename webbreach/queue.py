"""AI-guided scan queue — heuristic-based ordering of engines × targets."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from webbreach.findings import Finding, ScanResult, Severity


SEVERITY_SCORE = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass
class QueueItem:
    engine: str
    target: str
    score: float = 0.0
    priority: int = 0
    result: ScanResult | None = None


class ScanQueue:
    """Heuristic planner that orders engines × targets by likelihood of findings.

    Deterministic — no randomness, no network calls during planning.
    """

    # Engine priority weights (higher = scan earlier)
    ENGINE_WEIGHTS = {
        "sqli": 10,
        "xss": 9,
        "ssti": 8,
        "xxe": 7,
        "cmd": 7,
        "nosql": 7,
        "ssrf": 6,
        "traversal": 6,
        "smuggling": 5,
        "csrf": 5,
        "redirect": 4,
        "header_injection": 3,
        "cookie": 3,
        "fuzzer": 2,
    }

    # Parameter type bonuses
    PARAM_BONUS = {
        "id": 2, "name": 2, "q": 1, "file": 3, "host": 3,
        "url": 2, "next": 1, "val": 1, "msg": 1, "query": 3,
    }

    def __init__(self, engines: list[str], target_url: str, prior_hits: dict | None = None):
        self.target_url = target_url
        self.prior_hits = prior_hits or {}
        self._items: list[QueueItem] = []
        self._build_queue(engines)

    def _build_queue(self, engines: list[str]):
        for engine in engines:
            weight = self.ENGINE_WEIGHTS.get(engine, 1)
            prior = self.prior_hits.get(engine, 0)
            score = weight + prior * 3
            self._items.append(QueueItem(engine=engine, target=self.target_url, score=score))

        # Sort by score descending
        self._items.sort(key=lambda x: x.score, reverse=True)
        for i, item in enumerate(self._items):
            item.priority = i + 1

    @property
    def items(self) -> list[QueueItem]:
        return list(self._items)

    def record_result(self, engine: str, result: ScanResult):
        """Update scores based on scan results."""
        for item in self._items:
            if item.engine == engine:
                item.result = result
                # Boost subsequent items if findings were found
                if result.findings:
                    for other in self._items:
                        if other.priority > item.priority:
                            other.score += len(result.findings)
                    # Re-sort
                    self._items.sort(key=lambda x: x.score, reverse=True)
                    for i, it in enumerate(self._items):
                        it.priority = i + 1
                break

    def run_all(self, runner_fn) -> list[ScanResult]:
        """Execute all engines in priority order via runner_fn(engine) -> ScanResult."""
        results = []
        for item in self._items:
            result = runner_fn(item.engine)
            item.result = result
            self.record_result(item.engine, result)
            results.append(result)
        return results

    def summary(self) -> str:
        lines = ["Scan Queue (AI-prioritized):"]
        lines.append(f"  Target: {self.target_url}")
        lines.append(f"  Engines: {len(self._items)}")
        lines.append("")
        for item in self._items:
            status = "pending"
            if item.result:
                hits = len(item.result.findings) if item.result else 0
                status = f"{hits} findings"
            lines.append(f"  #{item.priority} {item.engine:20s} score={item.score:.1f}  {status}")
        return "\n".join(lines)
