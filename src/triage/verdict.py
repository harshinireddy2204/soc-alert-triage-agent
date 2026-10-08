"""The outcome of triaging one case."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Verdict:
    """What a triage policy decided.

    ``verdict`` is always the policy's best guess, even when it escalates, so that
    the evaluation can ask what would have happened had it been forced to decide.
    """

    verdict: str  # "malicious" or "benign"
    confidence: float  # 0.5 = coin flip, 1.0 = certain
    escalate: bool
    summary: str
    evidence: list[int] = field(default_factory=list)
    technique: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in ("malicious", "benign"):
            raise ValueError(f"verdict must be 'malicious' or 'benign', got {self.verdict!r}")
        self.confidence = float(min(1.0, max(0.0, self.confidence)))

    def to_dict(self) -> dict:
        return asdict(self)
