from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

RUNS_DIR = Path.home() / "pharos" / "runs"

@dataclass
class TargetSpec:
    ip: str
    platform: str = "unknown"
    version: Optional[str] = None
    cvss: float = 0.0
    corpus_hit: bool = False
    cve_id: Optional[str] = None
    authorized: bool = False

@dataclass
class PhaseResult:
    phase: str
    status: str = "ok"      # ok | skipped | error | gated
    skip_reason: str = ""
    data: dict = field(default_factory=dict)
    duration_ms: int = 0
    artifacts: list = field(default_factory=list)

@dataclass
class DecisionOutput:
    priority_level: str = "P4"
    total_score: float = 0.0
    attack_chain_summary: str = ""
    next_actions: list = field(default_factory=list)
    disclosure_urgency: str = "monitor"
    breach_confirmed: bool = False
    drift_score: float = 0.0
    blast_radius_estimate: int = 0
    case_study_path: str = ""

@dataclass
class RunSession:
    session_id: str
    target: TargetSpec
    run_dir: Path
    phases: list = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    decision: Optional[DecisionOutput] = None

    @classmethod
    def create(cls, target: TargetSpec) -> "RunSession":
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        sid = f"{ts}-{target.ip.replace('.', '-')}"
        run_dir = RUNS_DIR / sid
        run_dir.mkdir(parents=True, exist_ok=True)
        return cls(session_id=sid, target=target, run_dir=run_dir)

    def save(self):
        d = asdict(self)
        d["run_dir"] = str(self.run_dir)
        (self.run_dir / "session.json").write_text(json.dumps(d, indent=2))

    def add_phase(self, result: PhaseResult):
        self.phases.append(result)
        self.save()
