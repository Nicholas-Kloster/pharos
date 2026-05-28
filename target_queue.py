import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from state import TargetSpec

SENTINEL_LOG_DIR = Path.home() / ".local" / "share" / "sentinel" / "logs"


def parse_direct_target(ip: str, platform: str = "unknown",
                        version: Optional[str] = None,
                        cvss: float = 0.0) -> TargetSpec:
    """Parse a direct IP target specification."""
    return TargetSpec(ip=ip, platform=platform, version=version, cvss=cvss)


def load_sentinel_targets(log_dir: str = str(SENTINEL_LOG_DIR)) -> list[TargetSpec]:
    """Load all P1/P2 findings from sentinel NDJSON logs. Dedup by IP."""
    targets: dict[str, TargetSpec] = {}
    log_path = Path(log_dir)
    if not log_path.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    for log_file in sorted(log_path.glob("sentinel-*.ndjson"), reverse=True):
        try:
            for line in log_file.read_text().splitlines():
                if not line.strip():
                    continue
                finding = json.loads(line)
                if finding.get("priority_level") not in ("P1", "P2"):
                    continue
                try:
                    ts = datetime.fromisoformat(
                        finding.get("timestamp", "")).replace(tzinfo=timezone.utc)
                    if ts < cutoff:
                        continue
                except Exception:
                    pass
                for hit in finding.get("corpus_hits", []):
                    ip = hit.get("ip", "")
                    if not ip or ip in targets:
                        continue
                    platforms = finding.get("matched_platforms", ["unknown"])
                    targets[ip] = TargetSpec(
                        ip=ip,
                        platform=platforms[0] if platforms else "unknown",
                        version=hit.get("version"),
                        cvss=finding.get("cvss_score", 0.0),
                        corpus_hit=True,
                        cve_id=finding.get("cve_id"),
                    )
        except Exception:
            continue
    return list(targets.values())


def prioritize_targets(targets: list[TargetSpec]) -> list[TargetSpec]:
    """Score and rank: higher CVSS + corpus_hit = higher priority."""
    def score(t: TargetSpec) -> float:
        return (t.cvss / 10.0) * 0.6 + (0.4 if t.corpus_hit else 0.0)
    return sorted(targets, key=score, reverse=True)


def get_sentinel_target() -> Optional[TargetSpec]:
    """Return the single highest-priority unworked target from sentinel logs."""
    targets = prioritize_targets(load_sentinel_targets())
    return targets[0] if targets else None
