import time
from state import RunSession, PhaseResult
from tool_runner import run_tool

_GATE_FLAGS = [
    "hipaa", "clinical", "medical", "hospital", "patient",
    "military", "classified", "itar",
]
_GATE_CATEGORIES = ["honeypot_signal", "clinical_hipaa"]


def run_triage(session: RunSession) -> PhaseResult:
    t0 = time.time()
    ip = session.target.ip

    result = run_tool("aimap-profile", ["--target", ip, "--mode", "fast",
                                         "--format", "json"], timeout=60)
    duration_ms = int((time.time() - t0) * 1000)

    if not result.ok or not result.json_data:
        return PhaseResult(
            phase="triage", status="ok",
            data={"no_profile": True, "stderr": result.stderr[:200]},
            duration_ms=duration_ms
        )

    classification = result.json_data.get("classification", {})
    hits = classification.get("all_hits", [])
    ethics_flags = classification.get("ethics_flags", [])
    category = hits[0] if hits else "unknown"

    for blocked in _GATE_CATEGORIES:
        if blocked in hits:
            return PhaseResult(
                phase="triage", status="gated",
                skip_reason=f"category={blocked} — no active probing authorized",
                data={"category": blocked, "hits": hits},
                duration_ms=duration_ms
            )

    for flag in ethics_flags:
        for keyword in _GATE_FLAGS:
            if keyword in flag.lower():
                return PhaseResult(
                    phase="triage", status="gated",
                    skip_reason=f"ethics flag: {flag[:80]}",
                    data={"category": category, "ethics_flags": ethics_flags},
                    duration_ms=duration_ms
                )

    return PhaseResult(
        phase="triage", status="ok",
        data={
            "category":     category,
            "hits":         hits,
            "ethics_flags": ethics_flags,
            "disclosure":   result.json_data.get("disclosure", {}),
            "identity":     result.json_data.get("identity", {}),
        },
        duration_ms=duration_ms,
        artifacts=[]
    )
