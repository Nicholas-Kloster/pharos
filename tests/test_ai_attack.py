import math, sys
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))
from state import TargetSpec, RunSession, PhaseResult


def _session(platform="litellm", skip_ai=False):
    t = TargetSpec(ip="1.1.1.1", platform=platform, cvss=9.8,
                   corpus_hit=True, authorized=True)
    s = RunSession(session_id="test", target=t, run_dir=Path("/tmp/pharos-ai-test"))
    Path("/tmp/pharos-ai-test").mkdir(parents=True, exist_ok=True)
    skip = ["ai_attack"] if skip_ai else []
    s.phases = [
        PhaseResult(phase="stack_map", status="ok",
                    data={"llm_confirmed": True, "web_ports": [4000], "services": []}),
        PhaseResult(phase="exploit_surface", status="ok",
                    data={"skip_phases": skip, "llm_confirmed": not skip_ai}),
    ]
    return s


def test_ai_attack_skipped_when_flagged():
    from phases.ai_attack import run_ai_attack
    result = run_ai_attack(_session(skip_ai=True))
    assert result.status == "skipped"
    assert "no LLM" in result.skip_reason


def test_pcse_drift_identical():
    from phases.ai_attack import _pcse_drift
    v = [0.25, 1.0, 0.1, 0.15, 0.6, 0.4, 0.5, 5.0]
    assert _pcse_drift(v, v) < 0.01


def test_pcse_drift_orthogonal():
    from phases.ai_attack import _pcse_drift
    pre  = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    post = [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    assert _pcse_drift(pre, post) > 0.9


def test_breach_confirmed_high_hit_rate():
    from phases.ai_attack import _breach_confirmed
    assert _breach_confirmed(hit_rate=0.4, drift_score=0.1) is True


def test_breach_confirmed_combined_signals():
    from phases.ai_attack import _breach_confirmed
    assert _breach_confirmed(hit_rate=0.15, drift_score=0.30) is True


def test_breach_not_confirmed_low_signals():
    from phases.ai_attack import _breach_confirmed
    assert _breach_confirmed(hit_rate=0.05, drift_score=0.05) is False


def test_ai_attack_runs_with_no_tools():
    """Phase completes ok even when no NuClide tools are installed."""
    from phases.ai_attack import run_ai_attack
    with patch("phases.ai_attack.find_tool", return_value=None), \
         patch("phases.ai_attack._get_baseline_exchanges", return_value=[]):
        result = run_ai_attack(_session(skip_ai=False))
    assert result.status == "ok"
    assert "breach_confirmed" in result.data
    assert "drift_score" in result.data
