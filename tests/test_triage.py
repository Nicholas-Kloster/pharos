import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))

from state import TargetSpec, RunSession, PhaseResult

def _mock_session(ip="1.2.3.4", platform="litellm"):
    t = TargetSpec(ip=ip, platform=platform, cvss=9.8, corpus_hit=True)
    s = RunSession(session_id="test", target=t, run_dir=Path("/tmp/pharos-test"))
    Path("/tmp/pharos-test").mkdir(parents=True, exist_ok=True)
    return s

def test_triage_gates_honeypot():
    from phases.triage import run_triage
    with patch("phases.triage.run_tool") as mock_run:
        mock_run.return_value = MagicMock(
            ok=True,
            json_data={"classification": {"all_hits": ["honeypot_signal"], "ethics_flags": []}}
        )
        result = run_triage(_mock_session())
    assert result.status == "gated"
    assert "honeypot" in result.skip_reason.lower()

def test_triage_gates_hipaa():
    from phases.triage import run_triage
    with patch("phases.triage.run_tool") as mock_run:
        mock_run.return_value = MagicMock(
            ok=True,
            json_data={"classification": {
                "all_hits": ["clinical_hipaa"],
                "ethics_flags": ["HIPAA-adjacent network — no active probing"]}}
        )
        result = run_triage(_mock_session())
    assert result.status == "gated"

def test_triage_passes_commercial():
    from phases.triage import run_triage
    with patch("phases.triage.run_tool") as mock_run:
        mock_run.return_value = MagicMock(
            ok=True,
            json_data={"classification": {
                "all_hits": ["commercial_staging"],
                "ethics_flags": []}}
        )
        result = run_triage(_mock_session())
    assert result.status == "ok"
    assert result.data["category"] == "commercial_staging"

def test_triage_degrades_gracefully_on_tool_failure():
    from phases.triage import run_triage
    with patch("phases.triage.run_tool") as mock_run:
        mock_run.return_value = MagicMock(ok=False, json_data=None,
                                           stderr="binary not found")
        result = run_triage(_mock_session())
    assert result.status == "ok"
    assert result.data.get("no_profile") is True
