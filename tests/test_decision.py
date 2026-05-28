import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from state import TargetSpec, RunSession, PhaseResult


def _session(breach=True, corpus=True, hit_rate=0.4, cvss=9.8, drift=0.35,
             platform="litellm"):
    t = TargetSpec(ip="1.1.1.1", platform=platform, cvss=cvss,
                   corpus_hit=True, cve_id="CVE-2026-42208", authorized=True)
    s = RunSession(session_id="t", target=t, run_dir=Path("/tmp/pharos-dec-test"))
    Path("/tmp/pharos-dec-test").mkdir(parents=True, exist_ok=True)
    s.phases = [
        PhaseResult("triage",         "ok", data={"category": "commercial_staging"}),
        PhaseResult("stack_map",      "ok", data={
            "llm_confirmed": True, "secrets_found": 1, "services": []}),
        PhaseResult("exploit_surface","ok", data={
            "corpus_confirmed": corpus,
            "compliance_score": 2,
            "bare_modules": [{"module": "exploit_multi_http_x", "score": 0.72}],
            "attack_chain": "LITELLM_CVE_CONFIRMED → LLM_INJECT",
        }),
        PhaseResult("infra_attack",   "ok", data={
            "step_count": 5, "findings_count": 3,
            "final_summary": "Found 3 services"}),
        PhaseResult("ai_attack",      "ok", data={
            "breach_confirmed": breach, "hit_rate": hit_rate,
            "drift_score": drift, "evidence": ["HIT V1", "MISS V2"]}),
        PhaseResult("evidence",       "ok", data={
            "case_study_path": "/tmp/pharos-dec-test/case-study.md",
            "critical_findings": 2}),
    ]
    return s


def test_score_high_on_breach_plus_cve():
    from phases.decision import _score_session
    s = _session(breach=True, corpus=True, cvss=9.8)
    score = _score_session(s)
    assert score >= 0.75


def test_score_medium_on_corpus_no_breach():
    from phases.decision import _score_session
    s = _session(breach=False, hit_rate=0.05, drift=0.05, cvss=9.8)
    score = _score_session(s)
    assert 0.50 <= score < 0.80


def test_priority_p1_on_high_score():
    from phases.decision import _priority_level
    assert _priority_level(0.80) == "P1"
    assert _priority_level(0.75) == "P1"


def test_priority_p2_on_medium_score():
    from phases.decision import _priority_level
    assert _priority_level(0.60) == "P2"
    assert _priority_level(0.55) == "P2"


def test_disclosure_immediate_on_breach():
    from phases.decision import _disclosure_urgency
    assert _disclosure_urgency(0.5, breach_confirmed=True, corpus_confirmed=False) == "immediate"


def test_disclosure_7day_on_corpus_p2():
    from phases.decision import _disclosure_urgency
    assert _disclosure_urgency(0.6, breach_confirmed=False, corpus_confirmed=True) == "7-day"


def test_next_actions_not_empty():
    from phases.decision import run_decision
    s = _session()
    run_decision(s)
    assert s.decision is not None
    assert len(s.decision.next_actions) >= 2


def test_blast_radius_litellm():
    from phases.decision import _blast_radius
    est = _blast_radius("litellm", "CVE-2026-42208")
    assert est > 5000


def test_decision_sets_session_decision():
    from phases.decision import run_decision
    s = _session()
    result = run_decision(s)
    assert result.status == "ok"
    assert s.decision is not None
    assert s.decision.priority_level in ("P1", "P2", "P3", "P4")
    assert s.decision.total_score > 0
