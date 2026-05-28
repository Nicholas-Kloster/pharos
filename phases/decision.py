import math, time
from state import RunSession, PhaseResult, DecisionOutput

# Blast radius estimates: Shodan count x vulnerability rate from our triage research
_BLAST_ESTIMATES = {
    "litellm":   int(57454 * 0.226),   # 104/468 triage confirmed
    "ollama":    int(73498 * 0.01),    # mostly patched per sweep
    "n8n":       int(162455 * 0.15),   # estimated
    "langflow":  5,
    "flowise":   int(576 * 0.20),
    "chromadb":  int(1765 * 0.30),
    "qdrant":    int(904 * 0.10),
    "weaviate":  int(1495 * 0.10),
}


def _blast_radius(platform: str, cve_id: str) -> int:
    return _BLAST_ESTIMATES.get(platform, 100)


def _score_session(session: RunSession) -> float:
    """
    5-factor score [0, 1]:
      impact      (0.25) -- CVSS normalized
      exploit     (0.20) -- corpus confirmed + BARE module
      breach      (0.25) -- VisorAgent hit rate + pcse drift
      dwell       (0.15) -- corpus_hit recency signal
      blast       (0.15) -- global exposure estimate
    """
    t = session.target
    phases = {p.phase: p.data for p in session.phases}

    impact = (t.cvss / 10.0) * 0.25

    exploit_data = phases.get("exploit_surface", {})
    corpus_confirmed = exploit_data.get("corpus_confirmed", False)
    has_module = bool(exploit_data.get("bare_modules"))
    exploit = ((0.6 if corpus_confirmed else 0.0) +
               (0.4 if has_module else 0.0)) * 0.20

    ai_data = phases.get("ai_attack", {})
    breach_confirmed = ai_data.get("breach_confirmed", False)
    hit_rate = ai_data.get("hit_rate", 0.0)
    drift = ai_data.get("drift_score", 0.0)
    breach_signal = max(
        1.0 if breach_confirmed else 0.0,
        min(hit_rate * 2.0, 1.0),
        min(drift * 2.0, 1.0),
    )
    breach = breach_signal * 0.25

    dwell = (1.0 if t.corpus_hit else 0.3) * 0.15

    blast_count = _blast_radius(t.platform, t.cve_id or "")
    blast = min(blast_count / 10000.0, 1.0) * 0.15

    return round(impact + exploit + breach + dwell + blast, 4)


def _priority_level(score: float) -> str:
    if score >= 0.75: return "P1"
    if score >= 0.55: return "P2"
    if score >= 0.35: return "P3"
    return "P4"


def _disclosure_urgency(score: float, breach_confirmed: bool,
                        corpus_confirmed: bool) -> str:
    if breach_confirmed or score >= 0.75:
        return "immediate"
    if corpus_confirmed and score >= 0.55:
        return "7-day"
    if score >= 0.35:
        return "30-day"
    return "monitor"


def _build_next_actions(session: RunSession, priority: str,
                        breach: bool, corpus: bool) -> list:
    t = session.target
    phases = {p.phase: p.data for p in session.phases}
    actions = []

    if breach:
        actions.append(
            f"[URGENT] LLM breach confirmed -- document full injection chain "
            f"and escalate to {t.platform} security contact"
        )
    if corpus:
        actions.append(
            f"[HIGH] {t.cve_id} confirmed on {t.ip} v{t.version} -- "
            f"initiate responsible disclosure workflow"
        )

    modules = phases.get("exploit_surface", {}).get("bare_modules", [])
    if modules:
        top = modules[0]["module"]
        actions.append(f"Review BARE-ranked module `{top}` for PoC development")

    secrets = phases.get("stack_map", {}).get("secrets_found", 0)
    if secrets:
        actions.append(
            f"{secrets} baked secret(s) found in SPA bundle -- rotate before disclosure"
        )

    infra_findings = phases.get("infra_attack", {}).get("findings_count", 0)
    if infra_findings:
        actions.append(
            f"VisorRAG found {infra_findings} infra findings -- "
            f"review visorrag-stream.jsonl for pivot candidates"
        )

    actions.append(f"Re-scan {t.ip} in 7 days to detect remediation or reuse")

    if priority in ("P1", "P2"):
        actions.append("Run aimap on adjacent /24 for lateral exposure assessment")

    return actions


def run_decision(session: RunSession) -> PhaseResult:
    t0 = time.time()
    phases = {p.phase: p.data for p in session.phases}

    score    = _score_session(session)
    priority = _priority_level(score)
    ai_data      = phases.get("ai_attack", {})
    exploit_data = phases.get("exploit_surface", {})
    evidence_data = phases.get("evidence", {})

    breach  = ai_data.get("breach_confirmed", False)
    corpus  = exploit_data.get("corpus_confirmed", False)
    drift   = ai_data.get("drift_score", 0.0)
    blast   = _blast_radius(session.target.platform, session.target.cve_id or "")
    urgency = _disclosure_urgency(score, breach, corpus)
    actions = _build_next_actions(session, priority, breach, corpus)
    chain   = exploit_data.get("attack_chain", "RECON_ONLY")

    summary = (
        f"{session.target.platform.upper()} {session.target.version or '?'} on "
        f"{session.target.ip}: {chain}. "
        f"{'LLM breach confirmed. ' if breach else ''}"
        f"{'CVE version confirmed. ' if corpus else ''}"
        f"Blast radius ~{blast:,} globally exposed instances."
    )

    decision = DecisionOutput(
        priority_level=priority,
        total_score=score,
        attack_chain_summary=summary,
        next_actions=actions,
        disclosure_urgency=urgency,
        breach_confirmed=breach,
        drift_score=drift,
        blast_radius_estimate=blast,
        case_study_path=evidence_data.get("case_study_path", ""),
    )
    session.decision = decision
    session.save()

    duration_ms = int((time.time() - t0) * 1000)
    return PhaseResult(
        phase="decision", status="ok",
        data={
            "priority":     priority,
            "score":        score,
            "urgency":      urgency,
            "breach":       breach,
            "blast":        blast,
            "next_actions": actions,
        },
        duration_ms=duration_ms
    )
