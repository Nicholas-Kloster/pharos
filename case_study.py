"""Generates a Markdown case study from a completed RunSession."""
from datetime import datetime, timezone
from state import RunSession


def generate(session: RunSession) -> str:
    t = session.target
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    phases_data = {p.phase: p.data for p in session.phases}

    stack  = phases_data.get("stack_map", {})
    exploit = phases_data.get("exploit_surface", {})
    ai     = phases_data.get("ai_attack", {})
    infra  = phases_data.get("infra_attack", {})
    triage = phases_data.get("triage", {})

    breach           = ai.get("breach_confirmed", False)
    corpus_confirmed = exploit.get("corpus_confirmed", False)
    bare_top         = (exploit.get("bare_modules") or [{}])[0].get("module", "n/a")

    svc_list = "\n".join(
        f"  - {s['service']} port={s['port']} severity={s.get('severity','?')}"
        for s in stack.get("services", [])[:8]
    ) or "  - (no services detected)"

    secret_list = "\n".join(
        f"  - [{s['rule']}] `{s['match']}`"
        for s in stack.get("secrets", [])[:5]
    ) or "  - none"

    bare_list = "\n".join(
        f"  - {m['module']} (score={m['score']:.3f})"
        for m in exploit.get("bare_modules", [])[:5]
    ) or "  - none"

    evidence_lines = "\n".join(
        f"  {e}" for e in ai.get("evidence", [])[:5]
    )

    return f"""# PHAROS Case Study — {t.ip}

**Date:** {now}
**Platform:** {t.platform}
**Version:** {t.version or 'unknown'}
**CVE:** {t.cve_id or 'n/a'}
**CVSS:** {t.cvss}
**Session:** {session.session_id}

---

## Target Profile

- **Category:** {triage.get('category', 'unknown')}
- **Corpus Hit:** {'yes — version confirmed vulnerable' if corpus_confirmed else 'no'}
- **LLM Endpoint Confirmed:** {'yes' if stack.get('llm_confirmed') else 'no'}

## Service Stack

{svc_list}

## Baked Secrets

{secret_list}

## Exploit Ranking (BARE)

Top Metasploit modules by semantic similarity:
{bare_list}

## Attack Chain

`{exploit.get('attack_chain', 'RECON_ONLY')}`

## AI System Attack Results

- **Injection Hit Rate:** {ai.get('hit_rate', 'n/a')}
- **pcse Drift Score:** {ai.get('drift_score', 'n/a')}
- **Breach Confirmed:** {'**YES**' if breach else 'no'}

{('### Injection Evidence' + chr(10) + evidence_lines) if ai.get('evidence') else ''}

## Infrastructure Recon (VisorRAG)

- **Steps completed:** {infra.get('step_count', 0)}
- **Findings:** {infra.get('findings_count', 0)}
- **Summary:** {infra.get('final_summary', 'n/a')[:300]}

## Impact Assessment

{"**CRITICAL:** LLM injection breach confirmed. AI system can be weaponized against its operator." if breach else ""}
{"**HIGH:** Known-vulnerable version confirmed against CISA KEV CVE." if corpus_confirmed else ""}
{"Stack contains hardcoded API secrets baked into SPA bundles." if stack.get('secrets') else ""}

## Session Artifacts

- `{session.run_dir}/session.json` — full phase data
- `{session.run_dir}/aimap.json` — service fingerprint
- `{session.run_dir}/visorrag-stream.jsonl` — ReAct trace
- `{session.run_dir}/pharos-corpus.json` — adversarial test cases
"""
