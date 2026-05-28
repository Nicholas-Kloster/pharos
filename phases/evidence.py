import json, time
from pathlib import Path
from state import RunSession, PhaseResult
from tool_runner import run_tool, find_tool
from case_study import generate as generate_case_study


def _collect_critical_findings(session: RunSession) -> list:
    findings = []
    for phase in session.phases:
        if phase.phase == "stack_map":
            for svc in phase.data.get("services", []):
                if svc.get("severity") in ("critical", "high"):
                    findings.append({
                        "phase":    "stack_map",
                        "service":  svc.get("service"),
                        "severity": svc.get("severity"),
                        "org":      "",
                    })
            for s in phase.data.get("secrets", []):
                findings.append({
                    "phase":    "stack_map",
                    "service":  f"secret:{s.get('rule', '')}",
                    "severity": "high",
                    "org":      "",
                })
        elif phase.phase == "ai_attack":
            if phase.data.get("breach_confirmed"):
                findings.append({
                    "phase":    "ai_attack",
                    "service":  "llm-injection-breach",
                    "severity": "critical",
                    "org":      "",
                })
        elif phase.phase == "exploit_surface":
            if phase.data.get("corpus_confirmed"):
                cve = session.target.cve_id or "cve"
                findings.append({
                    "phase":    "exploit_surface",
                    "service":  f"{cve}-confirmed",
                    "severity": "critical",
                    "org":      "",
                })
    return findings


def _build_cortex_input(finding: dict, target) -> str:
    return f"""# {target.ip} — Authorization Context Analysis

## SKELETON
- Service {finding.get('service', '')} exposed on {target.ip}
- Platform: {target.platform} version {target.version or 'unknown'}
- Responds to unauthenticated HTTP requests

## VIOLATIONS
- Assumes right to serve model inference to any unauthenticated requester
- No authorization check before executing LLM workloads
- No rate limiting on inference requests
- Exposes internal model identifiers and configuration without consent

## CONTEXT
- {target.cve_id or 'No CVE'}: {finding.get('service', '')} at severity {finding.get('severity', '')}
- Part of global population of {target.platform} deployments confirmed vulnerable
- Operator appears unaware of exposure (no auth configured, default deployment)
"""


def run_evidence(session: RunSession) -> PhaseResult:
    t0 = time.time()
    run_dir = session.run_dir
    target = session.target

    critical_findings = _collect_critical_findings(session)

    # VisorLog ingest
    visorlog_ingested = 0
    if find_tool("visorlog"):
        for finding in critical_findings:
            r = run_tool("visorlog", [
                "add",
                "--ip",      target.ip,
                "--org",     finding.get("org", "unknown"),
                "--severity", finding.get("severity", "high"),
                "--tags",    f"PHAROS,{target.platform.upper()},"
                             f"{target.cve_id or 'NO-CVE'},AI-ATTACK",
                "--source",  "pharos",
                "--sector",  "commercial",
                "--country", "?",
            ], timeout=15)
            if r.ok:
                visorlog_ingested += 1

    # Cortex analysis on top finding
    cortex_severity = None
    if critical_findings and find_tool("cortex"):
        analysis_md = _build_cortex_input(critical_findings[0], target)
        cortex_in = run_dir / "cortex-input.md"
        cortex_in.write_text(analysis_md)
        cortex_r = run_tool("cortex", [
            "analyze", str(cortex_in),
            "--json", str(run_dir / "cortex-output.json"),
            "--output-dir", str(run_dir),
        ], timeout=30)
        if cortex_r.ok and (run_dir / "cortex-output.json").exists():
            try:
                cx = json.loads((run_dir / "cortex-output.json").read_text())
                cortex_severity = cx.get("analysis_summary", {}).get("severity")
            except Exception:
                pass

    # Generate case study
    case_study_md = generate_case_study(session)
    case_study_path = run_dir / "case-study.md"
    case_study_path.write_text(case_study_md)

    duration_ms = int((time.time() - t0) * 1000)
    return PhaseResult(
        phase="evidence", status="ok",
        data={
            "critical_findings":  len(critical_findings),
            "visorlog_ingested":  visorlog_ingested,
            "cortex_severity":    cortex_severity,
            "case_study_path":    str(case_study_path),
        },
        duration_ms=duration_ms,
        artifacts=[str(case_study_path)]
    )
