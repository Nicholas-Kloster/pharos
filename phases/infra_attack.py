import json, time
from pathlib import Path
from state import RunSession, PhaseResult
from tool_runner import run_tool, find_tool


def run_infra_attack(session: RunSession) -> PhaseResult:
    """
    Phase 4: VisorRAG autonomous recon chain.
    LLM drives aimap + visorgraph + menlohunt + nuclei in gVisor sandbox.
    Parses JSONL event stream to extract confirmed findings.
    """
    t0 = time.time()
    run_dir = session.run_dir
    ip = session.target.ip

    if not find_tool("visor"):
        return PhaseResult(phase="infra_attack", status="skipped",
                           skip_reason="visor binary not found",
                           duration_ms=0)

    stream_out = run_dir / "visorrag-stream.jsonl"
    result = run_tool(
        "visor",
        ["--target", ip, "--max-steps", "6", "--ephemeral"],
        timeout=600
    )

    stream_out.write_text(result.stdout)

    # Parse JSONL event stream
    findings = []
    step_count = 0
    final_summary = ""

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            etype = event.get("type", "")
            if etype == "observe":
                step_count += 1
                tool_used = event.get("tool", "")
                obs = event.get("result", "")[:300]
                if obs and tool_used:
                    findings.append({
                        "step":        event.get("step", step_count),
                        "tool":        tool_used,
                        "observation": obs,
                        "status":      event.get("status", "ok"),
                    })
            elif etype == "final":
                final_summary = event.get("message", "")[:500]
        except Exception:
            continue

    duration_ms = int((time.time() - t0) * 1000)
    return PhaseResult(
        phase="infra_attack",
        status="ok" if result.ok else "error",
        data={
            "step_count":     step_count,
            "findings_count": len(findings),
            "findings":       findings[:10],
            "final_summary":  final_summary,
            "visorrag_ok":    result.ok,
        },
        duration_ms=duration_ms,
        artifacts=[str(stream_out)]
    )
