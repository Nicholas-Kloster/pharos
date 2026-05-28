import csv, json, time
from pathlib import Path
from state import RunSession, PhaseResult
from tool_runner import run_tool, run_tool_to_file, find_tool

_WEB_PORTS = {80, 443, 3000, 4000, 5000, 7860, 8000, 8080, 8443, 8888}
_LLM_SERVICES = {
    "ollama", "litellm", "vllm", "langflow", "flowise", "dify",
    "open_webui", "openwebui", "n8n", "llm", "llama", "tgi",
    "openai", "anthropic", "inference"
}


def run_stack_map(session: RunSession) -> PhaseResult:
    t0 = time.time()
    ip = session.target.ip
    run_dir = session.run_dir

    aimap_out = run_dir / "aimap.json"
    aimap_result = run_tool_to_file(
        "aimap",
        ["-target", ip, "-threads", "10", "-timeout", "8s"],
        out_path=aimap_out,
        timeout=120
    )

    services = []
    auth_status = {}
    versions = {}
    web_ports_found = []
    llm_confirmed = False

    if aimap_result.json_data:
        report = aimap_result.json_data
        for svc in report.get("services", []):
            name = (svc.get("service") or svc.get("name") or "").lower()
            port = svc.get("port", 0)
            services.append({"service": name, "port": port,
                              "severity": svc.get("severity", "")})
            if svc.get("auth") is not None:
                auth_status[name] = svc["auth"]
            if port in _WEB_PORTS:
                web_ports_found.append(port)
            for keyword in _LLM_SERVICES:
                if keyword in name:
                    llm_confirmed = True
        for enum in report.get("enum_results", []):
            svc_name = (enum.get("service") or "").lower()
            v = enum.get("version") or ""
            if v:
                versions[svc_name] = v

    # js-extractor on first web port found
    secrets = []
    js_out = run_dir / "js-findings.csv"
    if web_ports_found:
        port = web_ports_found[0]
        scheme = "https" if port in (443, 8443) else "http"
        host_file = run_dir / "web-targets.txt"
        host_file.write_text(f"{scheme}://{ip}:{port}\n")
        run_tool(
            "js-extractor",
            ["extract", str(host_file), "--findings", str(js_out),
             "--workers", "5", "--timeout", "10"],
            timeout=60
        )
        if js_out.exists():
            try:
                with open(js_out) as f:
                    for row in csv.DictReader(f):
                        secrets.append({
                            "rule":    row.get("rule", ""),
                            "match":   row.get("match", "")[:80],
                            "snippet": row.get("snippet", "")[:100],
                        })
            except Exception:
                pass

    duration_ms = int((time.time() - t0) * 1000)
    artifacts = [str(aimap_out)] if aimap_out.exists() else []
    if js_out.exists():
        artifacts.append(str(js_out))

    return PhaseResult(
        phase="stack_map", status="ok",
        data={
            "services":      services,
            "auth_status":   auth_status,
            "versions":      versions,
            "web_ports":     web_ports_found,
            "llm_confirmed": llm_confirmed,
            "secrets_found": len(secrets),
            "secrets":       secrets[:10],
            "aimap_ok":      aimap_result.ok,
        },
        duration_ms=duration_ms,
        artifacts=artifacts
    )
