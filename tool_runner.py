"""
Subprocess wrapper for all NuClide tools.
Finds binaries in PATH / ~/go/bin / ~/Tools/<name>/<name>,
runs them with timeout, captures JSON or text output.
"""
import json, shutil, subprocess, time
from pathlib import Path
from typing import Optional

TOOL_PATHS = {
    "aimap":         ["aimap", "~/go/bin/aimap", "~/ai-recon/aimap/aimap"],
    "aimap-profile": ["~/ai-recon/aimap-profile/aimap_profile.py"],
    "visorlog":      ["visorlog", "~/go/bin/visorlog", "~/visorlog/visorlog"],
    "visorscuba":    ["visorscuba", "~/go/bin/visorscuba", "~/visorscuba/visorscuba"],
    "visor":         ["visor", "~/go/bin/visor", "~/visor-rag/visor"],
    "visoragent":    ["~/Tools/VisorAgent/visoragent"],
    "visorcorpus":   ["visorcorpus", "~/go/bin/visorcorpus", "~/Tools/VisorCorpus/visorcorpus"],
    "bare":          ["bare", "~/.local/bin/bare"],
    "js-extractor":  ["~/js-extractor/js-extractor.py"],
    "winnow":        ["~/winnow/winnow.py"],
    "cortex":        ["~/Tools/cortex-framework/analyzer.py"],
}


def find_tool(name: str) -> Optional[str]:
    """Find a NuClide tool binary. Returns path string or None."""
    candidates = TOOL_PATHS.get(name, [name])
    for c in candidates:
        expanded = str(Path(c).expanduser())
        if Path(expanded).exists():
            return expanded
        found = shutil.which(c)
        if found:
            return found
    return None


class ToolResult:
    def __init__(self, tool: str, ok: bool, stdout: str, stderr: str,
                 returncode: int, duration_ms: int, json_data=None):
        self.tool = tool
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.duration_ms = duration_ms
        self.json_data = json_data


def run_tool(name: str, args: list, timeout: int = 120,
             env: Optional[dict] = None) -> ToolResult:
    """Run a NuClide tool, return ToolResult with parsed JSON if available."""
    binary = find_tool(name)
    if not binary:
        return ToolResult(name, False, "", f"binary not found: {name}",
                          -1, 0, None)

    cmd = [binary] + args
    if binary.endswith(".py"):
        cmd = ["python3"] + cmd

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout,
            env=env,
        )
        duration_ms = int((time.time() - t0) * 1000)
        stdout = result.stdout.strip()

        # Try to parse JSON — first as full output, then last JSONL line
        json_data = None
        try:
            json_data = json.loads(stdout)
        except Exception:
            for line in reversed(stdout.splitlines()):
                line = line.strip()
                if line.startswith("{") or line.startswith("["):
                    try:
                        json_data = json.loads(line)
                        break
                    except Exception:
                        pass

        return ToolResult(
            tool=name,
            ok=(result.returncode == 0),
            stdout=stdout,
            stderr=result.stderr.strip(),
            returncode=result.returncode,
            duration_ms=duration_ms,
            json_data=json_data,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(name, False, "", f"timeout after {timeout}s",
                          -1, timeout * 1000, None)
    except Exception as e:
        return ToolResult(name, False, "", str(e), -1, 0, None)


def run_tool_to_file(name: str, args: list, out_path: Path,
                     timeout: int = 120) -> ToolResult:
    """Run tool with -o <out_path> appended, then read JSON from file."""
    full_args = args + ["-o", str(out_path)]
    result = run_tool(name, full_args, timeout=timeout)
    if out_path.exists():
        try:
            result.json_data = json.loads(out_path.read_text())
            result.ok = True
        except Exception:
            pass
    return result
