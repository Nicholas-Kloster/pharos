import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_parse_direct_target_ip():
    from target_queue import parse_direct_target
    t = parse_direct_target("1.2.3.4")
    assert t.ip == "1.2.3.4"
    assert t.platform == "unknown"
    assert t.authorized is False

def test_parse_direct_target_with_platform():
    from target_queue import parse_direct_target
    t = parse_direct_target("1.2.3.4", platform="litellm", version="1.82.6")
    assert t.platform == "litellm"
    assert t.version == "1.82.6"

def test_load_sentinel_targets_from_log(tmp_path):
    from target_queue import load_sentinel_targets
    log = tmp_path / "sentinel-2026-05-28.ndjson"
    from datetime import datetime, timezone
    log.write_text(json.dumps({
        "cve_id": "CVE-2026-42208",
        "priority_level": "P2",
        "cvss_score": 9.8,
        "matched_platforms": ["litellm"],
        "corpus_hits": [{"ip": "1.15.89.212", "version": "1.82.6", "org": "Hetzner"}],
        "corpus_count": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }) + "\n")
    targets = load_sentinel_targets(str(tmp_path))
    assert len(targets) == 1
    assert targets[0].ip == "1.15.89.212"
    assert targets[0].platform == "litellm"
    assert targets[0].cvss == 9.8
    assert targets[0].corpus_hit is True
    assert targets[0].cve_id == "CVE-2026-42208"

def test_load_sentinel_targets_skips_p3_p4(tmp_path):
    from target_queue import load_sentinel_targets
    from datetime import datetime, timezone
    log = tmp_path / "sentinel-2026-05-28.ndjson"
    log.write_text(json.dumps({
        "priority_level": "P3",
        "cvss_score": 5.0,
        "matched_platforms": ["n8n"],
        "corpus_hits": [{"ip": "9.9.9.9", "version": "1.0.0"}],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }) + "\n")
    targets = load_sentinel_targets(str(tmp_path))
    assert len(targets) == 0

def test_prioritize_targets():
    from target_queue import prioritize_targets
    from state import TargetSpec
    t1 = TargetSpec(ip="1.1.1.1", cvss=5.0, corpus_hit=False)
    t2 = TargetSpec(ip="2.2.2.2", cvss=9.8, corpus_hit=True)
    t3 = TargetSpec(ip="3.3.3.3", cvss=7.5, corpus_hit=True)
    ranked = prioritize_targets([t1, t2, t3])
    assert ranked[0].ip == "2.2.2.2"
    assert ranked[1].ip == "3.3.3.3"
