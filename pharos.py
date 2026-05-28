#!/usr/bin/env python3
"""
PHAROS — Autonomous two-layer offensive research agent for AI/ML infrastructure.

Usage:
    pharos run <ip>                          # triage + stack map only
    pharos run <ip> --authorized             # full chain (phases 1-7)
    pharos run --from-sentinel               # pull top P1/P2 from sentinel queue
    pharos run --from-sentinel --authorized  # full chain on sentinel target
    pharos status                            # list recent runs
    pharos report <session_id>              # print decision output for a run
"""
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from state import TargetSpec, RunSession, RUNS_DIR


def _import_phases():
    from phases.triage import run_triage
    from phases.stack_map import run_stack_map
    from phases.exploit_surface import run_exploit_surface
    from phases.infra_attack import run_infra_attack
    from phases.ai_attack import run_ai_attack
    from phases.evidence import run_evidence
    from phases.decision import run_decision
    return (run_triage, run_stack_map, run_exploit_surface,
            run_infra_attack, run_ai_attack, run_evidence, run_decision)


def cmd_run(args):
    from target_queue import get_sentinel_target, parse_direct_target

    if args.from_sentinel:
        target = get_sentinel_target()
        if not target:
            print("sentinel: no P1/P2 targets in queue"); return
    else:
        if not args.target:
            print("error: provide <ip> or --from-sentinel"); return
        target = parse_direct_target(args.target)

    target.authorized = args.authorized

    try:
        (run_triage, run_stack_map, run_exploit_surface,
         run_infra_attack, run_ai_attack, run_evidence, run_decision) = _import_phases()
    except ImportError:
        # Phases not yet built — run what exists
        run_triage = run_stack_map = run_exploit_surface = None
        run_infra_attack = run_ai_attack = run_evidence = run_decision = None

    session = RunSession.create(target)

    print(f"\nPHAROS  {target.ip}  platform={target.platform}  authorized={target.authorized}")
    print(f"  session: {session.session_id}")
    print(f"  run dir: {session.run_dir}\n")

    phases_passive = []
    phases_active = []

    if run_triage:         phases_passive.append(("triage",          run_triage))
    if run_stack_map:      phases_passive.append(("stack_map",       run_stack_map))
    if run_exploit_surface: phases_passive.append(("exploit_surface", run_exploit_surface))
    if run_infra_attack:   phases_active.append(("infra_attack",    run_infra_attack))
    if run_ai_attack:      phases_active.append(("ai_attack",       run_ai_attack))
    if run_evidence:       phases_active.append(("evidence",        run_evidence))
    if run_decision:       phases_active.append(("decision",        run_decision))

    phases_to_run = phases_passive + (phases_active if target.authorized else [])

    if not phases_to_run:
        print("  no phases built yet — scaffold only"); return

    for name, fn in phases_to_run:
        print(f"  [{name}]", end="", flush=True)
        result = fn(session)
        session.add_phase(result)
        status_str = {
            "ok":      "  ✓",
            "skipped": f"  –  {result.skip_reason}",
            "gated":   f"  ✗  GATED: {result.skip_reason}",
            "error":   "  ✗  ERROR",
        }.get(result.status, "  ?")
        print(status_str)
        if result.status == "gated":
            print(f"\n  Target gated at {name}: {result.skip_reason}")
            session.save(); return

    import datetime as _dt
    session.completed_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
    session.save()

    if session.decision:
        d = session.decision
        print(f"\n{'─'*60}")
        print(f"  {d.priority_level}  score={d.total_score:.3f}  "
              f"breach={'YES' if d.breach_confirmed else 'no'}  "
              f"drift={d.drift_score:.3f}")
        print(f"  {d.disclosure_urgency.upper()}: {d.attack_chain_summary[:120]}")
        for action in d.next_actions:
            print(f"    • {action}")
        if d.case_study_path:
            print(f"\n  Case study: {d.case_study_path}")


def cmd_status(_):
    if not RUNS_DIR.exists():
        print("No runs yet."); return
    runs = sorted(RUNS_DIR.iterdir(), reverse=True)[:10]
    if not runs:
        print("No runs yet."); return
    for r in runs:
        sf = r / "session.json"
        if not sf.exists(): continue
        s = json.loads(sf.read_text())
        phases_done = len(s.get("phases", []))
        d = s.get("decision") or {}
        print(f"  {r.name:<38}  phases={phases_done}  "
              f"priority={d.get('priority_level','?')}  "
              f"breach={d.get('breach_confirmed','?')}")


def cmd_report(args):
    matches = list(RUNS_DIR.glob(f"{args.session_id}*"))
    if not matches:
        print(f"session not found: {args.session_id}"); return
    print(json.dumps(json.loads((matches[0] / "session.json").read_text()), indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="PHAROS — AI/ML infrastructure offensive research agent")
    sub = p.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run")
    p_run.add_argument("target", nargs="?")
    p_run.add_argument("--from-sentinel", action="store_true")
    p_run.add_argument("--authorized", action="store_true",
                       help="Enable active phases 4-7 (requires written authorization)")

    sub.add_parser("status")
    p_rep = sub.add_parser("report")
    p_rep.add_argument("session_id")

    args = p.parse_args()
    {"run": cmd_run, "status": cmd_status, "report": cmd_report}.get(
        args.cmd, lambda _: p.print_help())(args)
