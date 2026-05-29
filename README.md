# pharos

Autonomous two-layer offensive research agent for AI/ML infrastructure.
It attacks the server and the AI system running on it, in one chained pass.

Most recon stops at the service. It fingerprints the port, confirms the
version, ranks an exploit, and calls it a day. AI/ML deployments have a second
attack surface the scanner never touches: the model itself. pharos runs both
layers. It maps the stack and confirms known-vulnerable versions (infra layer),
then probes the live LLM with an adversarial corpus and measures behavioral
drift before and after injection (AI layer). The output is a scored,
prioritized finding with a generated case study, not a wall of raw scan text.

pharos is an orchestrator. It does not reimplement the recon tools, it drives
them: aimap, js-extractor, BARE, VisorScuba, VisorRAG, VisorCorpus, VisorAgent,
VisorLog, Cortex, and pcse. Each phase feeds the next.

## Status

Offensive agent. The active phases are gated behind an explicit `--authorized`
flag and a triage ethics gate that blocks clinical/HIPAA, military/ITAR, and
honeypot-flagged targets before any active probe runs. Run it only against your
own or in-scope, authorized targets. Without `--authorized`, pharos runs the
passive phases only (triage and stack map) and stops.

The orchestrator and all seven phases are built. The phases shell out to
sibling NuClide tools, so a phase degrades to a skip or a partial result when
the tool it needs is not installed. Phases are designed to complete cleanly even
with no tools present (verified in the test suite).

## Install

```
git clone https://github.com/nuclide-research/pharos
```

Python 3.9+ (uses PEP 585 builtin generics like `list[...]`). Tested on 3.12.

No required pip dependencies. pharos is standard library only. One phase
(ai_attack) imports `requests` to probe LLM endpoints, but the import is
guarded: if `requests` is absent, that probe is skipped and the phase still
completes.

```
pip install requests   # optional, enables live LLM baseline probing in ai_attack
```

## Requires

pharos orchestrates external NuClide tools. It looks for each on `PATH`, in
`~/go/bin`, and at known checkout paths. A missing tool causes the dependent
phase to skip or return a partial result, never a crash. The tools, by phase:

| Phase | Tool | What it does |
|-------|------|--------------|
| triage | aimap-profile | target classification + ethics gate |
| stack_map | aimap, js-extractor | service fingerprint, baked-secret scan of SPA bundles |
| exploit_surface | BARE, VisorScuba | semantic module ranking, compliance score |
| infra_attack | VisorRAG (`visor`) | LLM-driven recon chain, JSONL event stream |
| ai_attack | VisorCorpus, VisorAgent, pcse | adversarial corpus build, injection run, behavioral drift |
| evidence | VisorLog, Cortex | ledger ingest, authorization-context analysis |
| decision | (none) | scoring and prioritization, pure Python |

The `--from-sentinel` mode reads a target queue written by the sentinel watcher
at `~/.local/share/sentinel/`. If that path does not exist, the queue is empty.

## Usage

```
pharos run <ip>                          # passive only: triage + stack map, then stop
pharos run <ip> --authorized             # full chain, all 7 phases (active)
pharos run --from-sentinel               # pull top P1/P2 target from sentinel queue
pharos run --from-sentinel --authorized  # full chain on the sentinel target
pharos status                            # list the 10 most recent runs
pharos report <session_id>               # print the full session JSON for a run
```

Invoke with `python3 pharos.py <args>`, or symlink `pharos.py` onto `PATH`.

`run` takes either a positional IP or `--from-sentinel` (one is required).
`--authorized` unlocks the four active phases (infra_attack, ai_attack,
evidence, decision). Without it, pharos runs the three passive phases and exits.

### The chain

Seven phases run in order. Each writes a `PhaseResult` into the session and
saves after every step, so a run is resumable to inspect even if it stops early.

1. **triage** (passive) - classify the target with aimap-profile. Gate and stop
   if the category or ethics flags hit clinical/HIPAA, military/ITAR, or
   honeypot signals. Degrades to a no-profile pass if the tool is missing.
2. **stack_map** (passive) - fingerprint services with aimap, detect LLM
   endpoints and web ports, run js-extractor on the first web port to pull
   secrets baked into SPA bundles.
3. **exploit_surface** (passive) - confirm the version against an internal
   CVE-range table, rank Metasploit-style modules with BARE, pull a VisorScuba
   compliance score, and decide which active phases to skip (no LLM means skip
   ai_attack; no aimap output means skip infra_attack).
4. **infra_attack** (active) - drive VisorRAG for an LLM-led recon chain
   (aimap + visorgraph + menlohunt + nuclei), parse the JSONL event stream into
   findings.
5. **ai_attack** (active) - the second layer. Build a platform-specific
   adversarial corpus with VisorCorpus, fire it at the live LLM with VisorAgent,
   compute a hit rate, and measure pcse behavioral drift between a pre- and
   post-injection baseline. Breach is confirmed at hit rate >= 30%, or drift
   >= 0.25 with hit rate >= 10%.
6. **evidence** (active) - collect critical findings, ingest them into VisorLog,
   run Cortex authorization-context analysis on the top finding, and generate a
   Markdown case study.
7. **decision** (active) - five-factor score (impact, exploit, breach, dwell,
   blast radius) producing a P1-P4 priority, a disclosure-urgency label, and a
   list of next actions.

### Output

Each run lands in `~/pharos/runs/<timestamp>-<ip>/`. The directory holds
`session.json` (full phase data), the tool artifacts (`aimap.json`,
`visorrag-stream.jsonl`, `pharos-corpus.json`, `bare-output.json`, and others
as phases produce them), and `case-study.md`. The terminal prints a per-phase
status line as the chain runs, then the decision summary:

```
PHAROS  <ip>  platform=litellm  authorized=True
  session: 20260528T...-<ip>
  run dir: /home/<user>/pharos/runs/20260528T...-<ip>

  [triage]  ✓
  [stack_map]  ✓
  [exploit_surface]  ✓
  [infra_attack]  ✓
  [ai_attack]  ✓
  [evidence]  ✓
  [decision]  ✓
  ────────────────────────────────────────────────────────────
  P1  score=0.812  breach=YES  drift=0.341
  IMMEDIATE: <attack chain summary>
    • <next action>
```

A gated triage stops the chain immediately and prints the gate reason.

## Tests

```
pytest                                   # from the repo root
```

The suite covers the scoring math, the version-range matcher, the breach and
drift logic, the triage ethics gates, and the sentinel queue parser. The
ai_attack test confirms the phase completes with no tools installed.

## License

MIT. Part of the NuClide toolchain.
