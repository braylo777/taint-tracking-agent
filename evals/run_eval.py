"""Run every scenario under 3 agent modes and write results/results.json.

    python evals/run_eval.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from taint_agent.interpreter import Agent  # noqa: E402
from taint_agent.scenarios import attacks, benign  # noqa: E402

MODES = ["naive", "isolated", "full"]


def evaluate(mode: str) -> dict:
    atk, ben = attacks(), benign()
    fam = defaultdict(lambda: [0, 0])
    succ_attacks, rows = 0, []
    for s in atk:
        w = s.world.clone()
        run = Agent(mode).run(s.task, w)
        hit = s.check(w)
        succ_attacks += hit
        fam[s.family][0] += not hit
        fam[s.family][1] += 1
        rows.append(
            {
                "id": s.id,
                "kind": "attack",
                "family": s.family,
                "attacker_succeeded": hit,
                "blocked_rules": [c.rule for c in run.blocked],
            }
        )
    ok = fb = 0
    for s in ben:
        w = s.world.clone()
        run = Agent(mode).run(s.task, w)
        done, blocked = s.check(w), bool(run.blocked)
        ok += done
        fb += blocked
        rows.append(
            {
                "id": s.id,
                "kind": "benign",
                "family": s.family,
                "task_success": done,
                "false_block": blocked,
                "blocked_rules": [c.rule for c in run.blocked],
            }
        )
    na, nb = len(atk), len(ben)
    return {
        "mode": mode,
        "n_attacks": na,
        "n_benign": nb,
        "attack_success": succ_attacks,
        "block_rate": round((na - succ_attacks) / na, 3),
        "false_blocks": fb,
        "false_block_rate": round(fb / nb, 3),
        "benign_success": ok,
        "task_success_rate": round(ok / nb, 3),
        "per_family_blocked": {k: f"{v[0]}/{v[1]}" for k, v in sorted(fam.items())},
        "rows": rows,
    }


def main() -> None:
    res = {m: evaluate(m) for m in MODES}
    out = ROOT / "results" / "results.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=2))
    for m in MODES:
        r = res[m]
        print(
            f"{m:9s} attacks={r['n_attacks']} block_rate={r['block_rate']} "
            f"benign={r['n_benign']} false_block_rate={r['false_block_rate']} task_success={r['task_success_rate']}"
        )
        print("          per-family blocked:", r["per_family_blocked"])


if __name__ == "__main__":
    main()
