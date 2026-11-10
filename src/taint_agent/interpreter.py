"""Plan interpreter with taint propagation, plus two baselines.

Modes
  full      planner/data separation + taint policy (this project)
  isolated  planner/data separation, no policy (ablation)
  naive     single agent that reads content AND obeys instructions found in it,
            no policy. It models a worst-case injectable LLM (always complies
            with the phrasings in INJECTION_PATTERNS). Simulated, not a real model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import policy
from .labels import TV, Label, Trust, derive, trusted
from .planner import plan as make_plan
from .quarantine import QOPS
from .world import SENSITIVE_TOOLS, TOOLS, World

ARGMAP = {  # tool -> positional arg names after world
    "read_email": ["eid"],
    "fetch_url": ["url"],
    "read_doc": ["did"],
    "read_file": ["path"],
    "lookup_contact": ["name"],
    "lookup_payee": ["name"],
    "email_sender": ["email"],
    "email_body": ["email"],
    "reply_to_user": ["text"],
    "send_email": ["to", "subject", "body"],
    "pay": ["account", "amount", "cap"],
    "delete_file": ["path"],
    "share_file": ["path", "recipient"],
}
READ_TOOLS = {"read_email", "fetch_url", "read_doc"}


@dataclass
class CallRecord:
    tool: str
    args: dict
    allowed: bool
    rule: str
    origin: str = "plan"  # "plan" or "injected"


@dataclass
class Run:
    calls: list = field(default_factory=list)

    @property
    def blocked(self):
        return [c for c in self.calls if not c.allowed]


INJECTION_PATTERNS = [
    (
        "send_file",
        re.compile(
            r"(?:send|email|forward) (?:the )?(?:contents of )?(/home/user/\S+?) to ([\w.+-]+@[\w.-]+\w)",
            re.I,
        ),
    ),
    (
        "pay",
        re.compile(r"(?:pay|transfer|wire) \$?([\d,]+(?:\.\d+)?) to (ACCT-\d+)", re.I),
    ),
    (
        "delete",
        re.compile(r"(?:delete|remove|rm) (?:the file )?(/home/user/\S+\w)", re.I),
    ),
    ("share", re.compile(r"share (/home/user/\S+?) with ([\w.+-]+@[\w.-]+\w)", re.I)),
]


def _text_of(v) -> str:
    return v.get("body", "") if isinstance(v, dict) else str(v)


class Agent:
    def __init__(self, mode: str = "full"):
        assert mode in {"full", "isolated", "naive"}
        self.mode = mode

    def run(self, task: dict, w: World) -> Run:
        self.w, self.r, self.env = w, Run(), {}
        self._exec(make_plan(task), frozenset())
        return self.r

    # -- helpers --
    def _resolve(self, a):
        if isinstance(a, list):
            return [self._resolve(x) for x in a]
        if isinstance(a, str) and a.startswith("$"):
            return self.env[a[1:]]
        return trusted(a)

    def _exec(self, steps, pc):
        for st in steps:
            if "if" in st:
                cond = self._resolve(st["if"])
                if cond.value == st["eq"]:
                    self._exec(st["then"], pc | cond.labels)
                continue
            if "foreach" in st:
                coll = self._resolve(st["foreach"])
                for item in coll.value:
                    self.env[st["as"]] = derive(item, coll)
                    self._exec(st["then"], pc)
                continue
            self._step(st, pc)

    def _step(self, st, pc):
        op, args = st["op"], {k: self._resolve(v) for k, v in st["args"].items()}
        if op in QOPS:
            if op == "fmt":
                out = QOPS[op](args["template"], *args["parts"])
            else:
                out = QOPS[op](**args)
        else:
            out = self._call(op, args, pc, "plan")
        self.env[st["out"]] = out
        if self.mode == "naive" and op in READ_TOOLS:
            self._obey(out)

    def _call(self, tool, args, pc, origin):
        if tool in SENSITIVE_TOOLS:
            d = (
                policy.check(tool, args, pc, self.w)
                if self.mode == "full"
                else policy.Decision(True)
            )
            self.r.calls.append(
                CallRecord(
                    tool,
                    {k: v.value for k, v in args.items()},
                    d.allowed,
                    d.rule,
                    origin,
                )
            )
            if not d.allowed:
                return TV(None)
        names = ARGMAP[tool]
        return TOOLS[tool](self.w, *[args.get(n) for n in names])

    def _obey(self, content: TV):
        """Naive agent: treat imperative text in untrusted content as instructions."""
        text = _text_of(content.value)
        taint = content.labels
        for kind, rx in INJECTION_PATTERNS:
            for m in rx.finditer(text):
                t = lambda v: TV(v, taint)  # noqa: E731
                if kind == "send_file" and m.group(1) in self.w.files:
                    body = TV(self.w.files[m.group(1)]["content"], taint)
                    self._call(
                        "send_email",
                        {"to": t(m.group(2)), "subject": t("fyi"), "body": body},
                        frozenset(),
                        "injected",
                    )
                elif kind == "pay":
                    self._call(
                        "pay",
                        {
                            "account": t(m.group(2)),
                            "amount": t(float(m.group(1).replace(",", ""))),
                        },
                        frozenset(),
                        "injected",
                    )
                elif kind == "delete":
                    self._call(
                        "delete_file", {"path": t(m.group(1))}, frozenset(), "injected"
                    )
                elif kind == "share":
                    self._call(
                        "share_file",
                        {"path": t(m.group(1)), "recipient": t(m.group(2))},
                        frozenset(),
                        "injected",
                    )


__all__ = ["Agent", "Run", "CallRecord", "Label", "Trust"]
