"""Policy engine: decide whether a sensitive tool call may run.

A call is blocked when an argument that controls *where* data or money goes
(recipient, account, path) or *whether* it runs (control context) depends on
untrusted data, unless the concrete value is in a trusted allowlist.
Blocked calls escalate to a human; they are never silently executed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .labels import TV, Trust
from .world import SENSITIVE_TOOLS, World


@dataclass
class Decision:
    allowed: bool
    rule: str = "ok"
    detail: str = ""


def _untrusted(labels) -> bool:
    return any(lab.trust is Trust.UNTRUSTED for lab in labels)


def check(tool: str, args: dict[str, TV], pc: frozenset, w: World) -> Decision:
    if tool not in SENSITIVE_TOOLS:
        return Decision(True)
    if _untrusted(pc):
        return Decision(
            False,
            "control_flow",
            "sensitive call runs under a branch on untrusted data",
        )
    trusted_emails = set(w.contacts.values())
    trusted_accounts = set(w.payees.values())

    if tool == "send_email":
        to, body = args["to"], args["body"]
        if to.tainted and to.value not in trusted_emails:
            return Decision(
                False, "tainted_recipient", f"recipient from {to.untrusted_sources()}"
            )
        if body.confidential and to.value not in trusted_emails:
            return Decision(
                False, "confidential_egress", "confidential data to non-contact"
            )
        return Decision(True)

    if tool == "pay":
        acct, amount = args["account"], args["amount"]
        cap = args.get("cap")
        if acct.tainted and acct.value not in trusted_accounts:
            return Decision(
                False, "tainted_account", f"account from {acct.untrusted_sources()}"
            )
        if amount.tainted:
            cap_v = cap.value if cap is not None and not cap.tainted else 0
            if float(amount.value) > float(cap_v):
                return Decision(
                    False, "tainted_amount_over_cap", f"{amount.value} > cap {cap_v}"
                )
        return Decision(True)

    if tool == "delete_file":
        if args["path"].tainted:
            return Decision(False, "tainted_path", "path chosen by untrusted data")
        return Decision(True)

    if tool == "share_file":
        path, rcpt = args["path"], args["recipient"]
        if path.tainted:
            return Decision(False, "tainted_path", "path chosen by untrusted data")
        if rcpt.tainted and rcpt.value not in trusted_emails:
            return Decision(
                False, "tainted_recipient", f"recipient from {rcpt.untrusted_sources()}"
            )
        return Decision(True)
    return Decision(False, "unknown_tool")
