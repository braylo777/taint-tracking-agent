"""Privileged planner (stand-in for a P-LLM).

It sees ONLY the user's request, never tool outputs, and emits a fixed program.
Untrusted content can therefore change data values flowing through the plan,
but it can never add, remove or reorder tool calls. This is a deterministic
template planner, not a language model.

Plan format: list of steps.
  {"out": "x", "op": "read_email", "args": {"eid": "e1"}}    literal args
  {"out": "y", "op": "summarize", "args": {"tv": "$x"}}      "$x" = variable ref
  {"if": "$s", "eq": "approved", "then": [...]}               control flow
"""

from __future__ import annotations


def _s(out, op, **args):
    return {"out": out, "op": op, "args": args}


def plan(task: dict) -> list[dict]:
    i = task["intent"]
    p = task
    if i == "summarize_email":
        return [
            _s("e", "read_email", eid=p["eid"]),
            _s("s", "summarize", tv="$e"),
            _s("_", "reply_to_user", text="$s"),
        ]
    if i == "summarize_web":
        return [
            _s("pg", "fetch_url", url=p["url"]),
            _s("s", "summarize", tv="$pg"),
            _s("_", "reply_to_user", text="$s"),
        ]
    if i == "web_summary_to_contact":
        return [
            _s("pg", "fetch_url", url=p["url"]),
            _s("s", "summarize", tv="$pg"),
            _s("to", "lookup_contact", name=p["contact"]),
            _s("_", "send_email", to="$to", subject="Summary", body="$s"),
        ]
    if i == "forward_email_to_contact":
        return [
            _s("e", "read_email", eid=p["eid"]),
            _s("b", "email_body", email="$e"),
            _s("to", "lookup_contact", name=p["contact"]),
            _s("_", "send_email", to="$to", subject="Fwd", body="$b"),
        ]
    if i == "reply_to_sender":
        return [
            _s("e", "read_email", eid=p["eid"]),
            _s("to", "email_sender", email="$e"),
            _s("_", "send_email", to="$to", subject="Re", body=p["text"]),
        ]
    if i == "pay_invoice_known_payee":
        return [
            _s("e", "read_email", eid=p["eid"]),
            _s("amt", "extract_amount", tv="$e"),
            _s("acct", "lookup_payee", name=p["payee"]),
            _s("_", "pay", account="$acct", amount="$amt", cap=p["cap"]),
        ]
    if i == "pay_invoice_account_in_email":
        return [
            _s("e", "read_email", eid=p["eid"]),
            _s("amt", "extract_amount", tv="$e"),
            _s("acct", "extract_account", tv="$e"),
            _s("_", "pay", account="$acct", amount="$amt", cap=p["cap"]),
        ]
    if i == "pay_if_approved":
        return [
            _s("e", "read_email", eid=p["eid"]),
            _s("st", "extract_field", tv="$e", name="status"),
            _s("acct", "lookup_payee", name=p["payee"]),
            {
                "if": "$st",
                "eq": "approved",
                "then": [
                    _s("_", "pay", account="$acct", amount=p["amount"], cap=p["amount"])
                ],
            },
        ]
    if i == "send_file_to_address_in_doc":
        return [
            _s("d", "read_doc", did=p["did"]),
            _s("to", "extract_email", tv="$d"),
            _s("f", "read_file", path=p["path"]),
            _s("_", "send_email", to="$to", subject="File", body="$f"),
        ]
    if i == "send_file_to_contact":
        return [
            _s("f", "read_file", path=p["path"]),
            _s("to", "lookup_contact", name=p["contact"]),
            _s("_", "send_email", to="$to", subject="File", body="$f"),
        ]
    if i == "send_file_to_formatted_address":
        # recipient is assembled from a fragment in the doc (laundering attempt)
        return [
            _s("d", "read_doc", did=p["did"]),
            _s("frag", "extract_field", tv="$d", name="user"),
            _s("to", "fmt", template="{}@" + p["domain"], parts=["$frag"]),
            _s("f", "read_file", path=p["path"]),
            _s("_", "send_email", to="$to", subject="File", body="$f"),
        ]
    if i == "send_file_to_contact_named_in_doc":
        return [
            _s("d", "read_doc", did=p["did"]),
            _s("nm", "extract_field", tv="$d", name="owner"),
            _s("to", "lookup_contact", name="$nm"),
            _s("f", "read_file", path=p["path"]),
            _s("_", "send_email", to="$to", subject="File", body="$f"),
        ]
    if i == "delete_files_listed_in_doc":
        return [
            _s("d", "read_doc", did=p["did"]),
            _s("ps", "extract_paths", tv="$d"),
            {"foreach": "$ps", "as": "p", "then": [_s("_", "delete_file", path="$p")]},
        ]
    if i == "delete_file":
        return [_s("_", "delete_file", path=p["path"])]
    if i == "share_file_with_contact":
        return [
            _s("to", "lookup_contact", name=p["contact"]),
            _s("_", "share_file", path=p["path"], recipient="$to"),
        ]
    if i == "share_file_with_address_in_email":
        return [
            _s("e", "read_email", eid=p["eid"]),
            _s("to", "extract_email", tv="$e"),
            _s("_", "share_file", path=p["path"], recipient="$to"),
        ]
    raise ValueError(f"unknown intent {i}")
