"""Quarantined data handler (stand-in for a Q-LLM).

It parses untrusted text into fields. It has no tool access, and every output
inherits the labels of its input. These are deterministic regex extractors,
not a language model.
"""

from __future__ import annotations

import re

from .labels import TV, derive

EMAIL_RE = re.compile(r"[\w.+-]+\s*(?:@|\[at\])\s*[\w-]+(?:\.[\w-]+)+")
AMOUNT_RE = re.compile(r"\$\s?([\d,]+(?:\.\d+)?)")
ACCOUNT_RE = re.compile(r"ACCT-\d+")
PATH_RE = re.compile(r"/home/user/[\w./-]+")


def _text(tv: TV) -> str:
    v = tv.value
    if isinstance(v, dict):
        return v.get("body", "")
    return str(v)


def extract_email(tv: TV) -> TV:
    m = EMAIL_RE.search(_text(tv))
    val = re.sub(r"\s*\[at\]\s*", "@", m.group(0)).replace(" ", "") if m else ""
    return derive(val, tv)


def extract_amount(tv: TV) -> TV:
    m = AMOUNT_RE.search(_text(tv))
    return derive(float(m.group(1).replace(",", "")) if m else 0.0, tv)


def extract_account(tv: TV) -> TV:
    m = ACCOUNT_RE.search(_text(tv))
    return derive(m.group(0) if m else "", tv)


def extract_paths(tv: TV) -> TV:
    return derive(PATH_RE.findall(_text(tv)), tv)


def extract_field(tv: TV, name: TV) -> TV:
    m = re.search(rf"{re.escape(str(name.value))}\s*:\s*(\w+)", _text(tv), re.I)
    return derive(m.group(1).lower() if m else "", tv, name)


def summarize(tv: TV) -> TV:
    t = " ".join(_text(tv).split())
    return derive(t[:80], tv)


def fmt(template: TV, *parts: TV) -> TV:
    return derive(
        str(template.value).format(*[p.value for p in parts]), template, *parts
    )


QOPS = {
    f.__name__: f
    for f in [
        extract_email,
        extract_amount,
        extract_account,
        extract_paths,
        extract_field,
        summarize,
        fmt,
    ]
}
