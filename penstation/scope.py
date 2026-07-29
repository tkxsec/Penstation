"""Engagement scope — parsed into something matchable.

Scope is written as free text on the project (`*.acme.com, 203.0.113.0/24`),
which is how you receive it from a client. To be useful it has to answer one
question about any value a tool reports: is this in scope?

It **warns, it does not block**. Recording an out-of-scope finding is normal
engagement work — you note it, mark it, and mention it in the report. A tool
that refused to let you write down something you observed would just get worked
around, and you would lose the record.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_SPLIT = re.compile(r"[,\s;]+")


def parse(text: str) -> list[str]:
    """Scope string -> individual rules."""
    return [p.strip().lower().rstrip(".") for p in _SPLIT.split(text or "") if p.strip()]


def _host_of(value: str) -> str:
    """The hostname or IP inside a domain, URL or host:port."""
    v = (value or "").strip().lower()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    elif v.count(":") == 1 and not v.startswith("["):
        head, _, tail = v.partition(":")
        if tail.isdigit():
            v = head
    return v.rstrip(".")


def _matches_rule(rule: str, host: str) -> bool:
    # CIDR or bare IP
    try:
        net = ipaddress.ip_network(rule, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    if rule.startswith("*."):
        base = rule[2:]
        # A wildcard covers the apex too: *.acme.com is understood to include
        # acme.com, which is how clients mean it in practice.
        return host == base or host.endswith("." + base)
    return host == rule


def matches(scope_text: str, value: str) -> bool:
    """Is this value in scope? An empty scope means everything is."""
    rules = parse(scope_text)
    if not rules:
        return True
    host = _host_of(value)
    if not host:
        return False
    return any(_matches_rule(r, host) for r in rules)


def describe(scope_text: str) -> dict:
    """Split scope into its parts, for display."""
    domains, nets, hosts = [], [], []
    for r in parse(scope_text):
        try:
            ipaddress.ip_network(r, strict=False)
            nets.append(r)
            continue
        except ValueError:
            pass
        (domains if r.startswith("*.") else hosts).append(r)
    return {"domains": domains, "networks": nets, "hosts": hosts}
