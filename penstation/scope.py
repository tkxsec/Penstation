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


def is_network(rule: str) -> bool:
    """Does this rule describe an address range rather than a host?

    The test is whether it parses as one, not whether it contains a slash.
    Scope gets pasted from a client's email, so `acme.com/` and
    `https://acme.com/login` both arrive — and read as networks under a slash
    test. That is not cosmetic: a domain classed as a network seeds no node, so
    the map opened empty, nothing counted as in scope, and `{{scope}}` had
    nothing to substitute, leaving the baseline command unrunnable.
    """
    try:
        ipaddress.ip_network(rule, strict=False)
        return True
    except ValueError:
        return False


def _clean(token: str) -> str:
    """One scope rule, as written -> what it actually names."""
    t = token.strip().lower().rstrip(".")
    if not t or is_network(t):
        return t                       # a real CIDR or bare IP, left alone
    if "://" in t:                     # pasted as a URL
        t = urlsplit(t).hostname or t.split("://", 1)[1]
    t = t.split("/", 1)[0]             # drop any path
    return t.strip().strip(".")


def parse(text: str) -> list[str]:
    """Scope string -> individual rules."""
    return [r for r in (_clean(p) for p in _SPLIT.split(text or "") if p.strip()) if r]


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
    # A bare domain is that host and nothing else. Subdomains are included only
    # when you write the star, because this flag decides what gets scanned, and
    # inferring authorisation from a name is how you end up on infrastructure
    # nobody signed for. `acme.com` in a statement of work usually does mean the
    # subdomains too — but "usually" is not something to encode: the cost of
    # writing `*.acme.com` is four characters, and the cost of assuming it is an
    # unauthorised scan.
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


def matching_rule(scope_text: str, value: str) -> str:
    """Which rule puts this value in scope, or "" if none does.

    The verdict alone is not enough to defend later: "in scope" and "in scope
    because *.acme.com covers it" are different claims, and only the second one
    survives being asked about.
    """
    host = _host_of(value)
    if not host:
        return ""
    for r in parse(scope_text):
        if _matches_rule(r, host):
            return r
    return ""


def problems(scope_text: str) -> list[tuple[str, str]]:
    """Rules that cannot do what they look like they do.

    Scope is typed by hand from a document, and a rule that matches nothing
    fails silently — the map simply shows less than you expected, which reads as
    "the scan found little" rather than "the scope has a typo in it".
    """
    out = []
    # Checked before parsing, because parsing repairs what it can: `10.0.0.0/33`
    # is not a network, so the path-stripping turns it into the bare address
    # `10.0.0.0` and the bad mask disappears along with the /24 you meant.
    for raw in (t.strip() for t in _SPLIT.split(scope_text or "")):
        if not raw or "/" not in raw or is_network(raw.lower()):
            continue
        try:
            ipaddress.ip_address(raw.split("/", 1)[0])
            out.append((raw, "not a valid network mask"))
        except ValueError:
            pass
    for rule in parse(scope_text):
        if is_network(rule):
            continue
        base = rule[2:] if rule.startswith("*.") else rule
        if not base:
            out.append((rule, "no host after the wildcard"))
        elif "," in base or ";" in base:
            out.append((rule, "looks like two rules run together"))
        elif "." not in base:
            out.append((rule, "no dot — not a domain, and not an address or range"))
        elif base.startswith("-") or base.endswith("-"):
            out.append((rule, "starts or ends with a hyphen"))
        elif not _DOMAIN.match(base):
            out.append((rule, "not a valid hostname"))
    return out


_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+\.?$", re.I)


def describe(scope_text: str) -> dict:
    """Split scope into its parts, for display."""
    domains, nets, hosts = [], [], []
    for r in parse(scope_text):
        if is_network(r):
            nets.append(r)
        else:
            (domains if r.startswith("*.") else hosts).append(r)
    return {"domains": domains, "networks": nets, "hosts": hosts}
