"""Engagement types — the registry of what kinds of test penstation knows.

A type owns its methodology: the phases it runs through, and in time whatever
else differs between an external test and an internal one. Registering a new
type means adding a module beside this one and listing it below; nothing outside
this package needs to change, and `projects.py` stays methodology-agnostic.
"""
from __future__ import annotations

from penstation.engagements import external

_MODULES = (external,)

# name -> module. Order here is the order the UI offers them in.
TYPES = {m.NAME: m for m in _MODULES}
DEFAULT = external.NAME


def sections_for(kind: str) -> list[tuple[str, str]]:
    """The phases of an engagement type, falling back to the default."""
    return list(TYPES.get(kind, TYPES[DEFAULT]).SECTIONS)


def label_for(kind: str) -> str:
    return TYPES.get(kind, TYPES[DEFAULT]).LABEL


def names() -> list[str]:
    return list(TYPES)
