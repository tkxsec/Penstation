"""External penetration test — testing what an outsider can reach.

Everything that makes this engagement type different from any other lives here.
Today that is the phase list; checklists, default tooling and report structure
belong here too as they arrive, so adding a type stays "write a module" rather
than "edit conditionals scattered through the app".
"""
from __future__ import annotations

NAME = "external"
LABEL = "External Penetration Test"

# The phases an external engagement runs through, in order. Keys are stored on
# project records, so renaming one needs a migration; the labels are display
# only and safe to reword.
SECTIONS = [
    ("reconnaissance",    "Reconnaissance"),
    ("active-scanning",   "Active Scanning"),
    ("web-analysis",      "Web Analysis"),
    ("password-spraying", "Password Spraying"),
    ("exploitation",      "Exploitation"),
]
