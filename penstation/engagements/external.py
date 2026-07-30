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


# The baseline toolset — what an external engagement is run with, installed into
# every project so the map has something to fill it in from the moment you start.
#
# These are declared as Dockerfiles rather than GitHub repos on purpose. nmap,
# dig, curl and openssl are distro packages, not repositories, so the install
# ladder has nothing to inspect — and pinning the base image is what makes the
# baseline actually reliable rather than merely old.
#
# `check` is the coverage kind this tool satisfies, so nmap and masscan both
# count as a port scan.
BACKBONE = [
    {
        "id": "bbot",
        "section": "reconnaissance",
        "check": "subdomain-enum",
        "consumes": [],                    # starts from the scope itself
        "purpose": "discovery — the one job no ancient tool does",
        # `-em dnsbrute dnsbrute_mutations` excludes the brute-force modules.
        # Re-verified against bbot 3.0.1 after the version bump, since a major
        # release can rename modules and a renamed one would fail silently:
        # `-l` resolves 124 modules, 122 with the exclusion, and the difference
        # is exactly those two.
        #
        # This matters. bbot's default `dns.brute_threads` is 1000 — still 1000
        # in 3.0.1, confirmed via --current-preset — passed
        # straight to massdns -s — a thousand concurrent DNS queries, which is
        # what knocked the network out during development. An earlier version of
        # this command used `-c dns.disable_brute_force=true`, a config key that
        # does not exist: bbot warned and carried on brute-forcing anyway.
        #
        # Everything else stays: recursion, passive sources and active modules
        # are all still on, because that is bbot's value.
        # -y skips the confirmation prompt. The runner closes stdin, so a scan
        # that asked for confirmation would stall rather than fail visibly.
        "run": "bbot -t {{scope}} -p subdomain-enum "
               "-em dnsbrute dnsbrute_mutations -y --json -o {{outdir}}",
        # The file that holds the answer to the question this command asks.
        #
        # The subdomain-enum preset declares `output_modules: [subdomains]`, and
        # that module writes the in-scope subdomains and nothing else. Everything
        # else bbot writes — output.json, debug.log, scan.log — is its own event
        # log, which by design contains affiliate hosts reached through the
        # target's MX/NS/SPF records. Promotion used to read all of it plus the
        # container's stdout, so a scan that correctly found no subdomains
        # presented 11 Google and Microsoft hosts as results, plus pip output
        # (bbot installs module deps at runtime) mistaken for hostnames.
        #
        # Read the answer, not the working.
        "result_file": "subdomains.txt",
        "dockerfile": (
            "FROM python:3.12-slim\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            "git build-essential && rm -rf /var/lib/apt/lists/*\n"
            # bbot 2.1.0 declared `dnspython<3.0.0,>=2.4.2` — unbounded in
            # practice — so pip installed dnspython 2.8.0 against a release that
            # predates it. The result was a stream of
            #   dnsresolve.py:235 resolve_event(): cannot unpack non-iterable object
            # on every DNS event. 3.0.1 constrains it to <2.9.0,>=2.7.0.
            #
            # dnspython is pinned too: pinning only the direct dependency is what
            # allowed the drift in the first place.
            "RUN pip install --no-cache-dir bbot==3.0.1 dnspython==2.8.0\n"
            'ENTRYPOINT ["bbot"]\n'
        ),
    },
    {
        "id": "dig",
        "section": "reconnaissance",
        "check": "resolve",
        "consumes": ["domain"],            # every domain on the map
        "purpose": "DNS resolution — format unchanged since the 1980s",
        # `+short` was wrong for a batch: with -f it prints bare IPs with no
        # indication of which name each belongs to — three domains produced five
        # unattributable addresses, so `domain resolves_to host` edges could not
        # be built at all. `+noall +answer` keeps name and address on one line.
        "run": "dig -f {{input}} +noall +answer",
        "dockerfile": (
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache bind-tools\n"
            'ENTRYPOINT ["dig"]\n'
        ),
    },
    {
        "id": "nmap",
        "section": "active-scanning",
        "check": "portscan",
        # hosts once dig has resolved some; domains before that, since nmap
        # resolves names itself.
        "consumes": ["host", "domain"],
        "purpose": "ports and services — XML schema stable for 15 years",
        # -oA writes all three formats from one scan: .xml to parse, .nmap to
        # read, .gnmap one line per host. Runs retain their files, so the extra
        # two are free evidence — and .gnmap is the one you grep during an
        # engagement. -oX alone would have thrown both away.
        # -iL first so the command reads target-first: what is being scanned,
        # then how. nmap is order-independent.
        #
        # -vv because without verbosity nmap prints nothing between "Starting
        # Nmap" and the final report — on a /24 with -sV that is a silent pane for
        # minutes with no way to tell a slow scan from a hung one. -vv adds each
        # open port the moment it is found ("Discovered open port 443/tcp on …")
        # rather than only at the end, so the log is useful while it runs.
        "run": "nmap -iL {{input}} -sV -T4 -vv -oA {{outdir}}/scan",
        "dockerfile": (
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache nmap nmap-scripts\n"
            'ENTRYPOINT ["nmap"]\n'
        ),
    },
    {
        "id": "curl",
        "section": "web-analysis",
        # curl takes one URL, not a list — there is no -iL equivalent, and the
        # container runs argv with no shell so `$(cat …)` cannot expand. It is
        # the tool for looking closely at one thing; probing 500 at once is a
        # different job. Click a node on the map to point it somewhere.
        "consumes": [],
        "check": "http-probe",
        "purpose": "HTTP headers of a single target, in detail",
        # -L follows redirects: a bare HEAD on http:// usually returns a 301 and
        # tells you nothing about the app behind it. Verified against a real
        # redirect — you see the 301 and the final 200.
        #
        # -v puts the whole exchange on the log: DNS, the TCP connect, the TLS
        # version and cipher negotiated, the certificate, and the request headers
        # sent as well as received — per redirect hop. Without it a failure is a
        # bare "curl: (6)" or "(28)" with no indication of which step broke, and a
        # success hides the TLS detail that is half the reason to look at all.
        # -s only silences the progress meter; -v writes to stderr regardless, and
        # -S keeps errors visible.
        "run": "curl -sSILv --max-time 10 https://{{target}}",
        "dockerfile": (
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache curl ca-certificates\n"
            'ENTRYPOINT ["curl"]\n'
        ),
    },
    {
        "id": "openssl",
        "section": "web-analysis",
        "check": "tls",
        "consumes": [],                    # one connection at a time, like curl
        "purpose": "certificate and TLS detail for one target",
        "run": "openssl s_client -connect {{target}}:443 -servername {{target}}",
        "dockerfile": (
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache openssl\n"
            'ENTRYPOINT ["openssl"]\n'
        ),
    },
]

BACKBONE_IDS = [t["id"] for t in BACKBONE]
