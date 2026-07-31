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
    ("reconnaissance",    "Passive Recon"),
    ("active-scanning",   "Active Recon"),
    # No baseline tool of their own — places to put what you add. They sit under
    # Reconnaissance in the sidebar and stay out of the Map checklist, which
    # lists the phases that actually run something.
    ("cloud-resources",   "Cloud Resources"),
    ("github-resources",  "GitHub Resources"),
    # Vulnerability scanning — Nessus and the like. Its own phase, not the port
    # scan: nmap says what is listening, this says what is wrong with it, and
    # the second is far louder and needs its own place in the methodology.
    ("vuln-scanning",     "Active Scanning"),
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
        # Which retained files are worth listing. bbot writes thirteen — the four
        # here plus debug.log, scan.log, error.log, preset.yml, wordcloud.tsv and
        # a couple of timestamped tables — and a wall of its own working notes
        # buries the outputs you came for. Everything is still on disk; this is
        # only what the run offers you as a link. Globs match the basename, and
        # a tool that declares nothing lists everything (nmap's three formats
        # are all output).
        "output_files": ["output.*", "subdomains.txt"],
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
        # No "source": github.com/projectdiscovery/subfinder is where the pinned
        # version comes from, but naming the repo here sends the install through
        # repo inspection, which is a GitHub API call the rest of the baseline
        # does not need and cannot fail on. It also read the README and replaced
        # this declared command with a bare `subfinder -d {{target}}`.
        "id": "subfinder",
        "section": "reconnaissance",
        # The same coverage kind as bbot on purpose: either satisfies "we looked
        # for subdomains". They are here together because their source lists
        # differ and public sources fail — crt.sh returned max_client_conn to
        # bbot and answered subfinder minutes later, which cost eight subdomains
        # with nothing logged above INFO. One passive tool is one bad afternoon
        # away from a quiet miss.
        "check": "subdomain-enum",
        "consumes": [],                    # starts from the scope itself
        # -d takes the whole comma-separated list, so a scope naming three
        # domains is one run. -all turns on every source rather than the fast
        # default: breadth is the entire reason this is here, and the sources it
        # adds are the ones bbot does not carry.
        #
        # No -silent, for the same reason nmap gets -vv: subfinder with -all can
        # sit for minutes, and its progress lines are how you tell a slow source
        # from a hung one. They go to stderr, so they never reach the results.
        "run": "subfinder -d {{targets}} -all -o {{outdir}}/subdomains.txt",
        # -o writes exactly the names it found and nothing else.
        "result_file": "subdomains.txt",
        "output_files": ["subdomains.txt"],
        # Built rather than pulled, and pinned like the rest of the baseline.
        # A Go binary needs no runtime, so the toolchain stays in the build
        # stage: shipping golang:1.24-alpine would be ~250MB of compiler to run
        # one static binary. ca-certificates is not optional — every source is
        # queried over HTTPS, and without it subfinder fails on all of them.
        "dockerfile": (
            "FROM golang:1.24-alpine AS build\n"
            "RUN apk add --no-cache git\n"
            "RUN go install -v github.com/projectdiscovery/subfinder/v2/"
            "cmd/subfinder@v2.14.0\n"
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache ca-certificates\n"
            "COPY --from=build /go/bin/subfinder /usr/local/bin/subfinder\n"
            'ENTRYPOINT ["subfinder"]\n'
        ),
    },
    {
        "id": "dig",
        "section": "reconnaissance",
        "check": "resolve",
        "consumes": ["domain"],            # every domain on the map
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
        # Timing and probe intensity come from the engagement's *scan* pace,
        # which is set separately from the web one. This is the more disruptive
        # half of the baseline — httpx fetches a page, this talks to whatever is
        # listening — and the two dials cost wildly different amounts, so one
        # setting for both would either make this unusable or make that loud.
        "run": "nmap -iL {{input}} -sV {{scan_probes}} {{scan_timing}} -vv "
               "-oA {{outdir}}/scan",
        # The XML, and nothing else. All three formats describe the same scan,
        # but only this one separates state, reason, service and version into
        # fields — and reading all three concatenated is what sent nmap's output
        # to the generic sweep, which found the addresses it already knew,
        # invented `nmap.org` from the report-a-bug footer, and offered not one
        # port. output_files stays unset so all three are still listed as
        # evidence; this only narrows what promotion reads.
        "result_file": "scan.xml",
        "dockerfile": (
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache nmap nmap-scripts\n"
            'ENTRYPOINT ["nmap"]\n'
        ),
    },
    {
        "id": "httpx",
        "section": "web-analysis",
        "check": "http-probe",
        # Ports first, hosts before nmap has produced any. This is the step
        # between "something is listening on 443" and "it is a Grafana login",
        # and the one the baseline was missing: nmap can hand back forty web
        # ports and curl takes one target at a time.
        "consumes": ["port", "host", "domain"],
        # This tool distinguishes its targets by hostname, so a port is not one
        # target but several: the address, and every name that resolves to it.
        #
        # Measured, not assumed. Probing a set of open ports by address returned
        # nothing belonging to the target at all: the ones on a platform's edge
        # addresses redirected to that platform's own marketing site, and the
        # ones behind a reverse proxy returned 404 with the proxy's default
        # certificate. That 404 is the proof rather than a dead end — the
        # application is there, it is chosen by the Host header, and only a
        # request naming it arrives at it.
        #
        # It also turns off the under-wildcard fold. That fold is right for a
        # port scanner — thirteen names on one address are one machine, and
        # scanning it thirteen times is waste — and wrong here, because at the
        # HTTP layer those names are routinely thirteen different applications.
        "vhosts": True,
        # -l a list, one probe each, concurrent. -sc/-title/-td/-tls-grab are
        # the four facts worth having for every target; -fr because a bare probe
        # of a redirecting host reports the redirect, not the app behind it.
        # -json so promotion reads structured records rather than a formatted
        # table, and -silent to keep the banner out of them.
        # -fhr, not -fr: follow a redirect only while it stays on the same host.
        # You still learn that a target redirects away — the status and the
        # Location are recorded — without sending a request to a third party the
        # engagement never authorised. Probing by address did exactly that, and
        # the destination's title and technologies are someone else's
        # application, which is not ours to fingerprint.
        #
        # -t/-rl come from the engagement's *web* pace, set separately from the
        # scan one. httpx's own defaults are 50 threads at 150 requests a
        # second, which is a burst most services absorb and some do not — and
        # probing by hostname aims many names at one host, so that concurrency
        # lands on a single machine rather than spreading across an estate.
        #
        # It is cheap at every setting: one request per target, so a few hundred
        # names is minutes rather than hours. The reason to slow it is being
        # noticed — a lot of distinct Host headers from one source address is
        # what enumeration detection looks for — not the load itself.
        "run": "httpx -l {{input}} -sc -title -td -tls-grab -fhr -silent "
               "-t {{web_threads}} -rl {{web_rate}} "
               "-json -o {{outdir}}/httpx.jsonl",
        "result_file": "httpx.jsonl",
        "output_files": ["httpx.jsonl"],
        # Same two-stage build as subfinder, pinned the same way. go.mod for
        # v1.10.0 asks for go 1.26.
        "dockerfile": (
            "FROM golang:1.26-alpine AS build\n"
            "RUN apk add --no-cache git\n"
            "RUN go install -v github.com/projectdiscovery/httpx/"
            "cmd/httpx@v1.10.0\n"
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache ca-certificates\n"
            "COPY --from=build /go/bin/httpx /usr/local/bin/httpx\n"
            'ENTRYPOINT ["httpx"]\n'
        ),
    },
    {
        "id": "curl",
        "section": "web-analysis",
        # curl takes one URL, not a list — there is no -iL equivalent, and the
        # container runs argv with no shell so `$(cat …)` cannot expand. It is
        # the tool for looking closely at one thing; probing 500 at once is
        # httpx's job. `targets` is the other half of that: the kinds of node
        # you can point it at from the map, which is where {{target}} comes
        # from rather than the project's primary domain.
        "consumes": [],
        "targets": ["domain", "host", "webapp"],
        "check": "http-probe",
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
        # Not webapp: s_client wants a host and a port, and a URL would arrive
        # with a scheme it cannot dial.
        "targets": ["domain", "host"],
        "run": "openssl s_client -connect {{target}}:443 -servername {{target}}",
        "dockerfile": (
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache openssl\n"
            'ENTRYPOINT ["openssl"]\n'
        ),
    },
]

BACKBONE_IDS = [t["id"] for t in BACKBONE]
