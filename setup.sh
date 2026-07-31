#!/usr/bin/env bash
# Set up penstation on an engagement box. One command, idempotent, safe to re-run.
#
#   sudo ./setup.sh
#
# Does the whole job: the install methods the ladder needs, the prefix installed
# tools land in, and penstation itself.
#
# It deliberately does NOT install the baseline toolset. penstation installs
# those itself through the ladder, and letting it do so is the first proof that
# the ladder works on this box.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi

cd "$(dirname "$0")"
REPO="$(pwd)"

# The account penstation runs as: whoever invoked sudo, or root on a box where
# you already are root. Everything user-owned below is created as them, not as
# root — a venv owned by root that a normal user has to run is a papercut you
# would hit on every git pull.
OWNER="${SUDO_USER:-root}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
as_owner() { if [ "$OWNER" = "root" ]; then "$@"; else sudo -u "$OWNER" "$@"; fi; }

say "1/5  install methods"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# git and curl for the clone and release rungs, golang for go install, pipx for
# Python tools, seclists because wordlists are a package rather than a problem.
apt-get install -y --no-install-recommends \
    git curl ca-certificates golang pipx seclists python3-venv

# bbot resolves its own dependencies at scan time — apt packages included. Even
# running as root that is the wrong moment for it: an engagement should not
# depend on PyPI and the Debian mirrors being reachable, and a scan should not
# install software. It is passed --no-deps, its Python dependencies are declared
# in the tool spec, and its one system dependency is 7z, provisioned here.
#
# The package name has moved (p7zip-full -> 7zip on newer Debian), and a missing
# 7z costs one bbot module rather than the install, so this must not be fatal.
apt-get install -y --no-install-recommends 7zip 2>/dev/null \
  || apt-get install -y --no-install-recommends p7zip-full 2>/dev/null \
  || echo "  note: no 7z package found — bbot modules needing it will be skipped"

say "2/5  penstation"
# A venv because Kali enforces PEP 668: a plain `pip install` outside one fails
# with externally-managed-environment, and that protection is worth keeping.
# Editable, so a git pull takes effect without reinstalling.
as_owner python3 -m venv "$REPO/.venv"
as_owner "$REPO/.venv/bin/pip" install -q --upgrade pip
as_owner "$REPO/.venv/bin/pip" install -q -e "$REPO"
echo "  installed into $REPO/.venv"

say "3/5  tool prefix"
# Where installed tools land. Not a security boundary — a naming one. The distro
# ships its own `httpx` and `subfinder`, several versions behind the ones the
# baseline pins, and both sit in /usr/bin. Installing ours somewhere we control,
# and looking there first, is what stops a scan silently running the wrong
# binary: penstation recorded /usr/bin/subfinder v2.6.0 for a recipe that had
# just installed v2.14.0.
#
# Asked rather than hardcoded, for the same reason the data dir is — nativeops.py
# already decides where this goes, and a second copy of that rule here would
# eventually chown a directory penstation is not using.
PREFIX="$("$REPO/.venv/bin/python" -c 'from penstation.tools.nativeops import SHARED_PREFIX; print(SHARED_PREFIX)')"
mkdir -p "$PREFIX"/bin "$PREFIX"/pipx "$PREFIX"/tools
chown -R "$OWNER" "$PREFIX"
echo "  $PREFIX → $OWNER"

say "4/5  engagement data"
# Asked rather than recomputed: paths.py already decides where state lives, and a
# second copy of that rule here would eventually chmod a directory penstation is
# not using.
DATA_DIR="$("$REPO/.venv/bin/python" -c 'from penstation.paths import DATA; print(DATA)')"
as_owner mkdir -p "$DATA_DIR"
chown -R "$OWNER" "$DATA_DIR"
chmod -R 700 "$DATA_DIR"
echo "  $DATA_DIR → $OWNER, 700"

say "5/5  what this box can offer"
for t in apt-get pipx go git curl python3; do
    printf '  %-10s %s\n' "$t" "$(command -v "$t" || echo '— missing')"
done
printf '  %-10s %s\n' "seclists" \
    "$([ -d /usr/share/seclists ] && echo /usr/share/seclists || echo '— missing')"

say "done"
cat <<EOF
  Start it:
    cd $REPO
    .venv/bin/penstation

  Reach the UI, from your laptop:
    ssh -L 8787:127.0.0.1:8787 <this box>
    then http://127.0.0.1:8787

  The baseline toolset installs itself on first run — that is the ladder's
  first real test. Watch it under Add Tool.
EOF
