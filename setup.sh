#!/usr/bin/env bash
# Set up penstation on an engagement box. One command, idempotent, safe to re-run.
#
#   sudo ./setup.sh
#
# Does the whole job: the install methods the ladder needs, the unprivileged
# accounts that keep downloaded code away from your data, and penstation itself.
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
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
as_owner() { if [ "$OWNER" = "root" ]; then "$@"; else sudo -u "$OWNER" "$@"; fi; }

say "1/6  install methods"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# git and curl for the clone and release rungs, golang for go install, pipx for
# Python tools, seclists because wordlists are a package rather than a problem.
apt-get install -y --no-install-recommends \
    git curl ca-certificates golang pipx seclists python3-venv

say "2/6  unprivileged accounts"
# Downloaded code never holds your access: one account installs, another runs.
# nologin because neither is ever meant to be a shell you sit in.
for u in noprivuser-install noprivuser-run; do
    if id "$u" >/dev/null 2>&1; then
        echo "  $u already exists"
    else
        useradd -m -s /usr/sbin/nologin "$u"
        echo "  created $u"
    fi
done

say "3/6  sudoers drop-in"
# Only needed when penstation runs unprivileged; root steps down with runuser and
# never needs a rule. A drop-in so the main sudoers file is untouched and undoing
# this is one `rm`.
if [ "$OWNER" = "root" ]; then
    echo "  penstation will run as root — runuser needs no rule, skipping"
else
    SUDOERS=/etc/sudoers.d/penstation
    cat > "$SUDOERS" <<EOF
$OWNER ALL=(noprivuser-install) NOPASSWD: /usr/bin/pipx, /usr/bin/go, /usr/bin/git, /usr/bin/python3, /usr/bin/rm
$OWNER ALL=(noprivuser-run)     NOPASSWD: ALL
$OWNER ALL=(root) NOPASSWD: /usr/bin/apt-get
EOF
    chmod 440 "$SUDOERS"
    # A malformed sudoers file is the one change here that can lock you out of a
    # box you cannot walk to. Verify, and remove it rather than leave it broken.
    if visudo -c >/dev/null 2>&1; then
        echo "  $SUDOERS written and verified"
    else
        rm -f "$SUDOERS"
        echo "  sudoers check FAILED — drop-in removed, nothing changed" >&2
        exit 1
    fi
fi

say "4/6  penstation"
# A venv because Kali enforces PEP 668: a plain `pip install` outside one fails
# with externally-managed-environment, and that protection is worth keeping.
# Editable, so a git pull takes effect without reinstalling.
as_owner python3 -m venv "$REPO/.venv"
as_owner "$REPO/.venv/bin/pip" install -q --upgrade pip
as_owner "$REPO/.venv/bin/pip" install -q -e "$REPO"
echo "  installed into $REPO/.venv"

say "5/6  engagement data"
# Asked rather than recomputed: paths.py already decides where state lives, and a
# second copy of that rule here would eventually chmod a directory penstation is
# not using.
DATA_DIR="$("$REPO/.venv/bin/python" -c 'from penstation.paths import DATA; print(DATA)')"
as_owner mkdir -p "$DATA_DIR"
chown -R "$OWNER" "$DATA_DIR"
chmod -R 700 "$DATA_DIR"
echo "  $DATA_DIR → $OWNER, 700 (the install and run accounts cannot read it)"

say "6/6  what this box can offer"
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

  It finds noprivuser-install and noprivuser-run by name — nothing to export.

  Reach the UI, from your laptop:
    ssh -L 8787:127.0.0.1:8787 <this box>
    then http://127.0.0.1:8787

  The baseline toolset installs itself on first run — that is the ladder's
  first real test. Watch it under Add Tool.
EOF
