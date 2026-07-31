#!/usr/bin/env bash
# Prepare an engagement box for penstation. Idempotent — safe to re-run.
#
# This installs the *install methods* and creates the unprivileged accounts.
# It deliberately does NOT install the baseline toolset: penstation installs
# those itself through the ladder, and letting it do so is the first proof that
# the ladder works on this box.
#
#   sudo ./scripts/setup-box.sh
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi

# The account penstation runs as. Defaults to whoever invoked sudo, falling back
# to root on a box where you are already root.
OWNER="${SUDO_USER:-root}"
# Asked rather than recomputed: paths.py already decides this, and a second
# copy of the rule here would eventually chmod a directory penstation is not
# using.
cd "$(dirname "$0")/.."
DATA_DIR="$(python3 -c 'from penstation.paths import DATA; print(DATA)')"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

say "1/5  install methods"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# git and curl for the clone and release rungs, golang for go install, pipx for
# Python tools, seclists because wordlists are a package rather than a problem,
# tmux so a dropped SSH session does not take a running scan with it.
apt-get install -y --no-install-recommends \
    git curl ca-certificates golang pipx seclists tmux

say "2/5  unprivileged accounts"
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

say "3/5  engagement data is not readable by them"
if [ -d "$DATA_DIR" ]; then
    chown -R "$OWNER" "$DATA_DIR"
    chmod -R 700 "$DATA_DIR"
    echo "  $DATA_DIR → $OWNER, 700"
else
    echo "  $DATA_DIR does not exist yet — re-run after penstation first starts"
fi

say "4/5  sudoers drop-in"
# Only needed when penstation runs unprivileged; root steps down with runuser and
# never needs a rule. Written to a drop-in so the main sudoers file is untouched
# and removal is one `rm`.
if [ "$OWNER" = "root" ]; then
    echo "  penstation will run as root — runuser needs no rule, skipping"
else
    SUDOERS=/etc/sudoers.d/penstation
    cat > "$SUDOERS" <<EOF
$OWNER ALL=(noprivuser-install) NOPASSWD: /usr/bin/pipx, /usr/bin/go, /usr/bin/git, /usr/bin/python3, /usr/bin/rm
$OWNER ALL=(noprivuser-run)     NOPASSWD: ALL
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

say "5/5  what this box can offer"
for t in apt-get pipx go git curl python3 tmux; do
    printf '  %-10s %s\n' "$t" "$(command -v "$t" || echo '— missing')"
done
printf '  %-10s %s\n' "seclists" \
    "$([ -d /usr/share/seclists ] && echo /usr/share/seclists || echo '— missing')"

say "done"
cat <<EOF
  Start penstation:   tmux new -s pen 'python3 serve.py'
  Reach the UI:       ssh -L 8787:127.0.0.1:8787 <this box>
                      then http://127.0.0.1:8787

  The baseline toolset installs itself on first run — that is the ladder's
  first real test. Watch it under Add Tool.
EOF
