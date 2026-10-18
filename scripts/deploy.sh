#!/usr/bin/env bash
#
# Dev deploy of ControlledBurn to an OPNsense box over SSH, without building
# a package. Mirrors what opnsense/plugins' Mk/plugins.mk does for
# `make install` + the package's +POST_INSTALL/+POST_DEINSTALL hooks:
# copy src/ into /usr/local, restart configd (new configd actions), run model
# migrations, reload plugin configuration, and clear the menu/template
# caches so menu, ACL and volt changes show up.
#
# Usage:
#   scripts/deploy.sh [install|remove]        (default: install)
#
# Environment:
#   CB_HOST   ssh destination (default: opnsense-testlab - define it in
#             ~/.ssh/config, including any ProxyJump needed to reach the
#             isolated lab network)
#   CB_FORCE  set to 1 to deploy to a host whose hostname doesn't contain
#             "testlab". The guard exists so the production firewall is
#             never hit by accident.
#
# Remote side needs: SSH enabled, a root login (or equivalent) that runs
# commands through a normal shell, and FreeBSD's tar (always present).

set -euo pipefail

ACTION="${1:-install}"
HOST="${CB_HOST:-opnsense-testlab}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/src"
MODEL="OPNsense/ControlledBurn"

case "$ACTION" in
    install|remove) ;;
    *) echo "usage: $0 [install|remove]" >&2; exit 2 ;;
esac

remote_hostname="$(ssh "$HOST" hostname)"
echo ">>> Target: $HOST (hostname: $remote_hostname)"
if [[ "$remote_hostname" != *testlab* && "${CB_FORCE:-0}" != "1" ]]; then
    echo "!!! Refusing: '$remote_hostname' doesn't look like the testlab. Set CB_FORCE=1 if you really mean it." >&2
    exit 1
fi

# Same file list `make install`/`make remove` use: every file under src/.
mapfile -t FILES < <(cd "$SRC" && find . -type f ! -path '*/__pycache__/*' ! -name '*.pyc' | sed 's|^\./||' | sort)

reload_cmds() {
    local hook="$1"   # POST_INSTALL or POST_DEINSTALL
    cat <<EOF
set -e
/usr/local/etc/rc.d/configd restart
if [ "$hook" = POST_INSTALL ] && [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then
    /usr/local/opnsense/mvc/script/run_migrations.php $MODEL
fi
if [ -f /usr/local/etc/rc.configure_plugins ]; then /usr/local/etc/rc.configure_plugins $hook; fi
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml
find /var/lib/php/cache -name '*.php' -delete
EOF
}

if [[ "$ACTION" == install ]]; then
    echo ">>> Copying ${#FILES[@]} files into /usr/local"
    (cd "$SRC" && tar --owner=0 --group=0 -cf - "${FILES[@]}") \
        | ssh "$HOST" 'tar -xpf - -C /usr/local'
    echo ">>> Reloading"
    reload_cmds POST_INSTALL | ssh "$HOST" sh
else
    echo ">>> Removing ${#FILES[@]} files from /usr/local"
    {
        echo 'set -e'
        for f in "${FILES[@]}"; do
            printf 'rm -f %q\n' "/usr/local/$f"
        done
        # remove now-empty plugin directories, deepest first; never fails on
        # shared directories that still hold other files
        (cd "$SRC" && find . -mindepth 1 -type d ! -name '__pycache__' | sed 's|^\./||' | sort -r) | while read -r d; do
            printf 'rmdir %q 2>/dev/null || true\n' "/usr/local/$d"
        done
    } | ssh "$HOST" sh
    echo ">>> Reloading"
    reload_cmds POST_DEINSTALL | ssh "$HOST" sh
fi

echo ">>> Done. Open https://<firewall>/ui/controlledburn (Firewall -> ControlledBurn)."
