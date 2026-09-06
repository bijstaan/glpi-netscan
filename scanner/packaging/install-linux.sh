#!/usr/bin/env bash
# Lay out the versioned install tree self-update needs, and install the unit.
#
# Run as root, from a directory containing the built `glpi-netscan` binary:
#
#   sudo ./install-linux.sh
#
# Self-update needs somewhere to put a second version and a symlink to flip
# between them, so a scanner dropped at /usr/bin can never update itself — the
# updater refuses rather than replacing a working binary with no way back. This
# script creates that layout:
#
#   /opt/glpi-netscan/versions/<version>/glpi-netscan
#   /opt/glpi-netscan/current -> versions/<version>
#   /opt/glpi-netscan/preflight.sh          (unversioned; guards the rollback)
#
# Re-running it installs another version alongside the existing ones and points
# `current` at it, which is also the supported way to intervene by hand on a
# machine whose updates are pinned.
set -euo pipefail

INSTALL_ROOT="${GLPI_NETSCAN_INSTALL_ROOT:-/opt/glpi-netscan}"
CONFIG_DIR="/etc/glpi-netscan"
USER_NAME="glpi-netscan"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

BINARY="${1:-${HERE}/glpi-netscan}"
[[ -x "$BINARY" ]] || { echo "no scanner binary at ${BINARY}" >&2; exit 1; }

# Ask the binary its own version rather than taking it from a filename or a
# build variable that could disagree with what it will report to GLPI. The
# updater compares the two, so a mismatch seeded here would surface later as a
# rejected update with a confusing message.
version="$("$BINARY" -version | sed 's/^glpi-netscan //')"
[[ -n "$version" ]] || { echo "could not determine the binary's version" >&2; exit 1; }

if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
fi

# 0750 throughout, which is what the self-updater also creates: the tree is
# owned by the service account, only that account and root ever run the scanner,
# and a first install should not be laid out more openly than the machine ends up
# after its first update.
install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "${INSTALL_ROOT}/versions"
install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "${INSTALL_ROOT}/versions/${version}"
install -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$BINARY" "${INSTALL_ROOT}/versions/${version}/glpi-netscan"

# preflight.sh stays root-owned: it is the thing that rescues the machine from a
# bad update, so the account that installs updates must not be able to rewrite
# it. It only needs to be readable and executable by the service.
install -m 0755 -o root -g root "${HERE}/preflight.sh" "${INSTALL_ROOT}/preflight.sh"

# Flipped through a temporary name so `current` is never briefly absent — a
# restart landing in that window would find nothing to start.
ln -sfn "${INSTALL_ROOT}/versions/${version}" "${INSTALL_ROOT}/current.new"
mv -Tf "${INSTALL_ROOT}/current.new" "${INSTALL_ROOT}/current"
chown -h "$USER_NAME:$USER_NAME" "${INSTALL_ROOT}/current"

install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$CONFIG_DIR"
if [[ ! -f "${CONFIG_DIR}/agent.conf" && -f "${HERE}/agent.conf.example" ]]; then
    install -m 0640 -o "$USER_NAME" -g "$USER_NAME" \
        "${HERE}/agent.conf.example" "${CONFIG_DIR}/agent.conf.example"
fi

install -m 0644 "${HERE}/glpi-netscan.service" /etc/systemd/system/glpi-netscan.service
systemctl daemon-reload

cat <<EOF

Installed glpi-netscan ${version} at ${INSTALL_ROOT}/versions/${version}.

Next, enroll it with the command shown under Setup > Network scanning in GLPI:

  glpi-netscan install --server https://glpi.example.com --secret <key>
  systemctl enable --now glpi-netscan
EOF
