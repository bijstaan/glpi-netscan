#!/usr/bin/env bash
# Rollback guard, run by the service manager BEFORE the scanner starts.
#
# This exists because the scanner cannot roll itself back from the one failure
# that matters most: a new version so broken it never runs. There is then no
# process left to notice the problem, and the machine is left with no working
# scanner — which from GLPI looks exactly like a scanner that has been switched
# off, with no remote way back.
#
# So the decision is made from outside the binary. Each start attempt increments
# a counter in the staged-update marker; once it reaches max_attempts the
# `current` symlink is pointed back at the previous version and the marker
# cleared.
#
# The scanner clears the marker itself once it has started AND reached GLPI, so
# a version that runs but cannot work — wrong CA, unparseable config — is caught
# by the same mechanism.
#
# Deliberately outside the versioned tree. If this script were part of a release
# it could itself be replaced by a broken one, and the guard would go down with
# the thing it is guarding.
set -euo pipefail

STATE_DIR="${GLPI_NETSCAN_STATE_DIR:-/var/lib/glpi-netscan}"
INSTALL_ROOT="${GLPI_NETSCAN_INSTALL_ROOT:-/opt/glpi-netscan}"
MARKER="${STATE_DIR}/update-pending.json"
REJECTED="${STATE_DIR}/update-rejected.json"

log() { echo "glpi-netscan preflight: $*" >&2; }

[[ -f "$MARKER" ]] || exit 0

read_field() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" "$MARKER" | head -1
}

attempts="$(read_field attempts)"
previous="$(read_field previous_version)"
new_version="$(read_field new_version)"
max_attempts="$(read_field max_attempts)"

attempts="${attempts:-0}"
# Read from the marker rather than hardcoded, so the limit has one definition
# (updater.MaxAttempts) instead of two that can drift apart.
max_attempts="${max_attempts:-3}"

# Quarantine the version we are rolling back from.
#
# The scanner reads this and refuses to install that version again. Without it
# the machine ping-pongs: we revert to the working version, it polls, is offered
# the same broken build, and stages it again — recording the broken version as
# its own rollback target, after which there is no way back at all.
quarantine() {
  cat > "${REJECTED}.tmp" <<JSON
{
  "version": "$1",
  "rejected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
  mv -f "${REJECTED}.tmp" "$REJECTED"
}

if [[ "$attempts" -ge "$max_attempts" ]]; then
  if [[ -n "$previous" && -d "${INSTALL_ROOT}/versions/${previous}" ]]; then
    log "version ${new_version} failed to start ${attempts} times; rolling back to ${previous}"
    ln -sfn "${INSTALL_ROOT}/versions/${previous}" "${INSTALL_ROOT}/current.new"
    mv -Tf "${INSTALL_ROOT}/current.new" "${INSTALL_ROOT}/current"
    quarantine "$new_version"
    rm -f "$MARKER"
  else
    # Nothing to go back to. Clearing the marker stops an unstartable version
    # being retried forever; the failure is in the journal, and the scanner's
    # version will stop advancing in GLPI, which is the signal an operator sees.
    log "version ${new_version} failed ${attempts} times and there is no previous version to restore"
    quarantine "$new_version"
    rm -f "$MARKER"
  fi
  exit 0
fi

next=$((attempts + 1))
tmp="${MARKER}.tmp"
sed "s/\"attempts\"[[:space:]]*:[[:space:]]*${attempts}/\"attempts\": ${next}/" "$MARKER" > "$tmp"
mv -f "$tmp" "$MARKER"

log "starting staged version ${new_version} (attempt ${next}/${max_attempts})"
