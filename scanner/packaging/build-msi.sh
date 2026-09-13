#!/usr/bin/env bash
# Build a Windows MSI from a binary produced by build.sh.
#
#   ./packaging/build-msi.sh <version> <arch>        # arch: amd64 | arm64
#
# Built with wixl, from GNOME's msitools:
#
#   apt-get install wixl        # note: a *separate* package from msitools,
#                               # which ships msiinfo/msibuild but not wixl
#
# wixl rather than the WiX Toolset for two reasons. WiX only ever emits an MSI
# on Windows, so a release could not be built in one place alongside everything
# else; and from v6 it requires accepting the Open Source Maintenance Fee EULA,
# with a fee due above a revenue threshold. wixl is LGPL, native, and has
# neither problem.
#
# The binary from build.sh is the input, so what the MSI installs is
# byte-identical to what a self-update would fetch. An installer that compiled
# its own copy would be testing a different artifact to the one the fleet runs.
#
# Signing is opt-in and needs osslsigncode:
#
#   SIGN_PFX       path to a code-signing certificate
#   SIGN_PASSWORD  its password
#   SIGN_TIMESTAMP RFC-3161 timestamp URL (default DigiCert's)
#
# Without them you get an unsigned MSI: fine for testing, but SmartScreen warns
# on it and many fleets refuse unsigned installers outright.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:?usage: build-msi.sh <version> <arch>}"
ARCH="${2:-amd64}"

DIST="dist/${VERSION}"
binary="${DIST}/glpi-netscan_${VERSION}_windows_${ARCH}.exe"
[[ -f "$binary" ]] || { echo "missing $binary — run VERSION=$VERSION ./build.sh" >&2; exit 1; }

for tool in wixl msiinfo msibuild; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool not found — install it with: apt-get install wixl msitools" >&2; exit 2; }
done

# MSI's ProductVersion is major.minor.build with a 65535 ceiling on each field,
# so a prerelease suffix has to be dropped for that field. The full version is
# passed separately and is what names the versioned directory — the scanner
# compares that name against the version it reports, so the two must agree.
msi_version="$(printf '%s' "$VERSION" | sed -E 's/^v//; s/[-+].*$//')"
if [[ ! "$msi_version" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]]; then
  echo "cannot express version '$VERSION' as an MSI ProductVersion" >&2
  exit 1
fi
full_version="${VERSION#v}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stage="${work}/stage"
mkdir -p "$stage"
# Named as the service expects to find it, not as the release artifact is named.
cp "$binary" "${stage}/glpi-netscan.exe"

out="${DIST}/glpi-netscan_${VERSION}_${ARCH}.msi"

# wixl has no arm64 target, so both architectures are built as x64 and the
# summary-information template is corrected below. The template is the only
# thing that differs: it is what tells Windows which platform the package is
# for, and everything else in the database is architecture-independent.
wixl -a x64 \
  -D "Version=${msi_version}" \
  -D "FullVersion=${full_version}" \
  -D "StageDir=${stage}" \
  -o "$out" packaging/glpi-netscan.wxs

case "$ARCH" in
  amd64) template="x64;1033" ;;
  arm64) template="Arm64;1033" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
msibuild "$out" -s "GLPI Netscan Scanner" "Bijstaan" "$template"

# Extend SecureCustomProperties so the deployment properties survive the crossing
# into the elevated execute sequence. It cannot be declared in the .wxs — that
# collides with the row MajorUpgrade generates — so the row is edited here.
# msiinfo emits CRLF, so every read of it is stripped: a trailing carriage
# return silently breaks both "$" anchors and last-field comparisons, which is
# exactly the kind of check that then passes on a broken package.
table() { msiinfo export "$out" "$1" | tr -d '\r'; }

existing="$(table Property | awk -F'\t' '$1=="SecureCustomProperties"{print $2}')"
msibuild "$out" -q "UPDATE \`Property\` SET \`Value\`='${existing:+${existing};}SERVER;ENROLLSECRET;CACERT;SCANNERNAME;NOUPDATES' WHERE \`Property\`='SecureCustomProperties'"

# --- verify -----------------------------------------------------------------
# A build that silently produces a subtly wrong MSI is worse than one that
# fails: these are the properties the installer is *for*, and every one of them
# has been wrong at some point in this file's history.
fail() { echo "MSI verification failed: $*" >&2; exit 1; }

props="$(table Property)"
grep -q "^SecureCustomProperties.*ENROLLSECRET" <<<"$props" || fail "ENROLLSECRET is not a secure property"
grep -q "^MsiHiddenProperties.*ENROLLSECRET" <<<"$props" || fail "ENROLLSECRET is not hidden from logs"
grep -q "^ProductVersion	${msi_version}$" <<<"$props" || fail "ProductVersion is not ${msi_version}"

# The versioned directory must be named exactly what the binary reports.
table Directory | awk -F'\t' -v v="$full_version" '$1=="VersionDir" && $3==v {found=1} END{exit !found}' \
  || fail "the versioned directory is not named ${full_version}"

# The service must exist, run unprivileged, and start on demand (3) so that
# nothing runs before msi-install has enrolled it.
table ServiceInstall \
  | awk -F'\t' '$2=="GLPINetscan" && $5==3 && $9=="NT AUTHORITY\\LocalService" {found=1} END{exit !found}' \
  || fail "the service is missing, privileged, or set to auto-start before enrolment"

# 3090 = deferred (1024) + no-impersonate (2048) + run an installed file (18).
# Without no-impersonate it would run as the invoking user and be unable to
# configure a service; without deferred it could not run elevated at all.
table CustomAction \
  | awk -F'\t' '$1=="MsiInstall" && $2==3090 {found=1} END{exit !found}' \
  || fail "MsiInstall is not a deferred, non-impersonated file action"

# A directory property formats with a trailing backslash, so a bare
# "[INSTALLFOLDER]" ends the argument with \" — an escaped quote to Windows'
# command-line parser, which then swallows the rest of the line into that one
# argument. The .wxs appends a period to prevent it; this is the assertion that
# stops it coming back. It cost a run of silent 1603s to find once.
table CustomAction \
  | awk -F'\t' '$4 ~ /\[INSTALLFOLDER\]"/ {bad=1} END{exit bad}' \
  || fail "a custom action quotes [INSTALLFOLDER] directly; write \"[INSTALLFOLDER].\" so the trailing backslash cannot escape the closing quote"

# 3186 = deferred (1024) + no-impersonate (2048) + continue (64) + run an EXE
# named by a property (50). NOT 18: a type 18 action names a File table row and
# msiexec resolves it to that file's installed path when it writes the script,
# which during an uninstall is a path the component no longer has. The action
# then fails to schedule at all — "Return value 3", nothing launched, 1603 —
# and Return="ignore" does not cover it, because there is no exit code to
# ignore. A property is just a string, so it resolves whatever the component is
# doing.
table CustomAction \
  | awk -F'\t' '$1=="MsiUninstall" && $2==3186 {found=1} END{exit !found}' \
  || fail "MsiUninstall is not a deferred, non-impersonated property action; a FileKey action cannot be scheduled during uninstall"

# And the property has to name the binary inside the directory this package
# actually installs, or the uninstall action launches nothing. Built here as
# a literal rather than an awk -v: awk reads escape sequences in a -v value,
# and a version starting with a digit turns \0.0.0-ci into an octal escape.
want_exe="[INSTALLFOLDER]versions\\${full_version}\\glpi-netscan.exe"
table CustomAction | grep -qF "SetUninstallExe	51	UninstallExe	${want_exe}" \
  || fail "SetUninstallExe does not point at ${want_exe}"

# Where each custom action actually landed. wixl resolves Before=/After=
# anchors against whatever it has placed so far, so these are pinned by number
# in the .wxs — and a number is only worth pinning if something checks it.
# MsiUninstall in front of InstallInitialize (1500) cannot be scheduled at all;
# MsiInstall in front of InstallServices (5800) would configure a service that
# does not exist yet.
seq="$(msiinfo export "$out" InstallExecuteSequence | tr -d '\r')"
want_seq() {
  grep -q "^$1	.*	$2$" <<<"$seq" || fail "$1 is not sequenced at $2"
}
want_seq SetNoUpdates 1402
want_seq SetUninstallExe 1403
want_seq MsiUninstall 2001
want_seq MsiInstall 5801

grep -q "^Template: ${template}$" <<<"$(msiinfo suminfo "$out" | tr -d '\r')" || fail "summary template is not ${template}"

if [[ -n "${SIGN_PFX:-}" ]]; then
  timestamp="${SIGN_TIMESTAMP:-http://timestamp.digicert.com}"
  echo "==> signing"
  command -v osslsigncode >/dev/null 2>&1 || { echo "SIGN_PFX is set but osslsigncode is not installed" >&2; exit 1; }
  osslsigncode sign -pkcs12 "$SIGN_PFX" -pass "${SIGN_PASSWORD:-}" \
    -h sha256 -ts "$timestamp" -in "$out" -out "${out}.signed"
  mv "${out}.signed" "$out"
else
  echo "warning: no SIGN_PFX — producing an unsigned MSI that SmartScreen will warn on" >&2
fi

sha="$(sha256sum "$out" | cut -d' ' -f1)"
printf '%s  %s\n' "$sha" "$(basename "$out")" > "${out}.sha256"

cat <<EOF

${out}
  sha256 ${sha}
  size   $(stat -c%s "$out")

Deploy with:
  msiexec /i $(basename "$out") /qn SERVER=https://glpi.example.com ENROLLSECRET=<key>
EOF
