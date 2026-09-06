#!/usr/bin/env bash
# Build the scanner for the platforms an MSP realistically deploys to.
#
# Static, dependency-free binaries: the whole point of a Go scanner rather than
# glpi-agent's Perl stack is that deploying to a remote site is copying one file.
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
OUT="${OUT:-dist/$VERSION}"
LDFLAGS="-s -w -X github.com/bijstaan/glpi-netscan/internal/version.Version=$VERSION"

mkdir -p "$OUT"

# Linux and Windows only. macOS is deliberately absent: a scanner is placed on
# a server or a small always-on box at a site, and Apple sells neither.
targets=(
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
  "windows/arm64"
)

for target in "${targets[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  name="glpi-netscan_${VERSION}_${os}_${arch}"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"

  echo "building $target"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/${name}${ext}" ./cmd/glpi-netscan

  ( cd "$OUT" && sha256sum "${name}${ext}" > "${name}${ext}.sha256" )
done

# Publishing a release in GLPI asks for the version, platform, architecture,
# URL, SHA-256 and size. Everything but the URL is known here, so print it
# rather than making someone re-derive it by hand — a mistyped checksum is
# refused by every scanner in the fleet, silently, until someone looks.
echo
echo "publish these under Setup > Network scanning > Published packages:"
printf '%-10s %-8s %-66s %s\n' PLATFORM ARCH SHA-256 SIZE
for target in "${targets[@]}"; do
  os="${target%/*}"; arch="${target#*/}"
  name="glpi-netscan_${VERSION}_${os}_${arch}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  file="$OUT/${name}${ext}"
  printf '%-10s %-8s %-66s %s\n' "$os" "$arch" "$(cut -d" " -f1 < "${file}.sha256")" "$(stat -c%s "$file")"
done

echo
echo "artifacts in $OUT"
