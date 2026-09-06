// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package updater implements the scanner's self-update.
//
// The shape is deliberately the same as the osquery agent's, because a site
// running both should not have to hold two models of how its fleet upgrades:
// the server publishes a verified package, tells a stable subset of the fleet
// about it, and each agent stages it, restarts onto it, and proves it works —
// or is rolled back from outside by a preflight script.
//
// The one substantive difference is the payload. The osquery agent ships a
// bundle (supervisor, osqueryd, extension, preflight) and therefore unpacks a
// tar.gz; a scanner is a single static binary, so a package here is just that
// binary. That removes archive extraction — and its path-traversal, symlink
// and file-mode handling — from the most safety-critical path in the program,
// which is worth more than the bandwidth an archive would save. Compression is
// still available for free: Go's HTTP client negotiates gzip transparently, so
// a server configured to compress the download needs nothing here.
package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bijstaan/glpi-netscan/internal/client"
	"github.com/bijstaan/glpi-netscan/internal/config"
	"github.com/bijstaan/glpi-netscan/internal/version"
)

// MarkerName records an update that has been staged but not yet proven good.
//
// Read by the preflight script before the service starts, which is what makes
// rollback possible in the case the scanner cannot handle itself: a new binary
// so broken it never runs. There is no process left to notice that, so the
// decision has to be made from outside the binary.
const MarkerName = "update-pending.json"

// MaxAttempts is how many failed starts the preflight script tolerates before
// reverting. Kept here as the single definition; preflight.sh reads it from
// the marker rather than hardcoding a second copy.
const MaxAttempts = 3

// RejectedName quarantines a version that was rolled back.
//
// Written by the preflight script, because it is the only party that witnesses
// the rollback. Without it a rolled-back machine ping-pongs: preflight reverts
// to the working version, that version polls, is offered the same broken build
// again, stages it again — and because staging records whatever `current` points
// at as the rollback target, the second attempt records the *broken* version as
// the thing to fall back to. One bad release then has no way back at all.
//
// Quarantine is per-version and permanent until a different version is offered,
// so publishing a fix reaches the machine immediately while the broken build
// stays refused.
const RejectedName = "update-rejected.json"

// Rejected records a version this machine has already failed to start.
type Rejected struct {
	Version    string `json:"version"`
	RejectedAt string `json:"rejected_at"`
}

// Marker is the staged-update record shared with the preflight script.
type Marker struct {
	PreviousVersion string `json:"previous_version"`
	NewVersion      string `json:"new_version"`
	Attempts        int    `json:"attempts"`
	MaxAttempts     int    `json:"max_attempts"`
	StagedAt        string `json:"staged_at"`
}

// ErrNotVersioned means this install has no versioned tree to update into —
// the scanner was installed as a plain binary rather than by the package.
var ErrNotVersioned = errors.New("install root has no versions directory; self-update needs a package install")

// Updater applies packages offered by the server.
type Updater struct {
	cfg config.Config
	api *client.Client
}

func New(cfg config.Config, api *client.Client) *Updater {
	return &Updater{cfg: cfg, api: api}
}

// Arch reports the architecture in the vocabulary the server publishes under.
func Arch() string { return runtime.GOARCH }

// Platform reports the OS in the vocabulary the server publishes under.
func Platform() string { return runtime.GOOS }

func (u *Updater) markerPath() string {
	return filepath.Join(u.cfg.StateDir, MarkerName)
}

func (u *Updater) rejectedPath() string {
	return filepath.Join(u.cfg.StateDir, RejectedName)
}

func (u *Updater) versionsDir() string {
	return filepath.Join(u.cfg.InstallRoot, "versions")
}

func (u *Updater) currentLink() string {
	return filepath.Join(u.cfg.InstallRoot, "current")
}

// Consider applies an update offer from a job poll.
//
// Returns true when a new version has been staged and activated, meaning the
// process should exit so the service manager restarts it onto that version.
func (u *Updater) Consider(offer *client.UpdateOffer) (bool, error) {
	if offer == nil || !offer.Available || offer.Package == nil {
		return false, nil
	}

	pkg := *offer.Package
	if pkg.Version == "" {
		return false, nil
	}

	if !u.cfg.UpdatesEnabled {
		// The server offers an update but this host has opted out. Said once
		// per poll rather than silently ignored: an operator looking at a
		// scanner that will not move off an old version needs to see why here,
		// because from the server it is indistinguishable from a scanner that
		// never received the offer.
		log.Printf("update to %s offered but disabled on this host (updates_enabled = false)", pkg.Version)
		return false, nil
	}

	if sameVersion(pkg.Version, version.Version) {
		return false, nil
	}

	// This machine has already tried this version and could not start it.
	// Retrying automatically would loop forever; the fix is a new release, not
	// another attempt at the same one.
	if rejected := u.rejectedVersion(); rejected != "" && sameVersion(rejected, pkg.Version) {
		log.Printf("update to %s offered but this host already failed to start it; "+
			"refusing until a different version is published", pkg.Version)
		return false, nil
	}

	// An update is staged and unresolved — we are running neither it nor,
	// necessarily, what the marker calls previous. Staging a second update on
	// top would overwrite the rollback target with a version that has not
	// proven anything, which is the one state preflight cannot recover from.
	if pending, ok := u.pendingMarker(); ok && !sameVersion(pending.NewVersion, version.Version) {
		log.Printf("update to %s offered but %s is still staged and unconfirmed; "+
			"leaving the rollback record intact", pkg.Version, pending.NewVersion)
		return false, nil
	}

	log.Printf("update offered: %s (running %s, ring %d of %d%%)",
		pkg.Version, version.Version, offer.Ring, offer.RolloutPercent)

	if err := u.apply(pkg); err != nil {
		return false, err
	}

	return true, nil
}

// ConfirmHealthy clears a staged-update marker once the new version has proven
// it can both run and reach the server.
//
// Reaching the server is the load-bearing half. Merely starting is not enough:
// a version that runs but cannot work — wrong CA, unparseable config, a
// protocol change — would otherwise be recorded as a successful update, the
// rollback guard cleared, and the previous version eventually pruned, leaving
// no way back without touching the machine.
func (u *Updater) ConfirmHealthy() {
	path := u.markerPath()

	raw, err := os.ReadFile(path)
	if err != nil {
		return // nothing staged
	}

	var marker Marker
	if err := json.Unmarshal(raw, &marker); err != nil {
		_ = os.Remove(path)
		return
	}

	if marker.NewVersion != "" && !sameVersion(marker.NewVersion, version.Version) {
		// We are not the version that was staged, so the preflight script has
		// probably rolled back already. Leaving the marker alone lets it finish
		// managing that; clearing it here would strand the rollback halfway.
		log.Printf("running version %s differs from the staged %s; leaving the update marker for preflight",
			version.Version, marker.NewVersion)
		return
	}

	if err := os.Remove(path); err != nil {
		log.Printf("could not clear update marker: %v", err)
		return
	}

	log.Printf("update to %s confirmed healthy (previous %s)", version.Version, marker.PreviousVersion)

	u.pruneOldVersions(marker.PreviousVersion)
}

// Pending reports whether an update is awaiting confirmation, so the first
// poll after a restart can be brought forward.
func (u *Updater) Pending() bool {
	_, ok := u.pendingMarker()
	return ok
}

// pendingMarker reads the staged-update record, if there is a readable one.
func (u *Updater) pendingMarker() (Marker, bool) {
	raw, err := os.ReadFile(u.markerPath())
	if err != nil {
		return Marker{}, false
	}

	var marker Marker
	if err := json.Unmarshal(raw, &marker); err != nil {
		return Marker{}, false
	}

	return marker, true
}

// rejectedVersion reports the version preflight last rolled back from.
func (u *Updater) rejectedVersion() string {
	raw, err := os.ReadFile(u.rejectedPath())
	if err != nil {
		return ""
	}

	var rejected Rejected
	if err := json.Unmarshal(raw, &rejected); err != nil {
		return ""
	}

	return rejected.Version
}

func (u *Updater) apply(pkg client.Package) error {
	// Refuse rather than improvise. A scanner dropped in at /usr/bin by hand
	// has nowhere to put a second version and no symlink to flip, and a
	// half-applied update there would replace a working binary with no way
	// back.
	if info, err := os.Stat(u.versionsDir()); err != nil || !info.IsDir() {
		return ErrNotVersioned
	}

	target := filepath.Join(u.versionsDir(), pkg.Version)
	staging := target + ".staging"

	_ = os.RemoveAll(staging)
	// 0750: this directory is renamed into place as versions/<v>, and the whole
	// install tree belongs to the unprivileged glpi-netscan account the service
	// runs as. Nothing else on the machine starts the scanner — the unit runs it
	// through the `current` symlink, and root is not stopped by a mode — so
	// there is no reason for the tree to be readable by every local account.
	if err := os.MkdirAll(staging, 0o750); err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	binary := filepath.Join(staging, BinaryName())
	if err := u.download(pkg, binary); err != nil {
		return err
	}

	if err := verifyPayload(binary, pkg.Version); err != nil {
		return fmt.Errorf("staged package rejected: %w", err)
	}

	_ = os.RemoveAll(target)
	if err := os.Rename(staging, target); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	previous, _ := filepath.EvalSymlinks(u.currentLink())

	marker := Marker{
		PreviousVersion: filepath.Base(previous),
		NewVersion:      pkg.Version,
		Attempts:        0,
		MaxAttempts:     MaxAttempts,
		StagedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	// The marker must exist before the symlink moves. In the other order a
	// crash in between would leave the new version active with no rollback
	// record, which is the one state the preflight script cannot recover from.
	if err := os.WriteFile(u.markerPath(), body, 0o600); err != nil {
		return fmt.Errorf("write update marker: %w", err)
	}

	if err := FlipCurrent(u.currentLink(), target); err != nil {
		_ = os.Remove(u.markerPath())
		return fmt.Errorf("activate: %w", err)
	}

	// A different version is now on its way in, so the old quarantine record no
	// longer describes anything and would only confuse the next diagnosis.
	if err := os.Remove(u.rejectedPath()); err != nil && !os.IsNotExist(err) {
		log.Printf("could not clear the rejected-version record: %v", err)
	}

	log.Printf("update to %s staged and activated (previous %s); restarting onto it",
		pkg.Version, marker.PreviousVersion)

	return nil
}

// download fetches a package and verifies it.
//
// Verification is the entire security model of self-update. An agent that
// installs whatever it downloads is a remote code execution channel into every
// machine running it, and TLS to the right host proves only where the bytes
// came from — not that they are the bytes the administrator published. The
// checksum is the administrator's statement about content, and it is checked
// before anything is ever executed.
func (u *Updater) download(pkg client.Package, dest string) error {
	want := strings.ToLower(strings.TrimSpace(pkg.SHA256))
	if len(want) != 64 {
		return fmt.Errorf("package %s has no usable checksum; refusing to install", pkg.Version)
	}

	// 0750, not 0755: the file has to be executable by the account that will
	// run it, and by nobody else. verifyPayload executes it as that same
	// account before it can become `current`, so nothing is lost by keeping it
	// off limits to the rest of the machine.
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o750)
	if err != nil {
		return err
	}
	// O_CREATE honours the umask, so a service started under a restrictive one
	// would otherwise land a binary it cannot execute — which surfaces only
	// after the symlink has already moved.
	if err := f.Chmod(0o750); err != nil {
		f.Close()
		return err
	}

	digest := sha256.New()

	// Bounded so a wrong or hostile URL cannot fill the disk. The slack above
	// the stated size lets the mismatch below produce a clear error rather than
	// a truncation that happens to hash differently.
	limit := pkg.Size + (1 << 20)
	if pkg.Size <= 0 {
		limit = 256 << 20
	}

	written, copyErr := u.api.Download(pkg.URL, io.MultiWriter(f, digest), limit)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}

	if pkg.Size > 0 && written != pkg.Size {
		return fmt.Errorf("size mismatch: expected %d bytes, got %d", pkg.Size, written)
	}

	got := hex.EncodeToString(digest.Sum(nil))
	if got != want {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", want, got)
	}

	log.Printf("package %s verified (%d bytes, sha256 %s)", pkg.Version, written, got)

	return nil
}

// verifyPayload runs the downloaded binary once, before it can become current.
//
// Cheap, and it catches the failures a checksum cannot: a package built for the
// wrong architecture, or the right bytes for the wrong version. Both are caught
// while the old version is still active and recoverable, which is the only time
// catching them is easy.
func verifyPayload(binary, expected string) error {
	info, err := os.Stat(binary)
	if err != nil {
		return fmt.Errorf("missing %s: %w", binary, err)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", binary)
	}

	out, err := exec.Command(binary, "-version").Output()
	if err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}

	// The binary prints "glpi-netscan <version>"; compare the version alone so
	// this does not break if the banner is ever reworded.
	reported := strings.TrimSpace(string(out))
	reported = strings.TrimPrefix(reported, "glpi-netscan ")
	if !sameVersion(reported, expected) {
		return fmt.Errorf("new binary reports version %q, expected %q", reported, expected)
	}

	return nil
}

// pruneOldVersions keeps the running and previous versions and removes the
// rest, so a long-lived scanner does not accumulate every release it has run.
//
// Called only after a confirmed-healthy update, so the version being kept as
// "previous" is always one that is known to work.
func (u *Updater) pruneOldVersions(keep string) {
	entries, err := os.ReadDir(u.versionsDir())
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if sameVersion(name, version.Version) || name == keep || strings.HasSuffix(name, ".staging") {
			continue
		}
		path := filepath.Join(u.versionsDir(), name)
		if err := os.RemoveAll(path); err != nil {
			log.Printf("could not remove old version %s: %v", path, err)
			continue
		}
		log.Printf("removed old version %s", name)
	}
}

func sameVersion(a, b string) bool {
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}
