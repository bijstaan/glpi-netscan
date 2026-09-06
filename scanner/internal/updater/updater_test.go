// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bijstaan/glpi-netscan/internal/client"
	"github.com/bijstaan/glpi-netscan/internal/config"
	"github.com/bijstaan/glpi-netscan/internal/version"
)

// fakeRelease builds a real executable that prints the banner the updater
// checks, so verifyPayload is exercised as it will be in production rather than
// against a stub. A shell script is enough: the updater only cares that the
// file runs and reports the right version.
func fakeRelease(t *testing.T, reported string) []byte {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the fake release is a shell script")
	}

	return []byte("#!/bin/sh\necho 'glpi-netscan " + reported + "'\n")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// serve publishes body at a URL and returns an updater wired to fetch it.
func serve(t *testing.T, body []byte) (*Updater, string, config.Config) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	cfg := config.Config{
		Server:         srv.URL,
		StateDir:       filepath.Join(root, "state"),
		InstallRoot:    filepath.Join(root, "install"),
		UpdatesEnabled: true,
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.InstallRoot, "versions"), 0o755); err != nil {
		t.Fatal(err)
	}

	// httptest speaks plain HTTP and the client refuses that by default, which
	// is the right default — the download itself is authenticated by checksum,
	// not by transport.
	api, err := client.New(client.Config{BaseURL: srv.URL, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}

	return New(cfg, api), srv.URL, cfg
}

func offer(url, ver, sum string, size int64) *client.UpdateOffer {
	return &client.UpdateOffer{
		Available: true,
		Package: &client.Package{
			Version: ver,
			URL:     url,
			SHA256:  sum,
			Size:    size,
		},
		Ring:           5,
		RolloutPercent: 50,
	}
}

func TestConsiderStagesAndActivates(t *testing.T) {
	body := fakeRelease(t, "9.9.9")
	up, url, cfg := serve(t, body)

	staged, err := up.Consider(offer(url, "9.9.9", sha256Hex(body), int64(len(body))))
	if err != nil {
		t.Fatalf("Consider: %v", err)
	}
	if !staged {
		t.Fatal("expected the update to be staged")
	}

	// `current` must resolve to the new version, and the binary must be there.
	resolved, err := filepath.EvalSymlinks(filepath.Join(cfg.InstallRoot, "current"))
	if err != nil {
		t.Fatalf("current symlink: %v", err)
	}
	if filepath.Base(resolved) != "9.9.9" {
		t.Errorf("current points at %s, want 9.9.9", filepath.Base(resolved))
	}
	if _, err := os.Stat(filepath.Join(resolved, BinaryName())); err != nil {
		t.Errorf("binary missing from the activated version: %v", err)
	}

	// The marker is what makes rollback possible; without it a version that
	// cannot start would never be reverted.
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, MarkerName))
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	var marker Marker
	if err := json.Unmarshal(raw, &marker); err != nil {
		t.Fatalf("marker is not valid JSON: %v", err)
	}
	if marker.NewVersion != "9.9.9" {
		t.Errorf("marker new_version = %q, want 9.9.9", marker.NewVersion)
	}
	if marker.MaxAttempts != MaxAttempts {
		t.Errorf("marker max_attempts = %d, want %d", marker.MaxAttempts, MaxAttempts)
	}

	// The staging directory must not survive: left behind, the next update to
	// the same version would find a populated directory and skip the download.
	if _, err := os.Stat(filepath.Join(cfg.InstallRoot, "versions", "9.9.9.staging")); !os.IsNotExist(err) {
		t.Error("staging directory was left behind")
	}
}

func TestConsiderRejectsBadChecksum(t *testing.T) {
	body := fakeRelease(t, "9.9.9")
	up, url, cfg := serve(t, body)

	bad := strings.Repeat("a", 64)
	staged, err := up.Consider(offer(url, "9.9.9", bad, int64(len(body))))
	if staged {
		t.Fatal("a package with the wrong checksum was staged")
	}
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want a checksum mismatch, got %v", err)
	}

	// Nothing may be activated on a rejected package — this is the whole point.
	if _, err := os.Lstat(filepath.Join(cfg.InstallRoot, "current")); !os.IsNotExist(err) {
		t.Error("current symlink was created for a rejected package")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, MarkerName)); !os.IsNotExist(err) {
		t.Error("an update marker was written for a rejected package")
	}
}

func TestConsiderRejectsVersionMismatch(t *testing.T) {
	// Correct bytes, correct checksum — but the binary reports a different
	// version than the manifest claims. This is what catches a package built
	// from the wrong commit, which no checksum can detect.
	body := fakeRelease(t, "1.2.3")
	up, url, cfg := serve(t, body)

	staged, err := up.Consider(offer(url, "9.9.9", sha256Hex(body), int64(len(body))))
	if staged {
		t.Fatal("a mislabelled package was staged")
	}
	if err == nil || !strings.Contains(err.Error(), "reports version") {
		t.Fatalf("want a version mismatch, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cfg.InstallRoot, "current")); !os.IsNotExist(err) {
		t.Error("current symlink was created for a mislabelled package")
	}
}

func TestConsiderRejectsSizeMismatch(t *testing.T) {
	body := fakeRelease(t, "9.9.9")
	up, url, _ := serve(t, body)

	staged, err := up.Consider(offer(url, "9.9.9", sha256Hex(body), int64(len(body))+500))
	if staged {
		t.Fatal("a short package was staged")
	}
	if err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("want a size mismatch, got %v", err)
	}
}

func TestConsiderHonoursHostOptOut(t *testing.T) {
	body := fakeRelease(t, "9.9.9")
	up, url, _ := serve(t, body)
	up.cfg.UpdatesEnabled = false

	staged, err := up.Consider(offer(url, "9.9.9", sha256Hex(body), int64(len(body))))
	if err != nil {
		t.Fatalf("opting out is not an error: %v", err)
	}
	if staged {
		t.Fatal("a pinned host staged an update")
	}
}

func TestConsiderIgnoresOwnVersion(t *testing.T) {
	body := fakeRelease(t, version.Version)
	up, url, _ := serve(t, body)

	staged, err := up.Consider(offer(url, version.Version, sha256Hex(body), int64(len(body))))
	if err != nil {
		t.Fatalf("Consider: %v", err)
	}
	if staged {
		t.Fatal("staged an update to the version already running")
	}
}

func TestConsiderTolerantOfNoOffer(t *testing.T) {
	up, _, _ := serve(t, nil)

	for name, o := range map[string]*client.UpdateOffer{
		"nil":              nil,
		"unavailable":      {Available: false},
		"available/no pkg": {Available: true},
	} {
		staged, err := up.Consider(o)
		if staged || err != nil {
			t.Errorf("%s: staged=%v err=%v, want false/nil", name, staged, err)
		}
	}
}

func TestApplyRefusesWithoutVersionedTree(t *testing.T) {
	// A scanner installed by hand at /usr/bin has nowhere to put a second
	// version. Refusing is the point: replacing the running binary in place
	// would leave no way back if the new one is broken.
	body := fakeRelease(t, "9.9.9")
	up, url, cfg := serve(t, body)
	if err := os.RemoveAll(filepath.Join(cfg.InstallRoot, "versions")); err != nil {
		t.Fatal(err)
	}

	_, err := up.Consider(offer(url, "9.9.9", sha256Hex(body), int64(len(body))))
	if err == nil || !strings.Contains(err.Error(), "versions directory") {
		t.Fatalf("want ErrNotVersioned, got %v", err)
	}
}

func TestConfirmHealthyClearsMarkerAndPrunes(t *testing.T) {
	up, _, cfg := serve(t, nil)

	versions := filepath.Join(cfg.InstallRoot, "versions")
	for _, v := range []string{version.Version, "0.0.1", "0.0.2"} {
		if err := os.MkdirAll(filepath.Join(versions, v), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	marker := Marker{PreviousVersion: "0.0.2", NewVersion: version.Version, MaxAttempts: MaxAttempts}
	body, _ := json.Marshal(marker)
	if err := os.WriteFile(filepath.Join(cfg.StateDir, MarkerName), body, 0o644); err != nil {
		t.Fatal(err)
	}

	up.ConfirmHealthy()

	if _, err := os.Stat(filepath.Join(cfg.StateDir, MarkerName)); !os.IsNotExist(err) {
		t.Error("marker survived a healthy confirmation")
	}
	// The immediately previous version stays: it is the only thing a manual
	// rollback has to fall back on.
	if _, err := os.Stat(filepath.Join(versions, "0.0.2")); err != nil {
		t.Error("the previous version was pruned")
	}
	if _, err := os.Stat(filepath.Join(versions, version.Version)); err != nil {
		t.Error("the running version was pruned")
	}
	if _, err := os.Stat(filepath.Join(versions, "0.0.1")); !os.IsNotExist(err) {
		t.Error("an older version was kept")
	}
}

func TestConfirmHealthyLeavesMarkerForAnotherVersion(t *testing.T) {
	// Running a version other than the staged one means preflight has rolled
	// back. Clearing the marker here would strand that rollback halfway.
	up, _, cfg := serve(t, nil)

	body, _ := json.Marshal(Marker{PreviousVersion: "0.0.1", NewVersion: "42.0.0"})
	path := filepath.Join(cfg.StateDir, MarkerName)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	up.ConfirmHealthy()

	if _, err := os.Stat(path); err != nil {
		t.Error("marker was cleared while running a different version")
	}
}

func TestPending(t *testing.T) {
	up, _, cfg := serve(t, nil)

	if up.Pending() {
		t.Error("Pending() is true with no marker")
	}
	if err := os.WriteFile(filepath.Join(cfg.StateDir, MarkerName), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !up.Pending() {
		t.Error("Pending() is false with a marker present")
	}
}

// TestPreflightRollsBack drives the real preflight script, because it is the
// only thing that can recover a machine whose new binary does not start — and
// it is written in shell, so nothing else in the Go test suite covers it.
func TestPreflightRollsBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight.sh is for the systemd install")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	script, err := filepath.Abs("../../packaging/preflight.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Skipf("preflight.sh not found: %v", err)
	}

	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	installRoot := filepath.Join(root, "install")
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if err := os.MkdirAll(filepath.Join(installRoot, "versions", v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(installRoot, "versions", "2.0.0"), filepath.Join(installRoot, "current")); err != nil {
		t.Fatal(err)
	}

	markerPath := filepath.Join(stateDir, MarkerName)
	write := func(m Marker) {
		body, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(markerPath, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func() {
		cmd := exec.Command("bash", script)
		cmd.Env = append(os.Environ(),
			"GLPI_NETSCAN_STATE_DIR="+stateDir,
			"GLPI_NETSCAN_INSTALL_ROOT="+installRoot,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("preflight failed: %v\n%s", err, out)
		}
	}
	attempts := func() int {
		raw, err := os.ReadFile(markerPath)
		if err != nil {
			return -1
		}
		var m Marker
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("preflight left the marker unparseable: %v\n%s", err, raw)
		}
		return m.Attempts
	}

	write(Marker{PreviousVersion: "1.0.0", NewVersion: "2.0.0", Attempts: 0, MaxAttempts: MaxAttempts})

	// MaxAttempts failed starts are tolerated: each only increments the
	// counter, and must leave the marker valid JSON since the agent parses the
	// same file. The revert happens on the start *after* the limit is reached.
	for want := 1; want <= MaxAttempts; want++ {
		run()
		if got := attempts(); got != want {
			t.Fatalf("after start %d, attempts = %d", want, got)
		}
		resolved, _ := filepath.EvalSymlinks(filepath.Join(installRoot, "current"))
		if filepath.Base(resolved) != "2.0.0" {
			t.Fatalf("rolled back early, at attempt %d", want)
		}
	}

	// The start that reaches the limit reverts.
	run()
	resolved, err := filepath.EvalSymlinks(filepath.Join(installRoot, "current"))
	if err != nil {
		t.Fatalf("current symlink after rollback: %v", err)
	}
	if filepath.Base(resolved) != "1.0.0" {
		t.Errorf("current is %s after rollback, want 1.0.0", filepath.Base(resolved))
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Error("marker survived the rollback, so the next start would roll back again")
	}

	// The quarantine record is what stops the restored version installing the
	// same broken build straight back again.
	raw, err := os.ReadFile(filepath.Join(stateDir, RejectedName))
	if err != nil {
		t.Fatalf("preflight did not quarantine the failed version: %v", err)
	}
	var rejected Rejected
	if err := json.Unmarshal(raw, &rejected); err != nil {
		t.Fatalf("the quarantine record is not valid JSON: %v\n%s", err, raw)
	}
	if rejected.Version != "2.0.0" {
		t.Errorf("quarantined version = %q, want 2.0.0", rejected.Version)
	}
}

// TestPreflightNoMarkerIsANoOp guards the ordinary case: the script runs before
// every single start, so a fault here takes the service down permanently.
func TestPreflightNoMarkerIsANoOp(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, _ := filepath.Abs("../../packaging/preflight.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("preflight.sh not found: %v", err)
	}

	root := t.TempDir()
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(),
		"GLPI_NETSCAN_STATE_DIR="+filepath.Join(root, "state"),
		"GLPI_NETSCAN_INSTALL_ROOT="+filepath.Join(root, "install"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("preflight must succeed when nothing is staged: %v\n%s", err, out)
	}
}

// TestUpdateOfferTolerantOfEmptyArray pins the PHP interop that would otherwise
// break every poll: an empty associative array serialises as `[]`, not `{}`,
// and a strict decode of the enclosing JobResponse would fail outright — so the
// scanner would stop receiving work, not merely stop updating.
func TestUpdateOfferTolerantOfEmptyArray(t *testing.T) {
	for _, body := range []string{`[]`, `null`, `{"available":false}`} {
		var resp client.JobResponse
		raw := fmt.Sprintf(`{"poll_interval":60,"update":%s}`, body)
		if err := json.Unmarshal([]byte(raw), &resp); err != nil {
			t.Fatalf("update=%s failed to decode: %v", body, err)
		}
		if resp.PollInterval != 60 {
			t.Errorf("update=%s lost the rest of the response", body)
		}
		if resp.Update.Available {
			t.Errorf("update=%s decoded as an available update", body)
		}
	}
}

// TestConsiderRefusesQuarantinedVersion covers the ping-pong: preflight reverts
// from a broken build, the restored version polls, and is offered that same
// build again. Retrying it would loop forever — and worse, the second staging
// records the broken version as its own rollback target, after which nothing
// can get the machine back.
func TestConsiderRefusesQuarantinedVersion(t *testing.T) {
	body := fakeRelease(t, "9.9.9")
	up, url, cfg := serve(t, body)

	rejected, _ := json.Marshal(Rejected{Version: "9.9.9", RejectedAt: "2026-01-01T00:00:00Z"})
	if err := os.WriteFile(filepath.Join(cfg.StateDir, RejectedName), rejected, 0o644); err != nil {
		t.Fatal(err)
	}

	staged, err := up.Consider(offer(url, "9.9.9", sha256Hex(body), int64(len(body))))
	if err != nil {
		t.Fatalf("refusing a quarantined version is not an error: %v", err)
	}
	if staged {
		t.Fatal("a version this host already failed to start was staged again")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, MarkerName)); !os.IsNotExist(err) {
		t.Error("a marker was written for a refused version")
	}
}

// TestConsiderAcceptsDifferentVersionAfterQuarantine: quarantine is per-version,
// so publishing a fix must reach the machine immediately.
func TestConsiderAcceptsDifferentVersionAfterQuarantine(t *testing.T) {
	body := fakeRelease(t, "9.9.10")
	up, url, cfg := serve(t, body)

	rejected, _ := json.Marshal(Rejected{Version: "9.9.9"})
	rejectedPath := filepath.Join(cfg.StateDir, RejectedName)
	if err := os.WriteFile(rejectedPath, rejected, 0o644); err != nil {
		t.Fatal(err)
	}

	staged, err := up.Consider(offer(url, "9.9.10", sha256Hex(body), int64(len(body))))
	if err != nil {
		t.Fatalf("Consider: %v", err)
	}
	if !staged {
		t.Fatal("a fixed release was refused because an older one was quarantined")
	}
	// The stale record would otherwise sit there misleading the next diagnosis.
	if _, err := os.Stat(rejectedPath); !os.IsNotExist(err) {
		t.Error("the quarantine record survived a successful update to another version")
	}
}

// TestConsiderRefusesWhileAnotherUpdateIsPending is the case the end-to-end run
// caught: an unconfirmed update is staged, and staging a second one over it
// would overwrite previous_version with a version that has proven nothing.
func TestConsiderRefusesWhileAnotherUpdateIsPending(t *testing.T) {
	body := fakeRelease(t, "9.9.9")
	up, url, cfg := serve(t, body)

	pending, _ := json.Marshal(Marker{PreviousVersion: "1.0.0", NewVersion: "8.8.8", MaxAttempts: MaxAttempts})
	markerPath := filepath.Join(cfg.StateDir, MarkerName)
	if err := os.WriteFile(markerPath, pending, 0o644); err != nil {
		t.Fatal(err)
	}

	staged, err := up.Consider(offer(url, "9.9.9", sha256Hex(body), int64(len(body))))
	if err != nil {
		t.Fatalf("declining while an update is in flight is not an error: %v", err)
	}
	if staged {
		t.Fatal("staged an update while another was unconfirmed")
	}

	raw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var after Marker
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if after.PreviousVersion != "1.0.0" || after.NewVersion != "8.8.8" {
		t.Errorf("the pending rollback record was overwritten: %+v", after)
	}
}

// Preflight is the in-process rollback guard used on Windows, where there is no
// ExecStartPre to hang a script from. It is not build-tagged, so it is tested
// here on the same terms as the shell guard it mirrors.
func preflightFixture(t *testing.T) (stateDir, installRoot string) {
	t.Helper()

	root := t.TempDir()
	stateDir = filepath.Join(root, "state")
	installRoot = filepath.Join(root, "install")

	for _, v := range []string{"1.0.0", "2.0.0"} {
		if err := os.MkdirAll(filepath.Join(installRoot, "versions", v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := FlipCurrent(filepath.Join(installRoot, "current"), filepath.Join(installRoot, "versions", "2.0.0")); err != nil {
		t.Fatal(err)
	}

	return stateDir, installRoot
}

func writeMarker(t *testing.T, stateDir string, m Marker) {
	t.Helper()
	body, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(stateDir, MarkerName), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightNoMarker(t *testing.T) {
	stateDir, installRoot := preflightFixture(t)

	if Preflight(stateDir, installRoot) {
		t.Fatal("asked to exit with nothing staged")
	}
}

func TestPreflightCountsThenRollsBack(t *testing.T) {
	stateDir, installRoot := preflightFixture(t)
	writeMarker(t, stateDir, Marker{PreviousVersion: "1.0.0", NewVersion: "2.0.0", MaxAttempts: MaxAttempts})

	markerPath := filepath.Join(stateDir, MarkerName)

	for want := 1; want <= MaxAttempts; want++ {
		if Preflight(stateDir, installRoot) {
			t.Fatalf("rolled back early, on attempt %d", want)
		}
		raw, err := os.ReadFile(markerPath)
		if err != nil {
			t.Fatalf("marker gone on attempt %d: %v", want, err)
		}
		var m Marker
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("marker unreadable on attempt %d: %v", want, err)
		}
		if m.Attempts != want {
			t.Fatalf("attempts = %d, want %d", m.Attempts, want)
		}
		// The rollback target must survive every increment, or the revert has
		// nothing to aim at when it finally happens.
		if m.PreviousVersion != "1.0.0" {
			t.Fatalf("previous_version became %q on attempt %d", m.PreviousVersion, want)
		}
	}

	if !Preflight(stateDir, installRoot) {
		t.Fatal("did not ask to exit after rolling back")
	}

	resolved, err := filepath.EvalSymlinks(filepath.Join(installRoot, "current"))
	if err != nil {
		t.Fatalf("current after rollback: %v", err)
	}
	if filepath.Base(resolved) != "1.0.0" {
		t.Errorf("current is %s after rollback, want 1.0.0", filepath.Base(resolved))
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Error("marker survived the rollback, so the next start would roll back again")
	}

	raw, err := os.ReadFile(filepath.Join(stateDir, RejectedName))
	if err != nil {
		t.Fatalf("the failed version was not quarantined: %v", err)
	}
	var rejected Rejected
	if err := json.Unmarshal(raw, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Version != "2.0.0" {
		t.Errorf("quarantined %q, want 2.0.0", rejected.Version)
	}
}

func TestPreflightWithNothingToRestore(t *testing.T) {
	// No previous version: retrying forever is worse than stopping, so the
	// marker is cleared and the version quarantined so it is not re-installed.
	stateDir, installRoot := preflightFixture(t)
	writeMarker(t, stateDir, Marker{NewVersion: "2.0.0", Attempts: MaxAttempts, MaxAttempts: MaxAttempts})

	if Preflight(stateDir, installRoot) {
		t.Error("asked to exit with no previous version to roll back to")
	}
	if _, err := os.Stat(filepath.Join(stateDir, MarkerName)); !os.IsNotExist(err) {
		t.Error("marker kept, so this would be retried forever")
	}
	if got := (&Updater{cfg: config.Config{StateDir: stateDir}}).rejectedVersion(); got != "2.0.0" {
		t.Errorf("quarantined %q, want 2.0.0", got)
	}
}

func TestPreflightDiscardsUnreadableMarker(t *testing.T) {
	// A corrupt marker cannot drive a rollback, and leaving it would block every
	// future update through the in-flight guard.
	stateDir, installRoot := preflightFixture(t)
	if err := os.WriteFile(filepath.Join(stateDir, MarkerName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	if Preflight(stateDir, installRoot) {
		t.Error("asked to exit on an unreadable marker")
	}
	if _, err := os.Stat(filepath.Join(stateDir, MarkerName)); !os.IsNotExist(err) {
		t.Error("an unreadable marker was kept and would block all future updates")
	}
}

// TestPreflightAgreesWithTheShellGuard pins the two implementations together.
// They are separate on purpose — the shell one survives a binary that cannot
// execute — but a machine must roll back after the same number of failed starts
// whichever platform it is on.
func TestPreflightAgreesWithTheShellGuard(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, _ := filepath.Abs("../../packaging/preflight.sh")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("preflight.sh not found: %v", err)
	}

	countStartsBeforeRollback := func(run func(state, install string) bool) int {
		stateDir, installRoot := preflightFixture(t)
		writeMarker(t, stateDir, Marker{PreviousVersion: "1.0.0", NewVersion: "2.0.0", MaxAttempts: MaxAttempts})

		for starts := 1; starts <= 10; starts++ {
			run(stateDir, installRoot)
			resolved, _ := filepath.EvalSymlinks(filepath.Join(installRoot, "current"))
			if filepath.Base(resolved) == "1.0.0" {
				return starts
			}
		}
		return -1
	}

	goStarts := countStartsBeforeRollback(func(state, install string) bool {
		return Preflight(state, install)
	})
	shellStarts := countStartsBeforeRollback(func(state, install string) bool {
		cmd := exec.Command("bash", script)
		cmd.Env = append(os.Environ(),
			"GLPI_NETSCAN_STATE_DIR="+state,
			"GLPI_NETSCAN_INSTALL_ROOT="+install,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("preflight.sh failed: %v\n%s", err, out)
		}
		return false
	})

	if goStarts != shellStarts {
		t.Errorf("rollback after %d starts in Go but %d in preflight.sh", goStarts, shellStarts)
	}
	if goStarts < 0 {
		t.Error("neither guard ever rolled back")
	}
}
