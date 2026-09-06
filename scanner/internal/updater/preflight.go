// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package updater

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Preflight is the rollback guard, run once at startup before any other work.
//
// It exists for Windows. On Linux the guard is preflight.sh, invoked by systemd
// as ExecStartPre, and that is strictly better: it runs even when the new binary
// cannot be executed at all, which is the failure the guard most needs to catch
// — there is no process left to notice it, and the machine is left with no
// working scanner and no remote way back.
//
// Windows has no ExecStartPre. The service control manager starts one binary,
// so a guard that runs before that binary must either be a second program or be
// inside it. Rather than ship a launcher whose only job is to start another
// program, the check runs in-process here, as the first thing main does.
//
// That leaves one case uncovered: a staged binary that cannot start as a process
// at all. It is narrow, because a version is only ever activated after the
// updater has already run it once and compared the version it printed — so a
// package for the wrong architecture, a truncated download, or a missing runtime
// is rejected while the old version is still active. What remains is a binary
// that runs standalone but dies as a service, and that one does reach this code.
//
// Returns true when the caller should exit: `current` has been repointed at the
// previous version, and continuing would mean running the version just reverted.
func Preflight(stateDir, installRoot string) bool {
	markerPath := filepath.Join(stateDir, MarkerName)

	raw, err := os.ReadFile(markerPath)
	if err != nil {
		return false // nothing staged; the ordinary case
	}

	var marker Marker
	if err := json.Unmarshal(raw, &marker); err != nil {
		// An unreadable marker cannot drive a rollback decision, and leaving it
		// would block every future update through the in-flight guard.
		log.Printf("preflight: discarding an unreadable update marker: %v", err)
		_ = os.Remove(markerPath)
		return false
	}

	limit := marker.MaxAttempts
	if limit <= 0 {
		limit = MaxAttempts
	}

	if marker.Attempts < limit {
		marker.Attempts++
		if body, err := json.MarshalIndent(marker, "", "  "); err == nil {
			// 0600. The marker is what a rollback decision is read from; only
			// this process and preflight.sh, both running as the service
			// account, ever touch it.
			if err := os.WriteFile(markerPath, body, 0o600); err != nil {
				log.Printf("preflight: could not record the start attempt: %v", err)
			}
		}
		log.Printf("preflight: starting staged version %s (attempt %d/%d)",
			marker.NewVersion, marker.Attempts, limit)
		return false
	}

	previous := marker.PreviousVersion
	previousDir := filepath.Join(installRoot, "versions", previous)

	if previous == "" {
		// Nothing to go back to. Clearing the marker stops an unstartable
		// version being retried forever; the version will simply stop advancing
		// in GLPI, which is the signal an operator sees.
		log.Printf("preflight: version %s failed %d times and there is no previous version to restore",
			marker.NewVersion, marker.Attempts)
		quarantine(stateDir, marker.NewVersion)
		_ = os.Remove(markerPath)
		return false
	}

	if _, err := os.Stat(previousDir); err != nil {
		log.Printf("preflight: version %s failed %d times but the previous version %s is gone: %v",
			marker.NewVersion, marker.Attempts, previous, err)
		quarantine(stateDir, marker.NewVersion)
		_ = os.Remove(markerPath)
		return false
	}

	log.Printf("preflight: version %s failed to start %d times; rolling back to %s",
		marker.NewVersion, marker.Attempts, previous)

	if err := FlipCurrent(filepath.Join(installRoot, "current"), previousDir); err != nil {
		log.Printf("preflight: rollback failed: %v", err)
		return false
	}

	quarantine(stateDir, marker.NewVersion)
	_ = os.Remove(markerPath)

	return true
}

// quarantine records a version this machine could not start, so the restored
// version does not immediately install it again. See RejectedName.
func quarantine(stateDir, version string) {
	if version == "" {
		return
	}

	body, err := json.MarshalIndent(Rejected{
		Version:    version,
		RejectedAt: time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return
	}

	// 0600, as for the marker: a quarantine record is the reason a machine will
	// refuse a published version, and nothing outside the service reads it.
	if err := os.WriteFile(filepath.Join(stateDir, RejectedName), body, 0o600); err != nil {
		log.Printf("preflight: could not quarantine %s: %v", version, err)
	}
}
