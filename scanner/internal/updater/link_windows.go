// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package updater

import (
	"fmt"
	"os"
	"os/exec"
)

// BinaryName is the executable inside a version directory.
//
// The extension is not cosmetic. Go's exec resolves a path with no recognised
// extension by trying each PATHEXT entry and failing if none exists, so a file
// saved as plain "glpi-netscan" cannot be executed at all — which would make
// the updater's own verification step reject every package it downloads.
func BinaryName() string { return "glpi-netscan.exe" }

// FlipCurrent repoints `current` at a version directory.
//
// A directory junction rather than a symlink: creating a symlink on Windows
// needs developer mode or SeCreateSymbolicLinkPrivilege, and while the service
// happens to run as LocalSystem and would have it, the installer and any manual
// intervention would not. A junction works for any administrator, and it is
// what install-windows.ps1 lays down — so the updated tree and the freshly
// installed tree are the same shape.
//
// Unlike the POSIX path this cannot be atomic: Windows will not rename over an
// existing directory, so the old junction is removed first. The gap is
// tolerable because it only occurs while the scanner is deliberately on its way
// out to restart, and a failure here is reported rather than silently leaving
// `current` missing.
func FlipCurrent(link, target string) error {
	if _, err := os.Lstat(link); err == nil {
		// RemoveAll follows the junction on some Windows versions; Remove does
		// not, and deleting the link must never delete the version it names.
		if err := os.Remove(link); err != nil {
			return fmt.Errorf("remove the existing current link: %w", err)
		}
	}

	// mklink is a cmd builtin, so it cannot be exec'd directly.
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create junction %s -> %s: %w (%s)", link, target, err, out)
	}

	return nil
}
