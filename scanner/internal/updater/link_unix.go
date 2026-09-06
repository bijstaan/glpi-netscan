// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package updater

import "os"

// BinaryName is the executable inside a version directory.
func BinaryName() string { return "glpi-netscan" }

// FlipCurrent repoints `current` at a version directory.
//
// Built from a temporary symlink and renamed over the old one, because rename
// is atomic: there is never an instant in which `current` does not exist, and a
// service restart landing in that window would otherwise find no binary at all.
func FlipCurrent(link, target string) error {
	tmp := link + ".new"
	_ = os.Remove(tmp)

	if err := os.Symlink(target, tmp); err != nil {
		return err
	}

	return os.Rename(tmp, link)
}
