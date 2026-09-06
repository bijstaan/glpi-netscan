// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package config

import (
	"os"
	"path/filepath"
)

// Windows keeps machine-wide state and configuration under ProgramData, and
// program files under Program Files — the same split the osquery agent's
// installer uses, so a host running both puts them in the places an
// administrator already expects to look.

// dataRoot is %ProgramData%\GLPINetscan.
//
// ProgramData is read from the environment rather than hardcoded to C:\ because
// it moves on systems installed to another drive, and a service that guessed
// would silently write its token somewhere nobody looks.
func dataRoot() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "GLPINetscan")
}

// DefaultStateDir is where the token and update markers live when unset.
func DefaultStateDir() string {
	if dir := os.Getenv("GLPI_NETSCAN_STATE_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(dataRoot(), "state")
}

// DefaultInstallRoot is the versioned install tree install-windows.ps1 creates.
func DefaultInstallRoot() string {
	if dir := os.Getenv("GLPI_NETSCAN_INSTALL_ROOT"); dir != "" {
		return dir
	}

	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "GLPI Netscan")
}

// DefaultPath is where the service looks for its configuration.
func DefaultPath() string {
	return filepath.Join(dataRoot(), "agent.conf")
}
