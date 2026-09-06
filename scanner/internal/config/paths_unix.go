// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package config

import "os"

// DefaultStateDir is where the token and update markers live when unset.
//
// Matches the systemd unit's StateDirectory=glpi-netscan, so the service and a
// hand-run `glpi-netscan install` agree on where the scanner's identity is kept
// without either having to be told.
func DefaultStateDir() string {
	if dir := os.Getenv("GLPI_NETSCAN_STATE_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/glpi-netscan"
}

// DefaultInstallRoot is the versioned install tree install-linux.sh creates.
func DefaultInstallRoot() string {
	if dir := os.Getenv("GLPI_NETSCAN_INSTALL_ROOT"); dir != "" {
		return dir
	}
	return "/opt/glpi-netscan"
}

// DefaultPath is where the service looks for its configuration.
func DefaultPath() string {
	return "/etc/glpi-netscan/agent.conf"
}
