// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

// subcommands dispatched before flag parsing.
var subcommands = map[string]func([]string) error{
	"install":       runInstall,
	"msi-install":   msiInstall,
	"msi-uninstall": msiUninstall,
}
