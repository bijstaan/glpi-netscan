// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package main

// subcommands dispatched before flag parsing.
//
// The msi-* pair is Windows-only: they drive the service control manager and a
// directory junction, neither of which exists here.
var subcommands = map[string]func([]string) error{
	"install": runInstall,
}
