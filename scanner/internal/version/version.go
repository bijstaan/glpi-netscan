// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package version carries the scanner's build identity.
package version

// Version is overridden at build time with -ldflags "-X .../version.Version=…".
var Version = "0.1.0-dev"

// String is what the scanner reports to GLPI at enrollment and in payloads.
func String() string { return "glpi-netscan " + Version }
