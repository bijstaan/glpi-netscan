// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package main

import (
	"context"
	"os/signal"
	"syscall"
)

// hostContext yields a context cancelled on an ordinary termination signal.
//
// On Linux the rollback guard is preflight.sh, run by systemd as ExecStartPre —
// which is why nothing here calls updater.Preflight: the shell guard already
// ran, and running it again would double-count the start attempt and revert a
// healthy version after half as many failures as intended.
func hostContext() (context.Context, func()) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// hostServe runs the agent directly. There is no service handshake to answer:
// systemd's Type=simple considers the process started as soon as it is forked.
func hostServe(serve func(context.Context) error) error {
	ctx, stop := hostContext()
	defer stop()

	return serve(ctx)
}

// runPreflight is a no-op here; preflight.sh owns this on Linux.
func runPreflight(stateDir, installRoot string) bool { return false }
