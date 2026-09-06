// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/bijstaan/glpi-netscan/internal/updater"
	"golang.org/x/sys/windows/svc"
)

// ServiceName is what the installer registers and the SCM addresses us by.
const ServiceName = "GLPINetscan"

func hostContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() {
		<-signals
		cancel()
	}()

	return ctx, cancel
}

// hostServe runs the scanner under the Windows service control manager when
// started by it, and as an ordinary console program otherwise.
//
// The distinction matters: a service that does not answer the SCM's start
// handshake within its timeout is killed as failed however healthy it is, while
// the same binary run by hand from a console must not try to talk to the SCM at
// all. svc.IsWindowsService() tells the two apart, so one binary serves both
// without a "run as service" flag anyone can get wrong.
func hostServe(serve func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	if !isService {
		ctx, cancel := hostContext()
		defer cancel()
		return serve(ctx)
	}

	return svc.Run(ServiceName, &scannerService{serve: serve})
}

// runPreflight applies the rollback guard. See updater.Preflight for why this
// runs in-process on Windows and as a separate script on Linux.
func runPreflight(stateDir, installRoot string) bool {
	return updater.Preflight(stateDir, installRoot)
}

type scannerService struct {
	serve func(context.Context) error
}

func (s *scannerService) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.serve(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus

			case svc.Stop, svc.Shutdown:
				// Acknowledged before the work is done: a sweep in flight can
				// take a while to unwind, and a service that goes quiet during
				// that window is reported as hung.
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}

		case err := <-done:
			// The scanner stopped on its own — it staged an update and wants to
			// come back on the new version. Reported as a clean exit so the
			// SCM's restart policy applies rather than recording a failure.
			if err != nil && !isRestartForUpdate(err) {
				return false, 1
			}
			return false, 0
		}
	}
}
