// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

import (
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/bijstaan/glpi-netscan/internal/client"
	"github.com/bijstaan/glpi-netscan/internal/sweep"
	"github.com/bijstaan/glpi-netscan/internal/trap"
)

// trapSupervisor starts, stops and restarts the notification listener as GLPI's
// policy changes.
//
// The policy arrives on every poll rather than once at startup, so that
// switching listening *off* reaches a running scanner as reliably as switching
// it on. A listener that could only ever be enabled remotely is one that has to
// be disabled by visiting the machine.
type trapSupervisor struct {
	api *client.Client

	mu       sync.Mutex
	current  string
	listener *trap.Listener
}

func newTrapSupervisor(api *client.Client) *trapSupervisor {
	return &trapSupervisor{api: api}
}

// apply reconciles the running listener with the policy just received.
func (s *trapSupervisor) apply(policy client.TrapPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := fingerprint(policy)
	if want == s.current {
		return
	}

	// Any change at all — port, ranges, or being switched off — stops the
	// existing listener first. Reconfiguring a bound socket in place would mean
	// a window where the old ranges still applied.
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
		log.Println("stopped listening for SNMP traps")
	}

	s.current = want

	if !policy.Enabled {
		return
	}

	allowed := parseRanges(policy.Ranges)
	if len(allowed) == 0 {
		log.Println("traps are enabled but no permitted source ranges were sent; not listening")
		return
	}

	listener := trap.New(trap.Config{
		Port:    uint16(policy.Port),
		Allowed: allowed,
	}, s.forward)

	s.listener = listener

	go func() {
		if err := listener.Run(); err != nil {
			// Binding 162 needs a capability the hardened unit does not grant
			// by default, and that is the failure people will actually hit, so
			// it is reported rather than retried silently.
			log.Printf("trap listener stopped: %v", err)
		}
	}()
}

// stop closes any running listener, so a shutdown releases the port.
func (s *trapSupervisor) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
		s.current = ""
	}
}

// forward hands a batch to GLPI.
func (s *trapSupervisor) forward(batch []trap.Notification) {
	if len(batch) == 0 {
		return
	}

	if err := s.api.ReportTraps(batch); err != nil {
		// Dropped rather than retried. A trap says "something changed, go and
		// look"; if it cannot be delivered now, the sweep that follows will
		// find the change anyway, and a retry queue would turn an outage into a
		// backlog that arrives all at once when GLPI returns.
		log.Printf("could not forward %d traps: %v", len(batch), err)
	}
}

// fingerprint is what decides whether the policy actually changed.
func fingerprint(policy client.TrapPolicy) string {
	if !policy.Enabled {
		return "off"
	}

	return "on:" + strconv.Itoa(policy.Port) + ":" + strings.Join(policy.Ranges, ",")
}

// parseRanges turns the target ranges into prefixes the listener can test.
//
// Anything unparseable is dropped rather than widened: a range the scanner
// cannot understand must not become "accept everything", which is what a
// permissive fallback would amount to on a listening socket.
func parseRanges(ranges []string) []netip.Prefix {
	addrs, err := sweep.ExpandRanges(ranges, sweep.MaxHosts)
	if err != nil && len(addrs) == 0 {
		return nil
	}

	// Expanded to individual addresses and collapsed back to /32s. Reusing the
	// same expansion the sweep uses means the set of addresses a trap may come
	// from is exactly the set the scanner would scan — one definition, not two
	// that can drift.
	out := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return out
}
