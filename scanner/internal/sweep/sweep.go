// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package sweep expands scan ranges and probes them concurrently.
package sweep

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/bijstaan/glpi-netscan/internal/collect"
	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/profile"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
	"github.com/bijstaan/glpi-netscan/internal/version"
)

// MaxHosts caps how many addresses one job may expand to.
//
// A mistyped prefix is the realistic failure here: /8 instead of /24 is one
// keystroke and 16 million probes. The cap turns that into a visible error
// rather than a scanner that appears hung for a week.
const MaxHosts = 65536

// Options control one sweep.
type Options struct {
	Port        uint16
	Timeout     time.Duration
	Retries     int
	Concurrency int
}

// Result is the outcome of sweeping one job.
type Result struct {
	Payloads    []payload.Inventory
	Discovered  int
	Inventoried int
	Failed      int
	Errors      []string

	// Found is what the discovery pass turned up, keyed by deviceid: the
	// credential that worked and the address it answered on. The inventory pass
	// needs both, and re-probing to find them again would give back the saving
	// discovery just made.
	Found map[string]Answered
}

// Answered is a device that responded to discovery.
type Answered struct {
	Host       string
	Credential snmpx.Credential
	Identity   collect.Identity
}

// ExpandRanges turns CIDRs, single addresses and `start-end` pairs into a
// deduplicated address list.
func ExpandRanges(ranges []string, limit int) ([]netip.Addr, error) {
	if limit <= 0 {
		limit = MaxHosts
	}

	seen := make(map[netip.Addr]struct{})
	out := make([]netip.Addr, 0, 256)

	add := func(a netip.Addr) error {
		if _, dup := seen[a]; dup {
			return nil
		}
		if len(out) >= limit {
			return fmt.Errorf("range expansion exceeds %d addresses", limit)
		}
		seen[a] = struct{}{}
		out = append(out, a)
		return nil
	}

	for _, raw := range ranges {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		switch {
		case strings.Contains(entry, "/"):
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", entry, err)
			}
			prefix = prefix.Masked()

			// Skip network and broadcast for IPv4 prefixes that have them;
			// probing them wastes two round trips per subnet and, on some
			// networks, generates noise a NOC will ask about.
			hosts := hostsIn(prefix)
			for _, a := range hosts {
				if err := add(a); err != nil {
					return nil, err
				}
			}

		case strings.Contains(entry, "-"):
			parts := strings.SplitN(entry, "-", 2)
			lo, err1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
			hi, err2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("bad range %q", entry)
			}
			if lo.BitLen() != hi.BitLen() {
				return nil, fmt.Errorf("mixed address families in %q", entry)
			}
			if hi.Less(lo) {
				lo, hi = hi, lo
			}
			for a := lo; ; a = a.Next() {
				if err := add(a); err != nil {
					return nil, err
				}
				if a == hi {
					break
				}
			}

		default:
			a, err := netip.ParseAddr(entry)
			if err != nil {
				return nil, fmt.Errorf("bad address %q: %w", entry, err)
			}
			if err := add(a); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// hostsIn lists the usable addresses of a prefix.
func hostsIn(p netip.Prefix) []netip.Addr {
	out := []netip.Addr{}
	addr := p.Addr()

	// A single-host prefix is the address itself.
	if p.Bits() == addr.BitLen() {
		return []netip.Addr{addr}
	}

	// /31 point-to-point links use both addresses (RFC 3021).
	skipEdges := addr.Is4() && p.Bits() <= 30

	first := addr
	if skipEdges {
		first = first.Next()
	}

	for a := first; p.Contains(a); a = a.Next() {
		next := a.Next()
		if skipEdges && !p.Contains(next) {
			break // a is the broadcast address
		}
		out = append(out, a)
	}

	return out
}

// Run probes every address with each credential in turn, and fully inventories
// the ones that answer.
func Run(
	ctx context.Context,
	addrs []netip.Addr,
	creds []snmpx.Credential,
	profiles []profile.Profile,
	opts Options,
) Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 32
	}

	var (
		mu     sync.Mutex
		result Result
	)

	work := make(chan netip.Addr)
	var wg sync.WaitGroup

	for range opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				invs, err := scanOne(addr.String(), creds, profiles, snmpx.Options{
					Port:    opts.Port,
					Timeout: opts.Timeout,
					Retries: opts.Retries,
				})

				mu.Lock()
				switch {
				case err != nil && len(invs) == 0:
					// Silence is the overwhelmingly common case on a sweep and
					// is not an error worth reporting; only a device that
					// answered and then failed is.
					if !isSilent(err) {
						result.Failed++
						result.Errors = append(result.Errors, addr.String()+": "+err.Error())
					}
				case len(invs) > 0:
					result.Discovered++
					result.Inventoried++
					// One address can yield several assets: a wireless
					// controller reports every access point behind it, and each
					// is its own serial-numbered box. Counted once as a
					// discovery — the address answered once — but submitted in
					// full.
					result.Payloads = append(result.Payloads, invs...)
				}
				mu.Unlock()
			}
		}()
	}

feed:
	for _, addr := range addrs {
		select {
		case <-ctx.Done():
			break feed
		case work <- addr:
		}
	}
	close(work)
	wg.Wait()

	result.Payloads = collect.DropShadowedMed(result.Payloads)

	return result
}

// Discover probes every address and submits what answers, without walking it.
//
// This is the pass that runs on every scan. It costs one GET per address per
// credential, against the 200-360ms a full walk costs even on a simulator, so
// it is what makes scanning a large range on a short interval affordable at
// all.
//
// It returns what it found rather than only counting it, because the inventory
// pass that follows needs the working credential and the address — and finding
// those again means probing again.
func Discover(
	ctx context.Context,
	addrs []netip.Addr,
	creds []snmpx.Credential,
	profiles []profile.Profile,
	opts Options,
) Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 32
	}

	var (
		mu     sync.Mutex
		result = Result{Found: map[string]Answered{}}
	)

	work := make(chan netip.Addr)
	var wg sync.WaitGroup

	for range opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				host := addr.String()
				inv, answered, err := probeOne(host, creds, profiles, snmpx.Options{
					Port:    opts.Port,
					Timeout: opts.Timeout,
					Retries: opts.Retries,
				})

				mu.Lock()
				switch {
				case err != nil:
					// Silence is the overwhelmingly common case on a sweep —
					// most addresses in a range are empty — and is not an error.
					if !isSilent(err) {
						result.Failed++
						result.Errors = append(result.Errors, host+": "+err.Error())
					}
				default:
					result.Discovered++
					result.Payloads = append(result.Payloads, inv)
					result.Found[inv.DeviceID] = answered
				}
				mu.Unlock()
			}
		}()
	}

feedDiscovery:
	for _, addr := range addrs {
		select {
		case <-ctx.Done():
			break feedDiscovery
		case work <- addr:
		}
	}

	close(work)
	wg.Wait()

	return result
}

// probeOne tries each credential until one answers the system group.
func probeOne(
	host string,
	creds []snmpx.Credential,
	profiles []profile.Profile,
	opts snmpx.Options,
) (payload.Inventory, Answered, error) {
	var lastErr error

	for _, cred := range creds {
		sess, err := snmpx.Dial(host, cred, opts)
		if err != nil {
			lastErr = err
			continue
		}

		ident, err := collect.Probe(sess)
		if err != nil {
			// A wrong credential and an empty address look the same from here.
			sess.Close()
			lastErr = err
			continue
		}

		markers := collect.Markers(sess, ident)
		sess.Close()

		dev := collect.DiscoveryDevice(ident)
		deviceID := DeviceID(host, ident)

		return collect.DiscoveryPayload(deviceID, host, ident, dev, markers, version.String()),
			Answered{Host: host, Credential: cred, Identity: ident},
			nil
	}

	if lastErr == nil {
		lastErr = errSilent
	}

	return payload.Inventory{}, Answered{}, lastErr
}

// InventoryThese performs the expensive pass, for the devices the server asked
// for and no others.
//
// The credential and address come from the discovery pass rather than being
// rediscovered: probing again to find out how to talk to a device we just
// talked to would give back most of what the split saves.
func InventoryThese(
	ctx context.Context,
	wanted []string,
	found map[string]Answered,
	profiles []profile.Profile,
	opts Options,
) Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 32
	}

	var (
		mu     sync.Mutex
		result Result
	)

	work := make(chan string)
	var wg sync.WaitGroup

	for range opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for deviceID := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				answered, ok := found[deviceID]
				if !ok {
					// The server asked for a device this sweep did not find.
					// Nothing to do: it will be discovered again when it answers.
					continue
				}

				invs, err := inventoryOne(answered, profiles, snmpx.Options{
					Port:    opts.Port,
					Timeout: opts.Timeout,
					Retries: opts.Retries,
				})

				mu.Lock()
				switch {
				case err != nil:
					result.Failed++
					result.Errors = append(result.Errors, answered.Host+": "+err.Error())
				case len(invs) > 0:
					result.Inventoried++
					result.Payloads = append(result.Payloads, invs...)
				}
				mu.Unlock()
			}
		}()
	}

feedInventory:
	for _, deviceID := range wanted {
		select {
		case <-ctx.Done():
			break feedInventory
		case work <- deviceID:
		}
	}

	close(work)
	wg.Wait()

	// A device walked directly in this pass outranks the same device described
	// second-hand by its switch.
	result.Payloads = collect.DropShadowedMed(result.Payloads)

	return result
}

// inventoryOne re-dials with the credential discovery already proved works.
func inventoryOne(
	answered Answered,
	profiles []profile.Profile,
	opts snmpx.Options,
) ([]payload.Inventory, error) {
	sess, err := snmpx.Dial(answered.Host, answered.Credential, opts)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	// Re-probed rather than reusing the discovery identity: a device that
	// rebooted between the two passes would otherwise be inventoried under a
	// stale name, and the probe is the cheap part.
	ident, err := collect.Probe(sess)
	if err != nil {
		return nil, err
	}

	return Inventory(sess, ident, answered.Host, profiles)
}

// scanOne tries each credential until one answers, then inventories the device.
func scanOne(
	host string,
	creds []snmpx.Credential,
	profiles []profile.Profile,
	opts snmpx.Options,
) ([]payload.Inventory, error) {
	var lastErr error

	for _, cred := range creds {
		sess, err := snmpx.Dial(host, cred, opts)
		if err != nil {
			lastErr = err
			continue
		}

		ident, err := collect.Probe(sess)
		if err != nil {
			// Wrong credential and unreachable host look the same from here,
			// so try the next credential before giving up on the address.
			sess.Close()
			lastErr = err
			continue
		}

		invs, err := Inventory(sess, ident, host, profiles)
		sess.Close()
		if err != nil {
			return nil, err
		}
		return invs, nil
	}

	if lastErr == nil {
		lastErr = errSilent
	}
	return nil, lastErr
}

// Inventory performs the full walk of one device and assembles its submission.
//
// Exported and shared with the `-once` path deliberately. This assembly existed
// in two places — here for the sweep, and again in the command for -once — and
// they drifted: printer supply levels were added to one and silently absent
// from every real scan, while the diagnostic that operators use to check their
// work showed them correctly. One function is the fix; a comment asking the
// next person to remember both would not have been.
func Inventory(
	sess *snmpx.Session,
	ident collect.Identity,
	host string,
	profiles []profile.Profile,
) ([]payload.Inventory, error) {
	resolved := profile.Resolve(profiles, ident.SysObjectID, ident.SysDescr)
	c := &collect.Collector{Session: sess, Profile: resolved, Ident: ident}

	dev, err := c.Device()
	if err != nil {
		return nil, err
	}
	ports, _ := c.Ports()
	ports = c.Enrich(ports)

	// Link aggregation. After Enrich, because it needs the interface types the
	// port walk established in order to tell a port-channel from an SVI.
	ports = collect.ApplyAggregations(ports, c.Aggregations(ports))
	comps, _ := c.Components()
	counters, _ := c.PageCounters()

	// Supply levels, for printers. Read whenever the device answers the marker
	// supplies table rather than only when it was classified as a printer:
	// multifunction devices that identify as something else still report toner,
	// and an empty table costs one walk that returns nothing.
	supplies, _ := c.Supplies()
	cartridges := collect.Cartridges(supplies)

	// Power state travels outside `content`; see payload.Power.
	var power *payload.Power
	if dev.Type == payload.TypePower {
		power = c.Power()
	}

	// Access points behind a controller. They are separate assets, not
	// components: a CAPWAP-tunnelled AP has no reachable address of its own, so
	// the controller is the only place they can come from, but each one is a
	// serial-numbered box that gets moved and replaced on its own.
	var extra []payload.Inventory
	wireless, aps := c.Wireless(ident.SysName)
	extra = collect.APInventories(ident.SysName, host, aps, version.String())

	// Endpoints the switch knows about via LLDP-MED. These are devices nothing
	// else in the estate can reach — a desk phone speaks no SNMP, but announces
	// its own model, serial and firmware to the port it is plugged into.
	if med := c.MedInventory(); len(med) > 0 {
		extra = append(extra, collect.MedInventories(
			med, c.LastNeighbours(), host, version.String())...)
	}

	// Without a serial or a MAC, GLPI's default import rules refuse the
	// device outright ("NetworkEquipment import denied"), so fall back to a
	// port address before giving up on an identity for it.
	if dev.MAC == "" {
		dev.MAC = collect.DeriveDeviceMAC(ports)
	}

	primary := payload.Inventory{
		DeviceID:    DeviceID(host, ident),
		Action:      string(payload.QueryInventory),
		ItemType:    payload.GLPIItemType(dev.Type),
		ScanAddress: host,
		Power:       power,
		Content: payload.Content{
			Device:        dev,
			Cartridges:    cartridges,
			Ports:         ports,
			Components:    comps,
			PageCounters:  counters,
			VersionClient: version.String(),
		},
		Wireless: wireless,
	}

	// The scanned device first: callers that only care about the address they
	// asked about can take the head without knowing about access points.
	return append([]payload.Inventory{primary}, extra...), nil
}

// DeviceID is the stable identity GLPI keys the asset on.
//
// It has to survive a device being renamed and an address being reassigned, so
// it prefers sysName and falls back to the address only when the device offers
// nothing better.
func DeviceID(host string, ident collect.Identity) string {
	name := ident.SysName
	if name == "" {
		name = host
	}
	return fmt.Sprintf("%s-%s", name, host)
}

var errSilent = fmt.Errorf("no SNMP response")

// isSilent reports whether an error just means "nothing there".
func isSilent(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "no SNMP response") ||
		strings.Contains(msg, "empty system group") ||
		strings.Contains(msg, "no response to system group") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "unreachable")
}
