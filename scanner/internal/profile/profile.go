// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package profile models the OID profiles that tell the scanner which OIDs to
// read for a given device.
//
// The scanner ships no vendor knowledge of its own: profiles arrive with the
// job from GLPI, which merges the shipped packs with any operator overrides.
// That keeps "extendable for device-specific OIDs" a server-side, web-editable
// concern rather than something that needs a new scanner build.
package profile

import (
	"regexp"
	"sort"
	"strings"
)

// Profile is one layer of OID definitions.
//
// A profile never has to be complete. The base profile carries the standard
// MIBs and always applies; vendor profiles layer on top and only need to name
// the fields they know better.
type Profile struct {
	Name string `json:"name"`

	// Higher priority is applied later, so it wins on conflicts. The base
	// profile sits at 0 and vendor profiles above it.
	Priority int `json:"priority"`

	Match Match `json:"match"`

	// Scalar OIDs, read with a single GET. Keyed by the payload field name.
	Device map[string]string `json:"device,omitempty"`

	// Column OIDs, walked and indexed by ifIndex.
	Ports map[string]string `json:"ports,omitempty"`

	// Column OIDs walked and indexed by entPhysicalIndex.
	Components map[string]string `json:"components,omitempty"`

	// Scalar OIDs for printer counters.
	PageCounters map[string]string `json:"pagecounters,omitempty"`

	// Overrides for the standard topology/metric table OIDs, keyed by the
	// names in collect.topologyDefaults. A device that puts its forwarding
	// table somewhere non-standard is a profile edit, not a code change.
	Topology map[string]string `json:"topology,omitempty"`

	// Power OIDs (UPS battery, input/output lines, outlets). Values may carry
	// a "*factor" scale suffix, because power MIBs report tenths of a volt or
	// amp and the factor differs per vendor for the same logical field.
	Power map[string]string `json:"power,omitempty"`

	// Wireless declares how to enumerate access points from a controller, or
	// radios from a standalone AP. Keyed the same way as Power: the collector
	// owns the mechanism (walk these columns, correlate by table index) and the
	// profile owns the OIDs, so a new vendor is a JSON file rather than a
	// release.
	Wireless map[string]string `json:"wireless,omitempty"`

	// Control declares writable OIDs. The only section whose contents are ever
	// written to hardware, and the only one where a wrong entry does not fail
	// visibly — it switches off something other than what was asked for.
	Control map[string]string `json:"control,omitempty"`

	// Switches whole collectors off for devices that implement a table badly.
	// Absent means enabled: a new device should work without configuration.
	Features map[string]bool `json:"features,omitempty"`

	// Forces the resulting asset type when this profile matches
	// ("NetworkEquipment", "Printer"). Empty means "decide from sysServices".
	ItemType string `json:"itemtype,omitempty"`
}

// Match decides whether a profile applies to a device.
type Match struct {
	// Matched as a prefix against sysObjectID. This is how netdiscovery
	// identifies vendors: the enterprise arc under 1.3.6.1.4.1 is assigned
	// per organisation, so a prefix is a reliable vendor/model discriminator.
	SysObjectIDPrefix []string `json:"sysobjectid_prefix,omitempty"`

	// Optional secondary filter for vendors that reuse one sysObjectID across
	// very different hardware.
	SysDescrRegex string `json:"sysdescr_regex,omitempty"`
}

// Applies reports whether this profile should be layered onto a device.
//
// A profile with no match rules is a base profile and always applies.
func (p Profile) Applies(sysObjectID, sysDescr string) bool {
	if len(p.Match.SysObjectIDPrefix) == 0 && p.Match.SysDescrRegex == "" {
		return true
	}

	if len(p.Match.SysObjectIDPrefix) > 0 {
		hit := false
		for _, prefix := range p.Match.SysObjectIDPrefix {
			if prefixMatch(sysObjectID, prefix) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}

	if p.Match.SysDescrRegex != "" {
		re, err := regexp.Compile(p.Match.SysDescrRegex)
		// An unparseable regex must not silently widen the match — a profile
		// the operator believed was scoped would start applying everywhere.
		if err != nil || !re.MatchString(sysDescr) {
			return false
		}
	}

	return true
}

// prefixMatch compares OIDs arc-wise rather than as strings, so that a prefix
// of "1.3.6.1.4.1.9.1" matches "1.3.6.1.4.1.9.1.500" but not the unrelated
// "1.3.6.1.4.1.91.1" — a plain strings.HasPrefix would accept both.
func prefixMatch(oid, prefix string) bool {
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	prefix = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(prefix), "."), ".")
	if oid == prefix {
		return true
	}
	return strings.HasPrefix(oid, prefix+".")
}

// Resolved is the flattened result of layering every applicable profile.
type Resolved struct {
	Device       map[string]string
	Ports        map[string]string
	Components   map[string]string
	PageCounters map[string]string
	Topology     map[string]string
	Power        map[string]string
	Wireless     map[string]string
	Control      map[string]string
	Features     map[string]bool
	ItemType     string
	Applied      []string
}

// Resolve layers every applicable profile in priority order.
func Resolve(profiles []Profile, sysObjectID, sysDescr string) Resolved {
	applicable := make([]Profile, 0, len(profiles))
	for _, p := range profiles {
		if p.Applies(sysObjectID, sysDescr) {
			applicable = append(applicable, p)
		}
	}

	// Stable sort so that two profiles at the same priority keep the order the
	// server sent them in, making the outcome reproducible.
	sort.SliceStable(applicable, func(i, j int) bool {
		return applicable[i].Priority < applicable[j].Priority
	})

	out := Resolved{
		Device:       map[string]string{},
		Ports:        map[string]string{},
		Components:   map[string]string{},
		PageCounters: map[string]string{},
		Topology:     map[string]string{},
		Power:        map[string]string{},
		Wireless:     map[string]string{},
		Control:      map[string]string{},
		Features:     map[string]bool{},
	}

	for _, p := range applicable {
		merge(out.Device, p.Device)
		merge(out.Ports, p.Ports)
		merge(out.Components, p.Components)
		merge(out.PageCounters, p.PageCounters)
		merge(out.Topology, p.Topology)
		merge(out.Power, p.Power)
		merge(out.Wireless, p.Wireless)
		merge(out.Control, p.Control)
		for k, v := range p.Features {
			// Booleans have no "unset" spelling, so a later profile always
			// wins; there is no delete semantics here as there is for OIDs.
			out.Features[k] = v
		}
		if p.ItemType != "" {
			out.ItemType = p.ItemType
		}
		out.Applied = append(out.Applied, p.Name)
	}

	return out
}

// merge copies src over dst. An empty value is a deliberate deletion: it lets a
// vendor profile suppress a base OID that the device answers wrongly, which is
// otherwise impossible to express.
func merge(dst, src map[string]string) {
	for k, v := range src {
		if strings.TrimSpace(v) == "" {
			delete(dst, k)
			continue
		}
		dst[k] = v
	}
}
