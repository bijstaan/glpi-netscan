// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"reflect"
	"testing"

	"github.com/bijstaan/glpi-netscan/internal/payload"
)

func TestStackPair(t *testing.T) {
	for _, tc := range []struct {
		suffix        string
		higher, lower int
		ok            bool
	}{
		{"1000.1", 1000, 1, true},
		{"9.2", 9, 2, true},
		// The ends of a stack, not relationships. Kept parseable here and
		// rejected by the caller, so the two concerns stay separate.
		{"1000.0", 1000, 0, true},
		{"0.9", 0, 9, true},
		{"1", 0, 0, false},
		{"1.2.3", 0, 0, false},
		{"a.b", 0, 0, false},
		{"", 0, 0, false},
	} {
		t.Run(tc.suffix, func(t *testing.T) {
			higher, lower, ok := stackPair(tc.suffix)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (higher != tc.higher || lower != tc.lower) {
				t.Errorf("got %d/%d, want %d/%d", higher, lower, tc.higher, tc.lower)
			}
		})
	}
}

func TestApplyAggregations(t *testing.T) {
	ports := []payload.Port{
		{IfNumber: 1, IfName: "Gi0/1"},
		{IfNumber: 4, IfName: "Gi0/4"},
		{IfNumber: 1000, IfName: "Po1"},
	}

	got := ApplyAggregations(ports, map[int][]int{1000: {1, 4}})

	for _, p := range got {
		switch p.IfNumber {
		case 1000:
			if !reflect.DeepEqual(p.Aggregate, []int{1, 4}) {
				t.Errorf("aggregator carries %v, want [1 4]", p.Aggregate)
			}
		default:
			// Members carry nothing. GLPI reads the list off the aggregator and
			// resolves it itself; marking members too would have it build the
			// aggregate twice from opposite ends.
			if p.Aggregate != nil {
				t.Errorf("member %d carries %v, want nil", p.IfNumber, p.Aggregate)
			}
		}
	}
}

// TestApplyAggregationsDropsUnknownMembers: GLPI resolves the member list by
// matching ifIndexes against ports it created, so naming one that does not
// exist produces an aggregate with a silent hole in it.
func TestApplyAggregationsDropsUnknownMembers(t *testing.T) {
	ports := []payload.Port{
		{IfNumber: 1},
		{IfNumber: 1000},
	}

	got := ApplyAggregations(ports, map[int][]int{1000: {1, 77}})

	for _, p := range got {
		if p.IfNumber != 1000 {
			continue
		}
		if !reflect.DeepEqual(p.Aggregate, []int{1}) {
			t.Errorf("aggregate = %v, want [1] with the unknown member dropped", p.Aggregate)
		}
	}
}

// TestApplyAggregationsNoMembersLeft: an aggregator whose members are all
// unknown gets no aggregate at all, rather than an empty one that would make
// GLPI record a port-channel containing nothing.
func TestApplyAggregationsNoMembersLeft(t *testing.T) {
	ports := []payload.Port{{IfNumber: 1000}}

	got := ApplyAggregations(ports, map[int][]int{1000: {77, 88}})

	if got[0].Aggregate != nil {
		t.Errorf("aggregate = %v, want nil", got[0].Aggregate)
	}
}

func TestTidy(t *testing.T) {
	// Sorted and de-duplicated so a repeated scan produces an identical
	// payload: GLPI compares what it receives against what it stored.
	got := tidy(map[int][]int{1000: {4, 1, 4, 1}})

	if !reflect.DeepEqual(got[1000], []int{1, 4}) {
		t.Errorf("got %v, want [1 4]", got[1000])
	}

	if tidy(map[int][]int{}) != nil {
		t.Error("an empty map should be nil, so the payload omits the key entirely")
	}
}

// TestAggregateIfTypesDefault documents the filter that separates a
// port-channel from an SVI, and the profile escape hatch for hardware that
// reports something else.
func TestAggregateIfTypesDefault(t *testing.T) {
	c := &Collector{}
	got := c.aggregateIfTypes()

	if !got[161] || !got[54] {
		t.Errorf("default set = %v, want ieee8023adLag(161) and propMultiplexor(54)", got)
	}
	// The type that must never be in here by default: an SVI stacks above its
	// ports exactly like an aggregator does.
	if got[53] {
		t.Error("propVirtual(53) is in the default set — every SVI would become a port-channel")
	}
}

func TestAggregateIfTypesFromProfile(t *testing.T) {
	c := &Collector{}
	c.Profile.Topology = map[string]string{aggKeyIfTypes: "6, 161"}

	got := c.aggregateIfTypes()
	if !got[6] || !got[161] {
		t.Errorf("got %v, want 6 and 161", got)
	}
	if got[54] {
		t.Error("an explicit list should replace the default, not extend it")
	}

	// Nonsense falls back rather than disabling the collector silently.
	c.Profile.Topology[aggKeyIfTypes] = "not-a-number"
	if got := c.aggregateIfTypes(); !got[161] {
		t.Errorf("unparseable list = %v, want the default set", got)
	}
}

func TestProfileOIDOverride(t *testing.T) {
	c := &Collector{}

	if got := c.profileOID(aggKeyStack, oidIfStackStatus); got != oidIfStackStatus {
		t.Errorf("with no profile = %q, want the standard OID", got)
	}

	c.Profile.Topology = map[string]string{aggKeyStack: "1.2.3.4"}
	if got := c.profileOID(aggKeyStack, oidIfStackStatus); got != "1.2.3.4" {
		t.Errorf("override = %q, want 1.2.3.4", got)
	}

	// An explicit empty value is a deliberate deletion — the same convention
	// profiles use everywhere else — so a device that answers the table with
	// nonsense can be told to stop.
	c.Profile.Topology[aggKeyStack] = ""
	if got := c.profileOID(aggKeyStack, oidIfStackStatus); got != "" {
		t.Errorf("explicit empty = %q, want the collector disabled", got)
	}
}

// TestParseLAGAttachment covers the authoritative source. The value is the
// aggregator's ifIndex; zero means the port is not in a bundle, which is the
// ordinary state of most ports on most switches.
func TestParseLAGAttachment(t *testing.T) {
	got := parseLAGAttachment(map[string]int64{
		"1": 1000, // Gi0/1 attached to Po1
		"4": 1000, // Gi0/4 attached to Po1
		"2": 0,    // not in a bundle — must not become aggregator 0
		"3": 0,
		"7": 1001, // a second bundle
		// A port attached to itself is nonsense and would create a
		// self-referential aggregate.
		"8": 8,
	})

	if !reflect.DeepEqual(got[1000], []int{1, 4}) {
		t.Errorf("Po1 members = %v, want [1 4]", got[1000])
	}
	if !reflect.DeepEqual(got[1001], []int{7}) {
		t.Errorf("second bundle = %v, want [7]", got[1001])
	}
	if _, ok := got[0]; ok {
		t.Error("unattached ports were collected under aggregator 0")
	}
	if _, ok := got[8]; ok {
		t.Error("a port attached to itself became an aggregate")
	}
}

// TestParseStackTableExcludesSVIs is the whole reason the stack table needs a
// filter. A switch's VLAN interface sits above its ports exactly like a
// port-channel does; without the interface-type check, every SVI becomes a
// port-channel containing half the estate.
func TestParseStackTableExcludesSVIs(t *testing.T) {
	types := map[int]int{
		1: 6, 2: 6, 3: 6, 4: 6, // physical ports
		9:    53,  // Vlan10, propVirtual — an SVI
		1000: 161, // Port-channel1, ieee8023adLag
	}

	got := parseStackTable(
		[]string{
			"1000.1", "1000.4", // the aggregation
			"9.2", "9.3", // the SVI, which must be ignored
			"1000.0", "0.9", // the ends of a stack, not relationships
		},
		types,
		defaultAggregateIfTypes,
	)

	if !reflect.DeepEqual(got[1000], []int{1, 4}) {
		t.Errorf("port-channel members = %v, want [1 4]", got[1000])
	}
	if _, ok := got[9]; ok {
		t.Errorf("the SVI was reported as an aggregate: %v", got[9])
	}
	if len(got) != 1 {
		t.Errorf("got %d aggregates, want 1", len(got))
	}
}

// TestParseStackTableUnknownHigherType: an interface the port walk never saw
// has no type, so it cannot be shown to be an aggregator. Reporting it anyway
// would let anything that stacks become a port-channel.
func TestParseStackTableUnknownHigherType(t *testing.T) {
	got := parseStackTable([]string{"500.1"}, map[int]int{1: 6}, defaultAggregateIfTypes)

	if len(got) != 0 {
		t.Errorf("got %v, want nothing for an interface of unknown type", got)
	}
}
