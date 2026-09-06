// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"sort"
	"strconv"
	"strings"

	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// Link aggregation: port-channels, bonds, LAGs, ether-channels.
//
// Two sources, in order of how much they can be trusted:
//
//   - IEEE8023-LAG-MIB's dot3adAggPortAttachedAggID says outright which
//     aggregator each physical port is currently attached to, and the MIB
//     defines the aggregator's identifier as its own ifIndex. Nothing has to be
//     inferred. Not every device implements it.
//   - ifStackTable (IF-MIB) says which interfaces are layered above which, and
//     everything implements it — but a LAG is not the only thing that stacks.
//     A VLAN interface sits above its physical ports too, and a tunnel above
//     its transport. Taking every stack entry as an aggregation would file a
//     switch's SVIs as port-channels.
//
// So the stack table is filtered by the *aggregator's* interface type, which is
// the one signal that separates a port-channel from an SVI. The default set is
// the two types that mean aggregation, and a profile can extend it for hardware
// that reports something else.
const (
	oidIfStackStatus              = "1.3.6.1.2.1.31.1.2.1.3"
	oidDot3adAggPortAttachedAggID = "1.2.840.10006.300.43.1.2.1.1.13"
)

// Profile keys, so a device that puts these elsewhere — or reports a
// port-channel as some other interface type — can be corrected without a
// release.
const (
	aggKeyStack     = "stack_status"
	aggKeyAttached  = "lag_attached_agg"
	aggKeyIfTypes   = "aggregate_iftypes"
	aggKeyIfTypeSep = ","
)

// defaultAggregateIfTypes are the IANAifType values that mean "this interface
// is an aggregation of others": ieee8023adLag and propMultiplexor. Vendors that
// report a port-channel as plain ethernetCsmacd(6) are not covered, and cannot
// be without treating every SVI as a LAG — those need the profile key.
var defaultAggregateIfTypes = map[int]bool{
	161: true, // ieee8023adLag
	54:  true, // propMultiplexor
}

// Aggregations maps each aggregator's ifIndex to its member ifIndexes.
//
// Ports are passed in rather than re-walked because the interface types are
// already known by the time this runs, and the filter needs them.
func (c *Collector) Aggregations(ports []payload.Port) map[int][]int {
	if len(ports) == 0 {
		return nil
	}

	// The authoritative source first. When a device answers it, the stack table
	// is not consulted at all: LACP knows which ports are actually *attached*,
	// while ifStackTable describes configuration and will happily list a member
	// that is down or unbundled.
	if attached := c.aggregationsFromLAG(); len(attached) > 0 {
		return attached
	}

	return c.aggregationsFromStack(ports)
}

// aggregationsFromLAG reads dot3adAggPortAttachedAggID.
//
// Indexed by the member port's ifIndex, valued with the aggregator's. Zero
// means "not currently attached to anything", which is the normal state of an
// idle port and must not be read as membership of aggregator 0.
func (c *Collector) aggregationsFromLAG() map[int][]int {
	oid := c.profileOID(aggKeyAttached, oidDot3adAggPortAttachedAggID)
	if oid == "" {
		return nil
	}

	rows, err := c.Session.Walk(oid)
	if err != nil || len(rows) == 0 {
		return nil
	}

	attached := make(map[string]int64, len(rows))
	for suffix, pdu := range rows {
		attached[suffix] = snmpx.Int(pdu)
	}

	return parseLAGAttachment(attached)
}

// parseLAGAttachment turns dot3adAggPortAttachedAggID rows into membership.
//
// Split from the walk so the rule can be tested: the value is the aggregator's
// ifIndex, and zero means "not attached to anything", which is the ordinary
// state of a port not in a bundle and must never be read as membership of an
// aggregator numbered zero.
func parseLAGAttachment(rows map[string]int64) map[int][]int {
	out := map[int][]int{}

	for suffix, value := range rows {
		member, err := strconv.Atoi(strings.Trim(suffix, "."))
		if err != nil {
			continue
		}

		aggregator := int(value)
		if aggregator <= 0 || aggregator == member {
			continue
		}

		out[aggregator] = append(out[aggregator], member)
	}

	return tidy(out)
}

// aggregationsFromStack reads ifStackTable, filtered by the aggregator's type.
func (c *Collector) aggregationsFromStack(ports []payload.Port) map[int][]int {
	oid := c.profileOID(aggKeyStack, oidIfStackStatus)
	if oid == "" {
		return nil
	}

	rows, err := c.Session.Walk(oid)
	if err != nil || len(rows) == 0 {
		return nil
	}

	types := map[int]int{}
	for _, p := range ports {
		types[p.IfNumber] = p.IfType
	}

	suffixes := make([]string, 0, len(rows))
	for suffix := range rows {
		suffixes = append(suffixes, suffix)
	}

	return parseStackTable(suffixes, types, c.aggregateIfTypes())
}

// parseStackTable turns ifStackTable indexes into membership.
//
// Split from the walk because this is where the judgement is: the table
// describes every kind of layering, and only some of it is aggregation.
func parseStackTable(suffixes []string, types map[int]int, aggregateTypes map[int]bool) map[int][]int {
	out := map[int][]int{}

	for _, suffix := range suffixes {
		higher, lower, ok := stackPair(suffix)
		if !ok {
			continue
		}

		// Zero on either side is the table saying "nothing above" or "nothing
		// below" — the ends of a stack, not a relationship.
		if higher == 0 || lower == 0 {
			continue
		}

		// The filter that keeps SVIs and tunnels out. Without it every VLAN
		// interface on the switch becomes a port-channel containing every port
		// in that VLAN.
		if !aggregateTypes[types[higher]] {
			continue
		}

		out[higher] = append(out[higher], lower)
	}

	return tidy(out)
}

// stackPair splits an ifStackTable index into its two ifIndexes.
func stackPair(suffix string) (int, int, bool) {
	parts := strings.Split(strings.Trim(suffix, "."), ".")
	if len(parts) != 2 {
		return 0, 0, false
	}

	higher, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	lower, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}

	return higher, lower, true
}

// aggregateIfTypes is the set of interface types that mean aggregation.
func (c *Collector) aggregateIfTypes() map[int]bool {
	spec := c.profileOID(aggKeyIfTypes, "")
	if spec == "" {
		return defaultAggregateIfTypes
	}

	out := map[int]bool{}
	for _, field := range strings.Split(spec, aggKeyIfTypeSep) {
		if n, err := strconv.Atoi(strings.TrimSpace(field)); err == nil && n > 0 {
			out[n] = true
		}
	}

	if len(out) == 0 {
		return defaultAggregateIfTypes
	}

	return out
}

// profileOID reads a topology-section override, falling back to the standard.
//
// Aggregation lives in the `topology` section rather than a section of its own:
// it is the same kind of thing as the forwarding and LLDP tables — a
// relationship between ports — and an operator looking to override it will look
// where the other port relationships are.
func (c *Collector) profileOID(key, fallback string) string {
	if c.Profile.Topology != nil {
		if v, ok := c.Profile.Topology[key]; ok {
			// An explicit empty value is a deliberate deletion, the same as
			// everywhere else profiles are merged: it turns the collector off
			// for hardware that answers the table with nonsense.
			return strings.TrimSpace(v)
		}
	}

	return fallback
}

// tidy sorts and de-duplicates, so a repeated scan produces an identical
// payload. GLPI compares what it receives against what it stored.
func tidy(in map[int][]int) map[int][]int {
	for aggregator, members := range in {
		sort.Ints(members)

		unique := members[:0]
		for i, m := range members {
			if i == 0 || members[i-1] != m {
				unique = append(unique, m)
			}
		}
		in[aggregator] = unique
	}

	if len(in) == 0 {
		return nil
	}

	return in
}

// ApplyAggregations attaches membership to the aggregator ports.
//
// GLPI wants the member list on the aggregator, as ifIndexes — it resolves them
// to port ids itself once every port has been created. Members carry nothing;
// they are ordinary ports that happen to be named by one.
//
// An aggregator whose members are not among the collected ports is dropped
// rather than reported: GLPI resolves the list by matching ifIndexes against
// ports it created, so naming one that does not exist produces an aggregate
// with a silent hole in it.
func ApplyAggregations(ports []payload.Port, aggregations map[int][]int) []payload.Port {
	if len(aggregations) == 0 {
		return ports
	}

	known := make(map[int]bool, len(ports))
	for _, p := range ports {
		known[p.IfNumber] = true
	}

	for i := range ports {
		members, ok := aggregations[ports[i].IfNumber]
		if !ok {
			continue
		}

		present := make([]int, 0, len(members))
		for _, m := range members {
			if known[m] {
				present = append(present, m)
			}
		}

		if len(present) > 0 {
			ports[i].Aggregate = present
		}
	}

	return ports
}
