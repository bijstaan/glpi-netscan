// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bijstaan/glpi-netscan/internal/profile"
)

// Device control: resolving a queued intent into an SNMP write.
//
// The queue in GLPI holds intent — "this port, down" — rather than an OID, for
// two reasons. A profile's control OIDs are matched on the device's sysObjectID
// and the scanner is the only party that knows it; and an audit row that says
// `Gi0/3 -> down` is still readable a year later, where one saying
// `1.3.6.1.2.1.2.2.1.7.3 = 2` is not.
//
// Exactly one control is built in. ifAdminStatus is standard, is indexed by
// ifIndex like everything else about a port, and means the same on every device
// implementing IF-MIB. Everything vendor-specific comes from a profile, because
// those are the ones where a wrong OID or a wrong index does not fail — it
// switches off something else.
const oidIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"

// ControlSpec is a resolved control: where to write, and what the named values
// mean.
type ControlSpec struct {
	OID    string
	Values map[string]int
}

// builtinControls are the standard writes, available without a profile.
var builtinControls = map[string]ControlSpec{
	"port_admin": {
		OID:    oidIfAdminStatus,
		Values: map[string]int{"up": 1, "down": 2},
	},
}

// ResolveControl works out the OID and value for a named action.
//
// A profile's `control` section wins over the built-in, so hardware that puts
// ifAdminStatus somewhere else — or that spells "down" differently — can be
// corrected without a release. The profile syntax is an OID followed by the
// value map:
//
//	"outlet_power": "1.3.6.1.4.1.318.1.1.26.9.2.4.1.5 on=1,off=2,cycle=3"
//
// Returns an error rather than a guess for anything it cannot resolve. This is
// the one code path in the scanner that changes the world, and the only safe
// response to "I am not sure what you meant" is to do nothing.
func ResolveControl(resolved profile.Resolved, action, value string) (string, int, error) {
	action = strings.TrimSpace(action)
	value = strings.TrimSpace(value)

	spec, err := controlSpec(resolved, action)
	if err != nil {
		return "", 0, err
	}

	n, ok := spec.Values[value]
	if !ok {
		return "", 0, fmt.Errorf("action %q has no value %q", action, value)
	}

	return spec.OID, n, nil
}

func controlSpec(resolved profile.Resolved, action string) (ControlSpec, error) {
	if raw, ok := resolved.Control[action]; ok {
		spec, err := parseControl(raw)
		if err != nil {
			return ControlSpec{}, fmt.Errorf("profile control %q: %w", action, err)
		}
		return spec, nil
	}

	if spec, ok := builtinControls[action]; ok {
		return spec, nil
	}

	return ControlSpec{}, fmt.Errorf("unknown control action %q", action)
}

// parseControl reads `OID name=value,name=value`.
func parseControl(raw string) (ControlSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ControlSpec{}, fmt.Errorf("empty")
	}

	oid, rest, found := strings.Cut(raw, " ")
	oid = strings.TrimSpace(oid)
	if oid == "" || !found || strings.TrimSpace(rest) == "" {
		return ControlSpec{}, fmt.Errorf("expected an OID followed by name=value pairs, got %q", raw)
	}

	values := map[string]int{}
	for _, pair := range strings.Split(rest, ",") {
		name, num, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return ControlSpec{}, fmt.Errorf("expected name=value, got %q", pair)
		}

		n, err := strconv.Atoi(strings.TrimSpace(num))
		if err != nil {
			return ControlSpec{}, fmt.Errorf("value for %q is not an integer: %q", name, num)
		}

		values[strings.TrimSpace(name)] = n
	}

	if len(values) == 0 {
		return ControlSpec{}, fmt.Errorf("no values declared")
	}

	return ControlSpec{OID: oid, Values: values}, nil
}

// ControlOID joins a resolved OID to the index the action names.
//
// The index is validated as numeric arcs rather than pasted in: it arrives over
// the wire, and this is the string that decides which port gets shut.
func ControlOID(oid, index string) (string, error) {
	index = strings.Trim(strings.TrimSpace(index), ".")
	if index == "" {
		return "", fmt.Errorf("no index")
	}

	for _, arc := range strings.Split(index, ".") {
		// Non-negative specifically: Atoi is happy with "-1", and an OID arc
		// cannot be negative. The device would reject it, but this string
		// decides which port gets shut and is not the place to rely on that.
		n, err := strconv.Atoi(arc)
		if err != nil || n < 0 {
			return "", fmt.Errorf("index %q is not a valid OID suffix", index)
		}
	}

	return strings.TrimRight(oid, ".") + "." + index, nil
}
