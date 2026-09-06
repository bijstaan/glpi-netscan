// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import "testing"

// GLPI resolves an LLDP neighbour by matching the far end's port
// logical_number, mac or *name* — so what goes in `ifdescr` must be the port
// name (lldpRemPortId when the subtype says so), not the human-readable
// description. Sending the description means the lookup never matches and the
// neighbour becomes a placeholder even when it is already inventoried.
func TestNeighbourConnUsesPortIdBySubtype(t *testing.T) {
	base := Neighbour{
		ChassisMAC: "00:1b:53:cc:00:11",
		SysName:    "phone-1042",
		PortID:     "eth0",
		PortDesc:   "uplink",
	}

	n := base
	n.PortIDSubtype = LldpPortIDInterfaceName
	if got := n.conn(); got.IfDescr != "eth0" {
		t.Errorf("interfaceName should use the port id, got %q", got.IfDescr)
	}

	n = base
	n.PortIDSubtype = LldpPortIDInterfaceAlias
	if got := n.conn(); got.IfDescr != "eth0" {
		t.Errorf("interfaceAlias should use the port id, got %q", got.IfDescr)
	}

	// A MAC port id is the strongest match GLPI has, so it goes to `mac`.
	n = base
	n.PortID = "00-1B-53-CC-00-99"
	n.PortIDSubtype = LldpPortIDMACAddress
	got := n.conn()
	if got.MAC != "00:1b:53:cc:00:99" {
		t.Errorf("macAddress subtype should populate mac, got %q", got.MAC)
	}
	if got.IfDescr != "" {
		t.Errorf("mac subtype should not also set ifdescr, got %q", got.IfDescr)
	}

	// Unknown/vendor encodings: the description is the better guess, and a
	// wrong ifdescr only costs a placeholder.
	n = base
	n.PortIDSubtype = 7 // local
	if got := n.conn(); got.IfDescr != "uplink" {
		t.Errorf("unknown subtype should fall back to the description, got %q", got.IfDescr)
	}

	// Chassis identity always travels regardless of subtype.
	if got := base.conn(); got.SysMAC != "00:1b:53:cc:00:11" || got.SysName != "phone-1042" {
		t.Errorf("chassis identity lost: %+v", got)
	}
}

func TestNormaliseMAC(t *testing.T) {
	for _, in := range []string{
		"00:1b:53:cc:00:11",
		"00-1B-53-CC-00-11",
		"001b53cc0011",
		"00 1b 53 cc 00 11",
	} {
		if got := normaliseMAC(in); got != "00:1b:53:cc:00:11" {
			t.Errorf("normaliseMAC(%q) = %q", in, got)
		}
	}
	// Anything that is not six octets is not a MAC and must not be guessed at.
	for _, bad := range []string{"", "eth0", "001b53cc", "001b53cc001122"} {
		if got := normaliseMAC(bad); got != "" {
			t.Errorf("normaliseMAC(%q) should be empty, got %q", bad, got)
		}
	}
}

// LldpSystemCapabilitiesMap is a BITS value numbered from the most significant
// bit of the first octet: bridge(2) = 0x20, telephone(5) = 0x04. A desk phone
// advertises both, because it contains a two-port switch — which is precisely
// why sysServices cannot be used to recognise one.
func TestLldpCapabilityBitPositions(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
		bit   int
		want  bool
	}{
		{"phone: bridge+telephone", []byte{0x24}, LldpCapTelephone, true},
		{"router+bridge is not a phone", []byte{0x28}, LldpCapTelephone, false},
		{"telephone alone", []byte{0x04}, LldpCapTelephone, true},
		{"empty", []byte{}, LldpCapTelephone, false},
	}

	for _, c := range cases {
		got := false
		index := c.bit / 8
		if index < len(c.bytes) {
			got = c.bytes[index]&(0x80>>(c.bit%8)) != 0
		}
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
