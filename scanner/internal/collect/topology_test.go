// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// The IEEE PortList is MSB-first: the top bit of the first byte is bridge
// port 1, not port 0 and not the low bit.
func TestPortsInBitmap(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
		want  []int
	}{
		{"first port only", []byte{0x80}, []int{1}},
		{"first byte, four ports", []byte{0xf0}, []int{1, 2, 3, 4}},
		{"last bit of first byte", []byte{0x01}, []int{8}},
		{"second byte", []byte{0x00, 0x80}, []int{9}},
		// A switch numbering bridge ports from 101 needs 14 bytes to reach
		// them; ports 101 and 102 are bits 5 and 6 of byte 13.
		{"high ports", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c, 0}, []int{101, 102}},
		{"empty", []byte{}, nil},
	}

	for _, c := range cases {
		got := portsInBitmap(gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: c.bytes})
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestPortsInBitmapIgnoresNonOctetString(t *testing.T) {
	if got := portsInBitmap(gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 5}); got != nil {
		t.Errorf("expected nil for a non-octet-string PDU, got %v", got)
	}
}

// FDB tables are indexed by the MAC itself, as six decimal arcs.
func TestMacFromArcs(t *testing.T) {
	if got := macFromArcs([]string{"0", "80", "86", "1", "2", "255"}); got != "00:50:56:01:02:ff" {
		t.Errorf("got %q", got)
	}
	// An all-zero address is padding, not a device.
	if got := macFromArcs([]string{"0", "0", "0", "0", "0", "0"}); got != "" {
		t.Errorf("all-zero MAC should be rejected, got %q", got)
	}
	if got := macFromArcs([]string{"0", "80", "86", "1", "2"}); got != "" {
		t.Errorf("short arc list should be rejected, got %q", got)
	}
	if got := macFromArcs([]string{"0", "80", "86", "1", "2", "300"}); got != "" {
		t.Errorf("out-of-range arc should be rejected, got %q", got)
	}
}

// Only dynamically learned entries are real neighbours. self(4) is the
// switch's own port address; reporting it would wire every switch to itself.
func TestFdbLearnedFiltersSelfAndMgmt(t *testing.T) {
	status := map[string]gosnmp.SnmpPDU{
		"learned": {Type: gosnmp.Integer, Value: 3},
		"self":    {Type: gosnmp.Integer, Value: 4},
		"mgmt":    {Type: gosnmp.Integer, Value: 5},
	}
	if !fdbLearned(status, "learned") {
		t.Error("learned(3) should be kept")
	}
	if fdbLearned(status, "self") {
		t.Error("self(4) should be dropped")
	}
	if fdbLearned(status, "mgmt") {
		t.Error("mgmt(5) should be dropped")
	}
	// A device that publishes no status table must not have everything dropped.
	if !fdbLearned(nil, "anything") {
		t.Error("absent status table should mean keep")
	}
	if !fdbLearned(status, "unknown-index") {
		t.Error("missing status row should mean keep")
	}
}

func TestAlternatives(t *testing.T) {
	got := Alternatives(" 1.2.3 | 4.5.6 |")
	if len(got) != 2 || got[0] != "1.2.3" || got[1] != "4.5.6" {
		t.Errorf("got %v", got)
	}
	if got := Alternatives(""); len(got) != 0 {
		t.Errorf("empty spec should yield nothing, got %v", got)
	}
}

func TestLiteral(t *testing.T) {
	if v, ok := Literal("=Cisco"); !ok || v != "Cisco" {
		t.Errorf("got %q %v", v, ok)
	}
	// An OID must never be mistaken for a literal.
	if _, ok := Literal("1.3.6.1.2.1.1.5.0"); ok {
		t.Error("an OID must not parse as a literal")
	}
}

// A value that exists but is empty must not satisfy a field, or the first
// alternative would always win regardless of whether it answered.
func TestMeaningful(t *testing.T) {
	if meaningful(gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("")}) {
		t.Error("empty octet string is not meaningful")
	}
	if !meaningful(gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("FOC123")}) {
		t.Error("non-empty octet string is meaningful")
	}
	if meaningful(gosnmp.SnmpPDU{Type: gosnmp.NoSuchInstance}) {
		t.Error("noSuchInstance is not meaningful")
	}
	if meaningful(gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 0}) {
		t.Error("zero integer is not meaningful")
	}
}

func TestFormatUptime(t *testing.T) {
	// TimeTicks are hundredths of a second.
	if got := FormatUptime(987654321); got != "114 days, 07:29:03" {
		t.Errorf("got %q", got)
	}
	if got := FormatUptime(0); got != "" {
		t.Errorf("zero uptime should be empty, got %q", got)
	}
}
