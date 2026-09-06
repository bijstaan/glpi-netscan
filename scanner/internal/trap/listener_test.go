// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package trap

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// send a v2c trap to the listener and wait for it to be forwarded.
func sendTrap(t *testing.T, port uint16, trapOID string) {
	t.Helper()

	client := &gosnmp.GoSNMP{
		Target:    "127.0.0.1",
		Port:      port,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   0,
	}
	if err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Conn.Close()

	_, err := client.SendTrap(gosnmp.SnmpTrap{
		Variables: []gosnmp.SnmpPDU{
			{Name: "1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: trapOID},
			{Name: "1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.Integer, Value: 3},
		},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestListenerReceivesAndNames(t *testing.T) {
	got := make(chan []Notification, 1)

	l := New(Config{
		Port:       11999,
		Allowed:    []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		FlushEvery: 200 * time.Millisecond,
	}, func(batch []Notification) { got <- batch })

	go func() { _ = l.Run() }()
	defer l.Close()
	time.Sleep(300 * time.Millisecond)

	sendTrap(t, 11999, "1.3.6.1.6.3.1.1.5.3")

	select {
	case batch := <-got:
		if len(batch) != 1 {
			t.Fatalf("got %d notifications, want 1", len(batch))
		}
		n := batch[0]
		if n.TrapOID != "1.3.6.1.6.3.1.1.5.3" {
			t.Errorf("trap oid = %q", n.TrapOID)
		}
		// Named, so an operator reading the list sees words rather than arcs.
		if n.TrapName != "linkDown" {
			t.Errorf("trap name = %q, want linkDown", n.TrapName)
		}
		if n.Varbinds["1.3.6.1.2.1.2.2.1.1.3"] != "3" {
			t.Errorf("varbinds = %v", n.Varbinds)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification was forwarded")
	}
}

// TestListenerRejectsOutOfRange is the rule that makes an unauthenticated
// datagram tolerable: a trap is only accepted from an address the scanner was
// already told to scan.
func TestListenerRejectsOutOfRange(t *testing.T) {
	got := make(chan []Notification, 1)

	l := New(Config{
		Port:       11998,
		Allowed:    []netip.Prefix{netip.MustParsePrefix("10.99.99.0/24")},
		FlushEvery: 200 * time.Millisecond,
	}, func(batch []Notification) { got <- batch })

	go func() { _ = l.Run() }()
	defer l.Close()
	time.Sleep(300 * time.Millisecond)

	sendTrap(t, 11998, "1.3.6.1.6.3.1.1.5.3")

	select {
	case batch := <-got:
		t.Fatalf("a trap from an address outside the permitted ranges was accepted: %+v", batch)
	case <-time.After(1500 * time.Millisecond):
		// Nothing forwarded, which is the point.
	}
}

// TestListenerRefusesWithoutRanges: an empty permitted set must close the
// listener rather than open it to everything.
func TestListenerRefusesWithoutRanges(t *testing.T) {
	l := New(Config{Port: 11997}, func([]Notification) {})
	if err := l.Run(); err == nil {
		l.Close()
		t.Error("listening was allowed with no permitted source ranges")
	}
}
