// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package sweep

import "testing"

func TestExpandCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	addrs, err := ExpandRanges([]string{"192.0.2.0/29"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	// /29 is 8 addresses; .0 and .7 are network and broadcast.
	if len(addrs) != 6 {
		t.Fatalf("expected 6 usable hosts, got %d (%v)", len(addrs), addrs)
	}
	if addrs[0].String() != "192.0.2.1" || addrs[5].String() != "192.0.2.6" {
		t.Fatalf("unexpected bounds: %v", addrs)
	}
}

// RFC 3021: both addresses of a /31 are usable on a point-to-point link.
func TestSlash31UsesBothAddresses(t *testing.T) {
	addrs, err := ExpandRanges([]string{"192.0.2.0/31"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses for a /31, got %d (%v)", len(addrs), addrs)
	}
}

func TestSlash32IsTheAddressItself(t *testing.T) {
	addrs, err := ExpandRanges([]string{"192.0.2.5/32"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].String() != "192.0.2.5" {
		t.Fatalf("unexpected: %v", addrs)
	}
}

func TestRangeAcceptsReversedBounds(t *testing.T) {
	addrs, err := ExpandRanges([]string{"192.0.2.10-192.0.2.8"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 3 {
		t.Fatalf("expected 3 addresses, got %d (%v)", len(addrs), addrs)
	}
}

func TestDuplicatesCollapse(t *testing.T) {
	addrs, err := ExpandRanges([]string{"192.0.2.1", "192.0.2.1", "192.0.2.0/30"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, a := range addrs {
		seen[a.String()]++
	}
	for ip, n := range seen {
		if n > 1 {
			t.Fatalf("%s appeared %d times", ip, n)
		}
	}
}

// A mistyped prefix (/8 instead of /24) must fail loudly rather than queue
// sixteen million probes.
func TestExpansionIsCapped(t *testing.T) {
	if _, err := ExpandRanges([]string{"10.0.0.0/8"}, 1024); err == nil {
		t.Fatal("expected an error when the cap is exceeded")
	}
}

func TestBadInputIsRejected(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "192.0.2.0/33", "192.0.2.1-::1"} {
		if _, err := ExpandRanges([]string{bad}, 100); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}
