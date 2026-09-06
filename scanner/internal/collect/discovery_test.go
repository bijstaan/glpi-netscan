// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"testing"

	"github.com/bijstaan/glpi-netscan/internal/payload"
)

func TestClassifyFromIdentity(t *testing.T) {
	// sysServices is a bitmask, not an enumeration — the classic mistake is to
	// compare it for equality and miss every device that also sets a bit for
	// something else.
	for _, tc := range []struct {
		name     string
		services int
		want     string
	}{
		{"switch: datalink + internet", 0x02 | 0x04, payload.TypeNetworking},
		{"router: datalink + internet + application", 0x02 | 0x04 | 0x40, payload.TypeNetworking},
		{"appliance: internet + application only", 0x04 | 0x40, payload.TypeUnmanaged},
		{"printer reports the same as any appliance", 72, payload.TypeUnmanaged},
		{"nothing reported", 0, payload.TypeUnmanaged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyFromIdentity(Identity{SysServices: tc.services})
			if got != tc.want {
				t.Errorf("classify(%d) = %q, want %q", tc.services, got, tc.want)
			}
		})
	}
}

func TestDiscoveryPayload(t *testing.T) {
	ident := Identity{
		SysName:     "core-sw-01",
		SysDescr:    "a switch",
		SysContact:  "netops",
		SysLocation: "MDF",
		SysServices: 0x02 | 0x04,
		UpTimeTicks: 12345,
	}
	markers := payload.Markers{UptimeTicks: 12345, IfTableLastChange: 77}

	inv := DiscoveryPayload("core-sw-01-10.0.0.1", "10.0.0.1", ident,
		DiscoveryDevice(ident), markers, "test")

	if inv.Action != string(payload.QueryDiscovery) {
		t.Errorf("action = %q, want netdiscovery", inv.Action)
	}
	if inv.ScanAddress != "10.0.0.1" {
		t.Errorf("scan_address = %q", inv.ScanAddress)
	}
	if inv.Markers == nil || inv.Markers.IfTableLastChange != 77 {
		t.Errorf("markers not carried: %+v", inv.Markers)
	}

	// A discovery must stay thin. Anything walked here is paid for on every
	// address of every range on every pass, which is what the split exists to
	// avoid.
	if len(inv.Content.Ports) != 0 || len(inv.Content.Components) != 0 {
		t.Errorf("discovery carried tables: %d ports, %d components",
			len(inv.Content.Ports), len(inv.Content.Components))
	}
	if inv.Content.Device.Name != "core-sw-01" {
		t.Errorf("name = %q", inv.Content.Device.Name)
	}
	if inv.Content.Device.Location != "MDF" {
		t.Errorf("location = %q", inv.Content.Device.Location)
	}
	// Serial and model belong to the inventory pass: reading them means
	// profile OIDs against a device we may be about to decide not to walk.
	if inv.Content.Device.Serial != "" || inv.Content.Device.Model != "" {
		t.Errorf("discovery read identity fields it should not: %+v", inv.Content.Device)
	}
}
