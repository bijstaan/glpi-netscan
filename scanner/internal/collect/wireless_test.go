// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"testing"

	"github.com/bijstaan/glpi-netscan/internal/payload"
)

func TestAPDeviceID(t *testing.T) {
	// The identity must be the AP's own, never the controller's. An AP moved to
	// a different controller is the same physical box, and a controller
	// replaced under warranty must not orphan every AP behind it.
	for _, tc := range []struct {
		name string
		ap   AccessPoint
		want string
	}{
		{"serial wins", AccessPoint{Name: "ap1", Serial: "FGL1", MAC: "00:11:22:33:44:55"}, "ap-FGL1"},
		{"mac when no serial", AccessPoint{Name: "ap1", MAC: "00:11:22:33:44:55"}, "ap-001122334455"},
		{"name as a last resort", AccessPoint{Name: "ap1"}, "ap-ap1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := apDeviceID(tc.ap); got != tc.want {
				t.Errorf("apDeviceID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAPInventories(t *testing.T) {
	aps := []AccessPoint{
		{Name: "ap-a", Serial: "S1", MAC: "00:11:22:33:44:01", Model: "M1", Location: "Floor 1", IP: "10.0.0.1"},
		{Name: "ap-b", MAC: "00:11:22:33:44:02"},
		// No serial and no MAC: unmatchable on the next scan, so every run would
		// create another copy. Skipped rather than duplicated.
		{Name: "ap-ghost"},
	}

	got := APInventories("wlc-1", "192.0.2.10", aps, "glpi-netscan test")

	if len(got) != 2 {
		t.Fatalf("got %d inventories, want 2 (the identity-less AP must be skipped)", len(got))
	}

	first := got[0]
	if first.ItemType != "NetworkEquipment" {
		t.Errorf("itemtype = %q, want NetworkEquipment", first.ItemType)
	}
	if first.Content.Device.Type != payload.TypeNetworking {
		t.Errorf("device type = %q", first.Content.Device.Type)
	}
	if first.Content.Device.Serial != "S1" || first.Content.Device.Model != "M1" {
		t.Errorf("device fields not carried: %+v", first.Content.Device)
	}
	if first.Content.Device.Location != "Floor 1" {
		t.Errorf("location not carried: %q", first.Content.Device.Location)
	}

	// The address the controller answered on, not the AP's own. The off-target
	// guard checks submissions against the ranges the scanner was told to
	// sweep, and an AP behind a controller legitimately sits outside them —
	// often on a management VLAN the scanner cannot reach at all.
	for _, inv := range got {
		if inv.ScanAddress != "192.0.2.10" {
			t.Errorf("%s: scan_address = %q, want the controller's address",
				inv.DeviceID, inv.ScanAddress)
		}
	}

	// The AP's own address still belongs on the asset.
	if len(first.Content.Device.IPs) != 1 || first.Content.Device.IPs[0] != "10.0.0.1" {
		t.Errorf("AP address missing from the asset: %v", first.Content.Device.IPs)
	}
	if len(got[1].Content.Device.IPs) != 0 {
		t.Errorf("an AP with no address should carry none, got %v", got[1].Content.Device.IPs)
	}
}

func TestDecodeStatus(t *testing.T) {
	const cisco = "1=associated,2=disassociated,3=downloading"

	for _, tc := range []struct{ mapping, in, want string }{
		{cisco, "1", "associated"},
		{cisco, "2", "disassociated"},
		// An unmapped code is passed through rather than blanked: an operator
		// seeing "7" knows the device said something and can map it, whereas an
		// empty cell says the scanner did not look.
		{cisco, "7", "7"},
		{"", "2", "2"},
		{cisco, "", ""},
		{" 1 = associated ", "1", "associated"},
	} {
		if got := decodeStatus(tc.mapping, tc.in); got != tc.want {
			t.Errorf("decodeStatus(%q, %q) = %q, want %q", tc.mapping, tc.in, got, tc.want)
		}
	}
}

func TestBlock(t *testing.T) {
	if got := Block("wlc", nil, nil); got != nil {
		t.Errorf("Block with nothing to report = %+v, want nil", got)
	}

	got := Block("wlc-1",
		[]SSID{{Name: "corp", Clients: 12}},
		[]AccessPoint{{Name: "ap-a", Serial: "S1", Status: "associated", Radios: 2, Clients: 5}})

	if got == nil {
		t.Fatal("Block returned nil with content to report")
	}
	if got.Controller != "wlc-1" {
		t.Errorf("controller = %q", got.Controller)
	}
	if len(got.SSIDs) != 1 || got.SSIDs[0].Clients != 12 {
		t.Errorf("ssids = %+v", got.SSIDs)
	}
	if len(got.AccessPoints) != 1 || got.AccessPoints[0].Status != "associated" {
		t.Errorf("aps = %+v", got.AccessPoints)
	}
}

func TestNormaliseIP(t *testing.T) {
	// A vendor returning a hex blob, a zero address or nothing at all must not
	// become a bogus address on the asset.
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.1"},
		{" 10.0.0.1 ", "10.0.0.1"},
		{"0.0.0.0", ""},
		{"", ""},
		{"not-an-address", ""},
		{"\x00\x01\x02\x03", ""},
	} {
		if got := normaliseIP(tc.in); got != tc.want {
			t.Errorf("normaliseIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRadiosByAP is the correlation that per-AP client counts depend on. Every
// vendor with a radio table indexes it one arc finer than the AP table, so a
// row belongs to the AP whose index is the longest prefix of it. Getting this
// wrong attributes one radio's clients to a different access point entirely.
func TestRadiosByAP(t *testing.T) {
	apIndexes := []string{"0.192.183.225.0.17", "0.192.183.225.0.18"}

	got := radiosByAP(
		apIndexes,
		map[string]string{
			"0.192.183.225.0.17.0": "1", "0.192.183.225.0.17.1": "2",
			"0.192.183.225.0.18.0": "1",
		},
		map[string]string{
			"0.192.183.225.0.17.0": "1", "0.192.183.225.0.17.1": "1",
			"0.192.183.225.0.18.0": "2",
		},
		map[string]int64{"0.192.183.225.0.17.0": 6, "0.192.183.225.0.17.1": 44},
		map[string]int64{
			"0.192.183.225.0.17.0": 9, "0.192.183.225.0.17.1": 14,
			"0.192.183.225.0.18.0": 4,
		},
		"1=2.4GHz,2=5GHz", "1=up,2=down",
	)

	if len(got["0.192.183.225.0.17"]) != 2 {
		t.Fatalf("first AP got %d radios, want 2", len(got["0.192.183.225.0.17"]))
	}
	if len(got["0.192.183.225.0.18"]) != 1 {
		t.Fatalf("second AP got %d radios, want 1", len(got["0.192.183.225.0.18"]))
	}

	first := got["0.192.183.225.0.17"]
	if first[0].Slot != "0" || first[1].Slot != "1" {
		t.Errorf("radios not ordered by slot: %+v", first)
	}
	if first[0].Band != "2.4GHz" || first[1].Band != "5GHz" {
		t.Errorf("bands not decoded: %+v", first)
	}
	if first[0].Channel != 6 || first[0].Clients != 9 {
		t.Errorf("first radio = %+v", first[0])
	}
	if got["0.192.183.225.0.18"][0].Status != "down" {
		t.Errorf("status not decoded: %+v", got["0.192.183.225.0.18"][0])
	}
}

// TestLongestAPPrefix: one AP index can be a prefix of another only by
// accident, but an accident here silently files a radio under the wrong access
// point — so the longest match wins, not the first.
func TestLongestAPPrefix(t *testing.T) {
	indexes := []string{"1.2", "1.2.3"}

	owner, slot := longestAPPrefix(indexes, "1.2.3.7")
	if owner != "1.2.3" || slot != "7" {
		t.Errorf("got owner=%q slot=%q, want 1.2.3 / 7", owner, slot)
	}

	owner, slot = longestAPPrefix(indexes, "1.2.9")
	if owner != "1.2" || slot != "9" {
		t.Errorf("got owner=%q slot=%q, want 1.2 / 9", owner, slot)
	}

	// A row belonging to no known AP is dropped rather than guessed at.
	if owner, _ = longestAPPrefix(indexes, "9.9.9"); owner != "" {
		t.Errorf("unrelated row was claimed by %q", owner)
	}
}
