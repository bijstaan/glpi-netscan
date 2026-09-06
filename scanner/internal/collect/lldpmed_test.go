// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"testing"

	"github.com/bijstaan/glpi-netscan/internal/payload"
)

func TestMedFirmware(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    MedEndpoint
		want string
	}{
		// Software first: on a handset that is the number that changes when it
		// is upgraded, and the one a technician would quote.
		{"all three", MedEndpoint{Hardware: "1.0", Firmware: "66.8", Software: "5.9"}, "5.9"},
		{"no software", MedEndpoint{Hardware: "1.0", Firmware: "66.8"}, "66.8"},
		{"hardware only", MedEndpoint{Hardware: "1.0"}, "1.0"},
		{"nothing", MedEndpoint{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := medFirmware(tc.e); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMedDeviceID(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    MedEndpoint
		n    Neighbour
		want string
	}{
		{"serial wins", MedEndpoint{Serial: "ABC123", Model: "VVX"}, Neighbour{ChassisMAC: "00:11:22:33:44:55"}, "med-ABC123"},
		{"mac when no serial", MedEndpoint{Model: "VVX"}, Neighbour{ChassisMAC: "00:11:22:33:44:55"}, "med-001122334455"},
		{"model as last resort", MedEndpoint{Model: "VVX"}, Neighbour{}, "med-VVX"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := medDeviceID(tc.e, tc.n); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A phone must not be identified by its model string. The whole point of
// reading the media policy table is that "advertised a voice policy" is
// something the MIB says, where "the model name looks like a phone" is a guess
// that turns cameras into telephones.
//
// The non-voice endpoint here is not merely typed differently — it is not sent
// at all, because GLPI has already created an Unmanaged for it from the same
// switch's LLDP data and a second submission cannot improve it.
func TestMedInventoriesOnlyVoiceEndpoints(t *testing.T) {
	endpoints := map[string]MedEndpoint{
		"0.3.1": {Index: "0.3.1", Manufacturer: "Polycom", Model: "VVX 411", Serial: "PH1", Voice: true},
		// Named like a phone, but advertises no voice policy. Still not a phone.
		"0.9.1": {Index: "0.9.1", Manufacturer: "Axis", Model: "IP Phone Doorstation", Serial: "CAM1"},
	}
	neighbours := map[int]Neighbour{
		3: {Index: "0.3.1", ChassisMAC: "00:1b:53:cc:00:22", SysName: "phone-1055", MgmtIP: "10.10.20.55"},
		9: {Index: "0.9.1", ChassisMAC: "00:40:8c:aa:00:09"},
	}

	got := MedInventories(endpoints, neighbours, "10.10.10.2", "test")
	if len(got) != 1 {
		t.Fatalf("got %d inventories, want only the voice endpoint: %+v", len(got), got)
	}

	phone := got[0]
	if phone.DeviceID != "med-PH1" {
		t.Fatalf("sent %q, want the voice endpoint", phone.DeviceID)
	}
	if phone.ItemType != "Phone" {
		t.Errorf("voice endpoint filed as %q, want Phone", phone.ItemType)
	}
	if phone.Content.Device.Name != "phone-1055" {
		t.Errorf("name %q, want the neighbour's sysName", phone.Content.Device.Name)
	}
	if phone.Content.Device.MAC != "00:1b:53:cc:00:22" {
		t.Errorf("MAC %q not joined from the neighbour record", phone.Content.Device.MAC)
	}
}

// The name falls back to what the switch knows when the neighbour record has no
// sysName, which is common for endpoints that were never given a hostname.
func TestMedInventoriesNamesFromManufacturerAndModel(t *testing.T) {
	got := MedInventories(
		map[string]MedEndpoint{"0.3.1": {Manufacturer: "Polycom", Model: "VVX 411", Serial: "PH1", Voice: true}},
		map[int]Neighbour{3: {Index: "0.3.1"}},
		"10.10.10.2", "test",
	)
	if len(got) != 1 {
		t.Fatalf("got %d inventories, want 1", len(got))
	}
	if got[0].Content.Device.Name != "Polycom VVX 411" {
		t.Errorf("name %q, want manufacturer and model", got[0].Content.Device.Name)
	}
}

// The scan address is the switch's, because that is how the scanner reached
// these assets. Setting it to the endpoint's own address would claim the
// scanner talked to a device that answers nothing, and the off-target guard
// checks provenance.
func TestMedInventoriesReportsTheSwitchAsScanAddress(t *testing.T) {
	got := MedInventories(
		map[string]MedEndpoint{"0.3.1": {Serial: "PH1", Model: "VVX", Voice: true}},
		map[int]Neighbour{3: {Index: "0.3.1", MgmtIP: "10.10.20.55"}},
		"10.10.10.2", "test",
	)
	if len(got) != 1 {
		t.Fatalf("got %d inventories, want 1", len(got))
	}
	if got[0].ScanAddress != "10.10.10.2" {
		t.Errorf("scan address %q, want the switch's", got[0].ScanAddress)
	}
	if len(got[0].Content.Device.IPs) != 1 || got[0].Content.Device.IPs[0] != "10.10.20.55" {
		t.Errorf("endpoint IP %v, want its own management address", got[0].Content.Device.IPs)
	}
}

// Without a serial or a MAC there is nothing stable to key on, so every sweep
// would create another copy of the same handset.
func TestMedInventoriesSkipsUnidentifiable(t *testing.T) {
	got := MedInventories(
		map[string]MedEndpoint{"0.3.1": {Model: "VVX", Voice: true}},
		map[int]Neighbour{},
		"10.10.10.2", "test",
	)
	if len(got) != 0 {
		t.Fatalf("got %d inventories, want none: %+v", len(got), got)
	}
}

func TestMedInventoriesEmpty(t *testing.T) {
	if got := MedInventories(nil, nil, "10.0.0.1", "test"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// The media policy table is indexed one arc wider than the inventory table.
// Dropping the wrong arc silently types every endpoint as a phone, or none.
func TestVoiceEndpoints(t *testing.T) {
	got := voiceEndpoints(map[string]string{
		"0.3.1.1":  "20",  // voice(1) on the phone
		"0.3.1.2":  "20",  // voiceSignaling(2) on the same phone
		"0.9.1.4":  "0",   // guestVoice(4) — not voice(1)
		"0.11.1.7": "100", // videoConferencing(7)
		"bad":      "1",   // too few arcs to carry an application type
	})

	if !got["0.3.1"] {
		t.Error("endpoint advertising voice(1) not recognised")
	}
	if got["0.9.1"] || got["0.11.1"] {
		t.Errorf("non-voice applications treated as voice: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("got %v, want only the voice endpoint", got)
	}
}

// A phone visible both ways must keep what the direct walk found. Letting the
// MED record through means GLPI merges them and the one with no interfaces
// wins, stripping the ports off the asset.
func TestDropShadowedMed(t *testing.T) {
	direct := payload.Inventory{
		DeviceID: "phone-10.10.20.42",
		Content: payload.Content{
			Device: &payload.Device{Serial: "8801234567890", Name: "phone-1042"},
			Ports:  []payload.Port{{IfName: "eth0", MAC: "00:1b:53:cc:00:11"}},
		},
	}
	shadow := payload.Inventory{
		DeviceID: "med-8801234567890",
		Content:  payload.Content{Device: &payload.Device{Serial: "8801234567890"}},
	}
	// Same handset, reported by the switch under a MAC the direct walk saw on a
	// port rather than as the device MAC.
	byMAC := payload.Inventory{
		DeviceID: "med-001b53cc0011",
		Content:  payload.Content{Device: &payload.Device{MAC: "00-1B-53-CC-00-11"}},
	}
	// Nothing else has ever heard of this one.
	only := payload.Inventory{
		DeviceID: "med-8C4470112233",
		Content:  payload.Content{Device: &payload.Device{Serial: "8C4470112233", Name: "phone-1055"}},
	}

	got := DropShadowedMed([]payload.Inventory{direct, shadow, byMAC, only})

	if len(got) != 2 {
		t.Fatalf("got %d payloads, want 2: %+v", len(got), got)
	}
	if got[0].DeviceID != direct.DeviceID {
		t.Errorf("direct walk dropped or reordered: %q", got[0].DeviceID)
	}
	if got[1].DeviceID != only.DeviceID {
		t.Errorf("kept %q, want the MED-only handset", got[1].DeviceID)
	}
}

// With nothing walked directly, every MED asset survives — otherwise a sweep
// of switches alone would report nothing.
func TestDropShadowedMedKeepsAllWhenNothingDirect(t *testing.T) {
	in := []payload.Inventory{
		{DeviceID: "med-A", Content: payload.Content{Device: &payload.Device{Serial: "A"}}},
		{DeviceID: "med-B", Content: payload.Content{Device: &payload.Device{Serial: "B"}}},
	}
	if got := DropShadowedMed(in); len(got) != 2 {
		t.Errorf("got %d, want 2", len(got))
	}
}

// Two unparseable MACs are not evidence of the same device.
func TestMacKeyRejectsMalformed(t *testing.T) {
	for _, in := range []string{"", "00:11:22", "not a mac", "zz:zz:zz:zz:zz:zz"} {
		if got := macKey(in); got != "" {
			t.Errorf("macKey(%q) = %q, want empty", in, got)
		}
	}
	if got := macKey("00-1B-53-CC-00-11"); got != "001b53cc0011" {
		t.Errorf("got %q", got)
	}
}
