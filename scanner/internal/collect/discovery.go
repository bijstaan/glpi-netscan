// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// Discovery: the cheap pass that decides whether the expensive one is needed.
//
// Measured against the SNMP simulators, a full inventory walk costs
// between 86 and 157 times what a probe does — roughly 2ms against 200-360ms,
// and that is with tiny tables on loopback. A 48-port switch across a WAN is
// far worse. So the cost of a sweep is dominated by full-walking the devices
// that *answer*, not by probing the addresses that do not, and the saving comes
// from not re-walking a device that has not changed since the last time.
//
// Which means discovery has to carry enough for someone to make that decision.
// These three counters are what the standard MIBs offer:
//
//   - ifTableLastChange   an interface was created or deleted
//   - ifStackLastChange   the layering between interfaces changed
//   - entLastChangeTime   the physical inventory changed — a module, a stack
//     member, a transceiver
//
// All three are sysUpTime-relative, so they are meaningless across a reboot —
// which does not matter, because a reboot is itself a reason to re-walk and is
// visible as uptime going backwards.
//
// What they deliberately do not catch is a port changing state, or a MAC moving
// between ports. Those change constantly and would defeat the whole point. The
// bound on that staleness is the inventory interval, not these counters.
const (
	oidIfTableLastChange = "1.3.6.1.2.1.31.1.5.0"
	oidIfStackLastChange = "1.3.6.1.2.1.31.1.6.0"
	oidEntLastChangeTime = "1.3.6.1.2.1.47.1.4.1.0"
)

// Markers reads the change counters, in one GET alongside the probe.
//
// Absent counters come back as zero, which is correct: a device that does not
// implement them offers no evidence of change, so the decision falls back to
// the interval. Errors are swallowed for the same reason — a missing scalar is
// the normal case on simple hardware, not a fault worth failing a sweep over.
func Markers(sess *snmpx.Session, ident Identity) payload.Markers {
	markers := payload.Markers{UptimeTicks: ident.UpTimeTicks}

	res, err := sess.Get([]string{
		oidIfTableLastChange,
		oidIfStackLastChange,
		oidEntLastChangeTime,
	})
	if err != nil {
		return markers
	}

	markers.IfTableLastChange = num(res, oidIfTableLastChange)
	markers.IfStackLastChange = num(res, oidIfStackLastChange)
	markers.EntityLastChange = num(res, oidEntLastChangeTime)

	return markers
}

// DiscoveryPayload builds the submission for the cheap pass.
//
// Deliberately thin. It carries what a discovery is *for* — something answers
// here, this is what it says it is — and the markers that let the server decide
// whether the expensive pass is warranted. No port walk, no tables.
//
// The device type is included because GLPI files a discovery into an asset type
// too, and classifying from sysServices and a couple of cheap probes is what
// stops every discovered device landing as Unmanaged and then being corrected
// on the next full walk.
func DiscoveryPayload(
	deviceID, host string,
	ident Identity,
	dev *payload.Device,
	markers payload.Markers,
	versionClient string,
) payload.Inventory {
	return payload.Inventory{
		DeviceID:    deviceID,
		Action:      string(payload.QueryDiscovery),
		ItemType:    payload.GLPIItemType(dev.Type),
		ScanAddress: host,
		Markers:     &markers,
		Content: payload.Content{
			Device:        dev,
			VersionClient: versionClient,
		},
	}
}

// DiscoveryDevice builds the identity block from a probe alone.
//
// No profile OIDs are read: those are GETs against a device we may be about to
// decide not to walk, and the whole point of this pass is that it costs almost
// nothing. Serial and model are left to the inventory pass.
func DiscoveryDevice(ident Identity) *payload.Device {
	dev := &payload.Device{
		Type:        classifyFromIdentity(ident),
		Name:        ident.SysName,
		Description: ident.SysDescr,
		Contact:     ident.SysContact,
		Location:    ident.SysLocation,
	}

	if dev.Name == "" {
		dev.Name = ident.SysName
	}

	return dev
}

// classifyFromIdentity types a device without walking anything.
//
// Only sysServices is available this cheaply, so this is coarser than the full
// classification — a printer looks like any other IP appliance here. That is
// the right trade: a discovery says "something is at this address and it speaks
// SNMP", and the inventory pass corrects the type when it runs. Guessing harder
// from sysObjectID would mean shipping a vendor table that goes stale.
func classifyFromIdentity(ident Identity) string {
	// datalink(2) plus internet(4) is a switch or router; the bits are a
	// bitmask, not an enumeration.
	const (
		datalink = 0x02
		internet = 0x04
	)

	if ident.SysServices&datalink != 0 && ident.SysServices&internet != 0 {
		return payload.TypeNetworking
	}

	return payload.TypeUnmanaged
}
