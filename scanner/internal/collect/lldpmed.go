// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"sort"
	"strconv"
	"strings"

	"github.com/bijstaan/glpi-netscan/internal/payload"
)

// LLDP-MED inventory: what a switch knows about the endpoints plugged into it.
//
// The devices this reaches are the ones nothing else can. A desk phone or a
// camera often speaks no SNMP at all, or speaks it only to a management VLAN
// the scanner cannot route to — but it announces its own manufacturer, model,
// serial number and firmware over LLDP-MED to the switch port it is plugged
// into, and the switch will hand all of that over. One scan of a switch
// therefore inventories a cupboard full of phones that could never be scanned.
//
// The same shape as access points behind a wireless controller: one scanned
// address, several assets, each keyed on its own identity rather than the
// device that reported it.
//
// OIDs from LLDP-EXT-MED-MIB (ANSI/TIA-1057), under the TIA OUI subtree
// 1.0.8802.1.1.2.1.5.4795. The inventory table's columns come out contiguous
// from .1 to .7, which is itself evidence the reading is right.
const (
	oidMedRemHardwareRev = "1.0.8802.1.1.2.1.5.4795.1.3.3.1.1"
	oidMedRemFirmwareRev = "1.0.8802.1.1.2.1.5.4795.1.3.3.1.2"
	oidMedRemSoftwareRev = "1.0.8802.1.1.2.1.5.4795.1.3.3.1.3"
	oidMedRemSerialNum   = "1.0.8802.1.1.2.1.5.4795.1.3.3.1.4"
	oidMedRemMfgName     = "1.0.8802.1.1.2.1.5.4795.1.3.3.1.5"
	oidMedRemModelName   = "1.0.8802.1.1.2.1.5.4795.1.3.3.1.6"
	oidMedRemAssetID     = "1.0.8802.1.1.2.1.5.4795.1.3.3.1.7"

	// The media policy table is indexed by (timeMark, localPort, remIndex,
	// applicationType) — one arc finer than the inventory table, with the
	// application type as the last arc. Walking any column of it therefore says
	// which applications a neighbour advertised, which is how a phone is told
	// from a camera without guessing from the model string.
	oidMedRemMediaPolicyVlanID = "1.0.8802.1.1.2.1.5.4795.1.3.2.1.2"
)

// LldpMedAppVoice is application type voice(1) from LldpXMedMediaPolicyAppType.
//
// An endpoint advertising a voice media policy is a voice device. That is a
// statement the MIB makes, not an inference from a model name — which matters,
// because the alternative is filing every MED endpoint as a phone and turning
// an estate's cameras and door controllers into phones.
const LldpMedAppVoice = 1

// MedEndpoint is one endpoint as its switch describes it.
type MedEndpoint struct {
	// Index is the LLDP remote index (timeMark.localPort.remIndex), which is
	// what ties this back to the neighbour seen on a port.
	Index string

	Manufacturer string
	Model        string
	Serial       string
	Firmware     string
	Hardware     string
	Software     string
	AssetTag     string

	// Voice is true when the endpoint advertised a voice media policy.
	Voice bool
}

// MedInventory reads what the switch has learned about its endpoints.
func (c *Collector) MedInventory() map[string]MedEndpoint {
	// MED is an extension of LLDP, so it follows the LLDP switch: turning LLDP
	// off for a device means "do not do LLDP on this one", and the endpoint
	// records are also useless without the neighbour records to join them to.
	if !c.feature("lldp") {
		return nil
	}

	models := c.walkText(oidMedRemModelName)
	serials := c.walkText(oidMedRemSerialNum)
	mfgs := c.walkText(oidMedRemMfgName)

	// Nothing worth an asset without at least one of these. A switch that
	// implements the table but has nothing plugged into it answers with rows
	// full of empty strings, and those must not become assets.
	if len(models) == 0 && len(serials) == 0 && len(mfgs) == 0 {
		return nil
	}

	firmware := c.walkText(oidMedRemFirmwareRev)
	hardware := c.walkText(oidMedRemHardwareRev)
	software := c.walkText(oidMedRemSoftwareRev)
	assets := c.walkText(oidMedRemAssetID)
	voice := c.medVoiceEndpoints()

	indexes := map[string]struct{}{}
	for _, set := range []map[string]string{models, serials, mfgs, firmware, hardware, software, assets} {
		for idx := range set {
			indexes[idx] = struct{}{}
		}
	}

	out := map[string]MedEndpoint{}
	for idx := range indexes {
		e := MedEndpoint{Index: idx, Voice: voice[idx]}

		e.Manufacturer = strings.TrimSpace(mfgs[idx])
		e.Model = strings.TrimSpace(models[idx])
		e.Serial = strings.TrimSpace(serials[idx])
		e.Firmware = strings.TrimSpace(firmware[idx])
		e.Hardware = strings.TrimSpace(hardware[idx])
		e.Software = strings.TrimSpace(software[idx])
		e.AssetTag = strings.TrimSpace(assets[idx])

		// A row with no manufacturer, model or serial describes nothing. Some
		// switches keep the row after the endpoint is unplugged.
		if e.Manufacturer == "" && e.Model == "" && e.Serial == "" {
			continue
		}

		out[idx] = e
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// medVoiceEndpoints reports which neighbours advertised a voice media policy.
func (c *Collector) medVoiceEndpoints() map[string]bool {
	return voiceEndpoints(c.walkText(oidMedRemMediaPolicyVlanID))
}

// voiceEndpoints maps media policy rows back onto inventory rows.
//
// Split from the walk because this is index arithmetic on a table one arc wider
// than the one it keys into, and getting it wrong types every endpoint as a
// phone or none of them.
func voiceEndpoints(rows map[string]string) map[string]bool {
	out := map[string]bool{}
	for idx := range rows {
		arcs := strings.Split(idx, ".")
		if len(arcs) < 4 {
			continue
		}

		appType, err := strconv.Atoi(arcs[len(arcs)-1])
		if err != nil || appType != LldpMedAppVoice {
			continue
		}

		// Back to the inventory table's index by dropping the application arc.
		out[strings.Join(arcs[:len(arcs)-1], ".")] = true
	}

	return out
}

// walkText walks a column into strings keyed by the raw index suffix.
func (c *Collector) walkText(oid string) map[string]string {
	rows, err := c.Session.Walk(oid)
	if err != nil {
		return map[string]string{}
	}

	out := make(map[string]string, len(rows))
	for suffix, pdu := range rows {
		out[suffix] = text(pdu)
	}

	return out
}

// MedInventories turns voice endpoints into submissions of their own.
//
// Only voice endpoints. LLDP-MED reports inventory for everything plugged into
// the switch — cameras, door controllers, paging speakers — and all of it is
// real, but only the phones can be delivered to GLPI:
//
//   - A voice endpoint becomes a Phone, which is an itemtype GLPI has no other
//     record of, so the submission creates the asset and keeps its name, model,
//     serial, brand and asset tag. Not its firmware: GLPI's Phone has no
//     firmware field, and builds a firmware component only for wireless
//     controllers. It is collected anyway, because the cost is nothing and the
//     alternative is a collector that has to be rewritten if that changes.
//   - Anything else could only be an Unmanaged, and GLPI has already made one.
//     Every MED endpoint is by definition an LLDP neighbour of the switch, and
//     GLPI's own inventory creates an Unmanaged for each unmatched neighbour
//     while processing the switch. That asset wins: a later submission for the
//     same MAC is matched to its network port rather than applied to it, and
//     the model and serial are dropped. Verified by submitting one both before
//     and after the switch's own inventory — the outcome does not depend on
//     order — so emitting these would be code that runs, reports success, and
//     changes nothing.
//
// "Advertised a voice media policy" is what the MIB says, and the classifier is
// only ever used to decide what to send, never to describe a device as
// something the switch did not claim it was.
//
// scanAddress is the *switch's* address, not the endpoint's. The endpoint may
// have no address at all, and the off-target guard checks provenance: the
// scanner reached this asset by asking the switch.
func MedInventories(
	endpoints map[string]MedEndpoint,
	neighbours map[int]Neighbour,
	scanAddress, versionClient string,
) []payload.Inventory {
	if len(endpoints) == 0 {
		return nil
	}

	// The neighbour records carry the MAC and name; the MED table carries the
	// inventory. They share the LLDP remote index, so one is joined onto the
	// other by it.
	byIndex := map[string]Neighbour{}
	for _, n := range neighbours {
		if n.Index != "" {
			byIndex[n.Index] = n
		}
	}

	keys := make([]string, 0, len(endpoints))
	for idx := range endpoints {
		keys = append(keys, idx)
	}
	sort.Strings(keys)

	out := make([]payload.Inventory, 0, len(keys))
	for _, idx := range keys {
		e := endpoints[idx]
		n := byIndex[idx]

		// Without a serial or a MAC there is nothing stable to match on, so
		// every scan would create another copy. The same rule access points
		// behind a controller follow.
		if e.Serial == "" && n.ChassisMAC == "" {
			continue
		}

		// See above: a non-voice endpoint could only be filed as an Unmanaged,
		// and GLPI has already created that asset from the same switch's LLDP
		// data before this submission could arrive.
		if !e.Voice {
			continue
		}

		name := n.SysName
		if name == "" {
			name = strings.TrimSpace(strings.Join([]string{e.Manufacturer, e.Model}, " "))
		}
		if name == "" {
			name = e.Serial
		}

		dev := &payload.Device{
			Type:         payload.TypePhone,
			Name:         name,
			Manufacturer: e.Manufacturer,
			Model:        e.Model,
			Serial:       e.Serial,
			Firmware:     medFirmware(e),
			MAC:          n.ChassisMAC,
			AssetTag:     e.AssetTag,
		}
		if n.MgmtIP != "" {
			dev.IPs = []string{n.MgmtIP}
		}

		out = append(out, payload.Inventory{
			DeviceID:    medDeviceID(e, n),
			Action:      string(payload.QueryInventory),
			ItemType:    payload.GLPIItemType(payload.TypePhone),
			ScanAddress: scanAddress,
			Content: payload.Content{
				Device:        dev,
				VersionClient: versionClient,
			},
		})
	}

	return out
}

// medDeviceID keys the asset on the endpoint's own identity.
//
// Never on the switch's: a phone moved to a different desk is the same phone,
// and re-cabling a floor must not create a second copy of every handset.
func medDeviceID(e MedEndpoint, n Neighbour) string {
	switch {
	case e.Serial != "":
		return "med-" + e.Serial
	case n.ChassisMAC != "":
		return "med-" + strings.ReplaceAll(n.ChassisMAC, ":", "")
	default:
		return "med-" + e.Model
	}
}

// medFirmware picks the most useful of the three revision fields.
//
// LLDP-MED carries hardware, firmware and software revisions separately, and
// vendors disagree about which one holds the number a technician would call
// "the firmware". Software is preferred because on phones it is the field that
// changes when they are upgraded; firmware is the fallback.
func medFirmware(e MedEndpoint) string {
	for _, v := range []string{e.Software, e.Firmware, e.Hardware} {
		if v != "" {
			return v
		}
	}

	return ""
}

// MedDeviceIDPrefix marks an asset that came from a switch's MED tables rather
// than from talking to the device.
const MedDeviceIDPrefix = "med-"

// DropShadowedMed removes MED assets for devices the sweep also walked directly.
//
// A handset can be visible both ways: it answers SNMP on its own address *and*
// its switch reports it over LLDP-MED. Both submissions describe the same
// asset, so GLPI merges them — and the MED one, which knows nothing about the
// device's interfaces, then wins and strips the ports the direct walk found.
// Second-hand information overwriting first-hand information is a straight
// downgrade, and this is where it is prevented.
//
// The match is on serial and MAC rather than address, because the two sources
// disagree about addresses by nature: LLDP reports the endpoint's management
// address, which is often on a voice VLAN the scanner never sweeps.
func DropShadowedMed(payloads []payload.Inventory) []payload.Inventory {
	direct := map[string]struct{}{}

	for _, p := range payloads {
		if strings.HasPrefix(p.DeviceID, MedDeviceIDPrefix) {
			continue
		}

		dev := p.Content.Device
		if dev == nil {
			continue
		}

		if dev.Serial != "" {
			direct["s:"+strings.ToLower(dev.Serial)] = struct{}{}
		}
		if k := macKey(dev.MAC); k != "" {
			direct["m:"+k] = struct{}{}
		}

		// A phone's LLDP chassis ID is usually one of its own port MACs rather
		// than anything reported as the device MAC, so those count too.
		for _, port := range p.Content.Ports {
			if k := macKey(port.MAC); k != "" {
				direct["m:"+k] = struct{}{}
			}
		}
	}

	if len(direct) == 0 {
		return payloads
	}

	out := payloads[:0:0]
	for _, p := range payloads {
		if strings.HasPrefix(p.DeviceID, MedDeviceIDPrefix) && shadowed(p, direct) {
			continue
		}
		out = append(out, p)
	}

	return out
}

func shadowed(p payload.Inventory, direct map[string]struct{}) bool {
	dev := p.Content.Device
	if dev == nil {
		return false
	}

	if dev.Serial != "" {
		if _, ok := direct["s:"+strings.ToLower(dev.Serial)]; ok {
			return true
		}
	}
	if k := macKey(dev.MAC); k != "" {
		if _, ok := direct["m:"+k]; ok {
			return true
		}
	}

	return false
}

// macKey compares MACs by their digits alone, since the two sources that report
// one here need not agree on separators or case.
//
// Anything that is not twelve hex digits returns empty and is never compared:
// two unparseable MACs are not evidence of the same device, and treating them
// as one would discard a real asset.
func macKey(mac string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(mac) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}

	if b.Len() != 12 {
		return ""
	}

	return b.String()
}
