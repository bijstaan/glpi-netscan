// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// Wireless controllers and the access points behind them.
//
// The awkward fact about controller-based Wi-Fi is that the access points are
// real, individually serial-numbered assets that an MSP replaces, moves and
// bills for — and most of them cannot be scanned. A CAPWAP-tunnelled AP has no
// reachable management address of its own; the controller is the only thing
// that knows it exists. So scanning one address has to be able to produce many
// assets, which is why Inventory returns a slice.
//
// Every OID here comes from the profile, not from this file. The mechanism is
// generic — walk these columns, correlate rows by table index — so supporting
// Aruba or UniFi is a JSON profile rather than a code change. The one thing the
// collector does know is how to turn a table index into a MAC, because the
// vendors that matter index their AP table by the AP's own base MAC and that
// address is the most useful identity an AP has: it is what the switch it is
// plugged into will have learned.

// Wireless profile keys. Absent keys are simply not collected.
const (
	wlKeyAPName     = "ap_name"
	wlKeyAPModel    = "ap_model"
	wlKeyAPSerial   = "ap_serial"
	wlKeyAPLocation = "ap_location"
	wlKeyAPMAC      = "ap_mac"
	wlKeyAPIP       = "ap_ip"
	wlKeyAPStatus   = "ap_status"
	wlKeyAPFirmware = "ap_firmware"
	wlKeyAPRadios   = "ap_radios"
	wlKeyAPClients  = "ap_clients"
	// Not an OID: a "1=associated,2=disassociated" mapping for whatever
	// ap_status returns. Status enumerations are vendor-specific, so decoding
	// one in the collector would be right for Cisco and wrong for everyone
	// else — while a bare "2" on an asset page tells an operator nothing.
	wlKeyAPStatusMap = "ap_status_map"

	wlKeySSID        = "ssid"
	wlKeySSIDClients = "ssid_clients"

	// The radio table. Indexed more finely than the AP table — by (AP, radio
	// slot) on every vendor that has one — which is exactly why these cannot
	// simply be read alongside the AP columns.
	wlKeyRadioBand    = "radio_band"
	wlKeyRadioChannel = "radio_channel"
	wlKeyRadioClients = "radio_clients"
	wlKeyRadioStatus  = "radio_status"

	// Mappings, not OIDs. A radio reporting band "2" tells nobody anything, and
	// the enumeration differs per vendor, so decoding belongs in the profile
	// next to the OID it decodes.
	wlKeyRadioBandMap   = "radio_band_map"
	wlKeyRadioStatusMap = "radio_status_map"
)

// AccessPoint is one row of a controller's AP table, or a standalone AP.
type AccessPoint struct {
	Index    string // the raw table index, kept for correlation and diagnostics
	Name     string
	Model    string
	Serial   string
	Location string
	MAC      string
	IP       string
	Firmware string
	Status   string
	Radios   int
	Clients  int

	// Detail per radio, where the vendor publishes a radio table.
	RadioDetail []Radio
}

// SSID is one broadcast network, with the clients associated to it.
type SSID struct {
	Name    string
	Clients int
}

// Radio is one radio of one access point.
type Radio struct {
	Slot    string
	Band    string
	Channel int
	Clients int
	Status  string
}

// Wireless collects everything this device knows about Wi-Fi.
//
// Returns the block for the plugin's own table and the access points to raise
// as assets of their own. Both are empty on a device that is not doing Wi-Fi.
//
// Two shapes are handled by the same code. A *controller* enumerates access
// points that cannot be scanned themselves, and each becomes an asset. A
// *standalone* AP — UniFi, MikroTik — is the asset, and only publishes the
// networks it is broadcasting. Neither is special-cased: the AP table is walked
// if the profile declares one, the SSID table if it declares one, and whatever
// answers is what gets reported.
//
// The gate is deliberately cheap. The Cisco pack applies to every Cisco device
// because a controller's sysObjectID is a chassis OID like any other, so an
// ordinary switch would otherwise pay for six empty walks on every scan. One
// probe decides, and returns immediately when nothing answers.
func (c *Collector) Wireless(controller string) (*payload.Wireless, []AccessPoint) {
	if !c.hasWirelessTables() {
		return nil, nil
	}

	aps := c.AccessPoints()
	ssids := c.SSIDs()

	return Block(controller, ssids, aps), aps
}

// hasWirelessTables probes the one or two tables that decide whether anything
// else is worth walking.
func (c *Collector) hasWirelessTables() bool {
	for _, key := range []string{wlKeyAPName, wlKeySSID} {
		oid := c.wirelessOID(key)
		if oid == "" {
			continue
		}
		if rows, err := c.Session.Walk(oid); err == nil && len(rows) > 0 {
			return true
		}
	}

	return false
}

// AccessPoints enumerates the APs this device knows about.
func (c *Collector) AccessPoints() []AccessPoint {
	names := c.walkWireless(wlKeyAPName)
	if len(names) == 0 {
		// Without a name there is nothing worth creating an asset from, and
		// every vendor table that carries the other columns carries this one.
		return nil
	}

	models := c.walkWireless(wlKeyAPModel)
	serials := c.walkWireless(wlKeyAPSerial)
	locations := c.walkWireless(wlKeyAPLocation)
	macs := c.walkWireless(wlKeyAPMAC)
	ips := c.walkWireless(wlKeyAPIP)
	firmware := c.walkWireless(wlKeyAPFirmware)
	statuses := c.walkWireless(wlKeyAPStatus)
	radios := c.walkWirelessInts(wlKeyAPRadios)
	clients := c.walkWirelessInts(wlKeyAPClients)

	// The radio table, correlated back onto the APs it belongs to.
	indexes := make([]string, 0, len(names))
	for index := range names {
		indexes = append(indexes, index)
	}
	detail := radiosByAP(indexes,
		c.walkWireless(wlKeyRadioBand), c.walkWireless(wlKeyRadioStatus),
		c.walkWirelessInts(wlKeyRadioChannel), c.walkWirelessInts(wlKeyRadioClients),
		c.wirelessOID(wlKeyRadioBandMap), c.wirelessOID(wlKeyRadioStatusMap))

	out := make([]AccessPoint, 0, len(names))
	for index, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		ap := AccessPoint{
			Index:    index,
			Name:     name,
			Model:    strings.TrimSpace(models[index]),
			Serial:   strings.TrimSpace(serials[index]),
			Location: strings.TrimSpace(locations[index]),
			MAC:      normaliseMAC(macs[index]),
			IP:       normaliseIP(ips[index]),
			Firmware: strings.TrimSpace(firmware[index]),
			Status:   decodeStatus(c.wirelessOID(wlKeyAPStatusMap), statuses[index]),
			Radios:   int(radios[index]),
			Clients:  int(clients[index]),
		}

		ap.RadioDetail = detail[index]

		// Where the vendor publishes clients per radio rather than per AP —
		// Cisco and Aruba both do — the AP total is the sum. Only used when the
		// AP table itself did not report one, so a vendor that answers both
		// keeps its own figure rather than having it recomputed.
		if _, reported := clients[index]; !reported {
			for _, r := range ap.RadioDetail {
				ap.Clients += r.Clients
			}
		}

		// Radio count likewise: a vendor with no such column still knows how
		// many radios it just described.
		if ap.Radios == 0 {
			ap.Radios = len(ap.RadioDetail)
		}

		// Vendors that index the AP table by the AP's base MAC give us the
		// address for free, and it is the identity that matters most: it is
		// what the switch the AP is plugged into will have learned, so GLPI
		// can wire the AP to its switch port instead of inventing an Unmanaged
		// asset for a MAC it has already seen.
		if ap.MAC == "" {
			ap.MAC = macFromArcs(strings.Split(index, "."))
		}

		out = append(out, ap)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

// radiosByAP correlates a more finely indexed table back onto its access points.
//
// Every vendor with a radio table indexes it by (AP index, radio slot), which is
// the AP table's own index with one arc appended. So a row belongs to the AP
// whose index is the longest prefix of it — longest, not first, because AP
// indexes are MACs and one can be a prefix of another only by accident, but an
// accident here silently attributes a radio to the wrong access point.
//
// This is why per-AP client counts could not just be read as another AP column:
// the number lives one index level down, and summing it is the only honest way
// to answer "how many clients does this AP have".
func radiosByAP(apIndexes []string, bands, statuses map[string]string, channels, clients map[string]int64, bandMap, statusMap string) map[string][]Radio {
	if len(apIndexes) == 0 {
		return nil
	}

	// Every row of every radio column, so a radio that reports only a channel
	// still produces an entry.
	suffixes := map[string]struct{}{}
	for k := range bands {
		suffixes[k] = struct{}{}
	}
	for k := range statuses {
		suffixes[k] = struct{}{}
	}
	for k := range channels {
		suffixes[k] = struct{}{}
	}
	for k := range clients {
		suffixes[k] = struct{}{}
	}
	if len(suffixes) == 0 {
		return nil
	}

	out := map[string][]Radio{}
	for suffix := range suffixes {
		owner, slot := longestAPPrefix(apIndexes, suffix)
		if owner == "" {
			continue
		}
		out[owner] = append(out[owner], Radio{
			Slot:    slot,
			Band:    decodeStatus(bandMap, bands[suffix]),
			Channel: int(channels[suffix]),
			Clients: int(clients[suffix]),
			Status:  decodeStatus(statusMap, statuses[suffix]),
		})
	}

	for owner := range out {
		radios := out[owner]
		sort.Slice(radios, func(i, j int) bool { return radios[i].Slot < radios[j].Slot })
		out[owner] = radios
	}

	return out
}

// longestAPPrefix finds which AP a finer-indexed row belongs to, and what is
// left of the index once the AP's part is removed — the radio slot.
func longestAPPrefix(apIndexes []string, suffix string) (string, string) {
	best, rest := "", ""
	for _, index := range apIndexes {
		if !strings.HasPrefix(suffix, index+".") {
			continue
		}
		if len(index) > len(best) {
			best, rest = index, strings.TrimPrefix(suffix, index+".")
		}
	}
	return best, rest
}

// SSIDs lists the networks the controller broadcasts.
func (c *Collector) SSIDs() []SSID {
	names := c.walkWireless(wlKeySSID)
	if len(names) == 0 {
		return nil
	}

	clients := c.walkWirelessInts(wlKeySSIDClients)

	// Folded by name, summing clients. A virtual-AP table — UniFi's especially —
	// has one row per SSID *per radio*, so the same network appears two or three
	// times. Reporting it twice would be noise, and reporting either row alone
	// would understate the network by however many clients are on the other
	// band.
	totals := map[string]int{}
	order := make([]string, 0, len(names))
	for index, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, seen := totals[name]; !seen {
			order = append(order, name)
		}
		totals[name] += int(clients[index])
	}

	out := make([]SSID, 0, len(order))
	for _, name := range order {
		out = append(out, SSID{Name: name, Clients: totals[name]})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

// APInventories turns access points into submissions of their own.
//
// Each AP becomes a NetworkEquipment asset rather than a component of the
// controller, because that is what it is: a thing with a serial number that
// gets RMA'd, moved between sites and replaced independently. Filing them as
// components would make every one of those operations invisible.
//
// The controller association is recorded by the plugin rather than modelled as a
// GLPI relation: there is no "managed by" link between two NetworkEquipment
// assets. The physically true relationship — which switch port the AP is
// actually plugged into — is recovered for free by the existing topology
// correlation, because the switch has learned the AP's MAC.
// scanAddress is the address the *controller* answered on, not the AP's own.
// That is what provenance means here: the scanner reached this asset by asking
// that address, and the off-target guard checks submissions against the ranges
// the scanner was told to sweep. An AP behind a controller legitimately has an
// address outside those ranges — often on a management VLAN the scanner cannot
// reach at all — so reporting its own IP here would have every AP rejected by
// a guard that is working exactly as intended.
func APInventories(controller, scanAddress string, aps []AccessPoint, versionClient string) []payload.Inventory {
	out := make([]payload.Inventory, 0, len(aps))

	for _, ap := range aps {
		// An AP with neither a serial nor a MAC cannot be matched to an
		// existing asset on a later scan, so every scan would create a new one.
		// Skipping is better than filling GLPI with duplicates.
		if ap.Serial == "" && ap.MAC == "" {
			continue
		}

		dev := &payload.Device{
			Type:     payload.TypeNetworking,
			Name:     ap.Name,
			Model:    ap.Model,
			Serial:   ap.Serial,
			Location: ap.Location,
			MAC:      ap.MAC,
			Firmware: ap.Firmware,
		}
		if ap.IP != "" {
			dev.IPs = []string{ap.IP}
		}

		out = append(out, payload.Inventory{
			DeviceID:    apDeviceID(ap),
			Action:      string(payload.QueryInventory),
			ItemType:    payload.GLPIItemType(payload.TypeNetworking),
			ScanAddress: scanAddress,
			Content: payload.Content{
				Device:        dev,
				VersionClient: versionClient,
			},
		})
	}

	return out
}

// apDeviceID keys the asset on the AP's own identity, never on the controller's
// address: an AP moved to a different controller is the same physical box, and
// a controller replaced under warranty must not orphan sixty access points.
func apDeviceID(ap AccessPoint) string {
	switch {
	case ap.Serial != "":
		return "ap-" + ap.Serial
	case ap.MAC != "":
		return "ap-" + strings.ReplaceAll(ap.MAC, ":", "")
	default:
		return "ap-" + ap.Name
	}
}

// decodeStatus renders a vendor enumeration through the profile's mapping —
// AP status, radio status, radio band. All three are integers whose meaning is
// vendor-specific, and all three are useless to a reader undecoded.
//
// An unmapped value is returned unchanged rather than blanked: an operator
// seeing "7" at least knows the device said something, and can map it.
func decodeStatus(mapping, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || mapping == "" {
		return value
	}

	for _, pair := range strings.Split(mapping, ",") {
		code, label, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && strings.TrimSpace(code) == value {
			return strings.TrimSpace(label)
		}
	}

	return value
}

// --- profile plumbing -------------------------------------------------------

func (c *Collector) wirelessOID(key string) string {
	if c.Profile.Wireless == nil {
		return ""
	}
	return strings.TrimSpace(c.Profile.Wireless[key])
}

// walkWireless walks a profile-declared column, keyed by its table index.
func (c *Collector) walkWireless(key string) map[string]string {
	oid := c.wirelessOID(key)
	if oid == "" {
		return map[string]string{}
	}

	rows, err := c.Session.Walk(oid)
	if err != nil {
		return map[string]string{}
	}

	out := make(map[string]string, len(rows))
	for suffix, pdu := range rows {
		out[suffix] = snmpx.String(pdu)
	}

	return out
}

func (c *Collector) walkWirelessInts(key string) map[string]int64 {
	oid := c.wirelessOID(key)
	if oid == "" {
		return map[string]int64{}
	}

	rows, err := c.Session.Walk(oid)
	if err != nil {
		return map[string]int64{}
	}

	out := make(map[string]int64, len(rows))
	for suffix, pdu := range rows {
		out[suffix] = snmpx.Int(pdu)
	}

	return out
}

// normaliseIP keeps only what parses, so a vendor returning a hex blob or an
// empty string does not become a bogus address on the asset.
func normaliseIP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(v); err == nil && !addr.IsUnspecified() {
		return addr.String()
	}
	return ""
}

// Block renders the controller's operational view for the plugin's own table.
func Block(controller string, ssids []SSID, aps []AccessPoint) *payload.Wireless {
	if len(ssids) == 0 && len(aps) == 0 {
		return nil
	}

	out := &payload.Wireless{Controller: controller}

	for _, s := range ssids {
		out.SSIDs = append(out.SSIDs, payload.WirelessSSID{Name: s.Name, Clients: s.Clients})
	}
	for _, ap := range aps {
		wap := payload.WirelessAP{
			Name:     ap.Name,
			Serial:   ap.Serial,
			MAC:      ap.MAC,
			IP:       ap.IP,
			Model:    ap.Model,
			Location: ap.Location,
			Firmware: ap.Firmware,
			Status:   ap.Status,
			Radios:   ap.Radios,
			Clients:  ap.Clients,
		}

		for _, r := range ap.RadioDetail {
			wap.RadioDetail = append(wap.RadioDetail, payload.WirelessRadio{
				Slot:    r.Slot,
				Band:    r.Band,
				Channel: r.Channel,
				Clients: r.Clients,
				Status:  r.Status,
			})
		}

		out.AccessPoints = append(out.AccessPoints, wap)
	}

	return out
}
