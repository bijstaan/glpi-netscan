// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// Topology OIDs. All standard except the CDP block, which is Cisco's but is
// implemented by enough other vendors to be worth trying.
//
// Every one of these is overridable per profile via the `topology` section,
// keyed by the constant's map name below — a device that puts its forwarding
// table somewhere non-standard is then a profile edit, not a code change.
const (
	// BRIDGE-MIB (RFC 4188)
	OIDDot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"
	OIDDot1dTpFdbPort       = "1.3.6.1.2.1.17.4.3.1.2"
	OIDDot1dTpFdbStatus     = "1.3.6.1.2.1.17.4.3.1.3"

	// Q-BRIDGE-MIB (RFC 4363) — VLAN-aware forwarding table. Many switches
	// populate only this one, so both are tried and merged.
	OIDDot1qTpFdbPort   = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	OIDDot1qTpFdbStatus = "1.3.6.1.2.1.17.7.1.2.2.1.3"

	// Q-BRIDGE-MIB VLAN membership
	OIDDot1qVlanStaticName    = "1.3.6.1.2.1.17.7.1.4.3.1.1"
	OIDDot1qVlanEgressPorts   = "1.3.6.1.2.1.17.7.1.4.3.1.2"
	OIDDot1qVlanUntaggedPorts = "1.3.6.1.2.1.17.7.1.4.3.1.4"
	OIDDot1qPvid              = "1.3.6.1.2.1.17.7.1.4.5.1.1"

	// LLDP-MIB (IEEE 802.1AB)
	OIDLldpLocPortIdSubtype = "1.0.8802.1.1.2.1.3.7.1.2"
	OIDLldpLocPortID        = "1.0.8802.1.1.2.1.3.7.1.3"
	OIDLldpRemChassisID     = "1.0.8802.1.1.2.1.4.1.1.5"
	OIDLldpRemPortIDSubtype = "1.0.8802.1.1.2.1.4.1.1.6"
	OIDLldpRemPortID        = "1.0.8802.1.1.2.1.4.1.1.7"
	OIDLldpRemPortDesc      = "1.0.8802.1.1.2.1.4.1.1.8"
	OIDLldpRemSysName       = "1.0.8802.1.1.2.1.4.1.1.9"
	OIDLldpRemSysDesc       = "1.0.8802.1.1.2.1.4.1.1.10"
	OIDLldpRemManAddr       = "1.0.8802.1.1.2.1.4.2.1.3"

	// LLDP-MIB local system capabilities. LldpSystemCapabilitiesMap is a BITS
	// value, most significant bit first: other(0) repeater(1) bridge(2)
	// wlanAccessPoint(3) router(4) telephone(5) docsisCableDevice(6)
	// stationOnly(7).
	OIDLldpLocSysCapEnabled = "1.0.8802.1.1.2.1.3.6.0"

	// LldpCapTelephone is the bit a desk phone sets about itself.
	LldpCapTelephone = 5

	// CISCO-CDP-MIB
	OIDCdpCacheAddress  = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
	OIDCdpCacheDeviceID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
	OIDCdpCacheDevPort  = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
	OIDCdpCachePlatform = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

	// IF-MIB ifXTable — 64-bit counters and the real speed.
	OIDIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	OIDIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
	OIDIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
)

// topologyDefaults maps the profile override keys onto the constants above.
var topologyDefaults = map[string]string{
	"dot1d_base_port_ifindex": OIDDot1dBasePortIfIndex,
	"dot1d_fdb_port":          OIDDot1dTpFdbPort,
	"dot1d_fdb_status":        OIDDot1dTpFdbStatus,
	"dot1q_fdb_port":          OIDDot1qTpFdbPort,
	"dot1q_fdb_status":        OIDDot1qTpFdbStatus,
	"vlan_static_name":        OIDDot1qVlanStaticName,
	"vlan_egress_ports":       OIDDot1qVlanEgressPorts,
	"vlan_untagged_ports":     OIDDot1qVlanUntaggedPorts,
	"vlan_pvid":               OIDDot1qPvid,
	"lldp_loc_port_id":        OIDLldpLocPortID,
	"lldp_loc_port_subtype":   OIDLldpLocPortIdSubtype,
	"lldp_rem_chassis_id":     OIDLldpRemChassisID,
	"lldp_rem_port_id":        OIDLldpRemPortID,
	"lldp_rem_port_subtype":   OIDLldpRemPortIDSubtype,
	"lldp_rem_port_desc":      OIDLldpRemPortDesc,
	"lldp_rem_sys_name":       OIDLldpRemSysName,
	"lldp_rem_sys_desc":       OIDLldpRemSysDesc,
	"lldp_rem_man_addr":       OIDLldpRemManAddr,
	"lldp_loc_sys_cap":        OIDLldpLocSysCapEnabled,
	"cdp_device_id":           OIDCdpCacheDeviceID,
	"cdp_device_port":         OIDCdpCacheDevPort,
	"cdp_platform":            OIDCdpCachePlatform,
	"cdp_address":             OIDCdpCacheAddress,
	"if_hc_in_octets":         OIDIfHCInOctets,
	"if_hc_out_octets":        OIDIfHCOutOctets,
	"if_high_speed":           OIDIfHighSpeed,
}

// oid resolves a topology OID, honouring any profile override.
func (c *Collector) oid(key string) string {
	if custom, ok := c.Profile.Topology[key]; ok && strings.TrimSpace(custom) != "" {
		return custom
	}
	return topologyDefaults[key]
}

// feature reports whether a collector is enabled. Everything is on unless a
// profile explicitly turns it off, so a new device works without configuration
// and a device that implements one table badly can have just that table
// disabled.
func (c *Collector) feature(name string) bool {
	if v, ok := c.Profile.Features[name]; ok {
		return v
	}
	return true
}

// Neighbour is one discovered link partner.
type Neighbour struct {
	ChassisMAC string
	SysName    string
	SysDesc    string
	PortID     string
	// PortIDSubtype is LldpPortIdSubtype: interfaceAlias(1), portComponent(2),
	// macAddress(3), networkAddress(4), interfaceName(5), agentCircuitId(6),
	// local(7). It decides what PortID actually *is*, which decides how the
	// far end can be matched.
	PortIDSubtype int
	PortDesc      string
	MgmtIP        string
	FromCDP       bool

	// Index is the LLDP remote index (timeMark.localPort.remIndex). It is what
	// joins a neighbour to the LLDP-MED inventory the same switch reports for
	// it: the two tables share this index and nothing else.
	Index string
}

// PortIDSubtype values worth distinguishing.
const (
	LldpPortIDInterfaceAlias = 1
	LldpPortIDMACAddress     = 3
	LldpPortIDInterfaceName  = 5
)

// Enrich adds everything that needs a second pass over the ports: 64-bit
// counters, VLAN membership, and link-layer neighbours.
//
// Split out from Ports() because each of these is a whole-table walk that has
// to be cross-referenced with the port list, and because each is separately
// switchable — a device with a broken FDB should still yield VLANs.
func (c *Collector) Enrich(ports []payload.Port) []payload.Port {
	if len(ports) == 0 {
		return ports
	}

	byIfIndex := make(map[int]*payload.Port, len(ports))
	for i := range ports {
		byIfIndex[ports[i].IfNumber] = &ports[i]
	}

	if c.feature("hc_counters") {
		c.applyHighCapacity(byIfIndex)
	}

	// Bridge port numbering is its own space and is frequently *not* ifIndex —
	// the simulator deliberately offsets it. Everything below depends on this
	// mapping being right.
	bridgeToIf := c.bridgePortMap()

	if c.feature("vlans") {
		c.applyVLANs(byIfIndex, bridgeToIf)
	}

	neighbours := map[int]Neighbour{}
	defer func() { c.lastNeighbours = neighbours }()

	if c.feature("lldp") {
		for ifIndex, n := range c.lldpNeighbours(byIfIndex) {
			neighbours[ifIndex] = n
		}
	}
	if c.feature("cdp") {
		// CDP only fills gaps: where both are present LLDP is the standard and
		// is trusted.
		for ifIndex, n := range c.cdpNeighbours() {
			if _, exists := neighbours[ifIndex]; !exists {
				neighbours[ifIndex] = n
			}
		}
	}

	var fdb map[int][]string
	if c.feature("fdb") {
		fdb = c.forwardingTable(bridgeToIf)
	}

	for ifIndex, port := range byIfIndex {
		// A port is reported either as an LLDP/CDP link or as a set of learned
		// MACs, never both: GLPI's NetworkPort asset switches on the port's
		// `lldp` flag and interprets the whole connections array one way or the
		// other. A neighbour is the better signal, so it wins.
		if n, ok := neighbours[ifIndex]; ok {
			port.LLDP = true
			port.Connections = []payload.Conn{n.conn()}
			continue
		}

		if macs := fdb[ifIndex]; len(macs) > 0 {
			conns := make([]payload.Conn, 0, len(macs))
			for _, mac := range macs {
				conns = append(conns, payload.Conn{MAC: mac})
			}
			port.Connections = conns
		}
	}

	return ports
}

// conn renders a neighbour in the shape GLPI matches against.
//
// GLPI resolves an LLDP neighbour by looking for a port on the same item whose
// logical_number, mac or *name* matches — in that order — and only falls back
// to creating an Unmanaged asset when none does. So what goes in `ifdescr`
// has to be the far end's port **name**, not its human description: sending
// lldpRemPortDesc ("uplink") instead of lldpRemPortId ("eth0") means the
// lookup never matches and every neighbour becomes a placeholder, even one
// already inventoried.
func (n Neighbour) conn() payload.Conn {
	c := payload.Conn{
		SysMAC:   n.ChassisMAC,
		SysName:  n.SysName,
		SysDescr: n.SysDesc,
		IP:       n.MgmtIP,
	}

	switch n.PortIDSubtype {
	case LldpPortIDMACAddress:
		// The strongest match GLPI has: an exact port MAC.
		c.MAC = normaliseMAC(n.PortID)
	case LldpPortIDInterfaceName, LldpPortIDInterfaceAlias:
		c.IfDescr = n.PortID
	default:
		// Unknown or vendor-specific encoding: the description is the better
		// guess, and a wrong ifdescr only costs a placeholder.
		if n.PortDesc != "" {
			c.IfDescr = n.PortDesc
		} else {
			c.IfDescr = n.PortID
		}
	}

	if c.IfDescr == "" && c.MAC == "" {
		c.IfDescr = n.PortDesc
	}

	return c
}

// normaliseMAC accepts the several spellings LLDP implementations use for a
// port MAC and renders the colon-separated lower-case form GLPI stores.
func normaliseMAC(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		}
		return -1
	}, raw)

	if len(cleaned) != 12 {
		return ""
	}

	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, cleaned[i:i+2])
	}
	return strings.Join(parts, ":")
}

// applyHighCapacity overlays the 64-bit counters and real speed.
//
// The 32-bit ifSpeed gauge saturates at 4294967295 on anything above 4Gbps,
// and 32-bit octet counters wrap in under a minute on a loaded 10G link, so
// where ifXTable exists it is simply better data.
func (c *Collector) applyHighCapacity(byIfIndex map[int]*payload.Port) {
	if rows, err := c.Session.Walk(c.oid("if_hc_in_octets")); err == nil {
		for idx, pdu := range rows {
			if p := lookup(byIfIndex, idx); p != nil {
				if v := snmpx.Int(pdu); v > 0 {
					p.IfInBytes = v
				}
			}
		}
	}

	if rows, err := c.Session.Walk(c.oid("if_hc_out_octets")); err == nil {
		for idx, pdu := range rows {
			if p := lookup(byIfIndex, idx); p != nil {
				if v := snmpx.Int(pdu); v > 0 {
					p.IfOutBytes = v
				}
			}
		}
	}

	if rows, err := c.Session.Walk(c.oid("if_high_speed")); err == nil {
		for idx, pdu := range rows {
			p := lookup(byIfIndex, idx)
			if p == nil {
				continue
			}
			mbps := snmpx.Int(pdu)
			if mbps <= 0 {
				continue
			}
			// Only trust ifHighSpeed where ifSpeed could not have told the
			// truth; below the saturation point ifSpeed is more precise.
			if p.IfSpeed == 0 || p.IfSpeed >= 4294967295 {
				p.IfSpeed = mbps * 1_000_000
			}
		}
	}
}

// bridgePortMap maps dot1dBasePort numbers onto ifIndexes.
func (c *Collector) bridgePortMap() map[int]int {
	out := map[int]int{}

	rows, err := c.Session.Walk(c.oid("dot1d_base_port_ifindex"))
	if err != nil {
		return out
	}

	for idx, pdu := range rows {
		bridgePort, err := strconv.Atoi(idx)
		if err != nil {
			continue
		}
		if ifIndex := int(snmpx.Int(pdu)); ifIndex > 0 {
			out[bridgePort] = ifIndex
		}
	}

	return out
}

// forwardingTable returns the MACs learned behind each ifIndex.
func (c *Collector) forwardingTable(bridgeToIf map[int]int) map[int][]string {
	out := map[int][]string{}
	seen := map[string]map[string]bool{}

	record := func(ifIndex int, mac string) {
		if ifIndex <= 0 || mac == "" {
			return
		}
		key := strconv.Itoa(ifIndex)
		if seen[key] == nil {
			seen[key] = map[string]bool{}
		}
		if seen[key][mac] {
			return
		}
		seen[key][mac] = true
		out[ifIndex] = append(out[ifIndex], mac)
	}

	// Q-BRIDGE first: it is VLAN-aware and is the only one some switches fill.
	// Its index is <vlan>.<six MAC arcs>.
	if rows, err := c.Session.Walk(c.oid("dot1q_fdb_port")); err == nil {
		status := c.walkOrNil(c.oid("dot1q_fdb_status"))
		for idx, pdu := range rows {
			if !fdbLearned(status, idx) {
				continue
			}
			arcs := strings.Split(idx, ".")
			if len(arcs) < 7 {
				continue
			}
			mac := macFromArcs(arcs[len(arcs)-6:])
			record(bridgeToIf[int(snmpx.Int(pdu))], mac)
		}
	}

	// BRIDGE-MIB, indexed by the six MAC arcs alone.
	if rows, err := c.Session.Walk(c.oid("dot1d_fdb_port")); err == nil {
		status := c.walkOrNil(c.oid("dot1d_fdb_status"))
		for idx, pdu := range rows {
			if !fdbLearned(status, idx) {
				continue
			}
			arcs := strings.Split(idx, ".")
			if len(arcs) != 6 {
				continue
			}
			mac := macFromArcs(arcs)
			record(bridgeToIf[int(snmpx.Int(pdu))], mac)
		}
	}

	return out
}

// fdbLearned keeps only dynamically learned entries.
//
// The table also carries self(4) — the switch's own port addresses — and
// mgmt(5). Reporting those as "connected devices" would wire every switch to
// itself in GLPI's topology.
func fdbLearned(status map[string]gosnmp.SnmpPDU, index string) bool {
	if status == nil {
		return true // device does not publish status; assume the entry is real
	}
	pdu, ok := status[index]
	if !ok {
		return true
	}
	return snmpx.Int(pdu) == 3 // learned(3)
}

func (c *Collector) walkOrNil(oid string) map[string]gosnmp.SnmpPDU {
	rows, err := c.Session.Walk(oid)
	if err != nil {
		return nil
	}
	return rows
}

// macFromArcs turns six decimal OID arcs into a MAC address.
func macFromArcs(arcs []string) string {
	if len(arcs) != 6 {
		return ""
	}
	parts := make([]string, 0, 6)
	allZero := true
	for _, a := range arcs {
		n, err := strconv.Atoi(a)
		if err != nil || n < 0 || n > 255 {
			return ""
		}
		if n != 0 {
			allZero = false
		}
		parts = append(parts, fmt.Sprintf("%02x", n))
	}
	if allZero {
		return ""
	}
	return strings.Join(parts, ":")
}

// applyVLANs fills in per-port VLAN membership and the trunk flag.
func (c *Collector) applyVLANs(byIfIndex map[int]*payload.Port, bridgeToIf map[int]int) {
	names, err := c.Session.Walk(c.oid("vlan_static_name"))
	if err != nil || len(names) == 0 {
		return
	}

	egress := c.walkOrNil(c.oid("vlan_egress_ports"))
	untagged := c.walkOrNil(c.oid("vlan_untagged_ports"))

	// Native VLAN per port, used to decide tagged vs untagged when the
	// untagged bitmap is absent.
	pvid := map[int]int{}
	if rows, err := c.Session.Walk(c.oid("vlan_pvid")); err == nil {
		for idx, pdu := range rows {
			if bp, err := strconv.Atoi(idx); err == nil {
				pvid[bridgeToIf[bp]] = int(snmpx.Int(pdu))
			}
		}
	}

	for vidStr, namePDU := range names {
		vid, err := strconv.Atoi(vidStr)
		if err != nil {
			continue
		}
		name := snmpx.String(namePDU)

		members := portsInBitmap(egress[vidStr])
		if len(members) == 0 {
			continue
		}
		untaggedMembers := map[int]bool{}
		for _, p := range portsInBitmap(untagged[vidStr]) {
			untaggedMembers[p] = true
		}

		for _, bridgePort := range members {
			ifIndex, ok := bridgeToIf[bridgePort]
			if !ok {
				continue
			}
			port := byIfIndex[ifIndex]
			if port == nil {
				continue
			}

			tagged := !untaggedMembers[bridgePort]
			// Where the untagged bitmap is missing, fall back to the port's
			// native VLAN: the PVID is by definition the untagged one.
			if untagged == nil {
				tagged = pvid[ifIndex] != vid
			}

			port.VLANs = append(port.VLANs, payload.VLAN{
				Number: vid,
				Name:   name,
				Tagged: tagged,
			})
		}
	}

	// A port carrying a tagged VLAN is a trunk. This drives GLPI's own
	// handling: it will not wire a trunk port to a single device even when the
	// forwarding table shows several MACs behind it.
	for _, port := range byIfIndex {
		for _, v := range port.VLANs {
			if v.Tagged {
				port.Trunk = true
				break
			}
		}
	}
}

// portsInBitmap decodes an IEEE PortList: an octet string in which the most
// significant bit of the first byte is bridge port 1.
func portsInBitmap(pdu gosnmp.SnmpPDU) []int {
	raw, ok := pdu.Value.([]byte)
	if !ok || len(raw) == 0 {
		return nil
	}

	out := []int{}
	for byteIndex, b := range raw {
		for bit := 0; bit < 8; bit++ {
			if b&(0x80>>bit) != 0 {
				out = append(out, byteIndex*8+bit+1)
			}
		}
	}
	return out
}

// lldpNeighbours returns the LLDP link partner per ifIndex.
func (c *Collector) lldpNeighbours(byIfIndex map[int]*payload.Port) map[int]Neighbour {
	chassis, err := c.Session.Walk(c.oid("lldp_rem_chassis_id"))
	if err != nil || len(chassis) == 0 {
		return nil
	}

	portIDs := c.walkOrNil(c.oid("lldp_rem_port_id"))
	portSubtypes := c.walkOrNil(c.oid("lldp_rem_port_subtype"))
	portDescs := c.walkOrNil(c.oid("lldp_rem_port_desc"))
	sysNames := c.walkOrNil(c.oid("lldp_rem_sys_name"))
	sysDescs := c.walkOrNil(c.oid("lldp_rem_sys_desc"))
	locPorts := c.lldpLocalPortMap(byIfIndex)
	mgmt := c.lldpManagementAddresses()

	out := map[int]Neighbour{}

	for idx, chassisPDU := range chassis {
		// Index is timeMark.localPortNum.remIndex.
		arcs := strings.Split(idx, ".")
		if len(arcs) < 3 {
			continue
		}
		localPort, err := strconv.Atoi(arcs[1])
		if err != nil {
			continue
		}

		ifIndex, ok := locPorts[localPort]
		if !ok {
			ifIndex = localPort // the common case: they are the same number
		}

		n := Neighbour{
			ChassisMAC:    snmpx.MAC(chassisPDU),
			SysName:       text(sysNames[idx]),
			SysDesc:       text(sysDescs[idx]),
			PortID:        text(portIDs[idx]),
			PortIDSubtype: int(snmpx.Int(portSubtypes[idx])),
			PortDesc:      text(portDescs[idx]),
			MgmtIP:        mgmt[strings.Join(arcs[:3], ".")],
			Index:         strings.Join(arcs[:3], "."),
		}

		// A neighbour with no identity at all is not worth reporting: GLPI
		// would create an empty Unmanaged asset for it.
		if n.ChassisMAC == "" && n.SysName == "" {
			continue
		}

		out[ifIndex] = n
	}

	return out
}

// lldpLocalPortMap maps lldpLocPortNum onto ifIndex.
//
// The two are usually equal, but not on every platform — some index LLDP local
// ports from 1 regardless of ifIndex. Where lldpLocPortId names an interface,
// that name is matched against the ports we already collected.
func (c *Collector) lldpLocalPortMap(byIfIndex map[int]*payload.Port) map[int]int {
	out := map[int]int{}

	ids, err := c.Session.Walk(c.oid("lldp_loc_port_id"))
	if err != nil {
		return out
	}

	byName := map[string]int{}
	for ifIndex, port := range byIfIndex {
		if port.IfName != "" {
			byName[strings.ToLower(port.IfName)] = ifIndex
		}
		if port.IfDescr != "" {
			byName[strings.ToLower(port.IfDescr)] = ifIndex
		}
	}

	for idx, pdu := range ids {
		localPort, err := strconv.Atoi(idx)
		if err != nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(snmpx.String(pdu)))
		if ifIndex, ok := byName[name]; ok {
			out[localPort] = ifIndex
		}
	}

	return out
}

// lldpManagementAddresses extracts the neighbour's management IP.
//
// The address is encoded in the *index*, not the value: the row key ends with
// addrSubtype, length, then the address bytes.
func (c *Collector) lldpManagementAddresses() map[string]string {
	out := map[string]string{}

	rows, err := c.Session.Walk(c.oid("lldp_rem_man_addr"))
	if err != nil {
		return out
	}

	for idx := range rows {
		arcs := strings.Split(idx, ".")
		// timeMark.localPort.remIndex.addrSubtype.addrLen.<addr…>
		if len(arcs) < 6 {
			continue
		}
		subtype := arcs[3]
		length, err := strconv.Atoi(arcs[4])
		if err != nil || len(arcs) < 5+length {
			continue
		}
		addrArcs := arcs[5 : 5+length]

		var ip string
		switch subtype {
		case "1": // ipv4
			if length == 4 {
				ip = strings.Join(addrArcs, ".")
			}
		case "2": // ipv6
			if length == 16 {
				buf := make(net.IP, 0, 16)
				ok := true
				for _, a := range addrArcs {
					n, err := strconv.Atoi(a)
					if err != nil || n < 0 || n > 255 {
						ok = false
						break
					}
					buf = append(buf, byte(n))
				}
				if ok {
					ip = buf.String()
				}
			}
		}

		if ip != "" {
			out[strings.Join(arcs[:3], ".")] = ip
		}
	}

	return out
}

// cdpNeighbours reads the Cisco discovery cache, indexed by ifIndex.remIndex.
func (c *Collector) cdpNeighbours() map[int]Neighbour {
	devices, err := c.Session.Walk(c.oid("cdp_device_id"))
	if err != nil || len(devices) == 0 {
		return nil
	}

	ports := c.walkOrNil(c.oid("cdp_device_port"))
	platforms := c.walkOrNil(c.oid("cdp_platform"))
	addrs := c.walkOrNil(c.oid("cdp_address"))

	out := map[int]Neighbour{}

	for idx, pdu := range devices {
		arcs := strings.Split(idx, ".")
		if len(arcs) < 1 {
			continue
		}
		ifIndex, err := strconv.Atoi(arcs[0])
		if err != nil {
			continue
		}

		n := Neighbour{
			SysName: text(pdu),
			PortID:  text(ports[idx]),
			SysDesc: text(platforms[idx]),
			MgmtIP:  cdpAddress(addrs[idx]),
			FromCDP: true,
		}
		if n.SysName == "" {
			continue
		}
		out[ifIndex] = n
	}

	return out
}

// cdpAddress decodes cdpCacheAddress, which is a raw 4-byte IPv4 address.
func cdpAddress(pdu gosnmp.SnmpPDU) string {
	raw, ok := pdu.Value.([]byte)
	if !ok || len(raw) != 4 {
		return ""
	}
	return net.IP(raw).String()
}

func text(pdu gosnmp.SnmpPDU) string {
	if pdu.Value == nil {
		return ""
	}
	return snmpx.String(pdu)
}

func lookup(byIfIndex map[int]*payload.Port, idx string) *payload.Port {
	n, err := strconv.Atoi(idx)
	if err != nil {
		return nil
	}
	return byIfIndex[n]
}

// AdvertisesCapability reports whether the device advertises an LLDP system
// capability about itself.
//
// This is the only vendor-independent way to recognise a desk phone. sysServices
// cannot do it: a phone has an embedded two-port switch, so it sets the datalink
// bit and looks like network gear. Nor can sysObjectID, which only works for
// vendors already in a profile — an unknown handset still answers this.
func (c *Collector) AdvertisesCapability(bit int) bool {
	res, err := c.Session.Get([]string{c.oid("lldp_loc_sys_cap")})
	if err != nil {
		return false
	}

	for _, pdu := range res {
		raw, ok := pdu.Value.([]byte)
		if !ok || len(raw) == 0 {
			continue
		}
		// BITS are numbered from the most significant bit of the first octet.
		index := bit / 8
		if index >= len(raw) {
			continue
		}
		if raw[index]&(0x80>>(bit%8)) != 0 {
			return true
		}
	}

	return false
}
