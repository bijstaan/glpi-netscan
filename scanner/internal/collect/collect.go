// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package collect turns an SNMP session into a GLPI inventory payload.
//
// Which OIDs get read is entirely profile-driven — this package knows how to
// walk a column and coerce a value, not which OID holds a serial number on a
// particular switch. That separation is what makes device-specific OIDs an
// operator concern (a profile edited in GLPI) rather than a code change.
package collect

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/profile"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// Standard OIDs used for identification and classification, before any profile
// is resolved. Everything else arrives in the profile.
const (
	OIDSysDescr    = "1.3.6.1.2.1.1.1.0"
	OIDSysObjectID = "1.3.6.1.2.1.1.2.0"
	OIDSysUpTime   = "1.3.6.1.2.1.1.3.0"
	OIDSysContact  = "1.3.6.1.2.1.1.4.0"
	OIDSysName     = "1.3.6.1.2.1.1.5.0"
	OIDSysLocation = "1.3.6.1.2.1.1.6.0"
	OIDSysServices = "1.3.6.1.2.1.1.7.0"

	// IP-MIB, for device and per-port addresses.
	OIDIPAdEntAddr    = "1.3.6.1.2.1.4.20.1.1"
	OIDIPAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2"

	// PRINTER-MIB; presence of a marker counter is the reliable signal that a
	// device is a printer, more so than sysObjectID guesswork.
	OIDPrtMarkerLifeCount = "1.3.6.1.2.1.43.10.2.1.4"
)

// Identity is the cheap first look at a device: enough to decide whether it is
// worth a full walk, which profiles apply, and what kind of asset it becomes.
type Identity struct {
	SysDescr    string
	SysObjectID string
	SysName     string
	SysContact  string
	SysLocation string
	SysServices int
	UpTimeTicks int64
}

// Probe performs discovery: a single GET of the system group.
//
// This is the query run against every address in a range, so it stays one
// round-trip. A device that does not answer this is not SNMP-capable and is
// never escalated to a full inventory walk.
func Probe(sess *snmpx.Session) (Identity, error) {
	res, err := sess.Get([]string{
		OIDSysDescr, OIDSysObjectID, OIDSysUpTime,
		OIDSysContact, OIDSysName, OIDSysLocation, OIDSysServices,
	})
	if err != nil {
		return Identity{}, err
	}
	if len(res) == 0 {
		return Identity{}, fmt.Errorf("no response to system group")
	}

	id := Identity{
		SysDescr:    str(res, OIDSysDescr),
		SysObjectID: str(res, OIDSysObjectID),
		SysName:     str(res, OIDSysName),
		SysContact:  str(res, OIDSysContact),
		SysLocation: str(res, OIDSysLocation),
		SysServices: int(num(res, OIDSysServices)),
		UpTimeTicks: num(res, OIDSysUpTime),
	}

	// A device that answers the OID but returns nothing useful is not a device
	// we can inventory; treat it as a miss so it does not become a ghost asset.
	if id.SysDescr == "" && id.SysObjectID == "" && id.SysName == "" {
		return id, fmt.Errorf("empty system group")
	}

	return id, nil
}

// Collector performs a full inventory walk.
type Collector struct {
	Session *snmpx.Session
	Profile profile.Resolved
	Ident   Identity

	// lastNeighbours is what the most recent Enrich learned over LLDP and CDP.
	// Retained because the LLDP-MED inventory has to be joined onto it by the
	// LLDP remote index, and walking the neighbour tables a second time to
	// recover something just computed would be a waste of the device's time.
	lastNeighbours map[int]Neighbour
}

// LastNeighbours returns the link partners the last Enrich found.
func (c *Collector) LastNeighbours() map[int]Neighbour {
	return c.lastNeighbours
}

// Device builds the `network_device` object.
func (c *Collector) Device() (*payload.Device, error) {
	dev := &payload.Device{
		Type:        c.classify(),
		Name:        c.Ident.SysName,
		Description: c.Ident.SysDescr,
		Contact:     c.Ident.SysContact,
		Location:    c.Ident.SysLocation,
		Uptime:      FormatUptime(c.Ident.UpTimeTicks),
		Credentials: c.Session.Credential().ID,
	}

	// Profile-driven scalars, fetched in one batch.
	fields := make([]string, 0, len(c.Profile.Device))
	for field := range c.Profile.Device {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	// Literal values are applied first and cost no SNMP request. They exist
	// because plenty of devices expose no manufacturer OID at all, while their
	// sysObjectID says exactly who made them — a vendor profile can then simply
	// assert it.
	oids := make([]string, 0, len(fields))
	for _, f := range fields {
		if literal, ok := Literal(c.Profile.Device[f]); ok {
			applyDeviceLiteral(dev, f, literal)
			continue
		}
		oids = append(oids, Alternatives(c.Profile.Device[f])...)
	}

	if len(oids) > 0 {
		res, err := c.Session.Get(oids)
		if err == nil {
			for _, field := range fields {
				if _, isLiteral := Literal(c.Profile.Device[field]); isLiteral {
					continue
				}
				// Try each alternative in order and apply the first that
				// actually answers, rather than the first that exists.
				for _, oid := range Alternatives(c.Profile.Device[field]) {
					pdu, ok := res[strings.TrimPrefix(oid, ".")]
					if !ok || !meaningful(pdu) {
						continue
					}
					applyDeviceField(dev, field, pdu)
					break
				}
			}
		}
	}

	if ips, err := c.deviceIPs(); err == nil && len(ips) > 0 {
		dev.IPs = ips
	}

	return dev, nil
}

// classify picks the schema's asset type.
//
// A profile may force it. Otherwise: a live marker counter means a printer,
// and sysServices' datalink/internet bits mean networking gear. Anything else
// is reported Unmanaged rather than guessed — GLPI models that as a real asset
// an operator can promote, which is strictly better than a wrong guess that
// creates a NetworkEquipment for someone's laptop.
func (c *Collector) classify() string {
	if c.Profile.ItemType != "" {
		return c.Profile.ItemType
	}

	if rows, err := c.Session.Walk(OIDPrtMarkerLifeCount); err == nil && len(rows) > 0 {
		return payload.TypePrinter
	}

	// A marker supplies table is the other half of the same evidence. Some
	// printers — small inkjets especially — report toner and ink but no life
	// count at all, and would otherwise be filed as Unmanaged despite having
	// told us what they are.
	if rows, err := c.Session.Walk(oidPrtMarkerSuppliesLevel); err == nil && len(rows) > 0 {
		return payload.TypePrinter
	}

	// Checked before sysServices, because power gear reports itself as an
	// ordinary IP-managed appliance and would otherwise fall through to
	// Unmanaged. The test is behavioural — does it answer a battery or outlet
	// table — rather than a guess from sysObjectID.
	if c.IsPowerDevice() {
		return payload.TypePower
	}

	// Likewise before sysServices: a desk phone contains a two-port switch and
	// therefore sets the datalink bit, so sysServices alone would file every
	// handset as network equipment.
	if c.feature("phone") && c.AdvertisesCapability(LldpCapTelephone) {
		return payload.TypePhone
	}

	const (
		datalinkBit = 1 << 1 // OSI layer 2
		internetBit = 1 << 2 // OSI layer 3
	)
	if c.Ident.SysServices&(datalinkBit|internetBit) != 0 {
		return payload.TypeNetworking
	}

	return payload.TypeUnmanaged
}

// deviceIPs collects every address the device owns, minus loopback.
func (c *Collector) deviceIPs() ([]string, error) {
	rows, err := c.Session.Walk(OIDIPAdEntAddr)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(rows))
	for _, pdu := range rows {
		ip := snmpx.String(pdu)
		if usableIP(ip) {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Ports walks every profile-declared port column and assembles one entry per
// ifIndex.
func (c *Collector) Ports() ([]payload.Port, error) {
	if len(c.Profile.Ports) == 0 {
		return nil, nil
	}

	// One walk per column, then transpose by index. Walking columns rather
	// than doing a GET per (port, field) is the difference between one request
	// and several thousand on a 48-port switch.
	columns := map[string]map[string]gosnmp.SnmpPDU{}
	for field, spec := range c.Profile.Ports {
		// A device that does not implement one optional column should still
		// yield every other column, so a failed walk is skipped rather than
		// fatal; alternatives let a profile name a fallback column.
		if rows := c.walkFirst(spec); len(rows) > 0 {
			columns[field] = rows
		}
	}

	indexes := map[string]struct{}{}
	for _, rows := range columns {
		for idx := range rows {
			indexes[idx] = struct{}{}
		}
	}
	if len(indexes) == 0 {
		return nil, nil
	}

	ipsByIndex := c.portIPs()

	ordered := make([]string, 0, len(indexes))
	for idx := range indexes {
		ordered = append(ordered, idx)
	}
	sort.Slice(ordered, func(i, j int) bool { return numericLess(ordered[i], ordered[j]) })

	ports := make([]payload.Port, 0, len(ordered))
	for _, idx := range ordered {
		port := payload.Port{}
		if n, err := strconv.Atoi(idx); err == nil {
			port.IfNumber = n
		}

		for field, rows := range columns {
			pdu, ok := rows[idx]
			if !ok {
				continue
			}
			applyPortField(&port, field, pdu)
		}

		if ips, ok := ipsByIndex[port.IfNumber]; ok {
			port.IPs = ips
		}

		ports = append(ports, port)
	}

	return ports, nil
}

// portIPs maps ifIndex to the addresses configured on it.
func (c *Collector) portIPs() map[int][]string {
	out := map[int][]string{}

	addrs, err := c.Session.Walk(OIDIPAdEntAddr)
	if err != nil {
		return out
	}
	idxs, err := c.Session.Walk(OIDIPAdEntIfIndex)
	if err != nil {
		return out
	}

	// Both columns are indexed by the IP address itself, so the row key joins
	// them.
	for key, pdu := range addrs {
		ip := snmpx.String(pdu)
		if !usableIP(ip) {
			continue
		}
		idxPDU, ok := idxs[key]
		if !ok {
			continue
		}
		ifIndex := int(snmpx.Int(idxPDU))
		out[ifIndex] = append(out[ifIndex], ip)
	}

	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// Components walks ENTITY-MIB columns into stack/module entries.
func (c *Collector) Components() ([]payload.Component, error) {
	if len(c.Profile.Components) == 0 {
		return nil, nil
	}

	columns := map[string]map[string]gosnmp.SnmpPDU{}
	for field, spec := range c.Profile.Components {
		if rows := c.walkFirst(spec); len(rows) > 0 {
			columns[field] = rows
		}
	}

	indexes := map[string]struct{}{}
	for _, rows := range columns {
		for idx := range rows {
			indexes[idx] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(indexes))
	for idx := range indexes {
		ordered = append(ordered, idx)
	}
	sort.Slice(ordered, func(i, j int) bool { return numericLess(ordered[i], ordered[j]) })

	out := make([]payload.Component, 0, len(ordered))
	for _, idx := range ordered {
		comp := payload.Component{}
		if n, err := strconv.Atoi(idx); err == nil {
			comp.Index = n
		}
		for field, rows := range columns {
			pdu, ok := rows[idx]
			if !ok {
				continue
			}
			applyComponentField(&comp, field, pdu)
		}
		// Entries with nothing identifying are chassis scaffolding, not parts
		// worth recording as assets.
		if comp.Name == "" && comp.Serial == "" && comp.Model == "" {
			continue
		}
		out = append(out, comp)
	}

	return out, nil
}

// PageCounters reads printer counters declared by the profile.
func (c *Collector) PageCounters() (*payload.PageCounters, error) {
	if len(c.Profile.PageCounters) == 0 {
		return nil, nil
	}

	pc := &payload.PageCounters{}
	found := false

	for field, spec := range c.Profile.PageCounters {
		// Counters are sometimes scalars and sometimes single-row columns
		// depending on the model, so accept either.
		var value int64
		for _, oid := range Alternatives(spec) {
			if res, err := c.Session.Get([]string{oid}); err == nil {
				for _, pdu := range res {
					if v := snmpx.Int(pdu); v > 0 {
						value = v
					}
				}
			}
			if value == 0 {
				if rows, err := c.Session.Walk(oid); err == nil {
					for _, pdu := range rows {
						if v := snmpx.Int(pdu); v > 0 {
							value = v
							break
						}
					}
				}
			}
			if value > 0 {
				break
			}
		}
		if value <= 0 {
			continue
		}
		if applyCounterField(pc, field, int(value)) {
			found = true
		}
	}

	if !found {
		return nil, nil
	}
	return pc, nil
}

// FormatUptime renders SNMP TimeTicks (hundredths of a second) in the
// "X days, HH:MM:SS" shape the schema asks for.
func FormatUptime(ticks int64) string {
	if ticks <= 0 {
		return ""
	}
	secs := ticks / 100
	days := secs / 86400
	secs %= 86400
	h := secs / 3600
	m := (secs % 3600) / 60
	s := secs % 60
	return fmt.Sprintf("%d days, %02d:%02d:%02d", days, h, m, s)
}

// --- field application ------------------------------------------------------

func applyDeviceField(dev *payload.Device, field string, pdu gosnmp.SnmpPDU) {
	switch field {
	case "name":
		setStr(&dev.Name, pdu)
	case "description":
		setStr(&dev.Description, pdu)
	case "serial":
		setStr(&dev.Serial, pdu)
	case "manufacturer":
		setStr(&dev.Manufacturer, pdu)
	case "model":
		setStr(&dev.Model, pdu)
	case "location":
		setStr(&dev.Location, pdu)
	case "contact":
		setStr(&dev.Contact, pdu)
	case "firmware":
		setStr(&dev.Firmware, pdu)
	case "assettag":
		setStr(&dev.AssetTag, pdu)
	case "mac":
		if mac := snmpx.MAC(pdu); mac != "" {
			dev.MAC = mac
		}
	case "uptime":
		if v := snmpx.Int(pdu); v > 0 {
			dev.Uptime = FormatUptime(v)
		}
	case "ram":
		// HOST-RESOURCES reports memory in KB; the schema wants MiB.
		if v := snmpx.Int(pdu); v > 0 {
			dev.RAM = int(v / 1024)
		}
	case "memory":
		if v := snmpx.Int(pdu); v > 0 {
			dev.Memory = int(v / 1024)
		}
	case "cpu":
		if v := snmpx.Int(pdu); v > 0 {
			dev.CPU = int(v)
		}
	}
}

func applyPortField(port *payload.Port, field string, pdu gosnmp.SnmpPDU) {
	switch field {
	case "ifname":
		setStr(&port.IfName, pdu)
	case "ifdescr":
		setStr(&port.IfDescr, pdu)
	case "ifalias":
		setStr(&port.IfAlias, pdu)
	case "iflastchange":
		if v := snmpx.Int(pdu); v > 0 {
			port.IfLastChange = FormatUptime(v)
		}
	case "mac":
		if mac := snmpx.MAC(pdu); mac != "" {
			port.MAC = mac
		}
	case "iftype":
		port.IfType = int(snmpx.Int(pdu))
	case "ifmtu":
		port.IfMTU = int(snmpx.Int(pdu))
	case "ifspeed":
		port.IfSpeed = snmpx.Int(pdu)
	case "ifstatus":
		port.IfStatus = int(snmpx.Int(pdu))
	case "ifinternalstatus":
		// Schema constrains this to 1..3; anything else (a device reporting
		// ifAdminStatus 4+) is dropped rather than failing the whole payload.
		if v := int(snmpx.Int(pdu)); v >= 1 && v <= 3 {
			port.IfInternalStatus = v
		}
	case "ifportduplex":
		if v := int(snmpx.Int(pdu)); v >= 1 && v <= 3 {
			port.IfPortDuplex = v
		}
	case "ifinbytes":
		port.IfInBytes = snmpx.Int(pdu)
	case "ifoutbytes":
		port.IfOutBytes = snmpx.Int(pdu)
	case "ifinerrors":
		port.IfInErrors = snmpx.Int(pdu)
	case "ifouterrors":
		port.IfOutErrors = snmpx.Int(pdu)
	}
}

func applyComponentField(comp *payload.Component, field string, pdu gosnmp.SnmpPDU) {
	switch field {
	case "name":
		setStr(&comp.Name, pdu)
	case "description":
		setStr(&comp.Description, pdu)
	case "serial":
		setStr(&comp.Serial, pdu)
	case "model":
		setStr(&comp.Model, pdu)
	case "manufacturer":
		setStr(&comp.Manufacturer, pdu)
	case "firmware":
		setStr(&comp.Firmware, pdu)
	case "type":
		setStr(&comp.Type, pdu)
	case "fru":
		// TruthValue: true(1), false(2). Passed through as the integer the
		// schema asks for rather than coerced to a bool.
		if v := int(snmpx.Int(pdu)); v == 1 || v == 2 {
			comp.FRU = v
		}
	case "contained_index":
		comp.ContainedIndex = int(snmpx.Int(pdu))
	case "stack_number":
		comp.StackNumber = int(snmpx.Int(pdu))
	}
}

func applyCounterField(pc *payload.PageCounters, field string, v int) bool {
	switch field {
	case "total":
		pc.Total = v
	case "black":
		pc.Black = v
	case "color":
		pc.Color = v
	case "printtotal":
		pc.PrintTotal = v
	case "printblack":
		pc.PrintBlack = v
	case "printcolor":
		pc.PrintColor = v
	case "copytotal":
		pc.CopyTotal = v
	case "copyblack":
		pc.CopyBlack = v
	case "copycolor":
		pc.CopyColor = v
	case "scanned":
		pc.ScannedPage = v
	case "faxtotal":
		pc.FaxTotal = v
	case "rectoverso":
		pc.RectoVerso = v
	default:
		return false
	}
	return true
}

// --- helpers ----------------------------------------------------------------

func setStr(dst *string, pdu gosnmp.SnmpPDU) {
	// Only overwrite with something real: a device answering an OID with an
	// empty string must not blank a value another OID already supplied.
	if v := snmpx.String(pdu); v != "" {
		*dst = v
	}
}

func str(res map[string]gosnmp.SnmpPDU, oid string) string {
	pdu, ok := res[strings.TrimPrefix(oid, ".")]
	if !ok {
		return ""
	}
	return snmpx.String(pdu)
}

func num(res map[string]gosnmp.SnmpPDU, oid string) int64 {
	pdu, ok := res[strings.TrimPrefix(oid, ".")]
	if !ok {
		return 0
	}
	return snmpx.Int(pdu)
}

// usableIP filters out the addresses that would only add noise to an asset:
// loopback, unspecified and link-local.
func usableIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

// numericLess orders SNMP index suffixes numerically where possible, so port 2
// sorts before port 10 rather than after it.
func numericLess(a, b string) bool {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		return ai < bi
	}
	return a < b
}

// DeriveDeviceMAC picks a base MAC address for the device from its ports.
//
// Many devices expose no serial via ENTITY-MIB, and GLPI's import rules key on
// serial or MAC — a device with neither is refused outright by the default
// "import denied" rule. The lowest-numbered physical port's address is the
// conventional stand-in for a chassis MAC and is stable across reboots, which
// is what makes it usable as an identity.
func DeriveDeviceMAC(ports []payload.Port) string {
	best := -1
	mac := ""

	for _, p := range ports {
		if p.MAC == "" {
			continue
		}
		// Skip loopback, which reports no address anyway, and any port whose
		// index we could not read.
		if p.IfNumber <= 0 {
			continue
		}
		if best == -1 || p.IfNumber < best {
			best = p.IfNumber
			mac = p.MAC
		}
	}

	return mac
}

// Alternatives splits a profile OID specification into candidates.
//
// A field may name several OIDs separated by "|", tried in order until one
// answers. This exists because profile layering is otherwise destructive: a
// higher-priority profile that overrides `serial` replaces the base OID
// outright, so a profile which applies broadly can blank out good data on
// every device that does not implement its preferred OID. Alternatives let
// such a profile say "prefer mine, fall back to the standard one".
func Alternatives(spec string) []string {
	parts := strings.Split(spec, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// walkFirst walks each alternative until one returns rows.
func (c *Collector) walkFirst(spec string) map[string]gosnmp.SnmpPDU {
	for _, oid := range Alternatives(spec) {
		if rows, err := c.Session.Walk(oid); err == nil && len(rows) > 0 {
			return rows
		}
	}
	return nil
}

// meaningful reports whether a PDU carries a usable value, as opposed to
// existing but being empty or zero. Only a value that passes this is allowed
// to satisfy a field and stop the search through its alternatives.
func meaningful(pdu gosnmp.SnmpPDU) bool {
	switch pdu.Type {
	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return false
	case gosnmp.OctetString:
		return strings.TrimSpace(snmpx.String(pdu)) != ""
	default:
		return snmpx.Int(pdu) != 0
	}
}

// Literal recognises a profile value that is a constant rather than an OID.
//
// Spelled with a leading "=", e.g. `manufacturer = =Cisco`. OIDs are dotted
// decimal and can never begin with "=", so the two are unambiguous.
func Literal(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "=") {
		return strings.TrimSpace(spec[1:]), true
	}
	return "", false
}

// applyDeviceLiteral sets a constant device field.
func applyDeviceLiteral(dev *payload.Device, field, value string) {
	if value == "" {
		return
	}
	switch field {
	case "name":
		dev.Name = value
	case "description":
		dev.Description = value
	case "serial":
		dev.Serial = value
	case "manufacturer":
		dev.Manufacturer = value
	case "model":
		dev.Model = value
	case "location":
		dev.Location = value
	case "contact":
		dev.Contact = value
	case "firmware":
		dev.Firmware = value
	case "assettag":
		dev.AssetTag = value
	}
}
