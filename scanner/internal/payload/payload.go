// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package payload models GLPI's native inventory format for network devices.
//
// The shapes here follow `vendor/glpi-project/inventory_format/inventory.schema.json`
// as shipped with GLPI, not a reimplementation of it. Emitting the documented
// format is the whole point of the design: GLPI already knows how to turn
// NETDISCOVERY/NETINVENTORY content into NetworkEquipment, Printer and
// Unmanaged assets with their ports, IPs and components, so the scanner has no
// business creating assets itself.
//
// Every field is `omitempty`. GLPI validates submissions against the schema,
// and a key present with a zero value is not the same as an absent key — an
// empty `serial` will happily overwrite a good one recorded earlier.
package payload

import "encoding/json"

// Query identifies which half of the network inventory protocol a submission
// belongs to. Discovery is the cheap sweep that says "something answers here";
// inventory is the full walk of a device already known to speak SNMP.
type Query string

const (
	QueryDiscovery Query = "netdiscovery"
	QueryInventory Query = "netinventory"
)

// Inventory is one submission for one device.
type Inventory struct {
	DeviceID string `json:"deviceid"`
	Action   string `json:"action"`
	ItemType string `json:"itemtype,omitempty"`
	JobID    int    `json:"jobid,omitempty"`

	// Power carries UPS/PDU state. Plugin-only, like ScanAddress.
	Power *Power `json:"power,omitempty"`

	// Wireless travels outside `content` for the same reason Power does: GLPI's
	// inventory format has no place for it. network_device carries no comment
	// field, and its `description` is the device's sysDescr — writing "managed
	// by controller X" there would overwrite a real fact with a different one.
	// The plugin stores this in its own table and renders it on a tab.
	Wireless *Wireless `json:"wireless,omitempty"`

	// Markers ride on a discovery submission and are how the server decides
	// whether a full walk is warranted. See collect.Markers.
	Markers *Markers `json:"markers,omitempty"`

	// ScanAddress is the address this device was actually contacted on.
	//
	// Not part of GLPI's format and never forwarded to it — it exists so the
	// plugin can check a submission against the ranges it handed out. The
	// addresses a device *reports* are not usable for that: a switch commonly
	// answers on a management address that is not the one in its IP-MIB (an
	// SVI, a NAT, a second interface), so validating on reported IPs rejects
	// perfectly legitimate scans.
	ScanAddress string `json:"scan_address,omitempty"`

	Content Content `json:"content"`
}

// Content is the payload body.
type Content struct {
	Device       *Device       `json:"network_device,omitempty"`
	Ports        []Port        `json:"network_ports,omitempty"`
	Components   []Component   `json:"network_components,omitempty"`
	PageCounters *PageCounters `json:"pagecounters,omitempty"`
	Cartridges   Cartridges    `json:"cartridges,omitempty"`

	VersionClient string `json:"versionclient,omitempty"`
}

// Device is the `network_device` object. `type` is the only required member,
// and the schema pins it to a closed vocabulary — see DeviceType.
type Device struct {
	Type         string   `json:"type"`
	Name         string   `json:"name,omitempty"`
	Description  string   `json:"description,omitempty"`
	Serial       string   `json:"serial,omitempty"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Model        string   `json:"model,omitempty"`
	MAC          string   `json:"mac,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	Location     string   `json:"location,omitempty"`
	Contact      string   `json:"contact,omitempty"`
	Uptime       string   `json:"uptime,omitempty"`
	Firmware     string   `json:"firmware,omitempty"`
	AssetTag     string   `json:"assettag,omitempty"`
	RAM          int      `json:"ram,omitempty"`
	Memory       int      `json:"memory,omitempty"`
	CPU          int      `json:"cpu,omitempty"`
	Credentials  int      `json:"credentials,omitempty"`
}

// Port is one `network_ports` entry, keyed by ifIndex.
//
// The status/type members are integers, not the strings their MIB names might
// suggest: ifstatus is IF-MIB's ifOperStatus enum (up(1), down(2), …),
// ifinternalstatus is ifAdminStatus and the schema constrains it to 1..3.
// Emitting these as strings is silently rejected by GLPI's validator.
type Port struct {
	IfNumber         int    `json:"ifnumber,omitempty"`
	IfName           string `json:"ifname,omitempty"`
	IfDescr          string `json:"ifdescr,omitempty"`
	IfAlias          string `json:"ifalias,omitempty"`
	IfType           int    `json:"iftype,omitempty"`
	IfMTU            int    `json:"ifmtu,omitempty"`
	IfSpeed          int64  `json:"ifspeed,omitempty"`
	IfStatus         int    `json:"ifstatus,omitempty"`
	IfInternalStatus int    `json:"ifinternalstatus,omitempty"`
	IfPortDuplex     int    `json:"ifportduplex,omitempty"`
	IfLastChange     string `json:"iflastchange,omitempty"`
	IfInBytes        int64  `json:"ifinbytes,omitempty"`
	IfOutBytes       int64  `json:"ifoutbytes,omitempty"`

	IfInErrors  int64    `json:"ifinerrors,omitempty"`
	IfOutErrors int64    `json:"ifouterrors,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Trunk       bool     `json:"trunk,omitempty"`
	LLDP        bool     `json:"lldp,omitempty"`
	VLANs       []VLAN   `json:"vlans,omitempty"`
	Connections []Conn   `json:"connections,omitempty"`

	// Aggregate lists the ifIndexes this port aggregates, and is set only on
	// the aggregator. GLPI resolves them to port ids itself once every port
	// exists, so members carry nothing: they are ordinary ports that happen to
	// be named by one.
	Aggregate []int `json:"aggregate,omitempty"`
}

// VLAN membership on a port.
type VLAN struct {
	Number int    `json:"number,omitempty"`
	Name   string `json:"name,omitempty"`
	Tagged bool   `json:"tagged,omitempty"`
}

// Conn is one neighbour seen on a port — either a MAC learned from the bridge
// forwarding table, or a full neighbour record from LLDP/CDP. This is what
// lets GLPI draw links between a switch port and the device behind it.
type Conn struct {
	MAC      string `json:"mac,omitempty"`
	IfNumber int    `json:"ifnumber,omitempty"`
	SysMAC   string `json:"sysmac,omitempty"`
	IfDescr  string `json:"ifdescr,omitempty"`
	IP       string `json:"ip,omitempty"`
	SysDescr string `json:"sysdescr,omitempty"`
	SysName  string `json:"sysname,omitempty"`
}

// Component is one `network_components` entry — a stack member, module, PSU or
// transceiver from ENTITY-MIB.
type Component struct {
	Index          int    `json:"index,omitempty"`
	ContainedIndex int    `json:"contained_index,omitempty"`
	Name           string `json:"name,omitempty"`
	Type           string `json:"type,omitempty"`
	Description    string `json:"description,omitempty"`
	Serial         string `json:"serial,omitempty"`
	Model          string `json:"model,omitempty"`
	Manufacturer   string `json:"manufacturer,omitempty"`
	Firmware       string `json:"firmware,omitempty"`
	// entPhysicalIsFRU is a TruthValue — true(1)/false(2) — and the schema
	// types it as an integer, not a boolean. Emitting `true` here fails
	// validation, so the SNMP value is carried through as-is.
	FRU         int `json:"fru,omitempty"`
	StackNumber int `json:"stack_number,omitempty"`
}

// PageCounters is the printer counter block.
type PageCounters struct {
	Total       int `json:"total,omitempty"`
	Black       int `json:"black,omitempty"`
	Color       int `json:"color,omitempty"`
	PrintTotal  int `json:"printtotal,omitempty"`
	PrintBlack  int `json:"printblack,omitempty"`
	PrintColor  int `json:"printcolor,omitempty"`
	CopyTotal   int `json:"copytotal,omitempty"`
	CopyBlack   int `json:"copyblack,omitempty"`
	CopyColor   int `json:"copycolor,omitempty"`
	ScannedPage int `json:"scanned,omitempty"`
	FaxTotal    int `json:"faxtotal,omitempty"`
	RectoVerso  int `json:"rectoverso,omitempty"`
}

// Cartridges carries printer supply levels as percentages, keyed by GLPI's
// cartridge vocabulary — `tonerblack`, `drumcyan`, `wastetoner` and so on.
//
// Not free-form, despite what the wire format suggests. GLPI matches these keys
// against Cartridge::knownTags(), and anything outside that list is stored but
// never labelled, so it surfaces in the UI as an untranslated string with no
// meaning. The mapping from the MIB's supply types onto these names lives in
// collect.Supply.Tag().
type Cartridges map[string]int

// MarshalJSON renders the map wrapped in a single-element array.
//
// This is not decoration. GLPI's Cartridge asset reads `$this->data[0]` and
// then iterates it as property/value pairs, so it wants an array whose first
// element is the object — while the published schema describes an array of
// {name, value} objects, which its own handler would not understand. The array
// form satisfies both: the schema does not forbid other properties, and the
// handler gets the object where it looks for it.
func (c Cartridges) MarshalJSON() ([]byte, error) {
	if len(c) == 0 {
		return []byte("null"), nil
	}

	return json.Marshal([]map[string]int{c})
}

// UnmarshalJSON accepts either shape, so a payload can be round-tripped through
// the plugin's own tests and fixtures without special-casing.
func (c *Cartridges) UnmarshalJSON(data []byte) error {
	var wrapped []map[string]int
	if err := json.Unmarshal(data, &wrapped); err == nil {
		out := Cartridges{}
		for _, m := range wrapped {
			for k, v := range m {
				out[k] = v
			}
		}
		*c = out
		return nil
	}

	var flat map[string]int
	if err := json.Unmarshal(data, &flat); err != nil {
		return err
	}
	*c = Cartridges(flat)

	return nil
}

// Device types accepted by the schema's `type` pattern:
//
//	^(Unmanaged|Computer|Networking|Printer|Storage|Power|Phone|Video|KVM)$
//
// Anything outside this set fails validation, so a device the scanner cannot
// classify is reported as Unmanaged rather than guessed at — GLPI has a
// first-class Unmanaged asset for exactly that case, and an operator can
// promote it later.
const (
	TypeUnmanaged  = "Unmanaged"
	TypeComputer   = "Computer"
	TypeNetworking = "Networking"
	TypePrinter    = "Printer"
	TypeStorage    = "Storage"
	TypePower      = "Power"
	TypePhone      = "Phone"
	TypeVideo      = "Video"
	TypeKVM        = "KVM"
)

// GLPIItemType maps the schema's `network_device.type` vocabulary onto the GLPI
// class that should own the asset.
//
// This must be set on the submission's top-level `itemtype`: GLPI reads it in
// extractMetadata() and *defaults to Computer* when it is absent, so an
// unset itemtype does not fail — it quietly files every switch and printer as
// a computer. Only the types with a dedicated MainAsset get their own class;
// the rest land on Unmanaged, which is GLPI's designed home for "seen, not
// yet classified" and can be promoted by an operator.
func GLPIItemType(deviceType string) string {
	switch deviceType {
	case TypeNetworking:
		return "NetworkEquipment"
	case TypePrinter:
		return "Printer"
	case TypePower:
		// GLPI has a first-class PDU asset covering rack strips, UPSes and
		// ATSes. Core's inventory pipeline cannot build one — there is no
		// MainAsset\PDU — so the plugin creates it directly and this value is
		// the routing signal rather than something core ever sees.
		return "PDU"
	case TypePhone:
		return "Phone"
	case TypeComputer:
		return "Computer"
	default:
		return "Unmanaged"
	}
}

// --- power devices ----------------------------------------------------------
//
// Power data is carried *outside* `content`, alongside `scan_address`, and is
// never forwarded to GLPI's inventory pipeline. Two reasons: the inventory
// schema has no vocabulary for batteries, outlets or load, and GLPI has no
// MainAsset for PDU — so core could not build the asset even if the schema
// allowed the data through. The plugin creates the native GLPI `PDU` itself
// and keeps the live state in its own tables.

// Power is the collected state of a UPS, PDU or ATS.
type Power struct {
	// Kind is "ups", "pdu" or "ats". It decides the GLPI PDU *type*, which is
	// how an operator tells a UPS from a rack strip in the asset list.
	Kind string `json:"kind"`

	Battery      *Battery `json:"battery,omitempty"`
	OutputSource string   `json:"output_source,omitempty"`
	Input        []Line   `json:"input,omitempty"`
	Output       []Line   `json:"output,omitempty"`
	Outlets      []Outlet `json:"outlets,omitempty"`
	Sensors      []Sensor `json:"sensors,omitempty"`
	Alarms       []string `json:"alarms,omitempty"`
}

// Markers are the standard "when did this last change" counters.
//
// All sysUpTime-relative, so they are only comparable within one boot — which
// is why the uptime itself is carried alongside. Zero means the device does not
// implement the counter, not that nothing has changed.
type Markers struct {
	UptimeTicks       int64 `json:"uptime_ticks,omitempty"`
	IfTableLastChange int64 `json:"iftable_last_change,omitempty"`
	IfStackLastChange int64 `json:"ifstack_last_change,omitempty"`
	EntityLastChange  int64 `json:"entity_last_change,omitempty"`
}

// Wireless is a controller's view of its estate.
type Wireless struct {
	// Controller is this device's own name, repeated on each AP submission so
	// the plugin can record who manages what without a second lookup.
	Controller   string         `json:"controller,omitempty"`
	SSIDs        []WirelessSSID `json:"ssids,omitempty"`
	AccessPoints []WirelessAP   `json:"access_points,omitempty"`
}

// WirelessSSID is one broadcast network.
type WirelessSSID struct {
	Name    string `json:"name"`
	Clients int    `json:"clients"`
}

// WirelessAP is one access point as the controller reports it.
//
// Deliberately not the same struct as the asset submission: this is the
// operational view — is it up, how many clients — while the asset itself is
// created through the ordinary NetworkEquipment path so it gets a serial, a
// model and a switch port like any other piece of hardware.
type WirelessAP struct {
	Name     string `json:"name"`
	Serial   string `json:"serial,omitempty"`
	MAC      string `json:"mac,omitempty"`
	IP       string `json:"ip,omitempty"`
	Model    string `json:"model,omitempty"`
	Location string `json:"location,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	Status   string `json:"status,omitempty"`
	Radios   int    `json:"radios,omitempty"`
	Clients  int    `json:"clients"`

	RadioDetail []WirelessRadio `json:"radios_detail,omitempty"`
}

// WirelessRadio is one radio of one access point.
//
// Separate from the AP because the vendors publish it separately, indexed one
// level finer — and because "which band is busy" is a different question from
// "is this AP up", asked by a different person.
type WirelessRadio struct {
	Slot    string `json:"slot,omitempty"`
	Band    string `json:"band,omitempty"`
	Channel int    `json:"channel,omitempty"`
	Clients int    `json:"clients"`
	Status  string `json:"status,omitempty"`
}

// Battery is the UPS battery block. Absent on a PDU.
type Battery struct {
	Status           string  `json:"status,omitempty"`
	ChargePercent    int     `json:"charge_percent,omitempty"`
	RuntimeMinutes   int     `json:"runtime_minutes,omitempty"`
	VoltageV         float64 `json:"voltage_v,omitempty"`
	CurrentA         float64 `json:"current_a,omitempty"`
	TemperatureC     int     `json:"temperature_c,omitempty"`
	SecondsOnBattery int     `json:"seconds_on_battery,omitempty"`
	ReplaceIndicated bool    `json:"replace_indicated,omitempty"`
}

// Line is one input or output line/phase.
type Line struct {
	Index       int     `json:"index"`
	VoltageV    float64 `json:"voltage_v,omitempty"`
	CurrentA    float64 `json:"current_a,omitempty"`
	PowerW      int     `json:"power_w,omitempty"`
	FrequencyHz float64 `json:"frequency_hz,omitempty"`
	LoadPercent int     `json:"load_percent,omitempty"`
}

// Outlet is one switched or metered socket.
type Outlet struct {
	Index    int     `json:"index"`
	Name     string  `json:"name,omitempty"`
	State    string  `json:"state,omitempty"` // on | off | unknown
	CurrentA float64 `json:"current_a,omitempty"`
	PowerW   int     `json:"power_w,omitempty"`
}

// Sensor is an ENTITY-SENSOR-MIB reading — inlet temperature, humidity, and on
// many PDUs the per-bank current and power too.
type Sensor struct {
	Index int     `json:"index"`
	Name  string  `json:"name,omitempty"`
	Type  string  `json:"type,omitempty"`
	Value float64 `json:"value,omitempty"`
	Units string  `json:"units,omitempty"`
}
