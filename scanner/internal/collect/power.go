// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// Power OIDs.
//
// The defaults are UPS-MIB (RFC 1628), which is the only standard in this
// space — there is no IETF PDU MIB, so rack strips are reached entirely
// through vendor profiles. Every key here is overridable under a profile's
// `power` section.
//
// Values verified against the published MIBs, not recalled: the scaling in
// particular is not guessable. RFC 1628 reports battery voltage in tenths of a
// volt, currents in tenths of an amp, and frequency in tenths of a hertz,
// while voltages on the input and output line tables are plain RMS volts.
const (
	OIDUpsIdentManufacturer = "1.3.6.1.2.1.33.1.1.1.0"
	OIDUpsIdentModel        = "1.3.6.1.2.1.33.1.1.2.0"

	OIDUpsBatteryStatus    = "1.3.6.1.2.1.33.1.2.1.0"
	OIDUpsSecondsOnBattery = "1.3.6.1.2.1.33.1.2.2.0"
	OIDUpsMinutesRemaining = "1.3.6.1.2.1.33.1.2.3.0"
	OIDUpsChargeRemaining  = "1.3.6.1.2.1.33.1.2.4.0"
	OIDUpsBatteryVoltage   = "1.3.6.1.2.1.33.1.2.5.0*0.1"
	OIDUpsBatteryCurrent   = "1.3.6.1.2.1.33.1.2.6.0*0.1"
	OIDUpsBatteryTemp      = "1.3.6.1.2.1.33.1.2.7.0"

	OIDUpsInputFrequency = "1.3.6.1.2.1.33.1.3.3.1.2*0.1"
	OIDUpsInputVoltage   = "1.3.6.1.2.1.33.1.3.3.1.3"
	OIDUpsInputCurrent   = "1.3.6.1.2.1.33.1.3.3.1.4*0.1"
	OIDUpsInputPower     = "1.3.6.1.2.1.33.1.3.3.1.5"

	OIDUpsOutputSource    = "1.3.6.1.2.1.33.1.4.1.0"
	OIDUpsOutputFrequency = "1.3.6.1.2.1.33.1.4.2.0*0.1"
	OIDUpsOutputVoltage   = "1.3.6.1.2.1.33.1.4.4.1.2"
	OIDUpsOutputCurrent   = "1.3.6.1.2.1.33.1.4.4.1.3*0.1"
	OIDUpsOutputPower     = "1.3.6.1.2.1.33.1.4.4.1.4"
	OIDUpsOutputLoad      = "1.3.6.1.2.1.33.1.4.4.1.5"

	OIDUpsAlarmsPresent = "1.3.6.1.2.1.33.1.6.1.0"
	OIDUpsAlarmDescr    = "1.3.6.1.2.1.33.1.6.2.1.2"

	// ENTITY-SENSOR-MIB, joined to ENTITY-MIB names.
	OIDEntSensorType    = "1.3.6.1.2.1.99.1.1.1.1"
	OIDEntSensorScale   = "1.3.6.1.2.1.99.1.1.1.2"
	OIDEntSensorPrec    = "1.3.6.1.2.1.99.1.1.1.3"
	OIDEntSensorValue   = "1.3.6.1.2.1.99.1.1.1.4"
	OIDEntSensorStatus  = "1.3.6.1.2.1.99.1.1.1.5"
	OIDEntSensorUnits   = "1.3.6.1.2.1.99.1.1.1.6"
	OIDEntPhysicalNames = "1.3.6.1.2.1.47.1.1.1.1.7"
)

var powerDefaults = map[string]string{
	"battery_status":     OIDUpsBatteryStatus,
	"seconds_on_battery": OIDUpsSecondsOnBattery,
	"battery_runtime":    OIDUpsMinutesRemaining,
	"battery_charge":     OIDUpsChargeRemaining,
	"battery_voltage":    OIDUpsBatteryVoltage,
	"battery_current":    OIDUpsBatteryCurrent,
	"battery_temp":       OIDUpsBatteryTemp,
	"battery_replace":    "",
	"output_source":      OIDUpsOutputSource,
	"output_frequency":   OIDUpsOutputFrequency,
	"alarms_present":     OIDUpsAlarmsPresent,
	"alarm_descr":        OIDUpsAlarmDescr,

	"input_frequency": OIDUpsInputFrequency,
	"input_voltage":   OIDUpsInputVoltage,
	"input_current":   OIDUpsInputCurrent,
	"input_power":     OIDUpsInputPower,

	"output_voltage": OIDUpsOutputVoltage,
	"output_current": OIDUpsOutputCurrent,
	"output_power":   OIDUpsOutputPower,
	"output_load":    OIDUpsOutputLoad,

	// No standard exists for these; a vendor profile supplies them.
	"outlet_name":    "",
	"outlet_state":   "",
	"outlet_current": "",
	"outlet_power":   "",
}

func (c *Collector) powerOID(key string) string {
	if custom, ok := c.Profile.Power[key]; ok {
		return strings.TrimSpace(custom)
	}
	return powerDefaults[key]
}

// IsPowerDevice reports whether this looks like a UPS, PDU or ATS.
//
// A profile may assert it. Otherwise the test is behavioural: does the device
// answer the standard UPS battery group, or a profile-declared outlet table?
// sysServices cannot decide this — power gear reports itself as an ordinary
// IP-managed appliance, indistinguishable from anything else with a web
// interface.
func (c *Collector) IsPowerDevice() bool {
	if c.Profile.ItemType == payload.TypePower {
		return true
	}
	if !c.feature("power") {
		return false
	}

	if spec := c.powerOID("battery_status"); spec != "" {
		if v, ok := c.scalar(spec); ok && v != 0 {
			return true
		}
	}
	if spec := c.powerOID("outlet_name"); spec != "" {
		if rows := c.walkFirst(stripScale(spec)); len(rows) > 0 {
			return true
		}
	}

	return false
}

// PowerKind distinguishes a UPS from a rack strip.
//
// A battery is the discriminator: a PDU has none. This maps onto the GLPI PDU
// *type* dropdown, which is what lets an operator filter the two apart.
func (c *Collector) PowerKind() string {
	if v, ok := c.scalar(c.powerOID("battery_status")); ok && v != 0 {
		return "ups"
	}
	if v, ok := c.scalar(c.powerOID("battery_charge")); ok && v != 0 {
		return "ups"
	}
	return "pdu"
}

// Power collects the full power picture.
func (c *Collector) Power() *payload.Power {
	if !c.feature("power") {
		return nil
	}

	p := &payload.Power{Kind: c.PowerKind()}

	if p.Kind == "ups" {
		p.Battery = c.battery()
		if v, ok := c.scalar(c.powerOID("output_source")); ok {
			p.OutputSource = outputSourceName(int(v))
		}
	}

	p.Input = c.lines("input_voltage", "input_current", "input_power", "input_frequency", "")
	p.Output = c.lines("output_voltage", "output_current", "output_power", "output_frequency", "output_load")
	p.Outlets = c.outlets()
	p.Sensors = c.sensors()
	p.Alarms = c.alarms()

	// A "power device" with no readings at all is almost certainly a
	// misclassification; reporting it would create an empty PDU asset.
	if p.Battery == nil && len(p.Input) == 0 && len(p.Output) == 0 &&
		len(p.Outlets) == 0 && len(p.Sensors) == 0 {
		return nil
	}

	return p
}

func (c *Collector) battery() *payload.Battery {
	b := &payload.Battery{}
	any := false

	if v, ok := c.scalar(c.powerOID("battery_status")); ok && v != 0 {
		b.Status = batteryStatusName(int(v))
		any = true
	}
	if v, ok := c.scalar(c.powerOID("battery_charge")); ok {
		b.ChargePercent = int(v)
		any = true
	}
	if v, ok := c.scalar(c.powerOID("battery_runtime")); ok {
		b.RuntimeMinutes = int(v)
		any = true
	}
	if v, ok := c.scalar(c.powerOID("battery_voltage")); ok {
		b.VoltageV = round1(v)
		any = true
	}
	if v, ok := c.scalar(c.powerOID("battery_current")); ok {
		b.CurrentA = round1(v)
	}
	if v, ok := c.scalar(c.powerOID("battery_temp")); ok {
		b.TemperatureC = int(v)
		any = true
	}
	if v, ok := c.scalar(c.powerOID("seconds_on_battery")); ok {
		b.SecondsOnBattery = int(v)
	}
	// TruthValue-ish: APC uses batteryNeedsReplacing(2).
	if v, ok := c.scalar(c.powerOID("battery_replace")); ok {
		b.ReplaceIndicated = int(v) == 2
	}

	if !any {
		return nil
	}
	return b
}

// lines assembles the input or output line table.
func (c *Collector) lines(voltage, current, power, frequency, load string) []payload.Line {
	cols := map[string]map[string]gosnmp.SnmpPDU{}
	scales := map[string]float64{}

	for _, key := range []string{voltage, current, power, load} {
		spec := c.powerOID(key)
		if spec == "" {
			continue
		}
		oid, scale := splitScale(spec)
		if rows := c.walkFirst(oid); len(rows) > 0 {
			cols[key] = rows
			scales[key] = scale
		}
	}

	if len(cols) == 0 {
		return nil
	}

	// Frequency is a scalar on most UPSes even though voltage is a table, so
	// it is read once and applied to every line rather than walked.
	var freq float64
	if spec := c.powerOID(frequency); spec != "" {
		if v, ok := c.scalar(spec); ok {
			freq = round1(v)
		}
	}

	indexes := map[string]struct{}{}
	for _, rows := range cols {
		for idx := range rows {
			indexes[idx] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(indexes))
	for idx := range indexes {
		ordered = append(ordered, idx)
	}
	sort.Slice(ordered, func(i, j int) bool { return numericLess(ordered[i], ordered[j]) })

	out := make([]payload.Line, 0, len(ordered))
	for _, idx := range ordered {
		line := payload.Line{FrequencyHz: freq}
		if n, err := strconv.Atoi(idx); err == nil {
			line.Index = n
		}
		if pdu, ok := cols[voltage][idx]; ok {
			line.VoltageV = round1(float64(snmpx.Int(pdu)) * scales[voltage])
		}
		if pdu, ok := cols[current][idx]; ok {
			line.CurrentA = round1(float64(snmpx.Int(pdu)) * scales[current])
		}
		if pdu, ok := cols[power][idx]; ok {
			line.PowerW = int(math.Round(float64(snmpx.Int(pdu)) * scales[power]))
		}
		if pdu, ok := cols[load][idx]; ok {
			line.LoadPercent = int(snmpx.Int(pdu))
		}
		out = append(out, line)
	}

	return out
}

// outlets reads the vendor outlet table.
func (c *Collector) outlets() []payload.Outlet {
	names := c.walkScaled("outlet_name")
	states := c.walkScaled("outlet_state")
	currents := c.walkScaled("outlet_current")
	powers := c.walkScaled("outlet_power")

	if len(names.rows) == 0 && len(states.rows) == 0 {
		return nil
	}

	indexes := map[string]struct{}{}
	for _, set := range []scaledRows{names, states, currents, powers} {
		for idx := range set.rows {
			indexes[idx] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(indexes))
	for idx := range indexes {
		ordered = append(ordered, idx)
	}
	sort.Slice(ordered, func(i, j int) bool { return numericLess(ordered[i], ordered[j]) })

	out := make([]payload.Outlet, 0, len(ordered))
	for _, idx := range ordered {
		o := payload.Outlet{}
		if n, err := strconv.Atoi(idx); err == nil {
			o.Index = n
		}
		if pdu, ok := names.rows[idx]; ok {
			o.Name = snmpx.String(pdu)
		}
		if pdu, ok := states.rows[idx]; ok {
			o.State = outletStateName(int(snmpx.Int(pdu)))
		}
		if pdu, ok := currents.rows[idx]; ok {
			o.CurrentA = round1(float64(snmpx.Int(pdu)) * currents.scale)
		}
		if pdu, ok := powers.rows[idx]; ok {
			o.PowerW = int(math.Round(float64(snmpx.Int(pdu)) * powers.scale))
		}
		out = append(out, o)
	}

	return out
}

// sensors reads ENTITY-SENSOR-MIB, joined to the ENTITY-MIB component names.
//
// This is the standard way modern PDUs expose inlet temperature, humidity and
// per-bank current, so it is worth having even though nothing else in the
// scanner uses ENTITY-SENSOR.
func (c *Collector) sensors() []payload.Sensor {
	values, err := c.Session.Walk(OIDEntSensorValue)
	if err != nil || len(values) == 0 {
		return nil
	}

	types := c.walkOrNil(OIDEntSensorType)
	scales := c.walkOrNil(OIDEntSensorScale)
	precs := c.walkOrNil(OIDEntSensorPrec)
	units := c.walkOrNil(OIDEntSensorUnits)
	status := c.walkOrNil(OIDEntSensorStatus)
	names := c.walkOrNil(OIDEntPhysicalNames)

	ordered := make([]string, 0, len(values))
	for idx := range values {
		ordered = append(ordered, idx)
	}
	sort.Slice(ordered, func(i, j int) bool { return numericLess(ordered[i], ordered[j]) })

	out := make([]payload.Sensor, 0, len(ordered))
	for _, idx := range ordered {
		// operStatus ok(1); anything else is a sensor reporting that its own
		// reading is unusable, so the value must not be recorded as fact.
		if pdu, ok := status[idx]; ok && snmpx.Int(pdu) != 1 {
			continue
		}

		s := payload.Sensor{}
		if n, err := strconv.Atoi(idx); err == nil {
			s.Index = n
		}
		if pdu, ok := names[idx]; ok {
			s.Name = snmpx.String(pdu)
		}
		if pdu, ok := types[idx]; ok {
			s.Type = sensorTypeName(int(snmpx.Int(pdu)))
		}
		if pdu, ok := units[idx]; ok {
			s.Units = snmpx.String(pdu)
		}

		raw := float64(snmpx.Int(values[idx]))
		// The reported value is an integer; entPhySensorScale gives its SI
		// magnitude and entPhySensorPrecision the number of implied decimal
		// places. Ignoring precision reports 22.3 degrees as 223.
		if pdu, ok := precs[idx]; ok {
			if p := int(snmpx.Int(pdu)); p > 0 {
				raw /= math.Pow(10, float64(p))
			}
		}
		if pdu, ok := scales[idx]; ok {
			raw *= sensorScaleFactor(int(snmpx.Int(pdu)))
		}
		s.Value = round2(raw)

		if s.Name == "" && s.Type == "" {
			continue
		}
		out = append(out, s)
	}

	return out
}

func (c *Collector) alarms() []string {
	spec := c.powerOID("alarm_descr")
	if spec == "" {
		return nil
	}

	rows, err := c.Session.Walk(stripScale(spec))
	if err != nil || len(rows) == 0 {
		return nil
	}

	seen := map[string]bool{}
	out := []string{}
	for _, pdu := range rows {
		// The value is an OID naming a well-known alarm condition; the MIB
		// carries no human text for it, so the leaf is mapped here.
		name := alarmName(snmpx.String(pdu))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// --- helpers ----------------------------------------------------------------

type scaledRows struct {
	rows  map[string]gosnmp.SnmpPDU
	scale float64
}

func (c *Collector) walkScaled(key string) scaledRows {
	spec := c.powerOID(key)
	if spec == "" {
		return scaledRows{scale: 1}
	}
	oid, scale := splitScale(spec)
	return scaledRows{rows: c.walkFirst(oid), scale: scale}
}

// scalar reads one value, honouring alternatives and a scale suffix.
func (c *Collector) scalar(spec string) (float64, bool) {
	if strings.TrimSpace(spec) == "" {
		return 0, false
	}

	for _, alt := range Alternatives(spec) {
		oid, scale := splitScale(alt)
		res, err := c.Session.Get([]string{oid})
		if err != nil {
			continue
		}
		pdu, ok := res[strings.TrimPrefix(oid, ".")]
		if !ok || !meaningful(pdu) {
			continue
		}
		return float64(snmpx.Int(pdu)) * scale, true
	}

	return 0, false
}

// splitScale parses `OID*factor`.
//
// Power MIBs are full of tenths — decivolts, deciamps, decihertz — and the
// factor differs per vendor for the same logical field, so it belongs in the
// profile next to the OID rather than in code.
func splitScale(spec string) (string, float64) {
	spec = strings.TrimSpace(spec)
	oid, factor, found := strings.Cut(spec, "*")
	if !found {
		return oid, 1
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(factor), 64)
	if err != nil || f == 0 {
		return strings.TrimSpace(oid), 1
	}
	return strings.TrimSpace(oid), f
}

func stripScale(spec string) string {
	oid, _ := splitScale(spec)
	return oid
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func round2(v float64) float64 { return math.Round(v*100) / 100 }

// batteryStatusName maps upsBatteryStatus.
func batteryStatusName(v int) string {
	switch v {
	case 1:
		return "unknown"
	case 2:
		return "normal"
	case 3:
		return "low"
	case 4:
		return "depleted"
	}
	return ""
}

// outputSourceName maps upsOutputSource. "onBattery" is the one that matters
// operationally: it means the UPS is carrying the load.
func outputSourceName(v int) string {
	switch v {
	case 1:
		return "other"
	case 2:
		return "none"
	case 3:
		return "normal"
	case 4:
		return "bypass"
	case 5:
		return "battery"
	case 6:
		return "booster"
	case 7:
		return "reducer"
	}
	return ""
}

// outletStateName covers the two common vendor encodings, which agree that
// 1 is on and 2 is off.
func outletStateName(v int) string {
	switch v {
	case 1:
		return "on"
	case 2:
		return "off"
	}
	return "unknown"
}

// sensorTypeName maps entPhySensorType.
func sensorTypeName(v int) string {
	switch v {
	case 1:
		return "other"
	case 2:
		return "unknown"
	case 3:
		return "voltsAC"
	case 4:
		return "voltsDC"
	case 5:
		return "amperes"
	case 6:
		return "watts"
	case 7:
		return "hertz"
	case 8:
		return "celsius"
	case 9:
		return "percentRH"
	case 10:
		return "rpm"
	case 11:
		return "cmm"
	case 12:
		return "truthvalue"
	}
	return ""
}

// sensorScaleFactor maps entPhySensorScale, an SI magnitude where units(9)
// is 10^0.
func sensorScaleFactor(v int) float64 {
	if v < 1 || v > 17 {
		return 1
	}
	return math.Pow(10, float64((v-9)*3))
}

// alarmName maps the well-known upsAlarm* OIDs to readable text.
func alarmName(oid string) string {
	const prefix = "1.3.6.1.2.1.33.1.6.3."
	if !strings.HasPrefix(oid, prefix) {
		return oid
	}
	switch strings.TrimPrefix(oid, prefix) {
	case "1":
		return "battery bad"
	case "2":
		return "on battery"
	case "3":
		return "low battery"
	case "4":
		return "depleted battery"
	case "5":
		return "temperature bad"
	case "6":
		return "input bad"
	case "7":
		return "output bad"
	case "8":
		return "output overload"
	case "9":
		return "on bypass"
	case "10":
		return "bypass bad"
	case "11":
		return "output off as requested"
	case "12":
		return "UPS off as requested"
	case "13":
		return "charger failed"
	case "14":
		return "UPS output off"
	case "15":
		return "UPS system off"
	case "16":
		return "fan failure"
	case "17":
		return "fuse failure"
	case "18":
		return "general fault"
	case "19":
		return "diagnostic test failed"
	case "20":
		return "communications lost"
	case "21":
		return "awaiting power"
	case "22":
		return "shutdown pending"
	case "23":
		return "shutdown imminent"
	case "24":
		return "test in progress"
	}
	return oid
}
