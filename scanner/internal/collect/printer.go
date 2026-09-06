// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// Printer supplies, from the Printer MIB (RFC 3805).
//
// Every printer worth managing implements prtMarkerSuppliesTable, so this needs
// no vendor OIDs and no per-model profile: toner, ink, drums, waste bottles and
// fuser kits all come from the same two tables on an HP, a Kyocera and a Brother
// alike.
//
// The awkward part is not reading the values but refusing to invent them. The
// MIB uses negative levels to say "I do not know" — and a supply whose level is
// unknown must not be reported as 0%, because 0% reads as "empty" to everyone
// who sees it. That produces two opposite failures at once: toner ordered for
// printers that do not need it, and a genuinely empty cartridge lost in a list
// where everything already says empty.
const (
	oidPrtMarkerSuppliesColorantIndex = "1.3.6.1.2.1.43.11.1.1.3"
	oidPrtMarkerSuppliesClass         = "1.3.6.1.2.1.43.11.1.1.4"
	oidPrtMarkerSuppliesType          = "1.3.6.1.2.1.43.11.1.1.5"
	oidPrtMarkerSuppliesDescription   = "1.3.6.1.2.1.43.11.1.1.6"
	oidPrtMarkerSuppliesSupplyUnit    = "1.3.6.1.2.1.43.11.1.1.7"
	oidPrtMarkerSuppliesMaxCapacity   = "1.3.6.1.2.1.43.11.1.1.8"
	oidPrtMarkerSuppliesLevel         = "1.3.6.1.2.1.43.11.1.1.9"

	oidPrtMarkerColorantValue = "1.3.6.1.2.1.43.12.1.1.4"
)

// prtMarkerSuppliesLevel / prtMarkerSuppliesMaxCapacity sentinel values.
const (
	levelOther         = -1 // present, amount not reportable
	levelUnknown       = -2
	levelSomeRemaining = -3 // "there is some left", quantity unspecified
)

// prtMarkerSuppliesSupplyUnit values that matter here. The rest are physical
// units (grams, millilitres, sheets) that are only meaningful as a ratio
// against max capacity, which is how they are treated.
const unitPercent = 19

// prtMarkerSuppliesClass. Only the receptacle case changes how a level reads,
// but the consumed case is named so the distinction is visible at the call site.
const (
	classConsumed   = 3 //nolint:unused // documents the counterpart of classReceptacle
	classReceptacle = 4 // a waste bottle: level counts up, not down
)

// Supply is one row of prtMarkerSuppliesTable.
type Supply struct {
	// Device and Index together are the table's two-part index
	// (hrDeviceIndex, prtMarkerSuppliesIndex).
	Device int
	Index  int

	Description string
	Class       int
	Type        int
	Unit        int
	MaxCapacity int64
	Level       int64
	Colorant    string
}

// Supplies reads every marker supply the device reports.
func (c *Collector) Supplies() ([]Supply, error) {
	levels, err := c.walkInts(oidPrtMarkerSuppliesLevel)
	if err != nil {
		return nil, err
	}
	if len(levels) == 0 {
		return nil, nil
	}

	classes, _ := c.walkInts(oidPrtMarkerSuppliesClass)
	types, _ := c.walkInts(oidPrtMarkerSuppliesType)
	units, _ := c.walkInts(oidPrtMarkerSuppliesSupplyUnit)
	maxima, _ := c.walkInts(oidPrtMarkerSuppliesMaxCapacity)
	colorantIdx, _ := c.walkInts(oidPrtMarkerSuppliesColorantIndex)
	descriptions, _ := c.walkStrings(oidPrtMarkerSuppliesDescription)

	// prtMarkerColorantTable is indexed by (hrDeviceIndex, colorantIndex), and
	// a supply points into it by colorant index within its own device — so the
	// device half of the key has to be carried through rather than assumed to
	// be 1. Multi-engine devices exist and get this wrong otherwise.
	colorants, _ := c.walkStrings(oidPrtMarkerColorantValue)

	out := make([]Supply, 0, len(levels))
	for key, level := range levels {
		device, index := key.device, key.index

		s := Supply{
			Device:      device,
			Index:       index,
			Level:       level,
			Class:       int(classes[key]),
			Type:        int(types[key]),
			Unit:        int(units[key]),
			MaxCapacity: maxima[key],
			Description: strings.TrimSpace(descriptions[key]),
		}

		if ci, ok := colorantIdx[key]; ok && ci > 0 {
			s.Colorant = strings.TrimSpace(colorants[tableKey{device: device, index: int(ci)}])
		}

		out = append(out, s)
	}

	// Stable order so a repeated scan produces an identical payload; GLPI
	// compares what it receives against what it stored.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		return out[i].Index < out[j].Index
	})

	return out, nil
}

// tableKey is a two-part SNMP table index.
type tableKey struct {
	device int
	index  int
}

// parseTableKey reads the index suffix left over after a walk.
//
// prtMarkerSuppliesTable is indexed by (hrDeviceIndex, prtMarkerSuppliesIndex),
// so the suffix is normally two arcs. A single arc is accepted because some
// firmware flattens the table to one index, and treating that as device 0 keeps
// every row of such a device consistent with itself — which is all the key is
// used for.
func parseTableKey(suffix string) (tableKey, bool) {
	parts := strings.Split(strings.Trim(suffix, "."), ".")

	switch len(parts) {
	case 1:
		index, err := strconv.Atoi(parts[0])
		if err != nil {
			return tableKey{}, false
		}
		return tableKey{index: index}, true
	case 2:
		device, err := strconv.Atoi(parts[0])
		if err != nil {
			return tableKey{}, false
		}
		index, err := strconv.Atoi(parts[1])
		if err != nil {
			return tableKey{}, false
		}
		return tableKey{device: device, index: index}, true
	}

	return tableKey{}, false
}

// walkInts walks a column into integers keyed by table index.
func (c *Collector) walkInts(root string) (map[tableKey]int64, error) {
	rows, err := c.Session.Walk(root)
	if err != nil {
		return nil, err
	}

	out := make(map[tableKey]int64, len(rows))
	for suffix, pdu := range rows {
		if key, ok := parseTableKey(suffix); ok {
			out[key] = snmpx.Int(pdu)
		}
	}

	return out, nil
}

// walkStrings walks a column into strings keyed by table index.
func (c *Collector) walkStrings(root string) (map[tableKey]string, error) {
	rows, err := c.Session.Walk(root)
	if err != nil {
		return nil, err
	}

	out := make(map[tableKey]string, len(rows))
	for suffix, pdu := range rows {
		if key, ok := parseTableKey(suffix); ok {
			out[key] = snmpx.String(pdu)
		}
	}

	return out, nil
}

// Percent is the supply level as a percentage, and whether one is knowable.
//
// False means "do not report a number", which is different from zero. A caller
// that treats the two the same turns every unreadable supply into an empty one.
func (s Supply) Percent() (int, bool) {
	// Any negative level is the printer declining to answer: other(-1),
	// unknown(-2) and someRemaining(-3) are the values the MIB defines, and
	// anything else negative is outside it. someRemaining is the one that shows
	// why this must not become zero — it means there IS some left, so 0% would
	// be exactly backwards.
	if s.Level < 0 {
		return 0, false
	}

	// Some devices report the level already scaled, with max capacity set to
	// 100 or to an unknown sentinel.
	if s.Unit == unitPercent {
		return clampPercent(int(s.Level)), true
	}

	if s.MaxCapacity <= 0 {
		return 0, false
	}

	return clampPercent(int((s.Level * 100) / s.MaxCapacity)), true
}

func clampPercent(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// IsWasteReceptacle reports whether a rising level is bad news.
//
// It matters for reading the number: on a consumed supply the percentage is how
// much is left, on a receptacle it is how full it is. GLPI stores one number per
// property with no room for that distinction, so it is not inverted here —
// inverting would be a guess dressed as data — but it is what the description
// suffix exists to make legible.
func (s Supply) IsWasteReceptacle() bool {
	if s.Class == classReceptacle {
		return true
	}

	switch s.Type {
	case 4, 8, 14, 24, 25, 26: // wasteToner, wasteInk, wasteWax, wasteWater, wasteTransfer, wasteBottle
		return true
	}

	return false
}

// Tag maps a supply onto GLPI's cartridge vocabulary.
//
// GLPI does not accept arbitrary names: Cartridge::knownTags() is a closed list,
// and a property outside it is stored but never labelled, so it shows up in the
// UI as a bare string with no translation and no meaning. The mapping below is
// from the MIB's type enum, falling back to the description only when the type
// is other(1) or unknown(2) — which cheap printers do report.
//
// Returns "" for a supply that has no sensible GLPI equivalent, which is better
// than filing it under a tag that means something else.
func (s Supply) Tag() string {
	colored := func(base string) string {
		return base + s.colorSuffix()
	}

	switch s.Type {
	case 3, 21: // toner, tonerCartridge
		return colored("toner")
	case 5, 6, 7: // ink, inkCartridge, inkRibbon
		return colored("cartridge")
	case 9: // opc — the photoconductor, universally called the drum
		return colored("drum")
	case 10:
		return "developer"
	case 4, 8, 14, 24, 26: // the waste receptacles
		return "wastetoner"
	case 25: // wasteTransfer belongs with the transfer kit it comes from
		return "transferkit"
	case 11, 15, 17, 22: // fuserOil, fuser, fuserOilWick, fuserOiler
		return "fuserkit"
	case 20:
		return "transferkit"
	case 18, 19, 27: // cleanerUnit, fuserCleaningPad, cleanerRoller
		return "cleaningkit"
	case 28:
		return "staples"
	case 1, 2: // other, unknown — fall through to the description
	default:
		return ""
	}

	return s.tagFromDescription()
}

// tagFromDescription guesses from the human-readable label.
//
// Only reached when the device declined to type the supply. Ordered so the more
// specific words win: "waste toner bottle" must not match "toner" first.
func (s Supply) tagFromDescription() string {
	d := strings.ToLower(s.Description)

	switch {
	case strings.Contains(d, "waste"):
		return "wastetoner"
	case strings.Contains(d, "maintenance"):
		return "maintenancekit"
	case strings.Contains(d, "fuser"):
		return "fuserkit"
	case strings.Contains(d, "transfer"):
		return "transferkit"
	case strings.Contains(d, "clean"):
		return "cleaningkit"
	case strings.Contains(d, "developer"):
		return "developer"
	case strings.Contains(d, "staple"):
		return "staples"
	case strings.Contains(d, "drum") || strings.Contains(d, "photoconductor") || strings.Contains(d, "imaging"):
		return "drum" + s.colorSuffix()
	case strings.Contains(d, "toner"):
		return "toner" + s.colorSuffix()
	case strings.Contains(d, "ink") || strings.Contains(d, "cartridge"):
		return "cartridge" + s.colorSuffix()
	}

	return ""
}

// colorSuffix normalises a colorant onto GLPI's colour vocabulary.
//
// Defaults to black rather than to nothing: a bare "toner" is not one of
// GLPI's tags, so a mono printer reporting an uncoloured toner would otherwise
// produce a property GLPI cannot label at all.
func (s Supply) colorSuffix() string {
	source := s.Colorant
	if source == "" {
		source = s.Description
	}
	source = strings.ToLower(source)

	// Light shades first: "light cyan" contains "cyan".
	for _, c := range []struct{ match, tag string }{
		{"light cyan", "cyanlight"},
		{"cyanlight", "cyanlight"},
		{"light magenta", "magentalight"},
		{"magentalight", "magentalight"},
		{"dark grey", "darkgrey"},
		{"dark gray", "darkgrey"},
		{"cyan", "cyan"},
		{"magenta", "magenta"},
		{"yellow", "yellow"},
		{"black", "black"},
		{"grey", "grey"},
		{"gray", "grey"},
	} {
		if strings.Contains(source, c.match) {
			return c.tag
		}
	}

	return "black"
}

// Cartridges renders supplies into the map GLPI stores against the printer.
//
// Percentages only, keyed by GLPI's tag vocabulary. Supplies whose level the
// printer would not report are omitted entirely rather than sent as zero.
//
// A duplicate tag keeps the lower percentage. Devices really do report two rows
// for one colour — a cartridge and its integrated drum, or two engines — and
// whichever needs attention first is the one worth surfacing.
func Cartridges(supplies []Supply) payload.Cartridges {
	if len(supplies) == 0 {
		return nil
	}

	out := payload.Cartridges{}
	for _, s := range supplies {
		tag := s.Tag()
		if tag == "" {
			continue
		}

		percent, ok := s.Percent()
		if !ok {
			continue
		}

		if existing, seen := out[tag]; seen && existing <= percent {
			continue
		}
		out[tag] = percent
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// SupplySummary is a one-line human description, for the scanner's own -once
// output and for logs. GLPI stores percentages; a person reading a terminal
// wants the units and the label too.
func SupplySummary(s Supply) string {
	label := s.Description
	if label == "" {
		label = fmt.Sprintf("supply %d.%d", s.Device, s.Index)
	}

	percent, ok := s.Percent()
	if !ok {
		return fmt.Sprintf("%s: level not reported", label)
	}

	suffix := ""
	if s.IsWasteReceptacle() {
		suffix = " full"
	}

	return fmt.Sprintf("%s: %d%%%s", label, percent, suffix)
}
