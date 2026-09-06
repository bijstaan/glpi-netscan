// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"testing"
)

func TestSupplyPercent(t *testing.T) {
	cases := []struct {
		name    string
		supply  Supply
		want    int
		wantOK  bool
		comment string
	}{
		{
			name:    "derived from level and capacity",
			supply:  Supply{Level: 7400, MaxCapacity: 10000, Unit: 13},
			want:    74,
			wantOK:  true,
			comment: "the common case: toner measured in tenths of grams",
		},
		{
			name:   "already a percentage",
			supply: Supply{Level: 88, MaxCapacity: 100, Unit: unitPercent},
			want:   88,
			wantOK: true,
		},
		{
			name:    "percent unit wins over capacity",
			supply:  Supply{Level: 60, MaxCapacity: -2, Unit: unitPercent},
			want:    60,
			wantOK:  true,
			comment: "devices report percent with an unknown capacity; the unit is authoritative",
		},
		{
			// The three that matter. Every one of these must be "no number",
			// never zero: 0% reads as empty, so an estate of unreadable
			// supplies would look like an estate of empty ones — and the one
			// printer that is genuinely empty becomes invisible in the noise.
			name:    "unknown level is not zero",
			supply:  Supply{Level: levelUnknown, MaxCapacity: 10000},
			wantOK:  false,
			comment: "unknown(-2)",
		},
		{
			name:    "other level is not zero",
			supply:  Supply{Level: levelOther, MaxCapacity: 10000},
			wantOK:  false,
			comment: "other(-1)",
		},
		{
			name:    "someRemaining is not zero",
			supply:  Supply{Level: levelSomeRemaining, MaxCapacity: 300000},
			wantOK:  false,
			comment: "someRemaining(-3) means there IS some left — zero would be backwards",
		},
		{
			name:   "capacity unknown and no percent unit",
			supply: Supply{Level: 500, MaxCapacity: -2, Unit: 13},
			wantOK: false,
		},
		{
			name:   "zero capacity does not divide",
			supply: Supply{Level: 500, MaxCapacity: 0, Unit: 13},
			wantOK: false,
		},
		{
			name:    "a genuine empty is still reported",
			supply:  Supply{Level: 0, MaxCapacity: 10000, Unit: 13},
			want:    0,
			wantOK:  true,
			comment: "0 with a known capacity is real and must not be suppressed",
		},
		{
			name:   "over capacity clamps",
			supply: Supply{Level: 11000, MaxCapacity: 10000, Unit: 13},
			want:   100,
			wantOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.supply.Percent()
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (%s)", ok, tc.wantOK, tc.comment)
			}
			if ok && got != tc.want {
				t.Errorf("percent = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSupplyTag(t *testing.T) {
	cases := []struct {
		name   string
		supply Supply
		want   string
	}{
		{"toner with colorant", Supply{Type: 3, Colorant: "cyan"}, "tonercyan"},
		{"toner cartridge type", Supply{Type: 21, Colorant: "magenta"}, "tonermagenta"},
		{"ink cartridge", Supply{Type: 6, Colorant: "yellow"}, "cartridgeyellow"},
		{"opc becomes a drum", Supply{Type: 9, Colorant: "black"}, "drumblack"},
		{"waste toner", Supply{Type: 4}, "wastetoner"},
		{"waste ink is still a waste bin", Supply{Type: 8}, "wastetoner"},
		{"fuser", Supply{Type: 15}, "fuserkit"},
		{"fuser oil is part of the fuser kit", Supply{Type: 11}, "fuserkit"},
		{"transfer unit", Supply{Type: 20}, "transferkit"},
		{"waste transfer belongs with the transfer kit", Supply{Type: 25}, "transferkit"},
		{"cleaner unit", Supply{Type: 18}, "cleaningkit"},
		{"developer", Supply{Type: 10}, "developer"},
		{"stapler", Supply{Type: 28}, "staples"},

		// A mono printer's toner has no colorant. "toner" alone is not one of
		// GLPI's tags, so it has to land somewhere it can be labelled.
		{"uncoloured toner defaults to black", Supply{Type: 3, Description: "Toner Cartridge"}, "tonerblack"},

		// Typed other(1)/unknown(2): the description is all there is.
		{"other typed, described as drum", Supply{Type: 1, Description: "Drum Unit DK-8360"}, "drumblack"},
		{"other typed, described as maintenance kit", Supply{Type: 1, Description: "Maintenance Kit MK-8360"}, "maintenancekit"},
		{"other typed, described as waste", Supply{Type: 2, Description: "Waste Toner Box"}, "wastetoner"},

		// "waste toner bottle" contains "toner" — the specific word has to win,
		// or a waste bin is reported as the black toner level and someone reads
		// a nearly-full bin as a nearly-full cartridge.
		{"waste beats toner in a description", Supply{Type: 1, Description: "Waste Toner Bottle"}, "wastetoner"},

		// Colour parsed out of the description when there is no colorant table,
		// which is how small inkjets report.
		{"colour from description", Supply{Type: 6, Description: "Cyan Ink LC427XLC"}, "cartridgecyan"},
		{"light cyan is not cyan", Supply{Type: 3, Colorant: "light cyan"}, "tonercyanlight"},
		{"light magenta is not magenta", Supply{Type: 3, Colorant: "light magenta"}, "tonermagentalight"},
		{"grey spelled the other way", Supply{Type: 3, Colorant: "gray"}, "tonergrey"},

		// Nothing sensible to map onto is better than a wrong tag.
		{"unmappable type", Supply{Type: 16}, ""},
		{"other typed with a useless description", Supply{Type: 1, Description: "Assembly 42"}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.supply.Tag(); got != tc.want {
				t.Errorf("Tag() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCartridges(t *testing.T) {
	supplies := []Supply{
		{Index: 1, Type: 3, Colorant: "black", Level: 7400, MaxCapacity: 10000, Unit: 13},
		{Index: 2, Type: 3, Colorant: "yellow", Level: 300, MaxCapacity: 10000, Unit: 13},
		// Unreadable: must not appear at all.
		{Index: 3, Type: 4, Level: levelUnknown, MaxCapacity: -2},
		{Index: 4, Type: 15, Level: levelSomeRemaining, MaxCapacity: 300000},
		// Unmappable: must not appear either.
		{Index: 5, Type: 16, Level: 50, MaxCapacity: 100, Unit: unitPercent},
	}

	got := Cartridges(supplies)

	want := map[string]int{"tonerblack": 74, "toneryellow": 3}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
	if _, ok := got["wastetoner"]; ok {
		t.Error("a supply with an unknown level was reported anyway")
	}
	if _, ok := got["fuserkit"]; ok {
		t.Error("a someRemaining supply was reported as a number")
	}
}

// TestCartridgesKeepsTheLowest: devices report two rows for one colour — a
// cartridge and its integrated drum, or two print engines. Whichever needs
// attention first is the one worth surfacing.
func TestCartridgesKeepsTheLowest(t *testing.T) {
	got := Cartridges([]Supply{
		{Index: 1, Type: 3, Colorant: "black", Level: 80, MaxCapacity: 100, Unit: unitPercent},
		{Index: 2, Type: 3, Colorant: "black", Level: 12, MaxCapacity: 100, Unit: unitPercent},
	})

	if got["tonerblack"] != 12 {
		t.Errorf("tonerblack = %d, want 12", got["tonerblack"])
	}
}

func TestCartridgesEmpty(t *testing.T) {
	if got := Cartridges(nil); got != nil {
		t.Errorf("Cartridges(nil) = %v, want nil", got)
	}
	// Everything unreadable is the same as nothing: no cartridges key at all,
	// rather than an empty object GLPI would have to interpret.
	if got := Cartridges([]Supply{{Type: 3, Level: levelUnknown}}); got != nil {
		t.Errorf("all-unreadable = %v, want nil", got)
	}
}

func TestIsWasteReceptacle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		supply Supply
		want   bool
	}{
		{"by class", Supply{Class: classReceptacle, Type: 3}, true},
		{"by type", Supply{Class: classConsumed, Type: 4}, true},
		{"ordinary toner", Supply{Class: classConsumed, Type: 3}, false},
		{"drum", Supply{Class: classConsumed, Type: 9}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.supply.IsWasteReceptacle(); got != tc.want {
				t.Errorf("IsWasteReceptacle() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseTableKey(t *testing.T) {
	for _, tc := range []struct {
		suffix string
		want   tableKey
		ok     bool
	}{
		{"1.4", tableKey{device: 1, index: 4}, true},
		{"2.11", tableKey{device: 2, index: 11}, true},
		{"7", tableKey{device: 0, index: 7}, true},
		{"", tableKey{}, false},
		{"1.2.3", tableKey{}, false},
		{"a.b", tableKey{}, false},
	} {
		t.Run(tc.suffix, func(t *testing.T) {
			got, ok := parseTableKey(tc.suffix)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("key = %+v, want %+v", got, tc.want)
			}
		})
	}
}
