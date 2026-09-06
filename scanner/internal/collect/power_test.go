// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"math"
	"testing"
)

// Power MIBs report tenths of a volt/amp/hertz, and the factor differs per
// vendor for the same logical field — so it travels in the profile next to the
// OID rather than being hard-coded.
func TestSplitScale(t *testing.T) {
	cases := []struct {
		spec      string
		wantOID   string
		wantScale float64
	}{
		{"1.3.6.1.2.1.33.1.2.5.0*0.1", "1.3.6.1.2.1.33.1.2.5.0", 0.1},
		{"1.3.6.1.2.1.33.1.2.5.0", "1.3.6.1.2.1.33.1.2.5.0", 1},
		{" 1.2.3 * 0.01 ", "1.2.3", 0.01},
		// A malformed factor must not silently zero the reading.
		{"1.2.3*abc", "1.2.3", 1},
		{"1.2.3*0", "1.2.3", 1},
	}

	for _, c := range cases {
		oid, scale := splitScale(c.spec)
		if oid != c.wantOID || scale != c.wantScale {
			t.Errorf("splitScale(%q) = (%q, %v), want (%q, %v)",
				c.spec, oid, scale, c.wantOID, c.wantScale)
		}
	}
}

// entPhySensorScale is an SI magnitude in which units(9) is 10^0, so the
// exponent is (value-9)*3.
func TestSensorScaleFactor(t *testing.T) {
	cases := map[int]float64{
		9:  1,    // units
		10: 1e3,  // kilo
		11: 1e6,  // mega
		8:  1e-3, // milli
		7:  1e-6, // micro
		0:  1,    // out of range, treated as unscaled
		99: 1,    // out of range
	}
	for in, want := range cases {
		if got := sensorScaleFactor(in); math.Abs(got-want) > want*1e-9 {
			t.Errorf("sensorScaleFactor(%d) = %v, want %v", in, got, want)
		}
	}
}

// The alarm table's value is an OID naming the condition; the MIB carries no
// human text for it. These were verified against UPS-MIB, not recalled.
func TestAlarmName(t *testing.T) {
	cases := map[string]string{
		"1.3.6.1.2.1.33.1.6.3.1":  "battery bad",
		"1.3.6.1.2.1.33.1.6.3.2":  "on battery",
		"1.3.6.1.2.1.33.1.6.3.6":  "input bad",
		"1.3.6.1.2.1.33.1.6.3.7":  "output bad",
		"1.3.6.1.2.1.33.1.6.3.11": "output off as requested",
		"1.3.6.1.2.1.33.1.6.3.23": "shutdown imminent",
	}
	for oid, want := range cases {
		if got := alarmName(oid); got != want {
			t.Errorf("alarmName(%s) = %q, want %q", oid, got, want)
		}
	}
	// An unknown alarm OID is passed through rather than dropped: an operator
	// can still look it up, whereas a silent omission hides a live condition.
	if got := alarmName("1.3.6.1.4.1.318.99"); got != "1.3.6.1.4.1.318.99" {
		t.Errorf("unknown alarm should pass through, got %q", got)
	}
}

func TestBatteryStatusName(t *testing.T) {
	for in, want := range map[int]string{1: "unknown", 2: "normal", 3: "low", 4: "depleted", 9: ""} {
		if got := batteryStatusName(in); got != want {
			t.Errorf("batteryStatusName(%d) = %q, want %q", in, got, want)
		}
	}
}

// "battery" is the operationally important value: the UPS is carrying the load.
func TestOutputSourceName(t *testing.T) {
	for in, want := range map[int]string{3: "normal", 4: "bypass", 5: "battery", 99: ""} {
		if got := outputSourceName(in); got != want {
			t.Errorf("outputSourceName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestOutletStateName(t *testing.T) {
	for in, want := range map[int]string{1: "on", 2: "off", 0: "unknown", 7: "unknown"} {
		if got := outletStateName(in); got != want {
			t.Errorf("outletStateName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestRounding(t *testing.T) {
	// 546 decivolts must render as 54.6, not 54.60000000000001.
	if got := round1(546 * 0.1); got != 54.6 {
		t.Errorf("round1 = %v", got)
	}
	if got := round2(22.34999); got != 22.35 {
		t.Errorf("round2 = %v", got)
	}
}
