// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package collect

import (
	"strings"
	"testing"

	"github.com/bijstaan/glpi-netscan/internal/profile"
)

func TestResolveControlBuiltin(t *testing.T) {
	var none profile.Resolved

	oid, value, err := ResolveControl(none, "port_admin", "down")
	if err != nil {
		t.Fatalf("port_admin/down: %v", err)
	}
	if oid != oidIfAdminStatus {
		t.Errorf("oid = %q, want ifAdminStatus", oid)
	}
	if value != 2 {
		t.Errorf("down = %d, want 2", value)
	}

	if _, v, err := ResolveControl(none, "port_admin", "up"); err != nil || v != 1 {
		t.Errorf("up = %d (%v), want 1", v, err)
	}
}

// TestResolveControlRefusesUnknown: this is the one code path in the scanner
// that changes the world, and the only safe answer to "I am not sure what you
// meant" is to do nothing at all.
func TestResolveControlRefusesUnknown(t *testing.T) {
	var none profile.Resolved

	if _, _, err := ResolveControl(none, "reboot_everything", "now"); err == nil {
		t.Error("an unknown action resolved instead of failing")
	}
	if _, _, err := ResolveControl(none, "port_admin", "sideways"); err == nil {
		t.Error("an unknown value resolved instead of failing")
	}
	// An empty value must not fall through to some zero-valued default: writing
	// 0 to ifAdminStatus is not "no change", it is an invalid write.
	if _, _, err := ResolveControl(none, "port_admin", ""); err == nil {
		t.Error("an empty value resolved instead of failing")
	}
}

func TestResolveControlProfileOverride(t *testing.T) {
	resolved := profile.Resolved{Control: map[string]string{
		"outlet_power": "1.3.6.1.4.1.318.1.1.26.9.2.4.1.5 on=1,off=2,cycle=3",
		// A vendor that spells ifAdminStatus differently, or means something
		// else by "down", overrides the built-in rather than fighting it.
		"port_admin": "1.3.6.1.4.1.9.9.99.1 up=2,down=7",
	}}

	oid, value, err := ResolveControl(resolved, "outlet_power", "cycle")
	if err != nil || oid != "1.3.6.1.4.1.318.1.1.26.9.2.4.1.5" || value != 3 {
		t.Errorf("outlet cycle = %q/%d (%v)", oid, value, err)
	}

	oid, value, err = ResolveControl(resolved, "port_admin", "down")
	if err != nil || oid != "1.3.6.1.4.1.9.9.99.1" || value != 7 {
		t.Errorf("overridden port_admin = %q/%d (%v)", oid, value, err)
	}
}

func TestParseControlRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"",
		"1.3.6.1.2.1.2.2.1.7",            // an OID with no values
		"1.3.6.1.2.1.2.2.1.7 up",         // a value with no number
		"1.3.6.1.2.1.2.2.1.7 up=notanum", // a number that is not one
		" ",
	} {
		if _, err := parseControl(raw); err == nil {
			t.Errorf("parseControl(%q) succeeded, want an error", raw)
		}
	}
}

// TestControlOID guards the string that decides which port gets shut. It
// arrives over the wire, so it is validated rather than pasted in.
func TestControlOID(t *testing.T) {
	got, err := ControlOID("1.3.6.1.2.1.2.2.1.7", "3")
	if err != nil || got != "1.3.6.1.2.1.2.2.1.7.3" {
		t.Errorf("got %q (%v)", got, err)
	}

	// A two-part index, as PoE and outlet tables use.
	if got, err := ControlOID("1.3.6.1.2.1.105.1.1.1.3", "1.7"); err != nil ||
		got != "1.3.6.1.2.1.105.1.1.1.3.1.7" {
		t.Errorf("two-part index = %q (%v)", got, err)
	}

	for _, bad := range []string{"", "..", "3; drop", "1.2.x", "-1"} {
		if _, err := ControlOID("1.3.6.1.2.1.2.2.1.7", bad); err == nil {
			t.Errorf("index %q was accepted", bad)
		}
	}
}

func TestBuiltinControlsAreMinimal(t *testing.T) {
	// Only standard, unambiguous writes are built in. Anything vendor-specific
	// belongs in a profile, because those are the ones where a wrong OID or a
	// wrong index does not fail — it switches off something else.
	if len(builtinControls) != 1 {
		t.Errorf("built-in controls = %d, want only the standard one", len(builtinControls))
	}
	spec, ok := builtinControls["port_admin"]
	if !ok {
		t.Fatal("port_admin is not built in")
	}
	if !strings.HasPrefix(spec.OID, "1.3.6.1.2.1.") {
		t.Errorf("the built-in control is not a standard MIB OID: %s", spec.OID)
	}
}
