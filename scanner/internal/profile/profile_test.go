// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package profile

import "testing"

// A string prefix is not an OID prefix: enterprise 9 (Cisco) and 91 are
// unrelated vendors, and strings.HasPrefix would match one against the other.
func TestPrefixMatchIsArcWise(t *testing.T) {
	cases := []struct {
		oid, prefix string
		want        bool
	}{
		{"1.3.6.1.4.1.9.1.500", "1.3.6.1.4.1.9.1", true},
		{"1.3.6.1.4.1.9.1", "1.3.6.1.4.1.9.1", true},
		{"1.3.6.1.4.1.91.1", "1.3.6.1.4.1.9", false},
		{"1.3.6.1.4.1.9", "1.3.6.1.4.1.9.1", false},
		{".1.3.6.1.4.1.9.1.500", "1.3.6.1.4.1.9.1.", true},
	}

	for _, c := range cases {
		if got := prefixMatch(c.oid, c.prefix); got != c.want {
			t.Errorf("prefixMatch(%q, %q) = %v, want %v", c.oid, c.prefix, got, c.want)
		}
	}
}

func TestProfileWithNoMatchRulesAppliesToEverything(t *testing.T) {
	p := Profile{Name: "base"}
	if !p.Applies("1.3.6.1.4.1.9.1.1", "anything") {
		t.Fatal("base profile should apply to every device")
	}
}

// An unparseable regex must narrow to nothing, never widen: a profile the
// operator believed was scoped must not start applying everywhere.
func TestInvalidRegexDoesNotWidenMatch(t *testing.T) {
	p := Profile{Match: Match{SysDescrRegex: "([unclosed"}}
	if p.Applies("1.3.6.1.4.1.9", "some device") {
		t.Fatal("a profile with a broken regex must not match")
	}
}

func TestResolveLayersByPriority(t *testing.T) {
	profiles := []Profile{
		{Name: "vendor", Priority: 10, Device: map[string]string{"serial": "1.2.3"}},
		{Name: "base", Priority: 0, Device: map[string]string{"serial": "9.9.9", "name": "1.1.1"}},
	}

	got := Resolve(profiles, "1.3.6.1.4.1.9", "x")

	if got.Device["serial"] != "1.2.3" {
		t.Errorf("higher priority should win, got %q", got.Device["serial"])
	}
	if got.Device["name"] != "1.1.1" {
		t.Errorf("base field should survive, got %q", got.Device["name"])
	}
	if len(got.Applied) != 2 || got.Applied[0] != "base" {
		t.Errorf("expected base applied first, got %v", got.Applied)
	}
}

// An empty OID deletes rather than sets — the only way a vendor profile can
// suppress a base OID that a device answers wrongly.
func TestEmptyValueSuppressesInheritedOid(t *testing.T) {
	profiles := []Profile{
		{Name: "base", Priority: 0, Device: map[string]string{"serial": "9.9.9"}},
		{Name: "vendor", Priority: 10, Device: map[string]string{"serial": ""}},
	}

	got := Resolve(profiles, "1.3.6.1.4.1.9", "x")
	if _, present := got.Device["serial"]; present {
		t.Fatalf("empty value should delete the field, got %q", got.Device["serial"])
	}
}

func TestNonMatchingProfileIsSkipped(t *testing.T) {
	profiles := []Profile{
		{Name: "base", Priority: 0, Device: map[string]string{"serial": "9.9.9"}},
		{
			Name:     "cisco",
			Priority: 10,
			Match:    Match{SysObjectIDPrefix: []string{"1.3.6.1.4.1.9"}},
			Device:   map[string]string{"serial": "1.2.3"},
		},
	}

	got := Resolve(profiles, "1.3.6.1.4.1.2011", "huawei")
	if got.Device["serial"] != "9.9.9" {
		t.Errorf("non-matching vendor profile must not apply, got %q", got.Device["serial"])
	}
}
