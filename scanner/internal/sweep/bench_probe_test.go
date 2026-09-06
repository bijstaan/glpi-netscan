// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package sweep

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bijstaan/glpi-netscan/internal/collect"
	"github.com/bijstaan/glpi-netscan/internal/profile"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// TestBenchProbeVsFull sizes the discovery/inventory split against the
// SNMP simulators: how much more a full walk costs than a probe.
//
// Skipped unless PROFILES points at a profile set, because it needs those
// containers running. Kept because the ratio is the entire justification for
// the split, and it is the kind of number that quietly stops being true.
//
//	PROFILES=/path/to/profiles.json go test ./internal/sweep -run BenchProbeVsFull -v
func TestBenchProbeVsFull(t *testing.T) {
	profilesPath := os.Getenv("PROFILES")
	if profilesPath == "" {
		t.Skip("set PROFILES to a profile set, with the SNMP simulators running")
	}

	raw, _ := os.ReadFile(profilesPath)
	var profiles []profile.Profile
	json.Unmarshal(raw, &profiles)

	cred := snmpx.Credential{Version: "2c", Community: "public"}
	for _, t := range []struct {
		name string
		port uint16
	}{
		{"switch", 1162}, {"ups", 1163}, {"pdu", 1164}, {"phone", 1165},
		{"printer", 1166}, {"inkjet", 1167}, {"wlc", 1168}, {"unifi", 1169},
	} {
		opts := snmpx.Options{Port: t.port, Timeout: 2 * time.Second, Retries: 1}

		start := time.Now()
		sess, err := snmpx.Dial("127.0.0.1", cred, opts)
		if err != nil {
			fmt.Println(t.name, "dial:", err)
			continue
		}
		ident, err := collect.Probe(sess)
		probe := time.Since(start)
		if err != nil {
			fmt.Println(t.name, "probe:", err)
			sess.Close()
			continue
		}

		start = time.Now()
		invs, err := Inventory(sess, ident, "127.0.0.1", profiles)
		full := time.Since(start)
		sess.Close()
		if err != nil {
			fmt.Println(t.name, "inventory:", err)
			continue
		}

		ports := 0
		if len(invs) > 0 {
			ports = len(invs[0].Content.Ports)
		}
		fmt.Printf("  %-8s probe %6.1fms   full %7.1fms   %5.1fx   (%d ports, %d payloads)\n",
			t.name, float64(probe.Microseconds())/1000, float64(full.Microseconds())/1000,
			float64(full)/float64(probe), ports, len(invs))
	}
}
