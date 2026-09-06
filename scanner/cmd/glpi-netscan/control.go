// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bijstaan/glpi-netscan/internal/client"
	"github.com/bijstaan/glpi-netscan/internal/collect"
	"github.com/bijstaan/glpi-netscan/internal/profile"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// runControls performs the device writes GLPI has queued, and reports each one.
//
// This is the only code in the scanner that changes anything on a device, and
// it is deliberately short and deliberately unforgiving. Every failure path
// reports rather than retries: a control action that half worked, or that gets
// attempted twice because the first attempt's outcome was unclear, is worse
// than one that visibly did not happen.
//
// The credential comes down with the action rather than from the scanner's own
// configuration, and it is a different credential from the ones used to read —
// so a scanner that is only ever given read communities cannot write even if
// something asks it to.
func runControls(api *client.Client, actions []client.ControlAction, profiles []profile.Profile) {
	if len(actions) == 0 {
		return
	}

	results := make([]client.ControlResult, 0, len(actions))

	for _, action := range actions {
		result := client.ControlResult{ID: action.ID}

		if err := performControl(action, profiles); err != nil {
			result.OK = false
			result.Result = err.Error()
			log.Printf("control %d (%s): %v", action.ID, action.Label, err)
		} else {
			result.OK = true
			result.Result = "applied"
			log.Printf("control %d: %s", action.ID, action.Label)
		}

		results = append(results, result)
	}

	if err := api.ReportControl(results); err != nil {
		// The write already happened; only the reporting failed. Logged loudly
		// because GLPI will show the action as still in flight until the next
		// report, and an operator needs to know the difference between "not
		// done" and "done but not confirmed".
		log.Printf("control results not reported (the writes were performed): %v", err)
	}
}

// performControl resolves one action and writes it.
func performControl(action client.ControlAction, profiles []profile.Profile) error {
	timeout := time.Duration(action.Options.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	port := uint16(action.Options.Port)
	if port == 0 {
		port = 161
	}

	sess, err := snmpx.Dial(action.Address, action.Credential, snmpx.Options{
		Port:    port,
		Timeout: timeout,
		Retries: action.Options.Retries,
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer sess.Close()

	// Probed before writing. The action names an address, and an address can be
	// reassigned between the scan that discovered a device and the moment
	// someone clicks a button — so this confirms something is still there and
	// answering before anything is switched. It also gives the profile
	// resolution below the sysObjectID it needs.
	ident, err := collect.Probe(sess)
	if err != nil {
		return fmt.Errorf("no answer from %s: %w", action.Address, err)
	}

	resolved := profile.Resolve(profiles, ident.SysObjectID, ident.SysDescr)

	oid, value, err := collect.ResolveControl(resolved, action.Action, action.Value)
	if err != nil {
		return err
	}

	full, err := collect.ControlOID(oid, action.Index)
	if err != nil {
		return err
	}

	return sess.SetInt(full, value)
}
