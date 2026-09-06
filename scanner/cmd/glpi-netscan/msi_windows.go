// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bijstaan/glpi-netscan/internal/config"
	"github.com/bijstaan/glpi-netscan/internal/updater"
	"github.com/bijstaan/glpi-netscan/internal/version"
)

// The MSI's post-install and pre-uninstall work, as subcommands of the agent
// rather than as a pile of custom actions in the installer.
//
// An MSI cannot express most of what has to happen here — a directory junction,
// a service binary path that ServiceInstall refuses to let you override, service
// failure actions, an ACL grant, an enrolment, a conditional start. Doing it
// with installer primitives means six separate shell-outs whose only error
// reporting is an exit code, and which no test can reach.
//
// Doing it here means one custom action, ordinary error messages, and logic that
// is exercised by `go test` on any platform. It also keeps the MSI and
// install-windows.ps1 honest with each other, because both end up calling the
// same code rather than two hand-written approximations of it.

// msiInstall is `glpi-netscan msi-install`.
func msiInstall(args []string) error {
	fs := flag.NewFlagSet("msi-install", flag.ExitOnError)
	installRoot := fs.String("install-root", config.DefaultInstallRoot(), "versioned install tree")
	server := fs.String("server", "", "GLPI base URL; enrolment is skipped when empty")
	secret := fs.String("secret", "", "enrollment key; enrolment is skipped when empty")
	caCert := fs.String("ca-cert", "", "PEM bundle for a private certificate authority")
	name := fs.String("name", "", "name shown in GLPI")
	noUpdates := fs.Bool("no-updates", false, "pin this host to the installed version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root := strings.TrimRight(*installRoot, `\`)
	confPath := config.DefaultPath()
	stateDir := config.DefaultStateDir()

	// The version directory is named for what this binary reports, which is
	// also what the MSI was told to name it. If those ever disagree the
	// updater's comparisons go wrong in confusing ways, so it is checked here
	// where the message can say so plainly.
	versionDir := filepath.Join(root, "versions", version.Version)
	if _, err := os.Stat(versionDir); err != nil {
		return fmt.Errorf("expected this version at %s: %w", versionDir, err)
	}

	if err := updater.FlipCurrent(filepath.Join(root, "current"), versionDir); err != nil {
		return fmt.Errorf("create the current junction: %w", err)
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create the state directory: %w", err)
	}

	// LOCAL SERVICE must be able to write both trees or the scanner cannot
	// record its token and self-update cannot lay down a new version. Program
	// Files denies that by default, so it has to be granted explicitly, and
	// only on these two directories.
	for _, dir := range []string{root, filepath.Dir(stateDir)} {
		if err := grantLocalService(dir); err != nil {
			return fmt.Errorf("grant LOCAL SERVICE access to %s: %w", dir, err)
		}
	}

	// ServiceInstall takes the binary path from its component's key file, which
	// is the versioned one, and offers no way to override it. Left alone the
	// SCM would keep launching the version the MSI installed however many times
	// the scanner updated itself, so self-update would be silently inert on
	// every MSI-installed machine.
	binPath := fmt.Sprintf(`"%s" -config "%s"`, filepath.Join(root, "current", updater.BinaryName()), confPath)
	if err := sc("config", ServiceName, "binPath=", binPath); err != nil {
		return fmt.Errorf("point the service at the current junction: %w", err)
	}

	// Restart on failure, and — via failureflag — on a clean exit too. The
	// scanner stops deliberately after staging an update so it comes back on
	// the new version; without the flag the SCM treats that stop as final and
	// the update never completes.
	if err := sc("failure", ServiceName, "reset=", "86400",
		"actions=", "restart/15000/restart/15000/restart/30000"); err != nil {
		return fmt.Errorf("set the service failure actions: %w", err)
	}
	if err := sc("failureflag", ServiceName, "1"); err != nil {
		return fmt.Errorf("set the service failure flag: %w", err)
	}

	if *server == "" || *secret == "" {
		// Deliberately leaves the service registered, stopped and on demand.
		// A deployment that omitted the credentials should not produce a
		// machine restart-looping against a server it was never told about.
		fmt.Println("installed without credentials; enrol with `glpi-netscan install` and start the service")
		return nil
	}

	enrollArgs := []string{
		"--server", *server,
		"--secret", *secret,
		"--ca-cert", *caCert,
		"--name", *name,
		"--install-root", root,
		"--config", confPath,
	}
	if *noUpdates {
		enrollArgs = append(enrollArgs, "--no-updates")
	}

	// A failed enrolment is reported but not fatal. `install` writes the
	// configuration before it contacts GLPI, so a server that is briefly
	// unreachable during a rollout still leaves a machine that enrols itself on
	// a later poll. Failing here would turn a short outage into hundreds of
	// failed deployments needing manual repair.
	enrolled := true
	if err := runInstall(enrollArgs); err != nil {
		fmt.Fprintln(os.Stderr, "enrolment did not complete; the scanner will retry:", err)
		enrolled = false
	}

	if _, err := os.Stat(confPath); err != nil {
		if enrolled {
			return fmt.Errorf("no configuration at %s after enrolment", confPath)
		}
		return nil
	}

	if err := sc("config", ServiceName, "start=", "auto"); err != nil {
		return fmt.Errorf("enable the service: %w", err)
	}
	if err := sc("start", ServiceName); err != nil {
		// Already-running is not an error worth failing an install over.
		fmt.Fprintln(os.Stderr, "could not start the service:", err)
	}

	return nil
}

// msiUninstall is `glpi-netscan msi-uninstall`, run before the files go.
func msiUninstall(args []string) error {
	fs := flag.NewFlagSet("msi-uninstall", flag.ExitOnError)
	installRoot := fs.String("install-root", config.DefaultInstallRoot(), "versioned install tree")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Removed with os.Remove, never RemoveAll: the junction points at a real
	// directory, and following it would delete the thing it names rather than
	// the link. Windows removes a junction with the same call that removes an
	// empty directory.
	link := filepath.Join(strings.TrimRight(*installRoot, `\`), "current")
	if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the current junction: %w", err)
	}

	return nil
}

// grantLocalService gives NT AUTHORITY\LocalService modify rights on a tree.
//
// (OI)(CI) makes the grant inheritable by files and subdirectories, so versions
// created later by self-update are covered without re-running this.
func grantLocalService(dir string) error {
	return run("icacls", dir, "/grant", `*S-1-5-19:(OI)(CI)M`, "/T", "/C", "/Q")
}

// sc drives the service control manager.
//
// `sc config binPath= x` really is two arguments with the trailing space inside
// the first: sc.exe parses `name=` and its value separately, and `binPath=x`
// silently does nothing.
func sc(args ...string) error {
	return run("sc", args...)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
