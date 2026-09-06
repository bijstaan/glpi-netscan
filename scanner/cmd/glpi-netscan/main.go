// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Command glpi-netscan is a lightweight SNMP network scanner for GLPI.
//
// It holds no OID knowledge and no scan policy of its own: ranges, credentials
// and OID profiles all arrive from the GLPI plugin at job time. That is what
// keeps the thing configurable from the web interface and what lets new
// device-specific OIDs ship without touching the binary.
//
// Two modes:
//
//	glpi-netscan -once -target 10.0.0.1 -profiles base.json -community public
//	glpi-netscan -config /etc/glpi-netscan/agent.conf
//
// The first is a local diagnostic that talks to no server; the second is the
// service, which enrolls with GLPI and then polls for work.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bijstaan/glpi-netscan/internal/client"
	"github.com/bijstaan/glpi-netscan/internal/collect"
	"github.com/bijstaan/glpi-netscan/internal/config"
	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/profile"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
	"github.com/bijstaan/glpi-netscan/internal/sweep"
	"github.com/bijstaan/glpi-netscan/internal/updater"
	"github.com/bijstaan/glpi-netscan/internal/version"
)

func main() {
	// `install` is a subcommand rather than a flag because it is the first
	// thing anyone runs and the one line they paste from GLPI: it writes the
	// configuration and enrolls in one step, so a wrong URL or a revoked
	// secret fails immediately and visibly rather than at the next service
	// start.
	if len(os.Args) > 1 {
		// `msi-install` and `msi-uninstall` are what the Windows installer
		// calls. They exist as subcommands rather than as installer custom
		// actions because an MSI cannot express most of what they do, and
		// because logic in the binary can be tested.
		if run, ok := subcommands[os.Args[1]]; ok {
			if err := run(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "%s failed: %v\n", os.Args[1], err)
				os.Exit(1)
			}
			return
		}
	}

	var (
		once     = flag.Bool("once", false, "scan a single target and print the payload, without contacting GLPI")
		target   = flag.String("target", "", "host to scan in -once mode")
		profiles = flag.String("profiles", "", "JSON file holding an array of OID profiles (-once mode)")

		snmpVersion = flag.String("snmp-version", "2c", "SNMP version: 1, 2c or 3")
		community   = flag.String("community", "public", "community string for v1/v2c")
		v3User      = flag.String("v3-user", "", "SNMPv3 username")
		v3Auth      = flag.String("v3-auth", "", "SNMPv3 auth protocol (MD5, SHA, SHA-256, SHA-512…)")
		v3AuthPass  = flag.String("v3-auth-pass", "", "SNMPv3 auth passphrase")
		v3Priv      = flag.String("v3-priv", "", "SNMPv3 privacy protocol (DES, AES, AES-256…)")
		v3PrivPass  = flag.String("v3-priv-pass", "", "SNMPv3 privacy passphrase")

		port    = flag.Uint("port", 161, "SNMP port")
		timeout = flag.Duration("timeout", 2*time.Second, "per-request timeout")
		retries = flag.Int("retries", 1, "retries per request")

		configPath = flag.String("config", config.DefaultPath(), "agent configuration file")
		insecure   = flag.Bool("insecure", false, "skip TLS verification (development only)")

		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	if !*once {
		if err := runAgent(*configPath, *insecure); err != nil && !errors.Is(err, errRestartForUpdate) {
			fmt.Fprintf(os.Stderr, "agent: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "-target is required with -once")
		os.Exit(2)
	}

	loaded, err := loadProfiles(*profiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profiles: %v\n", err)
		os.Exit(1)
	}

	cred := snmpx.Credential{
		Version:        *snmpVersion,
		Community:      *community,
		Username:       *v3User,
		AuthProtocol:   *v3Auth,
		AuthPassphrase: *v3AuthPass,
		PrivProtocol:   *v3Priv,
		PrivPassphrase: *v3PrivPass,
	}

	invs, err := ScanOne(*target, cred, loaded, snmpx.Options{
		Port:    uint16(*port),
		Timeout: *timeout,
		Retries: *retries,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan %s: %v\n", *target, err)
		os.Exit(1)
	}

	// Always an array, even for a single device. One address can produce several
	// assets — a wireless controller reports every access point behind it — and
	// this output exists to show exactly what would be submitted. A shape that
	// differed from the real submission is how printer supply levels came to
	// look correct here while being absent from every actual scan.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(invs); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}

// ScanOne probes a host and performs a full inventory walk.
//
// The assembly itself lives in sweep.Inventory, which is what the agent's own
// scans use. Sharing it is the point: this path exists so an operator can see
// exactly what the scanner would submit, and a diagnostic that builds its
// payload differently from the real thing is worse than no diagnostic at all.
func ScanOne(
	host string,
	cred snmpx.Credential,
	profiles []profile.Profile,
	opts snmpx.Options,
) ([]payload.Inventory, error) {
	sess, err := snmpx.Dial(host, cred, opts)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	ident, err := collect.Probe(sess)
	if err != nil {
		return nil, err
	}

	return sweep.Inventory(sess, ident, host, profiles)
}

// DeviceID is the stable identity GLPI keys the asset on. See sweep.DeviceID.
func DeviceID(host string, ident collect.Identity) string {
	return sweep.DeviceID(host, ident)
}

func loadProfiles(path string) ([]profile.Profile, error) {
	if path == "" {
		return nil, fmt.Errorf("-profiles is required with -once (the scanner ships no OIDs of its own)")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Accept either a bare profile object or an array of them, so a single
	// vendor profile can be tested without wrapping it.
	var many []profile.Profile
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}

	var one profile.Profile
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []profile.Profile{one}, nil
}

// --- server mode -------------------------------------------------------------

// runAgent enrolls if needed, then polls GLPI for work until interrupted.
func runAgent(configPath string, insecureOverride bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// The rollback guard, on the platforms where it lives inside the binary.
	// A no-op on Linux, where systemd runs preflight.sh before we are started —
	// running it twice would double-count the attempt and revert a healthy
	// version after half the intended number of failed starts.
	if runPreflight(cfg.StateDir, cfg.InstallRoot) {
		// `current` now points at the previous version, so this process is the
		// one just rolled back from. Exiting lets the service manager start the
		// restored version instead.
		return errRestartForUpdate
	}
	if insecureOverride {
		cfg.Insecure = true
	}

	api, err := client.New(client.Config{
		BaseURL:  cfg.Server,
		CAFile:   cfg.CAFile,
		Insecure: cfg.Insecure,
	})
	if err != nil {
		return err
	}

	if cfg.Insecure {
		log.Println("WARNING: TLS verification disabled; SNMP credentials will be accepted from an unverified server")
	}

	api.Token = cfg.LoadToken()
	if api.Token == "" {
		// A failed first enrolment is logged, not fatal. The poll loop below
		// presents an empty token, the server answers scanner_invalid, and the
		// existing re-enrolment path retries every interval — so a GLPI that is
		// briefly unreachable costs a poll rather than the machine.
		//
		// That matters most for mass deployment: an MSI rollout enrols hundreds
		// of hosts at once, and exiting here would turn a five-minute outage
		// into hundreds of scanners that never come up until someone visits
		// each one.
		if err := enrol(api, cfg); err != nil {
			log.Printf("initial enrollment failed, will retry: %v", err)
		}
	}

	up := updater.New(cfg, api)

	// Notification listening is reconciled on every poll; see trapSupervisor.
	traps := newTrapSupervisor(api)

	// A scanner that has just restarted onto a staged version polls sooner than
	// usual, because that first successful poll is what clears the rollback
	// marker. Waiting a full interval would leave a perfectly good version one
	// failed start away from being rolled back for no reason.
	interval := 60 * time.Second
	if up.Pending() {
		interval = 10 * time.Second
	}

	// Wrapped by the host layer so the same loop runs under systemd and under
	// the Windows service control manager, which needs its start and stop
	// handshakes answered or it kills the service as unresponsive.
	return hostServe(func(ctx context.Context) error {
		defer traps.stop()
		return pollLoop(ctx, cfg, api, up, traps, interval)
	})
}

func pollLoop(
	ctx context.Context,
	cfg config.Config,
	api *client.Client,
	up *updater.Updater,
	traps *trapSupervisor,
	interval time.Duration,
) error {
	for {
		next, offer, err := poll(ctx, api, traps)
		switch {
		case errors.Is(err, client.ErrScannerInvalid):
			// Revoked or deleted server-side. Discard the token and enroll
			// again rather than retrying a credential that will never work.
			log.Println("server rejected our token; re-enrolling")
			if clearErr := cfg.ClearToken(); clearErr != nil {
				log.Printf("could not clear token: %v", clearErr)
			}
			api.Token = ""
			if enrolErr := enrol(api, cfg); enrolErr != nil {
				log.Printf("re-enrollment failed: %v", enrolErr)
			}
		case err != nil:
			log.Printf("poll: %v", err)
		default:
			if next > 0 {
				interval = time.Duration(next) * time.Second
			}

			staged, updErr := up.Consider(offer)
			if updErr != nil {
				// A failed update is not a reason to stop scanning. The old
				// version is still running and still useful, and the offer will
				// be repeated on the next poll — so this is logged and the loop
				// continues rather than exiting and handing the machine to a
				// restart loop.
				log.Printf("update: %v", updErr)
			}
			if staged {
				log.Println("restarting to complete update")
				// Returning rather than calling os.Exit: under systemd an
				// abrupt exit skips the stop handshake and is reported as a
				// crash, which is both alarming and, with Restart=on-failure,
				// the only thing that would bring us back.
				return errRestartForUpdate
			}

			// Having reached the server on this version is the health signal a
			// staged update is waiting for. Skipped when this very poll staged
			// one: the marker then names the version we are about to restart
			// into rather than the one running, and confirming it would clear
			// the rollback guard before the new binary has proved anything.
			up.ConfirmHealthy()
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// isRestartForUpdate reports the deliberate-restart sentinel, so a service host
// can treat it as a clean stop rather than a crash.
func isRestartForUpdate(err error) bool { return errors.Is(err, errRestartForUpdate) }

// errRestartForUpdate unwinds runAgent after an update has been activated.
//
// A distinct value rather than a plain nil return so main can exit 0 — a clean,
// expected restart — while still telling the two apart in the log.
var errRestartForUpdate = errors.New("restarting onto a staged update")

func enrol(api *client.Client, cfg config.Config) error {
	if cfg.EnrollSecret == "" {
		return errors.New("no token stored and enroll_secret is not set")
	}

	hostname := cfg.Name
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	res, err := api.Enroll(client.EnrollRequest{
		EnrollSecret: cfg.EnrollSecret,
		Hostname:     hostname,
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		AgentVersion: version.Version,
	})
	if err != nil {
		return err
	}

	api.Token = res.ScannerToken
	if err := cfg.SaveToken(res.ScannerToken); err != nil {
		return fmt.Errorf("save token: %w", err)
	}

	log.Printf("enrolled as scanner %d", res.ScannerID)
	return nil
}

// poll fetches work, runs it, and reports. Returns the server's requested
// interval before the next poll and whatever it said about our version.
func poll(ctx context.Context, api *client.Client, traps *trapSupervisor) (int, *client.UpdateOffer, error) {
	res, err := api.Jobs(version.Version, updater.Platform(), updater.Arch())
	if err != nil {
		return 0, nil, err
	}

	// Trap policy first: it is cheap, and a scanner that has just been told to
	// stop listening should stop before it does anything else.
	traps.apply(res.Traps)

	// Queued device writes, before the sweep. An operator who has just asked
	// for a port to be shut is waiting on it; a full sweep first would make
	// that wait as long as the sweep.
	runControls(api, res.Actions, res.Profiles)

	for _, job := range res.Jobs {
		if err := runJob(ctx, api, job, res.Profiles); err != nil {
			log.Printf("job %d (%s): %v", job.JobID, job.TargetName, err)
		}
		if ctx.Err() != nil {
			break
		}
	}

	return res.PollInterval, &res.Update, nil
}

func runJob(ctx context.Context, api *client.Client, job client.Job, profiles []profile.Profile) error {
	addrs, err := sweep.ExpandRanges(job.Ranges, sweep.MaxHosts)
	if err != nil {
		// Report the failure rather than swallowing it, so the run row in GLPI
		// shows why a target produced nothing.
		_, _ = api.Report(client.ReportRequest{
			JobID:   job.JobID,
			Failed:  1,
			Message: err.Error(),
		})
		return err
	}

	timeout := time.Duration(job.Options.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	opts := sweep.Options{
		Port:        uint16(job.Options.Port),
		Timeout:     timeout,
		Retries:     job.Options.Retries,
		Concurrency: job.Options.Concurrency,
	}

	// --- discovery ---------------------------------------------------------
	// One GET per address. A full walk costs 86-157x this even against a local
	// simulator, so every address in the range can be visited on a short
	// interval as long as most of them stop here.
	started := time.Now()
	found := sweep.Discover(ctx, addrs, job.Credentials, profiles, opts)
	discoveryTook := time.Since(started)

	discovery, err := api.Report(client.ReportRequest{
		Phase:      "discovery",
		JobID:      job.JobID,
		Discovered: found.Discovered,
		Failed:     found.Failed,
		Message: fmt.Sprintf("%d addresses probed in %s; %d answered",
			len(addrs), discoveryTook.Round(time.Millisecond), found.Discovered),
		Payloads: found.Payloads,
	})
	if err != nil {
		return err
	}

	// --- inventory ---------------------------------------------------------
	// Only what the server asked for. A nil list means an older plugin that
	// does not know about the split, and everything found is walked — the
	// behaviour before this existed.
	wanted := discovery.InventoryWanted
	if wanted == nil {
		wanted = make([]string, 0, len(found.Found))
		for deviceID := range found.Found {
			wanted = append(wanted, deviceID)
		}
	}

	if len(wanted) > 0 {
		inventoryStarted := time.Now()
		walked := sweep.InventoryThese(ctx, wanted, found.Found, profiles, opts)

		message := fmt.Sprintf(
			"%d addresses probed in %s; %d answered; %d walked in %s",
			len(addrs), discoveryTook.Round(time.Millisecond), found.Discovered,
			walked.Inventoried, time.Since(inventoryStarted).Round(time.Millisecond),
		)
		if len(walked.Errors) > 0 {
			message += "; " + walked.Errors[0]
		} else if len(found.Errors) > 0 {
			message += "; " + found.Errors[0]
		}

		report, err := api.Report(client.ReportRequest{
			Phase:       "inventory",
			JobID:       job.JobID,
			Discovered:  found.Discovered,
			Inventoried: walked.Inventoried,
			Failed:      found.Failed + walked.Failed,
			Message:     message,
			Payloads:    walked.Payloads,
		})
		if err != nil {
			return err
		}

		logReport(job, len(addrs), discoveryTook, time.Since(inventoryStarted), found, walked, report)

		return nil
	}

	logReport(job, len(addrs), discoveryTook, 0, found, sweep.Result{}, discovery)

	return nil
}

// logReport prints one line an operator can read the split off.
//
// Both halves are shown because the interesting number is the ratio: a sweep
// that probes 254 addresses and walks two of them is the split working, and a
// sweep that walks everything it finds every time is a sign the interval or the
// change markers are not doing their job.
func logReport(
	job client.Job,
	addrs int,
	probing, walking time.Duration,
	found, walked sweep.Result,
	report *client.ReportResponse,
) {
	log.Printf(
		"job %d (%s): probed %d in %s, answered %d, walked %d in %s, accepted %d, rejected %d",
		job.JobID, job.TargetName, addrs, probing.Round(time.Millisecond),
		found.Discovered, walked.Inventoried, walking.Round(time.Millisecond),
		report.Accepted, report.Rejected,
	)
	for _, r := range report.Results {
		if !r.OK {
			log.Printf("  rejected %s: %v", r.DeviceID, r.Errors)
		}
	}
}

// runInstall writes the configuration and enrolls, so the service has
// everything it needs before it first starts.
//
// This is what the GLPI settings page hands an operator as a single pasteable
// line. Enrolling here rather than deferring to the service means the failure
// modes people actually hit — wrong URL, revoked secret, untrusted certificate
// — surface at the terminal they ran it from.
func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	server := fs.String("server", "", "GLPI base URL, e.g. https://glpi.example.com")
	secret := fs.String("secret", "", "enrollment secret from Setup > Network scanning")
	caCert := fs.String("ca-cert", "", "PEM bundle for a private certificate authority")
	name := fs.String("name", "", "name shown in GLPI (defaults to the system hostname)")
	confPath := fs.String("config", config.DefaultPath(), "where to write the configuration")
	insecure := fs.Bool("insecure", false, "skip TLS verification (development only)")
	installRoot := fs.String("install-root", config.DefaultInstallRoot(), "versioned install tree used by self-update")
	noUpdates := fs.Bool("no-updates", false, "pin this host to the installed version, whatever GLPI offers")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *server == "" || *secret == "" {
		return errors.New("--server and --secret are required")
	}

	cfg := config.Config{
		Server:       strings.TrimSuffix(*server, "/"),
		EnrollSecret: *secret,
		CAFile:       *caCert,
		Name:         *name,
		Insecure:     *insecure,
		StateDir:     config.DefaultStateDir(),
		InstallRoot:  *installRoot,
		// Set explicitly, not left at the zero value: Save() records the flag
		// only when it is off, so a zero-valued struct here would write
		// `updates_enabled = false` into every config this command produces and
		// pin the whole fleet — the exact opposite of the documented default.
		UpdatesEnabled: !*noUpdates,
	}

	if err := config.Save(*confPath, cfg); err != nil {
		return fmt.Errorf("write %s: %w", *confPath, err)
	}

	// Reload so the enrolment runs against exactly what the service will read,
	// rather than against the in-memory struct we happen to hold.
	loaded, err := config.Load(*confPath)
	if err != nil {
		return err
	}

	api, err := client.New(client.Config{
		BaseURL:  loaded.Server,
		CAFile:   loaded.CAFile,
		Insecure: loaded.Insecure,
	})
	if err != nil {
		return err
	}

	if err := enrol(api, loaded); err != nil {
		return err
	}

	fmt.Printf("enrolled successfully; configuration written to %s\n", *confPath)
	fmt.Println("start the service with: systemctl enable --now glpi-netscan")

	return nil
}
