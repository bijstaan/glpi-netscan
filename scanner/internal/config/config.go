// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package config loads the agent's configuration and persists its token.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the agent's on-disk configuration.
//
// Deliberately separate from the token: this file is the sort of thing config
// management writes and templates, while the token is machine state minted at
// enrollment. Keeping them apart means a config push cannot clobber a
// scanner's identity, and the token file can carry stricter permissions.
type Config struct {
	Server       string
	EnrollSecret string
	CAFile       string
	Insecure     bool
	StateDir     string
	Name         string

	// InstallRoot is the versioned install tree self-update writes into:
	// `versions/<version>/glpi-netscan` with a `current` symlink the service
	// unit starts from. Empty on a hand-dropped binary, which is why the
	// updater refuses to stage rather than improvising a swap.
	InstallRoot string

	// UpdatesEnabled lets an administrator refuse self-update on this host
	// whatever the server offers.
	//
	// Defaults to on, unlike the server-side switch which defaults to off. The
	// asymmetry is deliberate: the fleet-wide decision belongs to the operator
	// in GLPI, where it can be staged and reversed centrally, so nothing
	// happens until they turn it on there. This flag exists for the individual
	// machine that must be pinned — an appliance under change control, a
	// scanner mid-incident — and pinning is the exception, so it is the thing
	// you opt into.
	UpdatesEnabled bool
}

// Load reads a `key = value` file. Blank lines and `#` comments are ignored.
func Load(path string) (Config, error) {
	cfg := Config{
		StateDir:       DefaultStateDir(),
		InstallRoot:    DefaultInstallRoot(),
		UpdatesEnabled: true,
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		key, value, found := strings.Cut(text, "=")
		if !found {
			return cfg, fmt.Errorf("%s:%d: expected key = value", path, line)
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)

		switch key {
		case "server":
			cfg.Server = value
		case "enroll_secret":
			cfg.EnrollSecret = value
		case "ca_file":
			cfg.CAFile = value
		case "insecure":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return cfg, fmt.Errorf("%s:%d: insecure must be true or false", path, line)
			}
			cfg.Insecure = b
		case "state_dir":
			cfg.StateDir = value
		case "name":
			cfg.Name = value
		case "install_root":
			cfg.InstallRoot = value
		case "updates_enabled":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return cfg, fmt.Errorf("%s:%d: updates_enabled must be true or false", path, line)
			}
			cfg.UpdatesEnabled = b
		default:
			return cfg, fmt.Errorf("%s:%d: unknown key %q", path, line, key)
		}
	}

	if err := scanner.Err(); err != nil {
		return cfg, err
	}

	if cfg.Server == "" {
		return cfg, errors.New("server is required")
	}

	return cfg, nil
}

// TokenPath is the file holding this scanner's token.
func (c Config) TokenPath() string {
	return filepath.Join(c.StateDir, "scanner.token")
}

// LoadToken reads a previously saved token, returning "" when not enrolled.
func (c Config) LoadToken() string {
	raw, err := os.ReadFile(c.TokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// SaveToken persists the token with owner-only permissions.
//
// Written to a temporary file and renamed so that a crash mid-write cannot
// leave a truncated token, which would look like a revoked scanner and trigger
// a needless re-enroll.
func (c Config) SaveToken(token string) error {
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(c.StateDir, ".scanner.token.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	defer func() {
		// Best-effort cleanup if we failed before the rename.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, c.TokenPath())
}

// ClearToken forgets the stored token, forcing a re-enroll.
func (c Config) ClearToken() error {
	err := os.Remove(c.TokenPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Save writes a configuration file.
//
// Written with owner-only permissions and through a temporary file: it holds
// the enrollment secret, and a half-written config is indistinguishable from a
// corrupt one at the next start.
func Save(path string, cfg Config) error {
	dir := filepath.Dir(path)
	// 0750, matching what install-linux.sh creates: the file written into it
	// carries the enrollment secret, and only the scanner's own service account
	// has any business listing this directory.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# GLPI Netscan agent configuration.\n")
	b.WriteString("# Written by `glpi-netscan install`; safe to edit by hand.\n\n")
	fmt.Fprintf(&b, "server = %s\n", cfg.Server)
	if cfg.EnrollSecret != "" {
		fmt.Fprintf(&b, "enroll_secret = %s\n", cfg.EnrollSecret)
	}
	if cfg.CAFile != "" {
		fmt.Fprintf(&b, "ca_file = %s\n", cfg.CAFile)
	}
	if cfg.Name != "" {
		fmt.Fprintf(&b, "name = %s\n", cfg.Name)
	}
	// Always written, never elided when it happens to equal the default: the
	// default is environment-dependent, so a config that omits it can resolve
	// differently for the service than it did for `install` — which shows up
	// as the service failing to write its token somewhere it never chose.
	if cfg.StateDir != "" {
		fmt.Fprintf(&b, "state_dir = %s\n", cfg.StateDir)
	}
	if cfg.InstallRoot != "" {
		fmt.Fprintf(&b, "install_root = %s\n", cfg.InstallRoot)
	}
	// Written only when off, because off is not the default: a config that
	// silently pinned a scanner's version would be very hard to explain from
	// the server, where it looks like an update that never took.
	if !cfg.UpdatesEnabled {
		b.WriteString("updates_enabled = false\n")
	}
	if cfg.Insecure {
		b.WriteString("insecure = true\n")
	}

	tmp, err := os.CreateTemp(dir, ".agent.conf.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}
