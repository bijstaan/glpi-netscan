<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use Config;

/**
 * Plugin settings.
 */
final class Settings
{
    public const DEFAULTS = [
        // Reject scanner API calls that did not arrive over TLS. On by
        // default: the job response carries live SNMP credentials, so a
        // plaintext deployment hands community strings and v3 passphrases to
        // anyone on the path.
        'require_tls'      => 1,
        // Seconds between a scanner's job polls when it has nothing to do.
        'poll_interval'    => 60,
        // A scanner silent for longer than this is shown as stale.
        'stale_after'      => 900,
        // Accept inventory for addresses outside the target's declared ranges.
        // Off by default: a compromised scanner should not be able to rewrite
        // arbitrary assets by reporting on addresses nobody asked it to scan.
        'allow_off_target' => 0,
        // Record the discovered outlet count on the PDU via GLPI's Item_Plug.
        // The connector standard is not reported over SNMP, so the plug is
        // named neutrally rather than guessed.
        'record_outlet_count' => 1,
        // See setup.php: lets a switch's forwarding table resolve to a PDU
        // asset instead of an Unmanaged placeholder. Off by default because
        // asset_types is consulted widely across core.
        'pdu_in_asset_types' => 0,
        // Offer published packages to scanners at all. Off by default: turning
        // self-update on is a decision to let GLPI replace the binary running
        // on every scanner host, and that should be taken deliberately rather
        // than inherited from an upgrade.
        'update_enabled'  => 0,
        // Share of the fleet the current release has been rolled out to. Also
        // starts at 0, so enabling updates does not by itself move anything —
        // the two switches together are what makes "turn it on, then open the
        // tap" possible instead of one irreversible click.
        'rollout_percent' => 0,
        // Whether this instance may write to hardware at all. Off, and it stays
        // off through upgrades: installing a monitoring tool should never be
        // what makes an estate controllable. Even on, nothing can be controlled
        // until a target is given a write credential of its own.
        'allow_control' => 0,
        // Whether scanners listen for SNMP notifications. Off by default: it
        // opens a UDP port on every scanner, and a v1/v2c trap is an
        // unauthenticated datagram, so it should be a decision rather than a
        // side effect of installing.
        'allow_traps' => 0,
        // The port scanners listen on. 162 is the standard, and binding it
        // needs a capability the hardened systemd unit does not grant by
        // default — see packaging/glpi-netscan-traps.conf.
        'trap_port' => 162,
    ];

    /** @return array<string,int> */
    public static function all(): array
    {
        $stored = Config::getConfigurationValues(
            PLUGIN_GLPINETSCAN_CONFIG_CONTEXT,
            array_keys(self::DEFAULTS)
        );

        $out = [];
        foreach (self::DEFAULTS as $key => $default) {
            $value = $stored[$key] ?? null;
            $out[$key] = ($value === null || $value === '') ? $default : (int) $value;
        }

        $out['poll_interval']    = max(10, min(3600, $out['poll_interval']));
        $out['stale_after']      = max($out['poll_interval'] * 3, $out['stale_after']);
        $out['rollout_percent']  = max(0, min(100, $out['rollout_percent']));
        $out['trap_port']        = max(1, min(65535, $out['trap_port']));

        return $out;
    }

    public static function get(string $key): int
    {
        return self::all()[$key] ?? self::DEFAULTS[$key];
    }

    public static function save(array $input): void
    {
        $values = [];
        foreach (array_keys(self::DEFAULTS) as $key) {
            if (array_key_exists($key, $input)) {
                $values[$key] = (int) $input[$key];
            }
        }
        if ($values !== []) {
            Config::setConfigurationValues(PLUGIN_GLPINETSCAN_CONFIG_CONTEXT, $values);
        }
    }
}
