<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * A {@see TokenStore} backed by the plugin's own configuration.
 *
 * The names it accepts are prefixed and whitelisted rather than written
 * straight through: this is the one place a value that arrived over the
 * network becomes a configuration key, and an unconstrained name there would
 * let a vendor response decide which setting gets overwritten.
 */
final class ConfigTokenStore implements TokenStore
{
    /** Runtime tokens a vendor client is allowed to keep. */
    private const ALLOWED = ['apple_session_token'];

    public function get(string $name): string
    {
        if (!in_array($name, self::ALLOWED, true)) {
            return '';
        }

        return (string) Settings::get('warranty_' . $name);
    }

    public function put(string $name, string $value): void
    {
        if (!in_array($name, self::ALLOWED, true)) {
            return;
        }

        Settings::save(['warranty_' . $name => $value]);
    }
}
