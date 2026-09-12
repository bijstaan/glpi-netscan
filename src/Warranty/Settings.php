<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use Config;
use GLPIKey;
use RuntimeException;

/**
 * Warranty-lookup configuration.
 *
 * Scoped to this feature rather than being a settings class for the whole
 * plugin, because the rest of the plugin reads `glpi_configs` directly and
 * rewriting that was not this change's job.
 *
 * Two properties are load-bearing.
 *
 * **Everything is off and no vendor is configured.** Enabling the plugin must
 * never be what starts sending an estate's serial numbers to seven companies.
 * Each vendor is a separate switch on top of a master switch, because a site
 * may hold a Dell contract and have no arrangement at all with the others.
 *
 * **Credentials are encrypted by core, not by this class.** The keys returned
 * by {@see secretKeys()} are declared through the SECURED_CONFIGS hook in
 * setup.php, which is what makes `Config::setConfigurationValues()` encrypt
 * them on write, mask them in the history log, and re-encrypt them when an
 * administrator runs `glpi:security:changekey`. Doing it by hand here would
 * work until that rotation, and then silently orphan every key at once.
 */
final class Settings
{
    /** Shown in place of a stored secret, and posted back unchanged to keep it. */
    public const SECRET_PLACEHOLDER = '••••••••';

    /** @return array<string,int|string> */
    public static function defaults(): array
    {
        $defaults = [
            // Master switch. Off: nothing is contacted, the cron does nothing.
            'warranty_enabled' => 0,

            // How often a successful lookup is refreshed. A warranty is not a
            // fast-moving fact — what changes is somebody buying an extension —
            // so weekly is frequent enough to catch that and slow enough that a
            // thousand-machine estate is a few hundred calls a week.
            'warranty_interval_days' => 7,

            // Once cover has expired there is nothing left to learn unless
            // somebody renews, so those assets are checked far less often. This
            // is most of an ageing estate, and it is where the quota goes.
            'warranty_expired_interval_days' => 30,

            // A serial the vendor does not recognise is retried on this
            // cadence. Long, because "not found" is usually permanent — kit
            // registered to a reseller, or a serial the firmware made up.
            'warranty_unknown_interval_days' => 30,

            // Assets one cron run may look up. Keeps a first sync over a large
            // estate from spending an entire day's quota in one pass; the
            // remainder is picked up on the next run.
            'warranty_run_limit' => 200,

            'warranty_http_timeout' => 30,

            // Project onto the asset's Infocom. Off makes the plugin a
            // read-only reporter: lookups still run and the tab still shows
            // them, but no asset is written to.
            'warranty_write_infocom' => 1,

            // Fill the purchase date from the vendor's ship date when GLPI has
            // none. Never overwrites one that is already set — a finance-owned
            // date is not ours to correct.
            'warranty_set_buy_date' => 1,

            // Set the Infocom supplier to the manufacturer, creating the
            // Supplier record if it does not exist. Off by default: in an
            // estate bought through resellers the supplier is the reseller,
            // and overwriting that loses who to actually call.
            'warranty_set_supplier' => 0,

            // Overwrite warranty fields that were not written by this plugin.
            // Off: somebody typed those in, and a lookup that disagrees is not
            // automatically the one that is right.
            'warranty_overwrite_manual' => 0,

            // Sent to the vendors that price entitlements per region when the
            // asset itself does not say. Empty means each vendor's own default.
            'warranty_default_country' => '',
        ];

        foreach (Registry::vendorClasses() as $class) {
            $defaults['warranty_' . $class::key() . '_enabled'] = 0;

            foreach ($class::credentials() as $name => $spec) {
                $defaults[self::credentialKey($class::key(), $name)] = (string) ($spec['default'] ?? '');
            }
        }

        // Apple's session token: issued at runtime, not by an administrator,
        // and kept because the activation token it came from is spent.
        $defaults['warranty_apple_session_token'] = '';

        return $defaults;
    }

    public static function credentialKey(string $vendor, string $credential): string
    {
        return 'warranty_' . $vendor . '_' . $credential;
    }

    /**
     * Config keys holding a credential. Declared to SECURED_CONFIGS in setup.php.
     *
     * @return string[]
     */
    public static function secretKeys(): array
    {
        $keys = ['warranty_apple_session_token'];

        foreach (Registry::vendorClasses() as $class) {
            foreach ($class::credentials() as $name => $spec) {
                if ($spec['type'] === 'secret') {
                    $keys[] = self::credentialKey($class::key(), $name);
                }
            }
        }

        return $keys;
    }

    /** @return array<string,int|string> */
    public static function all(): array
    {
        $defaults = self::defaults();
        $stored   = Config::getConfigurationValues(
            PLUGIN_GLPINETSCAN_CONFIG_CONTEXT,
            array_keys($defaults)
        );

        $secrets = array_flip(self::secretKeys());
        $out     = [];

        foreach ($defaults as $key => $default) {
            $value = $stored[$key] ?? null;

            if ($value === null || $value === '') {
                $out[$key] = $default;
                continue;
            }

            if (isset($secrets[$key])) {
                // A secret that will not decrypt is treated as absent rather
                // than passed through as ciphertext. GLPI's key can be
                // regenerated or restored from a backup taken before it; an
                // encrypted blob sent as an API key produces a baffling 401
                // instead of an obvious "not configured".
                $plain     = (new GLPIKey())->decrypt((string) $value);
                $out[$key] = is_string($plain) ? $plain : '';
                continue;
            }

            $out[$key] = is_int($default) ? (int) $value : (string) $value;
        }

        return self::reconcile($out);
    }

    public static function get(string $key): int|string
    {
        return self::all()[$key] ?? self::defaults()[$key] ?? '';
    }

    public static function isEnabled(): bool
    {
        return (int) self::get('warranty_enabled') === 1;
    }

    /** Clamp the numbers that have a workable range, rather than refusing them. */
    private static function reconcile(array $s): array
    {
        $s['warranty_interval_days']         = max(1, min(365, (int) $s['warranty_interval_days']));
        $s['warranty_expired_interval_days'] = max(1, min(365, (int) $s['warranty_expired_interval_days']));
        $s['warranty_unknown_interval_days'] = max(1, min(365, (int) $s['warranty_unknown_interval_days']));
        $s['warranty_run_limit']             = max(1, min(5000, (int) $s['warranty_run_limit']));
        $s['warranty_http_timeout']          = max(5, min(300, (int) $s['warranty_http_timeout']));

        foreach (['warranty_enabled', 'warranty_write_infocom', 'warranty_set_buy_date',
            'warranty_set_supplier', 'warranty_overwrite_manual'] as $flag) {
            $s[$flag] = ((int) $s[$flag]) === 1 ? 1 : 0;
        }

        $s['warranty_default_country'] = strtoupper(substr(trim((string) $s['warranty_default_country']), 0, 2));

        return $s;
    }

    /**
     * Persist the keys present in $input, and nothing else.
     *
     * Only recognised keys are written, so one card's form cannot reset
     * another's — a checkbox absent from a submission is indistinguishable
     * from an unticked one, and rebuilding every setting from $_POST is how a
     * settings page quietly switches off half of itself.
     *
     * @param array<string,mixed> $input
     */
    public static function save(array $input): void
    {
        $defaults = self::defaults();
        $secrets  = array_flip(self::secretKeys());
        $values   = [];

        foreach ($defaults as $key => $default) {
            if (!array_key_exists($key, $input)) {
                continue;
            }

            $value = $input[$key];

            // The placeholder means "leave the stored secret alone". Writing
            // it through would replace a working credential with six bullets.
            if (isset($secrets[$key]) && (string) $value === self::SECRET_PLACEHOLDER) {
                continue;
            }

            $values[$key] = is_int($default) ? (int) $value : trim((string) $value);
        }

        if ($values === []) {
            return;
        }

        self::assertSecretsAreSecured($values, $secrets);

        Config::setConfigurationValues(PLUGIN_GLPINETSCAN_CONFIG_CONTEXT, $values);
    }

    /**
     * A tripwire, not a routine check.
     *
     * Secrets are handed to Config in plaintext and encrypted there, which is
     * only true while they are declared through SECURED_CONFIGS. If that
     * declaration is ever lost this must fail loudly rather than write seven
     * vendors' API credentials to the database in the clear.
     */
    private static function assertSecretsAreSecured(array $values, array $secrets): void
    {
        $key = new GLPIKey();

        foreach (array_keys($values) as $name) {
            if (!isset($secrets[$name]) || (string) $values[$name] === '') {
                continue;
            }

            if (!$key->isConfigSecured(PLUGIN_GLPINETSCAN_CONFIG_CONTEXT, $name)) {
                throw new RuntimeException(
                    "glpinetscan: refusing to store $name — it is not declared in SECURED_CONFIGS, "
                    . 'so it would be written unencrypted.'
                );
            }
        }
    }
}
