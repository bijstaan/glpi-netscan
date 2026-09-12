<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use GlpiPlugin\Glpinetscan\Warranty\Vendor\Apple;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Cisco;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Dell;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Fortinet;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Hp;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Hpe;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Juniper;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Lenovo;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Microsoft;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\PureStorage;

/**
 * Which vendors exist, which are switched on, and how to build one.
 *
 * The list is fixed rather than discovered through a plugin hook. A warranty
 * client is not a place to accept third-party code: it is handed the estate's
 * serial numbers and a support-portal credential, and every one of these is
 * written against an API whose exact behaviour had to be established from a
 * real payload. A site that needs an eighth vendor is better served by a patch
 * than by a hook that makes the credential path pluggable.
 *
 * ### Two answer shapes
 *
 * Seven of the ten answer about a **serial**: send a batch, get a batch back.
 * Microsoft and Pure Storage answer about a **fleet** — there is no per-device
 * endpoint, so the whole tenant or organisation is fetched once per run and
 * every subject is answered from it. The interface is the same either way; a
 * fleet vendor just caches its snapshot for the life of the object and declares
 * a large batch size. Juniper offers both and uses the serial form.
 *
 * ### Vendors deliberately absent
 *
 * Each of these was looked at and has no serial-number warranty API a plugin
 * can call, as of this release:
 *
 * - **Arista Networks** — the only public API on `arista.com` is the software
 *   download service (`custom_data/api`, as used by eos-downloader), and
 *   CloudVision's APIs describe devices under management rather than support
 *   entitlement. Warranty is the support portal's serial-number page.
 * - **Ubiquiti** — `api.ui.com` and the UniFi APIs return device inventory
 *   with no coverage data; warranty runs through the RMA web form at
 *   rma.ui.com, which needs proof of purchase rather than a serial.
 * - **Supermicro** — serial-number warranty check is a web form; RMA is email.
 * - **Zebra, APC/Schneider, Acer, ASUS, MSI, Dynabook/Toshiba, Fujitsu** —
 *   web form in every case. Scraping one would break silently and is not
 *   shipped here.
 * - **Cisco Meraki** — see {@see Cisco}: Meraki serials are not in SN2INFO.
 *
 * Where a vendor later publishes an API, adding it is one class plus one line
 * in {@see vendorClasses()}; everything else keys off the interface.
 */
final class Registry
{
    /**
     * @return array<class-string<Vendor>>
     */
    public static function vendorClasses(): array
    {
        return [
            Dell::class,
            Hp::class,
            Hpe::class,
            Lenovo::class,
            Apple::class,
            Cisco::class,
            Fortinet::class,
            Juniper::class,
            Microsoft::class,
            PureStorage::class,
        ];
    }

    /** @return array<string,class-string<Vendor>> keyed by vendor key */
    public static function byKey(): array
    {
        $out = [];
        foreach (self::vendorClasses() as $class) {
            $out[$class::key()] = $class;
        }

        return $out;
    }

    public static function classFor(string $key): ?string
    {
        return self::byKey()[$key] ?? null;
    }

    /**
     * The credentials configured for one vendor, decrypted.
     *
     * @return array<string,string>
     */
    public static function credentialsFor(string $key, ?array $settings = null): array
    {
        $class = self::classFor($key);
        if ($class === null) {
            return [];
        }

        $settings ??= Settings::all();
        $out        = [];

        foreach (array_keys($class::credentials()) as $name) {
            $out[$name] = (string) ($settings[Settings::credentialKey($key, $name)] ?? '');
        }

        return $out;
    }

    /** Switched on by an administrator, whether or not it is usable. */
    public static function isEnabled(string $key, ?array $settings = null): bool
    {
        $settings ??= Settings::all();

        return (int) ($settings['warranty_' . $key . '_enabled'] ?? 0) === 1;
    }

    /** Has every credential it needs. */
    public static function isConfigured(string $key, ?array $settings = null): bool
    {
        $class = self::classFor($key);

        return $class !== null && $class::isConfigured(self::credentialsFor($key, $settings));
    }

    /** Switched on *and* usable — the set the cron will actually call. */
    public static function isUsable(string $key, ?array $settings = null): bool
    {
        $settings ??= Settings::all();

        return self::isEnabled($key, $settings) && self::isConfigured($key, $settings);
    }

    /**
     * @return string[] keys of the vendors a sync run may use
     */
    public static function usableKeys(?array $settings = null): array
    {
        $settings ??= Settings::all();
        $out        = [];

        foreach (array_keys(self::byKey()) as $key) {
            if (self::isUsable($key, $settings)) {
                $out[] = $key;
            }
        }

        return $out;
    }

    /**
     * Build a ready-to-use client.
     *
     * Each vendor gets its own transport because the rate-limit floor is
     * per-vendor and, for Apple, so is the client certificate. Sharing one
     * would let a fast vendor's traffic consume a slow vendor's allowance.
     */
    public static function make(string $key, ?array $settings = null, ?Transport $transport = null): ?Vendor
    {
        $class = self::classFor($key);
        if ($class === null) {
            return null;
        }

        $settings ??= Settings::all();
        $credentials = self::credentialsFor($key, $settings);

        if ($transport === null) {
            $timeout = (int) ($settings['warranty_http_timeout'] ?? 30);

            // Apple is the only mutual-TLS vendor. Pure Storage also holds a
            // private key on disk, but signs a token with it rather than
            // presenting it to the transport.
            $transport = $class === Apple::class
                ? new HttpTransport(
                    $timeout,
                    $class::minInterval(),
                    $credentials['cert_path'] ?? null,
                    $credentials['cert_password'] ?? null
                )
                : new HttpTransport($timeout, $class::minInterval());
        }

        if ($class === Apple::class) {
            return new Apple($transport, $credentials, new ConfigTokenStore());
        }

        return new $class($transport, $credentials);
    }
}
