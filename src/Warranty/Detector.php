<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use GlpiPlugin\Glpinetscan\Warranty\Vendor\Hp;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Hpe;

/**
 * Which vendor, if any, should be asked about an asset.
 *
 * Harder than it sounds, for three reasons that all show up in a real estate.
 *
 * **Manufacturer strings are whatever the firmware said.** "Dell Inc.", "Dell
 * Computer Corporation", "LENOVO", "Hewlett-Packard" and "Cisco Systems, Inc."
 * are all one vendor each, and GLPI stores every variant it is given. Matching
 * is therefore on normalised substrings, longest alias first so "hewlett
 * packard enterprise" is not eaten by "hewlett packard".
 *
 * **HP and HPE report the same name.** The 2015 split left two companies, two
 * support organisations and two APIs, and an Aruba switch and an EliteBook can
 * both say "HP". Where the name does not settle it, the asset type does: the
 * client and print business went to HP Inc. and the server, storage and
 * networking business to HPE.
 *
 * **Some kit reports nothing useful.** SNMP devices frequently have no
 * manufacturer at all in GLPI because the enterprise OID did not map to one,
 * so the model string is consulted as a second source — a device whose model
 * is "FortiGate-60F" is a Fortinet whatever the manufacturer column says.
 *
 * Nothing is guessed from the serial's shape. A seven-character alphanumeric
 * is a Dell service tag and also a great many other things, and sending an
 * estate's serials to a vendor on that basis is both wrong and a disclosure.
 */
final class Detector
{
    /**
     * Model-string fragments that identify a vendor on their own.
     *
     * Only fragments that are product names rather than generic words, because
     * this runs against whatever an SNMP sysDescr produced.
     *
     * @var array<string,string[]>
     */
    private const MODEL_HINTS = [
        'cisco'    => ['catalyst', 'nexus', 'ios-xe', 'ios xe', 'aironet', 'isr', 'asr9', 'ws-c', 'ucs'],
        'fortinet' => ['fortigate', 'fortiswitch', 'fortiap', 'fortianalyzer', 'fortimanager', 'fortiwifi'],
        'hpe'      => ['procurve', 'aruba', 'proliant', 'aruba instant', 'flexnetwork', 'synergy', 'nimble'],
        'hp'       => ['elitebook', 'probook', 'laserjet', 'officejet', 'elitedesk', 'prodesk', 'zbook', 'designjet'],
        'dell'     => ['latitude', 'optiplex', 'precision', 'poweredge', 'powerswitch', 'powerconnect', 'inspiron', 'xps', 'vostro'],
        'lenovo'   => ['thinkpad', 'thinkcentre', 'thinkstation', 'thinksystem', 'thinkagile', 'ideapad', 'ideacentre'],
        'apple'    => ['macbook', 'imac', 'mac mini', 'mac studio', 'mac pro'],
        'juniper'  => ['junos', 'juniper', 'srx', 'qfx', 'mx960', 'ex4300', 'ex4600', 'ex9200'],
        'microsoft' => ['surface pro', 'surface laptop', 'surface book', 'surface go', 'surface studio'],
        'pure'     => ['flasharray', 'flashblade', 'purity'],
    ];

    /**
     * Model strings that identify a vendor by their *shape* rather than a word.
     *
     * Needed because of what SNMP discovery actually produces. A Cisco access
     * point routinely lands in GLPI with no manufacturer at all — the
     * enterprise OID did not map to one — and a model of `AIR-AP2802I-E-K9` or
     * `C9120AXI-E`, which contains no vendor name for a substring match to
     * find. Both were sitting in a real inventory, unmatched, which is how this
     * list came to exist.
     *
     * Anchored at the start, because these are product identifiers: an
     * unanchored `c9[0-9]{3}` would match somewhere inside half the world's
     * part numbers.
     *
     * @var array<string,string>
     */
    private const MODEL_PATTERNS = [
        // Aironet and Catalyst access points, Catalyst and Nexus switches,
        // ISR/ASR routers, and the Business range.
        'cisco' => '/^(air-(ap|ct|lap)|ws-c|c9[0-9]{3}|n[3579]k-|asr[0-9]{3,4}|isr[0-9]{3,4}|cbs[0-9]{3})/',

        // Juniper's chassis names as they appear in sysDescr: EX/QFX/MX/SRX/ACX
        // /PTX followed by a model number. Anchored, and requiring the digits,
        // so "mxchip" and "exagrid" are not mistaken for switches.
        'juniper' => '/^(ex[0-9]{4}|qfx[0-9]{4}|mx[0-9]{2,4}|srx[0-9]{3,4}|acx[0-9]{3,4}|ptx[0-9]{4})/',
    ];

    /**
     * Manufacturer fragments that must never reach a vendor client.
     *
     * Meraki is the one that matters: its serials are not in Cisco's SN2INFO,
     * so without this every Meraki access point in an estate produces a "serial
     * number does not exist" every night, for ever.
     *
     * @var array<string,string[]>
     */
    private const EXCLUDED = [
        'cisco' => ['meraki'],
    ];

    /** Asset types that belong to HPE rather than HP Inc. when the name is ambiguous. */
    private const HPE_ITEMTYPES = ['NetworkEquipment', 'PDU', 'Enclosure', 'Rack', 'Cluster'];

    /** The vendor key to ask about this asset, or null when nothing fits. */
    public static function detect(Subject $subject): ?string
    {
        return self::vendorFor($subject->manufacturer, $subject->model, $subject->itemtype);
    }

    public static function vendorFor(string $manufacturer, string $model = '', string $itemtype = ''): ?string
    {
        $name = self::normalise($manufacturer);

        if ($name !== '') {
            $key = self::matchAliases($name);

            if ($key !== null && self::isExcluded($key, $name . ' ' . self::normalise($model))) {
                return null;
            }

            if ($key !== null) {
                return self::disambiguate($key, $name, $itemtype);
            }
        }

        $model_text = self::normalise($model);
        if ($model_text === '') {
            return null;
        }

        // A model that names its maker outright — "Cisco C9130AXI-E" — is
        // settled by the same alias rules the manufacturer column uses, word
        // boundaries and the HP/HPE split included. Tried before the product
        // families below because it is the stronger signal of the two.
        $named = self::matchAliases($model_text);

        if ($named !== null) {
            return self::isExcluded($named, $model_text)
                ? null
                : self::disambiguate($named, $model_text, $itemtype);
        }

        foreach (self::MODEL_HINTS as $key => $fragments) {
            foreach ($fragments as $fragment) {
                if (str_contains($model_text, $fragment)) {
                    return self::isExcluded($key, $model_text) ? null : $key;
                }
            }
        }

        foreach (self::MODEL_PATTERNS as $key => $pattern) {
            if (preg_match($pattern, $model_text) === 1) {
                return self::isExcluded($key, $model_text) ? null : $key;
            }
        }

        return null;
    }

    /**
     * The vendor whose alias matches, preferring the most specific.
     *
     * Aliases are sorted by length because several of them are prefixes of
     * each other; matching in registry order would send every HPE asset to HP
     * Inc. and every Dell EMC array to the client-hardware endpoint.
     */
    private static function matchAliases(string $name): ?string
    {
        $candidates = [];

        foreach (Registry::byKey() as $key => $class) {
            foreach ($class::aliases() as $alias) {
                if (self::mentions($name, $alias)) {
                    $candidates[$alias] = $key;
                }
            }
        }

        if ($candidates === []) {
            return null;
        }

        uksort($candidates, static fn(string $a, string $b): int => mb_strlen($b) <=> mb_strlen($a));

        return reset($candidates);
    }

    /**
     * Does this manufacturer string mention this alias as a word?
     *
     * Word boundaries rather than a plain substring, because the short aliases
     * are destructive without them: "hp" matches "Sharp", "emc" matches
     * "Semcon", and "forti" would be fine but "ibm" appears inside plenty of
     * OEM strings that are nothing to do with Lenovo.
     */
    private static function mentions(string $name, string $alias): bool
    {
        return preg_match('/(?:^|\s)' . preg_quote($alias, '/') . '(?:\s|$)/', $name) === 1;
    }

    private static function isExcluded(string $key, string $haystack): bool
    {
        foreach (self::EXCLUDED[$key] ?? [] as $fragment) {
            if (str_contains($haystack, $fragment)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Settle HP Inc. against HPE.
     *
     * The name wins when it is explicit — "Hewlett Packard Enterprise", or one
     * of the brands only HPE owns. Otherwise the asset type decides, which is
     * right often enough to be useful and is the only signal available: an
     * inventoried switch that calls itself "HP" is a ProCurve, and an
     * inventoried laptop that calls itself "HP" is not.
     */
    private static function disambiguate(string $key, string $name, string $itemtype): string
    {
        if ($key !== Hp::key() && $key !== Hpe::key()) {
            return $key;
        }

        foreach (Hpe::aliases() as $alias) {
            if ($alias !== 'hp' && self::mentions($name, $alias)) {
                return Hpe::key();
            }
        }

        if ($itemtype !== '' && in_array($itemtype, self::HPE_ITEMTYPES, true)) {
            return Hpe::key();
        }

        return $key;
    }

    /**
     * Lower-cased, punctuation-free, single-spaced.
     *
     * The trailing corporate suffixes go too: "Inc", "Ltd", "GmbH", "Corp" and
     * "Co" appear in about half of these strings and in none of the aliases.
     */
    public static function normalise(string $value): string
    {
        $value = mb_strtolower(trim($value));
        $value = str_replace(['.', ',', '(', ')', '"', "'"], ' ', $value);
        $value = preg_replace('/\s+/', ' ', $value) ?? $value;
        $value = preg_replace('/\b(inc|incorporated|ltd|limited|llc|gmbh|corp|corporation|co|company|sa|ag|bv|nv|srl|s r l)\b/', ' ', $value) ?? $value;

        return trim(preg_replace('/\s+/', ' ', $value) ?? $value);
    }
}
