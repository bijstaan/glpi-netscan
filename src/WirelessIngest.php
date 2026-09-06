<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use NetworkPort;
use NetworkPortWifi;
use WifiNetwork;

/**
 * Wireless state: SSIDs, access points and radios.
 *
 * Stored in the plugin's own tables because GLPI's inventory format has nowhere
 * to put it. `network_device` carries no comment field, and its `description`
 * is the device's sysDescr — writing "managed by controller X" there would
 * overwrite a real fact with a different one. This is the same reason power
 * state lives in `powerdevices` rather than on the asset.
 *
 * The access points themselves are *not* created here. Each is submitted as an
 * ordinary NetworkEquipment through GLPI's own pipeline, so it gets a model, a
 * serial, an entity and a switch port like any other piece of hardware. What is
 * recorded here is the operational half — who manages it, whether it is up, how
 * many clients it has — and the association back to the controller, which GLPI
 * has no relation for.
 */
final class WirelessIngest
{
    public const SSID_TABLE = 'glpi_plugin_glpinetscan_wifinetworks';
    public const AP_TABLE   = 'glpi_plugin_glpinetscan_accesspoints';

    /**
     * Record what a controller (or standalone AP) reported.
     *
     * @param array<string,mixed> $wireless the payload's `wireless` block
     */
    public static function store(int $items_id, string $itemtype, array $wireless, int $scanners_id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $now = time();

        self::storeSSIDs($items_id, $itemtype, (array) ($wireless['ssids'] ?? []), $scanners_id, $now);
        self::storeAccessPoints($items_id, $itemtype, (array) ($wireless['access_points'] ?? []), $scanners_id, $now);

        // Rows not refreshed by this scan describe something the controller no
        // longer reports — an SSID deleted, an AP decommissioned. Removed so the
        // tab shows the estate as it is, not as it was. The AP *asset* is left
        // alone: an access point that has stopped reporting is exactly the one
        // an operator needs to still be able to find.
        foreach ([self::SSID_TABLE, self::AP_TABLE] as $table) {
            $DB->delete($table, [
                'items_id'   => $items_id,
                'itemtype'   => $itemtype,
                'last_seen'  => ['<', $now],
            ]);
        }
    }

    /** @param array<int,array<string,mixed>> $ssids */
    private static function storeSSIDs(int $items_id, string $itemtype, array $ssids, int $scanners_id, int $now): void
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($ssids as $ssid) {
            $name = trim((string) ($ssid['name'] ?? ''));
            if ($name === '') {
                continue;
            }

            $DB->updateOrInsert(self::SSID_TABLE, [
                'clients'                        => (int) ($ssid['clients'] ?? 0),
                'plugin_glpinetscan_scanners_id' => $scanners_id,
                'last_seen'                      => $now,
            ], [
                'items_id' => $items_id,
                'itemtype' => $itemtype,
                'name'     => $name,
            ]);
        }
    }

    /** @param array<int,array<string,mixed>> $aps */
    private static function storeAccessPoints(int $items_id, string $itemtype, array $aps, int $scanners_id, int $now): void
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($aps as $ap) {
            $name = trim((string) ($ap['name'] ?? ''));
            if ($name === '') {
                continue;
            }

            $serial = trim((string) ($ap['serial'] ?? ''));
            $mac    = trim((string) ($ap['mac'] ?? ''));

            $DB->updateOrInsert(self::AP_TABLE, [
                'serial'                         => $serial,
                'mac'                            => $mac,
                'ip'                             => trim((string) ($ap['ip'] ?? '')),
                'model'                          => trim((string) ($ap['model'] ?? '')),
                'location'                       => trim((string) ($ap['location'] ?? '')),
                'firmware'                       => trim((string) ($ap['firmware'] ?? '')),
                'status'                         => trim((string) ($ap['status'] ?? '')),
                'radios'                         => (int) ($ap['radios'] ?? 0),
                'clients'                        => (int) ($ap['clients'] ?? 0),
                // Radio detail as JSON. It is display-only — nothing joins on a
                // channel — and a table per radio would be three tables deep for
                // data whose only consumer renders it as one line each.
                'radio_detail'                   => json_encode($ap['radios_detail'] ?? [], JSON_THROW_ON_ERROR),
                'accesspoints_id'                => self::assetFor($serial, $mac),
                'plugin_glpinetscan_scanners_id' => $scanners_id,
                'last_seen'                      => $now,
            ], [
                'items_id' => $items_id,
                'itemtype' => $itemtype,
                'name'     => $name,
            ]);

            self::storeRadios($serial, $mac, (array) ($ap['radios_detail'] ?? []));
        }
    }

    /**
     * Find the NetworkEquipment this AP was created as.
     *
     * Matched on serial first, then MAC — the same order the scanner uses to
     * key the asset, so the two agree about what is the same access point.
     * Returns 0 when the asset does not exist yet, which happens on the first
     * scan: submissions are ingested in order and the controller comes first.
     * The next scan fills it in.
     */
    private static function assetFor(string $serial, string $mac): int
    {
        /** @var DBmysql $DB */
        global $DB;

        if ($serial !== '') {
            foreach ($DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_networkequipments',
                'WHERE'  => ['serial' => $serial, 'is_deleted' => 0],
                'LIMIT'  => 1,
            ]) as $row) {
                return (int) $row['id'];
            }
        }

        if ($mac !== '') {
            foreach ($DB->request([
                'SELECT' => ['items_id'],
                'FROM'   => NetworkPort::getTable(),
                'WHERE'  => ['mac' => $mac, 'itemtype' => 'NetworkEquipment'],
                'LIMIT'  => 1,
            ]) as $row) {
                return (int) $row['items_id'];
            }
        }

        return 0;
    }

    /**
     * Give each radio a wifi port on the access point's own asset.
     *
     * GLPI models a radio as a NetworkPort whose instantiation is
     * NetworkPortWifi, which is the right shape — a radio is an interface, it
     * has a band and a mode. The inventory format cannot express it (its
     * network_ports carry no wireless fields, and core only sets a wifi
     * instantiation from *computer* inventory), so it is written here.
     *
     * @param array<int,array<string,mixed>> $radios
     */
    private static function storeRadios(string $serial, string $mac, array $radios): void
    {
        /** @var DBmysql $DB */
        global $DB;

        if ($radios === []) {
            return;
        }

        $items_id = self::assetFor($serial, $mac);
        if ($items_id <= 0) {
            return;
        }

        $entities_id = 0;
        foreach ($DB->request([
            'SELECT' => ['entities_id'],
            'FROM'   => 'glpi_networkequipments',
            'WHERE'  => ['id' => $items_id],
            'LIMIT'  => 1,
        ]) as $row) {
            $entities_id = (int) $row['entities_id'];
        }

        foreach ($radios as $radio) {
            $slot = (string) ($radio['slot'] ?? '');
            $band = trim((string) ($radio['band'] ?? ''));
            $name = 'radio' . ($slot !== '' ? $slot : '');

            $ports_id = 0;
            foreach ($DB->request([
                'SELECT' => ['id'],
                'FROM'   => NetworkPort::getTable(),
                'WHERE'  => ['itemtype' => 'NetworkEquipment', 'items_id' => $items_id, 'name' => $name],
                'LIMIT'  => 1,
            ]) as $row) {
                $ports_id = (int) $row['id'];
            }

            $port = new NetworkPort();
            $input = [
                'itemtype'           => 'NetworkEquipment',
                'items_id'           => $items_id,
                'entities_id'        => $entities_id,
                'name'               => $name,
                'instantiation_type' => NetworkPortWifi::class,
                'logical_number'     => (int) $slot,
                'comment'            => self::radioComment($radio),
            ];

            if ($ports_id > 0) {
                $input['id'] = $ports_id;
                $port->update($input);
            } else {
                $ports_id = (int) $port->add($input);
            }

            if ($ports_id <= 0) {
                continue;
            }

            // `version` is GLPI's word for the 802.11 flavour, which is exactly
            // what the band decodes to. Mode is always access point: these are
            // radios of an AP, and nothing here would tell us otherwise.
            $wifi = new NetworkPortWifi();
            $wifiInput = [
                'networkports_id' => $ports_id,
                'version'         => mb_substr($band, 0, 20),
                'mode'            => 'ap',
            ];

            if ($wifi->getFromDBByCrit(['networkports_id' => $ports_id])) {
                $wifiInput['id'] = $wifi->getID();
                $wifi->update($wifiInput);
            } else {
                $wifi->add($wifiInput);
            }
        }
    }

    /**
     * Attach the networks a standalone access point broadcasts.
     *
     * Only for a device that *is* the AP. A controller's SSID list is
     * estate-wide and belongs to no single radio — the MIBs do not say which
     * network is on which radio of which AP — so inventing that link would be
     * fabrication. A UniFi or MikroTik AP reports exactly the networks it
     * serves, and those genuinely belong to it.
     *
     * @param array<int,array<string,mixed>> $ssids
     */
    public static function attachStandaloneNetworks(int $items_id, int $entities_id, array $ssids): void
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($ssids as $ssid) {
            $name = trim((string) ($ssid['name'] ?? ''));
            if ($name === '') {
                continue;
            }

            $network = new WifiNetwork();
            $networks_id = 0;
            if ($network->getFromDBByCrit(['essid' => $name, 'entities_id' => $entities_id])) {
                $networks_id = $network->getID();
            } else {
                $networks_id = (int) $network->add([
                    'name'        => $name,
                    'essid'       => $name,
                    'mode'        => 'infrastructure',
                    'entities_id' => $entities_id,
                ]);
            }

            if ($networks_id <= 0) {
                continue;
            }

            $portName = 'wlan-' . $name;

            $ports_id = 0;
            foreach ($DB->request([
                'SELECT' => ['id'],
                'FROM'   => NetworkPort::getTable(),
                'WHERE'  => ['itemtype' => 'NetworkEquipment', 'items_id' => $items_id, 'name' => $portName],
                'LIMIT'  => 1,
            ]) as $row) {
                $ports_id = (int) $row['id'];
            }

            $port = new NetworkPort();
            $input = [
                'itemtype'           => 'NetworkEquipment',
                'items_id'           => $items_id,
                'entities_id'        => $entities_id,
                'name'               => $portName,
                'instantiation_type' => NetworkPortWifi::class,
                'comment'            => sprintf(__('%d associated clients at last scan', 'glpinetscan'),
                                                (int) ($ssid['clients'] ?? 0)),
            ];

            if ($ports_id > 0) {
                $input['id'] = $ports_id;
                $port->update($input);
            } else {
                $ports_id = (int) $port->add($input);
            }

            if ($ports_id <= 0) {
                continue;
            }

            $wifi = new NetworkPortWifi();
            $wifiInput = [
                'networkports_id' => $ports_id,
                'wifinetworks_id' => $networks_id,
                'mode'            => 'ap',
            ];

            if ($wifi->getFromDBByCrit(['networkports_id' => $ports_id])) {
                $wifiInput['id'] = $wifi->getID();
                $wifi->update($wifiInput);
            } else {
                $wifi->add($wifiInput);
            }
        }
    }

    private static function radioComment(array $radio): string
    {
        $bits = [];
        if (($band = trim((string) ($radio['band'] ?? ''))) !== '') {
            $bits[] = $band;
        }
        if (($channel = (int) ($radio['channel'] ?? 0)) > 0) {
            $bits[] = sprintf(__('Channel %d', 'glpinetscan'), $channel);
        }
        if (($status = trim((string) ($radio['status'] ?? ''))) !== '') {
            $bits[] = $status;
        }
        $bits[] = sprintf(__('%d associated clients at last scan', 'glpinetscan'),
                          (int) ($radio['clients'] ?? 0));

        return implode(' — ', $bits);
    }

    /**
     * Everything recorded against one asset, for the tab.
     *
     * @return array{ssids:array<int,array<string,mixed>>,aps:array<int,array<string,mixed>>}
     */
    public static function forItem(int $items_id, string $itemtype): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $ssids = [];
        foreach ($DB->request([
            'FROM'  => self::SSID_TABLE,
            'WHERE' => ['items_id' => $items_id, 'itemtype' => $itemtype],
            'ORDER' => ['name'],
        ]) as $row) {
            $ssids[] = $row;
        }

        $aps = [];
        foreach ($DB->request([
            'FROM'  => self::AP_TABLE,
            'WHERE' => ['items_id' => $items_id, 'itemtype' => $itemtype],
            'ORDER' => ['name'],
        ]) as $row) {
            $aps[] = $row;
        }

        return ['ssids' => $ssids, 'aps' => $aps];
    }
}
