<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use Dropdown;
use Item_Plug;
use PDU;
use Plug;

/**
 * Turns a scanner's power report into a native GLPI `PDU` asset.
 *
 * Power devices do **not** go through core's inventory pipeline. Two
 * independent reasons:
 *
 *  - There is no `Glpi\Inventory\MainAsset\PDU`, so core cannot build a PDU
 *    even if it were handed one — the best it could do is file a UPS as an
 *    Unmanaged asset.
 *  - The inventory schema has no vocabulary for batteries, outlets or load, so
 *    the interesting half of the data has nowhere to go.
 *
 * GLPI *does* have a first-class PDU asset covering rack strips, UPSes and
 * ATSes, so this creates that directly and keeps the live state — which is not
 * inventory and would not belong in an asset table anyway — in the plugin's
 * own tables, surfaced as a tab on the asset.
 */
final class PowerIngest
{
    public const DEVICES_TABLE = 'glpi_plugin_glpinetscan_powerdevices';
    public const OUTLETS_TABLE = 'glpi_plugin_glpinetscan_outlets';

    /**
     * Ingest one power device.
     *
     * @param array $payload Full submission, including the `power` block.
     * @return array{ok:bool,errors:string[],itemtype:?string,items_id:?int}
     */
    public static function submit(Scanner $scanner, array $payload, ?Target $target): array
    {
        $deviceId = trim((string) ($payload['deviceid'] ?? ''));
        $power    = $payload['power'] ?? null;
        $device   = $payload['content']['network_device'] ?? [];

        if ($deviceId === '' || !is_array($power)) {
            return self::fail('missing deviceid or power block');
        }

        $entities_id = (int) $scanner->fields['entities_id'];
        $kind        = self::kind((string) ($power['kind'] ?? 'pdu'));

        $pdus_id = self::resolvePdu($deviceId, $device, $kind, $entities_id);
        if ($pdus_id <= 0) {
            return self::fail('could not create or match the PDU asset');
        }

        self::storeState($deviceId, $pdus_id, $scanner->getID(), $kind, $power);
        self::storeOutlets($deviceId, (array) ($power['outlets'] ?? []));
        self::storeOutletCount($pdus_id, count((array) ($power['outlets'] ?? [])));
        AssetPorts::store(
            PDU::class,
            $pdus_id,
            $entities_id,
            (array) ($payload['content']['network_ports'] ?? [])
        );

        return ['ok' => true, 'errors' => [], 'itemtype' => PDU::class, 'items_id' => $pdus_id];
    }

    /**
     * Find or create the PDU asset.
     *
     * Matching order matters. The plugin's own mapping wins because it is the
     * only identifier guaranteed stable across a rename *and* a readdressing;
     * serial is next because it is the strongest thing the device itself
     * reports. Name is deliberately **not** used as a match key — "pdu-mdf-a"
     * is exactly the sort of name that repeats in every rack of every site.
     */
    private static function resolvePdu(
        string $deviceId,
        array $device,
        string $kind,
        int $entities_id
    ): int {
        /** @var DBmysql $DB */
        global $DB;

        $pdu = new PDU();

        $pdus_id = 0;
        foreach ($DB->request([
            'FROM'  => self::DEVICES_TABLE,
            'WHERE' => ['deviceid' => $deviceId],
            'LIMIT' => 1,
        ]) as $row) {
            $pdus_id = (int) $row['pdus_id'];
        }

        if ($pdus_id > 0 && !$pdu->getFromDB($pdus_id)) {
            // The asset was deleted underneath us; fall through and recreate.
            $pdus_id = 0;
        }

        $serial = trim((string) ($device['serial'] ?? ''));
        if ($pdus_id === 0 && $serial !== '') {
            if ($pdu->getFromDBByCrit(['serial' => $serial, 'is_deleted' => 0])) {
                $pdus_id = $pdu->getID();
            }
        }

        $input = array_filter([
            'name'             => trim((string) ($device['name'] ?? '')),
            'serial'           => $serial,
            'otherserial'      => trim((string) ($device['assettag'] ?? '')),
            'comment'          => self::comment($device),
            'manufacturers_id' => self::dropdown('Manufacturer', $device['manufacturer'] ?? '', $entities_id),
            'pdumodels_id'     => self::dropdown('PDUModel', $device['model'] ?? '', $entities_id),
            'pdutypes_id'      => self::dropdown('PDUType', self::typeLabel($kind), $entities_id),
            'locations_id'     => self::dropdown('Location', $device['location'] ?? '', $entities_id),
        ], static fn($v) => $v !== '' && $v !== 0 && $v !== null);

        if ($pdus_id > 0) {
            $input['id'] = $pdus_id;
            $pdu->update($input);
            return $pdus_id;
        }

        $input['entities_id'] = $entities_id;
        if (($input['name'] ?? '') === '') {
            $input['name'] = $deviceId;
        }

        $created = $pdu->add($input);
        return $created ? (int) $created : 0;
    }

    /** Human label for the PDU type dropdown. */
    private static function typeLabel(string $kind): string
    {
        return match ($kind) {
            'ups' => 'UPS',
            'ats' => 'ATS',
            default => 'Rack PDU',
        };
    }

    private static function kind(string $raw): string
    {
        $raw = strtolower(trim($raw));
        return in_array($raw, ['ups', 'pdu', 'ats'], true) ? $raw : 'pdu';
    }

    private static function comment(array $device): string
    {
        $bits = array_filter([
            trim((string) ($device['description'] ?? '')),
            ($fw = trim((string) ($device['firmware'] ?? ''))) !== '' ? "Firmware: $fw" : '',
        ]);
        return implode("\n", $bits);
    }

    /** Resolve a dropdown value to its id, creating it when needed. */
    private static function dropdown(string $itemtype, $value, int $entities_id): int
    {
        $value = trim((string) $value);
        if ($value === '') {
            return 0;
        }
        $id = Dropdown::importExternal($itemtype, $value, $entities_id);
        return is_int($id) && $id > 0 ? $id : 0;
    }

    /** Write the latest state snapshot. */
    private static function storeState(
        string $deviceId,
        int $pdus_id,
        int $scanners_id,
        string $kind,
        array $power
    ): void {
        /** @var DBmysql $DB */
        global $DB;

        $battery = (array) ($power['battery'] ?? []);

        // A single row per device, overwritten each scan. This is deliberately
        // *not* a time series: it is "what the device says now", which is the
        // inventory-shaped question. Trending belongs in a monitoring system.
        $DB->updateOrInsert(
            self::DEVICES_TABLE,
            [
                'pdus_id'                        => $pdus_id,
                'plugin_glpinetscan_scanners_id' => $scanners_id,
                'kind'                           => $kind,
                'battery_status'                 => (string) ($battery['status'] ?? ''),
                'battery_charge'                 => (int) ($battery['charge_percent'] ?? 0),
                'battery_runtime_min'            => (int) ($battery['runtime_minutes'] ?? 0),
                'battery_voltage'                => (float) ($battery['voltage_v'] ?? 0),
                'battery_temp_c'                 => (int) ($battery['temperature_c'] ?? 0),
                'seconds_on_battery'             => (int) ($battery['seconds_on_battery'] ?? 0),
                'battery_replace'                => !empty($battery['replace_indicated']) ? 1 : 0,
                'output_source'                  => (string) ($power['output_source'] ?? ''),
                'input_json'                     => json_encode($power['input'] ?? [], JSON_THROW_ON_ERROR),
                'output_json'                    => json_encode($power['output'] ?? [], JSON_THROW_ON_ERROR),
                'sensors_json'                   => json_encode($power['sensors'] ?? [], JSON_THROW_ON_ERROR),
                'alarms_json'                    => json_encode($power['alarms'] ?? [], JSON_THROW_ON_ERROR),
                'last_seen'                      => time(),
            ],
            ['deviceid' => $deviceId]
        );
    }

    /** Replace the outlet list for a device. */
    private static function storeOutlets(string $deviceId, array $outlets): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $deviceRow = 0;
        foreach ($DB->request([
            'FROM'  => self::DEVICES_TABLE,
            'WHERE' => ['deviceid' => $deviceId],
            'LIMIT' => 1,
        ]) as $row) {
            $deviceRow = (int) $row['id'];
        }
        if ($deviceRow === 0) {
            return;
        }

        $seen = [];
        foreach ($outlets as $outlet) {
            if (!is_array($outlet)) {
                continue;
            }
            $index = (int) ($outlet['index'] ?? 0);
            if ($index <= 0) {
                continue;
            }
            $seen[] = $index;

            $DB->updateOrInsert(
                self::OUTLETS_TABLE,
                [
                    'name'      => (string) ($outlet['name'] ?? ''),
                    'state'     => (string) ($outlet['state'] ?? ''),
                    'current_a' => (float) ($outlet['current_a'] ?? 0),
                    'power_w'   => (int) ($outlet['power_w'] ?? 0),
                ],
                [
                    'plugin_glpinetscan_powerdevices_id' => $deviceRow,
                    'outlet_index'                       => $index,
                ]
            );
        }

        // Outlets that stopped being reported are gone — a strip was swapped
        // for a smaller one, or an expansion bank was removed. Leaving them
        // would show sockets that no longer exist.
        $where = ['plugin_glpinetscan_powerdevices_id' => $deviceRow];
        if ($seen !== []) {
            $where[] = ['NOT' => ['outlet_index' => $seen]];
        }
        $DB->delete(self::OUTLETS_TABLE, $where);
    }

    /**
     * Record the outlet count natively, via GLPI's Item_Plug.
     *
     * SNMP does not report the physical connector standard, so the plug is
     * named neutrally rather than guessed at — claiming "C13" because a device
     * has 24 sockets would be fabrication. The count is the part that is
     * actually known, and this is GLPI's native place to hold it.
     */
    private static function storeOutletCount(int $pdus_id, int $count): void
    {
        /** @var DBmysql $DB */
        global $DB;

        if ($count <= 0 || !Settings::get('record_outlet_count')) {
            return;
        }

        if (!class_exists(Item_Plug::class)) {
            self::storeOutletPlugs($pdus_id, $count);
            return;
        }

        $plugs_id = Dropdown::importExternal(Plug::class, 'Outlet (discovered)', 0);
        if (!is_int($plugs_id) || $plugs_id <= 0) {
            return;
        }

        $DB->updateOrInsert(
            Item_Plug::getTable(),
            ['number_plugs' => $count],
            ['plugs_id' => $plugs_id, 'itemtype' => PDU::class, 'items_id' => $pdus_id]
        );
    }

    /**
     * GLPI 12 dropped Item_Plug: a plug is now one row per physical outlet,
     * attached to its PDU through itemtype_main/items_id_main and numbered.
     * Outlets 1..count are kept as dynamic rows and anything numbered above
     * the count is removed, so a smaller replacement strip shrinks the list.
     * Rows a person added by hand (is_dynamic = 0) are never touched.
     */
    private static function storeOutletPlugs(int $pdus_id, int $count): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $pdu = new PDU();
        if (!$pdu->getFromDB($pdus_id)) {
            return;
        }

        $existing = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'number'],
            'FROM'   => Plug::getTable(),
            'WHERE'  => [
                'itemtype_main' => PDU::class,
                'items_id_main' => $pdus_id,
                'is_dynamic'    => 1,
            ],
        ]) as $row) {
            $existing[(int) $row['number']] = (int) $row['id'];
        }

        for ($number = 1; $number <= $count; $number++) {
            if (isset($existing[$number])) {
                continue;
            }
            $DB->insert(Plug::getTable(), [
                'name'          => sprintf('Outlet %d', $number),
                'number'        => $number,
                'itemtype_main' => PDU::class,
                'items_id_main' => $pdus_id,
                'entities_id'   => (int) $pdu->fields['entities_id'],
                'is_recursive'  => (int) ($pdu->fields['is_recursive'] ?? 0),
                'is_dynamic'    => 1,
                'date_creation' => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
                'date_mod'      => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
            ]);
        }

        $stale = array_values(array_filter(
            $existing,
            static fn(int $id, int $number): bool => $number > $count,
            ARRAY_FILTER_USE_BOTH
        ));
        if ($stale !== []) {
            $DB->delete(Plug::getTable(), ['id' => $stale]);
        }
    }

    /**
     * The stored state for a PDU, for the asset tab.
     *
     * @return array{device:array,outlets:array}|null
     */
    public static function forPdu(int $pdus_id): ?array
    {
        /** @var DBmysql $DB */
        global $DB;

        $device = null;
        foreach ($DB->request([
            'FROM'  => self::DEVICES_TABLE,
            'WHERE' => ['pdus_id' => $pdus_id],
            'LIMIT' => 1,
        ]) as $row) {
            $device = $row;
        }
        if ($device === null) {
            return null;
        }

        $outlets = [];
        foreach ($DB->request([
            'FROM'  => self::OUTLETS_TABLE,
            'WHERE' => ['plugin_glpinetscan_powerdevices_id' => (int) $device['id']],
            'ORDER' => 'outlet_index ASC',
        ]) as $row) {
            $outlets[] = $row;
        }

        return ['device' => $device, 'outlets' => $outlets];
    }

    /** @return array{ok:bool,errors:string[],itemtype:null,items_id:null} */
    private static function fail(string $message): array
    {
        return ['ok' => false, 'errors' => [$message], 'itemtype' => null, 'items_id' => null];
    }
}
