<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use Dropdown;
use Phone;

/**
 * Turns a scanned VoIP handset into a native GLPI `Phone` asset.
 *
 * Like power devices, phones bypass core's inventory pipeline — and for the
 * same verified reason. `Glpi\Inventory\MainAsset\Phone` extends the base
 * MainAsset, whose `prepare()` reads `hardware` and `bios` (the *computer*
 * inventory shape); only `MainAsset\NetworkEquipment` reads `network_device`.
 * Feeding a netinventory payload to core with `itemtype: Phone` therefore
 * produces an asset with no name, MAC or serial, which the "Phone constraint
 * (name)" rule then refuses outright.
 *
 * Unlike PDU, `Phone` *is* in `$CFG_GLPI['asset_types']`, so once the asset and
 * its management port exist a switch's forwarding table resolves to it with no
 * extra configuration.
 */
final class PhoneIngest
{
    public const MAP_TABLE = 'glpi_plugin_glpinetscan_assetmap';

    /**
     * @param array $payload Full submission.
     * @return array{ok:bool,errors:string[],itemtype:?string,items_id:?int}
     */
    public static function submit(Scanner $scanner, array $payload, ?Target $target): array
    {
        $deviceId = trim((string) ($payload['deviceid'] ?? ''));
        $device   = $payload['content']['network_device'] ?? [];

        if ($deviceId === '' || !is_array($device)) {
            return self::fail('missing deviceid or device block');
        }

        $entities_id = (int) $scanner->fields['entities_id'];

        $phones_id = self::resolvePhone($deviceId, $device, $entities_id);
        if ($phones_id <= 0) {
            return self::fail('could not create or match the Phone asset');
        }

        self::remember($deviceId, $phones_id, $scanner->getID());

        // A desk phone reports two interfaces: the switch uplink and the PC
        // passthrough port the user's computer is plugged into. Both are real
        // and both are recorded — the uplink MAC is what the switch learns.
        AssetPorts::store(
            Phone::class,
            $phones_id,
            $entities_id,
            (array) ($payload['content']['network_ports'] ?? [])
        );

        return ['ok' => true, 'errors' => [], 'itemtype' => Phone::class, 'items_id' => $phones_id];
    }

    /**
     * Find or create the phone.
     *
     * Same ordering as the PDU ingest: the plugin's own mapping first because
     * it survives a rename and a readdressing, then serial. Name is not a match
     * key — desk phones are commonly named after the extension or the desk, and
     * those repeat across sites.
     */
    private static function resolvePhone(string $deviceId, array $device, int $entities_id): int
    {
        /** @var DBmysql $DB */
        global $DB;

        $phone = new Phone();

        $phones_id = 0;
        foreach ($DB->request([
            'FROM'  => self::MAP_TABLE,
            'WHERE' => ['deviceid' => $deviceId, 'itemtype' => Phone::class],
            'LIMIT' => 1,
        ]) as $row) {
            $phones_id = (int) $row['items_id'];
        }

        if ($phones_id > 0 && !$phone->getFromDB($phones_id)) {
            $phones_id = 0;
        }

        $serial = trim((string) ($device['serial'] ?? ''));
        if ($phones_id === 0 && $serial !== '') {
            if ($phone->getFromDBByCrit(['serial' => $serial, 'is_deleted' => 0])) {
                $phones_id = $phone->getID();
            }
        }

        $manufacturer = trim((string) ($device['manufacturer'] ?? ''));

        $input = array_filter([
            'name'             => trim((string) ($device['name'] ?? '')),
            'serial'           => $serial,
            'otherserial'      => trim((string) ($device['assettag'] ?? '')),
            'comment'          => self::comment($device),
            'contact'          => trim((string) ($device['contact'] ?? '')),
            'manufacturers_id' => self::dropdown('Manufacturer', $manufacturer, $entities_id),
            'phonemodels_id'   => self::dropdown('PhoneModel', $device['model'] ?? '', $entities_id),
            'phonetypes_id'    => self::dropdown('PhoneType', 'VoIP', $entities_id),
            'locations_id'     => self::dropdown('Location', $device['location'] ?? '', $entities_id),
            // `brand` is a plain string column on Phone, distinct from the
            // manufacturer dropdown; GLPI shows it on the form, so filling it
            // saves the reader a lookup.
            'brand'            => $manufacturer,
        ], static fn($v) => $v !== '' && $v !== 0 && $v !== null);

        if ($phones_id > 0) {
            $input['id'] = $phones_id;
            $phone->update($input);
            return $phones_id;
        }

        $input['entities_id'] = $entities_id;
        if (($input['name'] ?? '') === '') {
            $input['name'] = $deviceId;
        }

        $created = $phone->add($input);
        return $created ? (int) $created : 0;
    }

    private static function comment(array $device): string
    {
        $bits = array_filter([
            trim((string) ($device['description'] ?? '')),
            ($fw = trim((string) ($device['firmware'] ?? ''))) !== '' ? "Firmware: $fw" : '',
        ]);
        return implode("\n", $bits);
    }

    private static function dropdown(string $itemtype, $value, int $entities_id): int
    {
        $value = trim((string) $value);
        if ($value === '') {
            return 0;
        }
        $id = Dropdown::importExternal($itemtype, $value, $entities_id);
        return is_int($id) && $id > 0 ? $id : 0;
    }

    /** Record the deviceid → asset mapping. */
    private static function remember(string $deviceId, int $items_id, int $scanners_id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->updateOrInsert(
            self::MAP_TABLE,
            [
                'items_id'                       => $items_id,
                'plugin_glpinetscan_scanners_id' => $scanners_id,
                'last_seen'                      => time(),
            ],
            ['deviceid' => $deviceId, 'itemtype' => Phone::class]
        );
    }

    /** @return array{ok:bool,errors:string[],itemtype:null,items_id:null} */
    private static function fail(string $message): array
    {
        return ['ok' => false, 'errors' => [$message], 'itemtype' => null, 'items_id' => null];
    }
}
