<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use CommonDBTM;
use DBmysql;
use QueryExpression;

/**
 * Which assets this plugin checks warranties for, and what it knows about them.
 *
 * **The only plugin-specific file in this subsystem.** Everything else under
 * `Warranty/` is byte-identical to glpi-osquery's copy and is projected from it
 * by `tools/sync-warranty.sh` in the monorepo; this is the seam, because the
 * two plugins own different parts of an estate. glpi-osquery covers the
 * machines its agent inventoried; this covers what the SNMP scanner found.
 *
 * That is three separate mappings, because the plugin records where an asset
 * came from in three places for three good reasons:
 *
 * - `seen` — everything that went through GLPI's native inventory pipeline:
 *   switches, routers, printers and the occasional server;
 * - `assetmap` — phones, which bypass the native pipeline because core's
 *   MainAsset\Phone never reads `network_device` and builds a nameless asset;
 * - `powerdevices` — UPSs and rack PDUs, which bypass it because core has no
 *   MainAsset for PDU at all.
 *
 * They are queried separately and merged rather than unioned in SQL: each has
 * its own index and its own shape, and three small indexed queries are cheaper
 * to read and cheaper to run than one derived table.
 */
final class Scope
{
    /**
     * The itemtypes the scanner can produce that GLPI can hold a warranty on.
     *
     * `Unmanaged` is absent deliberately: it is not in `$CFG_GLPI['infocom_types']`,
     * so there is nowhere to write the answer even if a vendor had one.
     */
    public const ITEMTYPES = ['NetworkEquipment', 'Printer', 'Phone', 'PDU', 'Computer'];

    /**
     * Assets due for a lookup, oldest schedule first.
     *
     * Never-checked assets come first so a fresh install fills in from nothing
     * rather than re-checking the same few every run.
     *
     * @return array<int,array{itemtype:string,items_id:int}>
     */
    public static function due(int $limit): array
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!$DB->tableExists(Record::TABLE)) {
            return [];
        }

        $limit = max(1, $limit);
        $rows  = [];

        foreach (self::sources() as $source) {
            if (!$DB->tableExists($source['table'])) {
                continue;
            }

            foreach ($DB->request(self::dueCriteria($source, $limit)) as $row) {
                $itemtype = (string) $row['itemtype'];

                if (!in_array($itemtype, self::ITEMTYPES, true)) {
                    continue;
                }

                // The same asset can appear in more than one mapping — a device
                // that was discovered and later re-filed as a PDU, say — and
                // looking it up twice in one run would spend two calls against
                // a vendor quota for one answer.
                $rows[$itemtype . '#' . (int) $row['items_id']] = [
                    'itemtype' => $itemtype,
                    'items_id' => (int) $row['items_id'],
                    'due'      => $row['next_check_at'] ?? null,
                ];
            }
        }

        // Never checked first, then oldest schedule. Done here rather than in
        // SQL because the candidates come from three queries.
        uasort($rows, static function (array $a, array $b): int {
            if (($a['due'] === null) !== ($b['due'] === null)) {
                return $a['due'] === null ? -1 : 1;
            }

            return (string) $a['due'] <=> (string) $b['due'];
        });

        $out = [];
        foreach (array_slice(array_values($rows), 0, $limit) as $row) {
            $out[] = ['itemtype' => $row['itemtype'], 'items_id' => $row['items_id']];
        }

        return $out;
    }

    /**
     * Where this plugin records the assets it produced.
     *
     * `itemtype` is a column on two of them and a constant on the third, so it
     * is described rather than assumed.
     *
     * @return array<int,array{table:string,items:string,itemtype:?string,where:array}>
     */
    public static function sources(): array
    {
        return [
            [
                'table'    => 'glpi_plugin_glpinetscan_seen',
                'items'    => 'items_id',
                'itemtype' => null,
                'where'    => [],
            ],
            [
                'table'    => 'glpi_plugin_glpinetscan_assetmap',
                'items'    => 'items_id',
                'itemtype' => null,
                'where'    => [],
            ],
            [
                // PDUs carry their mapping on the row that also holds their
                // state, so the itemtype is implied rather than stored.
                'table'    => 'glpi_plugin_glpinetscan_powerdevices',
                'items'    => 'pdus_id',
                'itemtype' => 'PDU',
                'where'    => [],
            ],
        ];
    }

    /**
     * The due query for one mapping table.
     *
     * Separated so it can be built and run against a scratch table without
     * installing anything.
     *
     * @param array{table:string,items:string,itemtype:?string,where:array} $source
     * @return array<string,mixed>
     */
    public static function dueCriteria(array $source, int $limit): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $table = $source['table'];

        $itemtype_expression = $source['itemtype'] === null
            ? $DB->quoteName($table . '.itemtype')
            : $DB->quoteValue($source['itemtype']);

        $on = [
            Record::TABLE => 'items_id',
            $table        => $source['items'],
            [
                'AND' => [
                    Record::TABLE . '.itemtype' => new QueryExpression($itemtype_expression),
                ],
            ],
        ];

        $where = $source['where'] + [
            $table . '.' . $source['items'] => ['>', 0],
            'OR' => [
                [Record::TABLE . '.id'            => null],
                [Record::TABLE . '.next_check_at' => null],
                [Record::TABLE . '.next_check_at' => ['<=', new QueryExpression('NOW()')]],
            ],
        ];

        if ($source['itemtype'] === null) {
            $where[$table . '.itemtype'] = self::ITEMTYPES;
        }

        return [
            'SELECT'    => [
                new QueryExpression($itemtype_expression . ' AS ' . $DB->quoteName('itemtype')),
                new QueryExpression(
                    $DB->quoteName($table . '.' . $source['items']) . ' AS ' . $DB->quoteName('items_id')
                ),
                Record::TABLE . '.next_check_at AS next_check_at',
            ],
            'FROM'      => $table,
            'LEFT JOIN' => [Record::TABLE => ['ON' => $on]],
            'WHERE'     => $where,
            'ORDER'     => [
                new QueryExpression($DB->quoteName(Record::TABLE . '.next_check_at') . ' IS NULL DESC'),
                Record::TABLE . '.next_check_at ASC',
            ],
            'LIMIT'     => max(1, $limit),
        ];
    }

    /**
     * Everything a vendor might need about one asset.
     *
     * Returns null when the asset is gone, deleted, a template, or has nothing
     * that could be a serial — all of which are ordinary states, not errors.
     * Network kit reaching the second of those is common: a switch whose
     * `entPhysicalSerialNum` came back empty is imported by MAC and has no
     * serial to ask a vendor about.
     */
    public static function subjectFor(string $itemtype, int $items_id, ?array $settings = null): ?Subject
    {
        if (!in_array($itemtype, self::ITEMTYPES, true)) {
            return null;
        }

        $item = getItemForItemtype($itemtype);

        if (!$item instanceof CommonDBTM || !$item->getFromDB($items_id)) {
            return null;
        }

        if (!empty($item->fields['is_deleted']) || !empty($item->fields['is_template'])) {
            return null;
        }

        $serial = trim((string) ($item->fields['serial'] ?? ''));
        if ($serial === '') {
            return null;
        }

        $settings ??= Settings::all();

        [$model, $part_number] = self::model($itemtype, $item);

        $subject = new Subject(
            itemtype: $itemtype,
            items_id: $items_id,
            serial: $serial,
            manufacturer: self::dropdownName('glpi_manufacturers', (int) ($item->fields['manufacturers_id'] ?? 0)),
            model: $model,
            part_number: $part_number,
            country: (string) ($settings['warranty_default_country'] ?? ''),
            name: (string) ($item->fields['name'] ?? '')
        );

        return $subject->isLookupable() ? $subject : null;
    }

    /**
     * The asset's model name and its product number.
     *
     * The model name matters more here than it does on the endpoint side: SNMP
     * kit frequently has no manufacturer in GLPI at all, because the enterprise
     * OID never mapped to one, and "FortiGate-60F" in the model is then the
     * only thing that identifies the vendor.
     *
     * @return array{0:string,1:string}
     */
    private static function model(string $itemtype, CommonDBTM $item): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $foreign = strtolower($itemtype) . 'models_id';
        $table   = 'glpi_' . strtolower($itemtype) . 'models';

        $models_id = (int) ($item->fields[$foreign] ?? 0);

        if ($models_id <= 0 || !$DB->tableExists($table)) {
            return ['', ''];
        }

        foreach (
            $DB->request([
                'SELECT' => ['name', 'product_number'],
                'FROM'   => $table,
                'WHERE'  => ['id' => $models_id],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return [
                trim((string) ($row['name'] ?? '')),
                trim((string) ($row['product_number'] ?? '')),
            ];
        }

        return ['', ''];
    }

    private static function dropdownName(string $table, int $id): string
    {
        /** @var DBmysql $DB */
        global $DB;

        if ($id <= 0) {
            return '';
        }

        foreach (
            $DB->request([
                'SELECT' => ['name'],
                'FROM'   => $table,
                'WHERE'  => ['id' => $id],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return trim((string) $row['name']);
        }

        return '';
    }

    /** Is this asset one the scheduled sync is responsible for? */
    public static function covers(string $itemtype, int $items_id): bool
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!in_array($itemtype, self::ITEMTYPES, true)) {
            return false;
        }

        foreach (self::sources() as $source) {
            if (!$DB->tableExists($source['table'])) {
                continue;
            }

            $where = [$source['items'] => $items_id];

            if ($source['itemtype'] === null) {
                $where['itemtype'] = $itemtype;
            } elseif ($source['itemtype'] !== $itemtype) {
                continue;
            }

            if (countElementsInTable($source['table'], $where) > 0) {
                return true;
            }
        }

        return false;
    }
}
