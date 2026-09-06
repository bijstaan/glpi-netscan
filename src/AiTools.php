<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use GlpiPlugin\Glpiai\Tool;

/**
 * What SNMP scanning knows, offered to glpi-ai's assistant as tools.
 *
 * Deliberately *not* the network inventory. Ports, connections and link status
 * end up in GLPI's own tables, and glpi-ai reads them there — a site with no
 * scanner still has that data from the native agent, and duplicating it here
 * would give the model two sources that disagree.
 *
 * What is here is the part that has nowhere else to live: the traps a device
 * sent, the state of a UPS, and what the wireless is doing. Each answers a
 * question the inventory cannot, and each is the kind of thing a technician
 * would otherwise find by opening three tabs.
 *
 * The trap tool is the one worth having. "The link dropped at some point last
 * night" is answerable from an inventory only by inference; a linkDown trap
 * with a timestamp answers it outright.
 *
 * Gated on GLPI's `networking` right rather than on `config`, which is what
 * this plugin uses for its own scanner and target records. Those are
 * configuration and belong to an administrator; this is diagnostic data about
 * network devices, and whoever may look at a switch may reasonably look at what
 * it reported. Gating a UPS battery level behind the configuration right would
 * mean a technician could not ask why the site lost power.
 */
final class AiTools
{
    private const MAX_ROWS = 30;

    /** @return Tool[] */
    public static function all(): array
    {
        return [
            self::alarms(),
            self::power(),
            self::wireless(),
        ];
    }

    // --------------------------------------------------------------- alarms

    private static function alarms(): Tool
    {
        return new Tool(
            name: 'network_alarms',
            description: 'Recent SNMP traps: what network devices reported, and when. Use this '
                . 'for anything that happened at a time nobody was watching — a link that '
                . 'dropped overnight, a device that rebooted, a power event. An inventory can '
                . 'only tell you the state now; a trap has a timestamp.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'device' => [
                        'type'        => 'string',
                        'description' => 'Device name or IP address. Empty returns everything '
                            . 'recent.',
                    ],
                    'hours' => [
                        'type'        => 'integer',
                        'description' => 'How far back to look. Defaults to 24.',
                    ],
                ],
            ],
            handler: [self::class, 'runAlarms'],
            right: 'networking',
            source: 'glpinetscan'
        );
    }

    /** @param array<string,mixed> $arguments */
    public static function runAlarms(array $arguments): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $device = trim((string) ($arguments['device'] ?? ''));
        $hours  = max(1, min(720, (int) ($arguments['hours'] ?? 24)));

        $where = [
            'received_at' => ['>=', date('Y-m-d H:i:s', strtotime("-$hours hours"))],
        ];

        if ($device !== '') {
            $ids = self::deviceIds($device);

            $where['OR'] = [
                ['address' => ['LIKE', '%' . $device . '%']],
            ];

            if ($ids !== []) {
                $where['OR'][] = ['items_id' => $ids, 'itemtype' => 'NetworkEquipment'];
            }
        }

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => Traps::TABLE,
                'WHERE' => $where,
                'ORDER' => 'received_at DESC',
                'LIMIT' => self::MAX_ROWS,
            ]) as $row
        ) {
            $out[] = [
                'when'    => (string) $row['received_at'],
                'device'  => self::nameFor((string) $row['itemtype'], (int) $row['items_id'])
                    ?: (string) $row['address'],
                'trap'    => (string) ($row['trap_name'] ?: $row['trap_oid']),
                'details' => mb_substr((string) $row['varbinds'], 0, 300),
            ];
        }

        return [
            'traps' => $out,
            'note'  => $out === []
                ? sprintf(
                    'No traps in the last %d hours. That means nothing was reported, not that '
                    . 'nothing happened — a device only sends traps if it is configured to.',
                    $hours
                )
                : '',
        ];
    }

    // ---------------------------------------------------------------- power

    private static function power(): Tool
    {
        return new Tool(
            name: 'power_status',
            description: 'The state of a UPS or PDU: whether it is on mains or battery, charge '
                . 'level, estimated runtime, and any alarms. Use it when a site has just had a '
                . 'power event, or when equipment is behaving as though it lost power.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'device' => [
                        'type'        => 'string',
                        'description' => 'Name or part of one. Empty returns every power device.',
                    ],
                ],
            ],
            handler: [self::class, 'runPower'],
            right: 'networking',
            source: 'glpinetscan'
        );
    }

    /** @param array<string,mixed> $arguments */
    public static function runPower(array $arguments): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $device = trim((string) ($arguments['device'] ?? ''));
        $where  = [];

        if ($device !== '') {
            $where['deviceid'] = ['LIKE', '%' . $device . '%'];
        }

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => 'glpi_plugin_glpinetscan_powerdevices',
                'WHERE' => $where,
                'ORDER' => 'last_seen DESC',
                'LIMIT' => self::MAX_ROWS,
            ]) as $row
        ) {
            $entry = [
                'device'    => (string) $row['deviceid'],
                'kind'      => (string) $row['kind'],
                'source'    => (string) $row['output_source'],
                'battery'   => (string) $row['battery_status'],
                'last_seen' => (string) $row['last_seen'],
            ];

            foreach (
                [
                    'battery_charge'       => 'charge_percent',
                    'battery_runtime_min'  => 'runtime_minutes',
                    'seconds_on_battery'   => 'seconds_on_battery',
                    'battery_temp_c'       => 'temperature_c',
                ] as $column => $label
            ) {
                if ($row[$column] !== null && $row[$column] !== '') {
                    $entry[$label] = $row[$column] + 0;
                }
            }

            if ((int) $row['battery_replace'] === 1) {
                $entry['battery_needs_replacing'] = true;
            }

            $alarms = json_decode((string) $row['alarms_json'], true);
            if (is_array($alarms) && $alarms !== []) {
                $entry['alarms'] = array_slice($alarms, 0, 10);
            }

            $out[] = $entry;
        }

        return ['power_devices' => $out];
    }

    // ------------------------------------------------------------- wireless

    private static function wireless(): Tool
    {
        return new Tool(
            name: 'wireless_status',
            description: 'Access points, their firmware, radios and how many clients each has. '
                . 'Use it for "the wifi is bad in that room" — an AP carrying far more clients '
                . 'than its neighbours, or one that is down, is usually the answer.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'search' => [
                        'type'        => 'string',
                        'description' => 'AP name, location or part of one. Empty lists them all.',
                    ],
                ],
            ],
            handler: [self::class, 'runWireless'],
            right: 'networking',
            source: 'glpinetscan'
        );
    }

    /** @param array<string,mixed> $arguments */
    public static function runWireless(array $arguments): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $search = trim((string) ($arguments['search'] ?? ''));
        $where  = [];

        if ($search !== '') {
            $where['OR'] = [
                ['name'     => ['LIKE', '%' . $search . '%']],
                ['location' => ['LIKE', '%' . $search . '%']],
                ['ip'       => ['LIKE', '%' . $search . '%']],
            ];
        }

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => 'glpi_plugin_glpinetscan_accesspoints',
                'WHERE' => $where,
                'ORDER' => 'clients DESC',
                'LIMIT' => self::MAX_ROWS,
            ]) as $row
        ) {
            $out[] = [
                'name'      => (string) $row['name'],
                'location'  => (string) $row['location'],
                'ip'        => (string) $row['ip'],
                'model'     => (string) $row['model'],
                'firmware'  => (string) $row['firmware'],
                'status'    => (string) $row['status'],
                'radios'    => (int) $row['radios'],
                'clients'   => (int) $row['clients'],
                'last_seen' => (string) $row['last_seen'],
            ];
        }

        return [
            'access_points' => $out,
            'note'          => $out === []
                ? 'No access points have been scanned.'
                : 'Ordered by client count. A big gap between neighbouring APs usually means one '
                  . 'is doing the work of two.',
        ];
    }

    // --------------------------------------------------------------- shared

    /** @return int[] */
    private static function deviceIds(string $name): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $ids = [];
        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_networkequipments',
                'WHERE'  => ['name' => ['LIKE', '%' . $name . '%'], 'is_deleted' => 0]
                    + getEntitiesRestrictCriteria('glpi_networkequipments', 'entities_id', '', true),
                'LIMIT'  => 10,
            ]) as $row
        ) {
            $ids[] = (int) $row['id'];
        }

        return $ids;
    }

    private static function nameFor(string $itemtype, int $items_id): string
    {
        if ($itemtype === '' || $items_id <= 0) {
            return '';
        }

        $item = getItemForItemtype($itemtype);

        return $item !== false && $item->getFromDB($items_id)
            ? (string) $item->fields['name']
            : '';
    }
}
