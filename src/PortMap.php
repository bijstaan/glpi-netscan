<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use DBmysql;
use IPAddress;
use NetworkName;
use NetworkPort;

/**
 * The state of one device's ports, assembled for the faceplate view.
 *
 * Reads GLPI's own tables and nothing else. The plugin deliberately keeps no
 * copy of the port inventory — the scan submits it through core's inventory
 * pipeline and core owns it from there — so this is a projection, not a
 * second store, and it works just as well on a switch some other agent
 * inventoried.
 *
 * The one piece of arithmetic that is genuinely this plugin's is the layout:
 * SNMP gives ifIndex and an interface name, neither of which says where a port
 * sits on the front of the box. GLPI 11 can show a real faceplate, but only
 * from a stencil — a photograph of that exact model with every port zone
 * placed on it by hand, per model, before anything is visible. Deriving the
 * position from the name instead costs nothing to set up and is right for the
 * naming every switch vendor actually uses; see facePosition().
 */
final class PortMap
{
    /**
     * How a tile is coloured. Each is a whole reading of the same switch:
     * what is up, what VLANs are where, what negotiated at what speed, and
     * what is on the other end.
     */
    public const MODES = ['status', 'vlan', 'speed', 'link'];

    /**
     * Ports that are not on the front of the box.
     *
     * Aggregates, aliases and loopbacks are real ports with real state, but
     * they have no physical position, and laying them out as if they did
     * invents a faceplate the device does not have.
     */
    private const LOGICAL_INSTANTIATIONS = [
        'NetworkPortAggregate',
        'NetworkPortAlias',
        'NetworkPortLocal',
        'NetworkPortDialup',
    ];

    /** Two rows below this many ports looks like a diagram of nothing. */
    private const SINGLE_ROW_MAX = 8;

    /**
     * Everything the view needs about one asset's ports.
     *
     * @return array{
     *     groups: array<int,array{key:string,label:string,rows:int,ports:array<int,array<string,mixed>>}>,
     *     logical: array<int,array<string,mixed>>,
     *     ports: array<int,array<string,mixed>>,
     *     vlans: array<int,array<string,mixed>>,
     *     counts: array<string,int>,
     *     scanned: ?array<string,mixed>
     * }
     */
    public static function forItem(string $itemtype, int $items_id): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $ports = [];
        foreach ($DB->request([
            'FROM'  => NetworkPort::getTable(),
            'WHERE' => [
                'itemtype'   => $itemtype,
                'items_id'   => $items_id,
                'is_deleted' => 0,
            ],
            'ORDER' => ['logical_number ASC', 'name ASC'],
        ]) as $row) {
            $ports[(int) $row['id']] = self::basePort($row);
        }

        if ($ports === []) {
            return [
                'groups'  => [],
                'logical' => [],
                'ports'   => [],
                'vlans'   => [],
                'counts'  => ['total' => 0, 'up' => 0, 'down' => 0, 'disabled' => 0, 'connected' => 0],
                'scanned' => self::scanState($itemtype, $items_id),
            ];
        }

        $ids   = array_keys($ports);
        $vlans = self::attachVlans($ports, $ids);
        self::attachAddresses($ports, $ids);
        self::attachPeers($ports, $ids);
        self::attachAggregates($ports, $ids);
        self::attachMetrics($ports, $ids);

        return [
            'groups'  => self::groups($ports),
            'logical' => array_values(array_filter($ports, static fn($p) => $p['logical'])),
            'ports'   => $ports,
            'vlans'   => $vlans,
            'counts'  => self::counts($ports),
            'scanned' => self::scanState($itemtype, $items_id),
        ];
    }

    /** The fields that come straight off the port row. */
    private static function basePort(array $row): array
    {
        $name  = trim((string) $row['name']);
        $place = self::facePosition($name !== '' ? $name : (string) $row['ifdescr']);

        // `ifstatus` is the operational state and `ifinternalstatus` the
        // administrative one — IF-MIB's ifOperStatus and ifAdminStatus. The
        // distinction is the whole difference between "nothing is plugged in"
        // and "somebody shut this port", which is the first question asked of
        // a port that is down. Only the administrative one is carried
        // separately; the operational one is already in `state`.
        $admin = self::statusCode($row['ifinternalstatus'] ?? null);
        $state = self::stateOf($row['ifstatus'] ?? null, $row['ifinternalstatus'] ?? null);

        $instantiation = (string) $row['instantiation_type'];
        $logical = in_array($instantiation, self::LOGICAL_INSTANTIATIONS, true)
            || $place === null;

        $speed = (int) $row['ifspeed'];

        return [
            'id'          => (int) $row['id'],
            'index'       => (int) $row['logical_number'],
            'name'        => $name !== '' ? $name : sprintf('#%d', (int) $row['logical_number']),
            'ifdescr'     => trim((string) $row['ifdescr']),
            'ifalias'     => trim((string) $row['ifalias']),
            'mac'         => trim((string) $row['mac']),
            'duplex'      => trim((string) $row['portduplex']),
            'trunk'       => (int) $row['trunk'] === 1,
            'lastup'      => (string) ($row['lastup'] ?? ''),
            'iflastchange' => trim((string) $row['iflastchange']),
            'speed'       => $speed,
            'speed_label' => self::speedLabel($speed),
            'speed_band'  => self::speedBand($speed),
            'admin'       => $admin,
            'state'       => $state,
            'group'       => $place['prefix'] ?? '',
            'position'    => $place['position'] ?? null,
            'logical'     => $logical,
            'instantiation' => $instantiation,
            'vlans'       => [],
            'native'      => null,
            'vlan_color'  => null,
            'ips'         => [],
            'peer'        => null,
            'aggregate'   => null,
            'members'     => [],
            'metrics'     => null,
        ];
    }

    /**
     * IF-MIB status, as an int.
     *
     * Core writes these as strings into a varchar column and different
     * inventory sources have written both the number and nothing at all, so
     * an empty value is "unknown" rather than 0 — 0 is not a status any MIB
     * defines, and treating it as one paints every port from a source that
     * omits the field bright red.
     */
    private static function statusCode(mixed $value): int
    {
        $value = trim((string) ($value ?? ''));
        return $value === '' ? 4 : (int) $value;
    }

    /**
     * The one word the tile is coloured by.
     *
     * Administratively down wins over operationally down: a shut port is also
     * a port with no link, and reporting the consequence instead of the cause
     * is what sends somebody to check a patch lead for an hour.
     *
     * Takes the raw column values rather than codes so that the whole
     * reading — including what an absent status means — is one testable
     * step; see tests/portmap-layout.php.
     */
    public static function stateOf(mixed $ifstatus, mixed $ifinternalstatus): string
    {
        $oper  = self::statusCode($ifstatus);
        $admin = self::statusCode($ifinternalstatus);

        if ($admin === 2) {
            return 'disabled';
        }
        return match ($oper) {
            1       => 'up',
            2       => 'down',
            3       => 'testing',
            5       => 'dormant',
            6       => 'absent',
            7       => 'lowerdown',
            default => 'unknown',
        };
    }

    /** Human-readable status, for the detail panel and the table. */
    public static function stateLabel(string $state): string
    {
        return match ($state) {
            'up'        => __('Up', 'glpinetscan'),
            'down'      => __('Down', 'glpinetscan'),
            'disabled'  => __('Administratively down', 'glpinetscan'),
            'testing'   => __('Testing', 'glpinetscan'),
            'dormant'   => __('Dormant', 'glpinetscan'),
            'absent'    => __('Not present', 'glpinetscan'),
            'lowerdown' => __('Lower layer down', 'glpinetscan'),
            default     => __('Unknown', 'glpinetscan'),
        };
    }

    /**
     * Where a port sits on the front of the box, read out of its name.
     *
     * The trailing number is the position and everything before it is the
     * module — which is exactly how every vendor names ports, whatever else
     * they disagree about: GigabitEthernet0/1, Ethernet1/48, ge-0/0/7, Te1/1/4,
     * port12, swp3, eth0. Splitting on the *last* run of digits keeps the
     * module in the prefix, so a stacked switch draws one faceplate per member
     * instead of one row with two port 1s in it.
     *
     * A name with no trailing number (Management, Loopback, Null) has no
     * position, and the caller files it as logical rather than guessing.
     *
     * @return ?array{prefix:string,position:int}
     */
    public static function facePosition(string $name): ?array
    {
        $name = trim($name);
        if ($name === '' || !preg_match('/^(.*?)(\d+)$/', $name, $m)) {
            return null;
        }

        return [
            'prefix'   => rtrim($m[1], ' -_/.'),
            'position' => (int) $m[2],
        ];
    }

    /**
     * Per-port VLAN membership, and the palette index each VLAN is drawn in.
     *
     * The native VLAN is the untagged one — by definition there is at most
     * one, and it is what the tile is coloured by, because it is what an
     * ordinary device plugged into that port lands in.
     *
     * @param array<int,array<string,mixed>> $ports
     * @param int[] $ids
     * @return array<int,array<string,mixed>> VLANs in use, keyed by VLAN id.
     */
    private static function attachVlans(array &$ports, array $ids): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $vlans = [];
        foreach ($DB->request([
            'SELECT' => [
                'glpi_networkports_vlans.networkports_id AS port',
                'glpi_networkports_vlans.tagged AS tagged',
                'glpi_vlans.id AS id',
                'glpi_vlans.tag AS tag',
                'glpi_vlans.name AS name',
            ],
            'FROM'   => 'glpi_networkports_vlans',
            'INNER JOIN' => [
                'glpi_vlans' => [
                    'FKEY' => ['glpi_networkports_vlans' => 'vlans_id', 'glpi_vlans' => 'id'],
                ],
            ],
            'WHERE'  => ['glpi_networkports_vlans.networkports_id' => $ids],
            'ORDER'  => ['glpi_vlans.tag ASC'],
        ]) as $row) {
            $port = (int) $row['port'];
            if (!isset($ports[$port])) {
                continue;
            }

            $vlans[(int) $row['id']] ??= [
                'id'    => (int) $row['id'],
                'tag'   => (int) $row['tag'],
                'name'  => (string) $row['name'],
                'ports' => 0,
            ];
            $vlans[(int) $row['id']]['ports']++;

            $ports[$port]['vlans'][] = [
                'id'     => (int) $row['id'],
                'tag'    => (int) $row['tag'],
                'name'   => (string) $row['name'],
                'tagged' => (int) $row['tagged'] === 1,
            ];

            if ((int) $row['tagged'] !== 1) {
                $ports[$port]['native'] = (int) $row['id'];
            }
        }

        // Colours are assigned by VLAN tag rather than by first appearance, so
        // the same VLAN keeps the same colour across every switch in the
        // estate — which is the only thing that makes comparing two faceplates
        // possible.
        uasort($vlans, static fn($a, $b) => $a['tag'] <=> $b['tag']);
        $colour = 0;
        foreach ($vlans as $id => $vlan) {
            $vlans[$id]['color'] = $colour % 10;
            $colour++;
        }

        foreach ($ports as $id => $port) {
            if ($port['native'] !== null && isset($vlans[$port['native']])) {
                $ports[$id]['vlan_color'] = $vlans[$port['native']]['color'];
            }
        }

        return $vlans;
    }

    /**
     * Addresses, through the NetworkName that GLPI hangs them off.
     *
     * @param array<int,array<string,mixed>> $ports
     * @param int[] $ids
     */
    private static function attachAddresses(array &$ports, array $ids): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $names = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'items_id'],
            'FROM'   => NetworkName::getTable(),
            'WHERE'  => [
                'itemtype'   => NetworkPort::class,
                'items_id'   => $ids,
                'is_deleted' => 0,
            ],
        ]) as $row) {
            $names[(int) $row['id']] = (int) $row['items_id'];
        }

        if ($names === []) {
            return;
        }

        foreach ($DB->request([
            'SELECT' => ['name', 'items_id'],
            'FROM'   => IPAddress::getTable(),
            'WHERE'  => [
                'itemtype'   => NetworkName::class,
                'items_id'   => array_keys($names),
                'is_deleted' => 0,
            ],
        ]) as $row) {
            $port = $names[(int) $row['items_id']] ?? 0;
            if (isset($ports[$port])) {
                $ports[$port]['ips'][] = (string) $row['name'];
            }
        }
    }

    /**
     * What is on the other end of each port.
     *
     * The wiring table is symmetric and stores each link once, so both
     * columns have to be searched and the *opposite* id taken. Resolving the
     * peer's asset is what turns "port 7 is up" into "port 7 is the warehouse
     * access point", which is the question the faceplate exists to answer.
     *
     * @param array<int,array<string,mixed>> $ports
     * @param int[] $ids
     */
    private static function attachPeers(array &$ports, array $ids): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $peerOf = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_networkports_networkports',
            'WHERE' => [
                'OR' => [
                    ['networkports_id_1' => $ids],
                    ['networkports_id_2' => $ids],
                ],
            ],
        ]) as $row) {
            $a = (int) $row['networkports_id_1'];
            $b = (int) $row['networkports_id_2'];

            if (isset($ports[$a])) {
                $peerOf[$a] = $b;
            }
            if (isset($ports[$b])) {
                $peerOf[$b] = $a;
            }
        }

        if ($peerOf === []) {
            return;
        }

        $peerPorts = [];
        foreach ($DB->request([
            'FROM'  => NetworkPort::getTable(),
            'WHERE' => ['id' => array_values(array_unique($peerOf))],
        ]) as $row) {
            $peerPorts[(int) $row['id']] = $row;
        }

        // Peer assets are fetched one itemtype at a time rather than one row
        // at a time: a 48-port switch is one query per connected asset class,
        // not one per cable.
        $byType = [];
        foreach ($peerPorts as $row) {
            $byType[(string) $row['itemtype']][] = (int) $row['items_id'];
        }

        $assets = [];
        foreach ($byType as $type => $wanted) {
            if (!is_a($type, CommonDBTM::class, true)) {
                continue;
            }
            $item = getItemForItemtype($type);
            if (!$item instanceof CommonDBTM) {
                continue;
            }
            foreach ($DB->request([
                'SELECT' => ['id', 'name'],
                'FROM'   => $item->getTable(),
                'WHERE'  => ['id' => array_values(array_unique($wanted))],
            ]) as $row) {
                $assets[$type][(int) $row['id']] = (string) $row['name'];
            }
        }

        foreach ($peerOf as $portId => $peerId) {
            $peer = $peerPorts[$peerId] ?? null;
            if ($peer === null) {
                continue;
            }

            $type = (string) $peer['itemtype'];
            $id   = (int) $peer['items_id'];
            $name = $assets[$type][$id] ?? '';

            $ports[$portId]['peer'] = [
                'port_id'   => $peerId,
                'port_name' => trim((string) $peer['name']),
                'port_mac'  => trim((string) $peer['mac']),
                'itemtype'  => $type,
                'items_id'  => $id,
                'name'      => $name !== '' ? $name : sprintf('%s #%d', $type, $id),
                'type_name' => is_a($type, CommonDBTM::class, true) ? $type::getTypeName(1) : $type,
                'url'       => is_a($type, CommonDBTM::class, true) && $id > 0
                    ? $type::getFormURLWithID($id)
                    : '',
            ];
        }
    }

    /**
     * Which ports are bundled, and into what.
     *
     * Recorded on the aggregator as a list of member port ids, so the
     * membership a member needs to show has to be inverted out of it.
     *
     * @param array<int,array<string,mixed>> $ports
     * @param int[] $ids
     */
    private static function attachAggregates(array &$ports, array $ids): void
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($DB->request([
            'FROM'  => 'glpi_networkportaggregates',
            'WHERE' => ['networkports_id' => $ids],
        ]) as $row) {
            $aggregator = (int) $row['networkports_id'];
            if (!isset($ports[$aggregator])) {
                continue;
            }

            $members = json_decode((string) $row['networkports_id_list'], true);
            if (!is_array($members)) {
                continue;
            }

            foreach ($members as $memberId) {
                $memberId = (int) $memberId;
                if (!isset($ports[$memberId])) {
                    continue;
                }
                $ports[$aggregator]['members'][] = [
                    'id'   => $memberId,
                    'name' => $ports[$memberId]['name'],
                ];
                $ports[$memberId]['aggregate'] = [
                    'id'   => $aggregator,
                    'name' => $ports[$aggregator]['name'],
                ];
            }
        }
    }

    /**
     * The most recent counter sample per port.
     *
     * Core keeps one row per port per day. Only the latest is shown: this is
     * a faceplate, not a graph, and the number that belongs next to a port is
     * "has this one been taking errors", which the newest sample answers.
     *
     * @param array<int,array<string,mixed>> $ports
     * @param int[] $ids
     */
    private static function attachMetrics(array &$ports, array $ids): void
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($DB->request([
            'FROM'  => 'glpi_networkportmetrics',
            'WHERE' => ['networkports_id' => $ids],
            'ORDER' => ['date DESC'],
        ]) as $row) {
            $port = (int) $row['networkports_id'];
            if (!isset($ports[$port]) || $ports[$port]['metrics'] !== null) {
                continue;
            }

            $ports[$port]['metrics'] = [
                'date'      => (string) $row['date'],
                'inbytes'   => (int) $row['ifinbytes'],
                'outbytes'  => (int) $row['ifoutbytes'],
                'inerrors'  => (int) $row['ifinerrors'],
                'outerrors' => (int) $row['ifouterrors'],
            ];
        }
    }

    /**
     * The faceplates, one per module.
     *
     * Ports are laid out in column order — 1 above 2, 3 above 4 — which is
     * how the sockets are physically arranged on every switch with two rows
     * of them, and the reason a technician can find port 23 on the picture
     * without counting.
     *
     * @param array<int,array<string,mixed>> $ports
     * @return array<int,array<string,mixed>>
     */
    private static function groups(array $ports): array
    {
        $groups = [];
        foreach ($ports as $port) {
            if ($port['logical']) {
                continue;
            }
            $groups[$port['group']][] = $port;
        }

        $out = [];
        foreach ($groups as $key => $members) {
            usort($members, static fn($a, $b) => $a['position'] <=> $b['position']);

            $out[] = [
                'key'   => (string) $key,
                'label' => $key !== '' ? (string) $key : __('Ports', 'glpinetscan'),
                'rows'  => count($members) > self::SINGLE_ROW_MAX ? 2 : 1,
                'ports' => $members,
            ];
        }

        // Modules in the order the device numbers them, so a stack reads
        // top-to-bottom the way it is racked.
        usort($out, static fn($a, $b) => [$a['ports'][0]['index'], $a['key']]
            <=> [$b['ports'][0]['index'], $b['key']]);

        return $out;
    }

    /** @param array<int,array<string,mixed>> $ports */
    private static function counts(array $ports): array
    {
        $counts = ['total' => 0, 'up' => 0, 'down' => 0, 'disabled' => 0, 'connected' => 0];

        foreach ($ports as $port) {
            $counts['total']++;
            if (isset($counts[$port['state']])) {
                $counts[$port['state']]++;
            }
            if ($port['peer'] !== null) {
                $counts['connected']++;
            }
        }

        return $counts;
    }

    /**
     * When this plugin last looked at the device, if it was this plugin.
     *
     * A faceplate is a picture of the past, and how far in the past decides
     * whether it can be acted on. Absent for an asset another inventory
     * source owns — in which case the view still works, it just cannot say
     * how fresh it is.
     *
     * @return ?array{last_discovery:int,last_inventory:int,address:string,stale:bool}
     */
    private static function scanState(string $itemtype, int $items_id): ?array
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!$DB->tableExists(Discovery::TABLE)) {
            return null;
        }

        foreach ($DB->request([
            'FROM'  => Discovery::TABLE,
            'WHERE' => ['itemtype' => $itemtype, 'items_id' => $items_id],
            'ORDER' => ['last_inventory DESC'],
            'LIMIT' => 1,
        ]) as $row) {
            $last = (int) $row['last_inventory'];
            return [
                'last_discovery' => (int) $row['last_discovery'],
                'last_inventory' => $last,
                'address'        => (string) $row['address'],
                'stale'          => $last > 0 && (time() - $last) > Settings::get('stale_after'),
            ];
        }

        return null;
    }

    /** ifSpeed is bits per second, and nobody reads a switch port in bits. */
    public static function speedLabel(int $bps): string
    {
        if ($bps <= 0) {
            return '';
        }
        if ($bps >= 1000000000) {
            $value = $bps / 1000000000;
            return sprintf('%s Gb/s', rtrim(rtrim(number_format($value, 1, '.', ''), '0'), '.'));
        }
        if ($bps >= 1000000) {
            return sprintf('%d Mb/s', (int) round($bps / 1000000));
        }
        return sprintf('%d kb/s', (int) round($bps / 1000));
    }

    /** The band a port is coloured by in speed mode. */
    public static function speedBand(int $bps): string
    {
        return match (true) {
            $bps >= 10000000000 => '10g',
            $bps >= 1000000000  => '1g',
            $bps >= 100000000   => '100m',
            $bps > 0            => '10m',
            default             => 'none',
        };
    }
}
