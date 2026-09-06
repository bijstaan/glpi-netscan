<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use IPAddress;
use NetworkName;
use NetworkPort;
use NetworkPortEthernet;
use Unmanaged;

/**
 * Management network ports for assets the plugin creates itself.
 *
 * Shared by the PDU and Phone ingests, which both bypass core's inventory
 * pipeline and therefore have to build their own ports. Everything here is
 * generic over itemtype; only `$CFG_GLPI['networkport_types']` decides whether
 * an itemtype may hold ports at all, and both PDU and Phone are in it.
 *
 * Ports matter for two separate reasons, and the second is easy to miss: they
 * record how to reach the device, *and* they carry the MAC that lets a switch's
 * forwarding table resolve to this asset instead of inventing an Unmanaged
 * placeholder for hardware GLPI already knows about.
 */
final class AssetPorts
{
    /**
     * Create or update an asset's ports from inventory `network_ports`.
     *
     * @param array $ports `network_ports` entries.
     */
    public static function store(
        string $itemtype,
        int $items_id,
        int $entities_id,
        array $ports
    ): void {
        /** @var DBmysql $DB */
        global $DB;

        $seen = [];

        foreach ($ports as $port) {
            if (!is_array($port)) {
                continue;
            }

            $mac = strtolower(trim((string) ($port['mac'] ?? '')));
            $ips = array_values(array_filter(
                (array) ($port['ips'] ?? []),
                static fn($ip) => is_string($ip) && trim($ip) !== ''
            ));

            // A port with neither an address nor a MAC records nothing useful
            // and cannot take part in topology.
            if ($mac === '' && $ips === []) {
                continue;
            }

            $logical = (int) ($port['ifnumber'] ?? 0);
            $name    = trim((string) ($port['ifname'] ?? $port['ifdescr'] ?? ''));
            if ($name === '') {
                $name = 'management';
            }

            $netport = new NetworkPort();
            $networkports_id = 0;
            if ($netport->getFromDBByCrit([
                'itemtype'       => $itemtype,
                'items_id'       => $items_id,
                'logical_number' => $logical,
            ])) {
                $networkports_id = $netport->getID();
            }

            $input = [
                'itemtype'           => $itemtype,
                'items_id'           => $items_id,
                'entities_id'        => $entities_id,
                'logical_number'     => $logical,
                'name'               => $name,
                'mac'                => $mac,
                'instantiation_type' => NetworkPortEthernet::class,
                'is_dynamic'         => 1,
            ];
            if (isset($port['ifmtu'])) {
                $input['ifmtu'] = (int) $port['ifmtu'];
            }
            if (isset($port['ifspeed'])) {
                $input['ifspeed'] = (int) $port['ifspeed'];
            }

            if ($networkports_id > 0) {
                $input['id'] = $networkports_id;
                $netport->update($input);
            } else {
                $networkports_id = (int) $netport->add($input);
            }

            if ($networkports_id <= 0) {
                continue;
            }
            $seen[] = $networkports_id;

            self::storeAddresses($networkports_id, $entities_id, $name, $ips, $itemtype, $items_id);
            self::retirePlaceholders($mac, $networkports_id);
        }

        // Drop ports we created previously that the device no longer reports.
        // Scoped to is_dynamic so an operator's hand-added port survives.
        $where = [
            'itemtype'   => $itemtype,
            'items_id'   => $items_id,
            'is_dynamic' => 1,
        ];
        if ($seen !== []) {
            $where[] = ['NOT' => ['id' => $seen]];
        }
        foreach ($DB->request(['FROM' => NetworkPort::getTable(), 'WHERE' => $where]) as $row) {
            $stale = new NetworkPort();
            $stale->delete(['id' => (int) $row['id']], true);
        }
    }

    /**
     * Attach a port's addresses.
     *
     * GLPI models this as NetworkPort → NetworkName → IPAddress rather than
     * hanging an address off the port, so both intermediate objects must exist
     * for the address to be searchable.
     *
     * @param string[] $ips
     */
    private static function storeAddresses(
        int $networkports_id,
        int $entities_id,
        string $name,
        array $ips,
        string $itemtype,
        int $items_id
    ): void {
        /** @var DBmysql $DB */
        global $DB;

        $netname = new NetworkName();
        $networknames_id = 0;
        if ($netname->getFromDBByCrit([
            'itemtype' => NetworkPort::class,
            'items_id' => $networkports_id,
        ])) {
            $networknames_id = $netname->getID();
        }

        if ($networknames_id === 0) {
            if ($ips === []) {
                return;
            }
            $networknames_id = (int) $netname->add([
                'itemtype'    => NetworkPort::class,
                'items_id'    => $networkports_id,
                'entities_id' => $entities_id,
                'name'        => $name,
                'is_dynamic'  => 1,
            ]);
        }

        if ($networknames_id <= 0) {
            return;
        }

        $keep = [];
        foreach ($ips as $ip) {
            $ip = trim($ip);
            $address = new IPAddress();
            if ($address->getFromDBByCrit([
                'itemtype' => NetworkName::class,
                'items_id' => $networknames_id,
                'name'     => $ip,
            ])) {
                $keep[] = $address->getID();
                continue;
            }

            $id = (int) $address->add([
                'itemtype'     => NetworkName::class,
                'items_id'     => $networknames_id,
                'entities_id'  => $entities_id,
                'name'         => $ip,
                // mainitem lets GLPI trace an address back to the asset rather
                // than only to the network name.
                'mainitemtype' => $itemtype,
                'mainitems_id' => $items_id,
                'is_dynamic'   => 1,
            ]);
            if ($id > 0) {
                $keep[] = $id;
            }
        }

        $where = [
            'itemtype'   => NetworkName::class,
            'items_id'   => $networknames_id,
            'is_dynamic' => 1,
        ];
        if ($keep !== []) {
            $where[] = ['NOT' => ['id' => $keep]];
        }
        foreach ($DB->request(['FROM' => IPAddress::getTable(), 'WHERE' => $where]) as $row) {
            $stale = new IPAddress();
            $stale->delete(['id' => (int) $row['id']], true);
        }
    }

    /**
     * Remove the Unmanaged placeholder a switch created for this MAC.
     *
     * A switch that learns a MAC before the device itself has been scanned
     * makes GLPI invent an `Unmanaged` asset — that is what Unmanaged is for.
     * Once the device *has* been identified two ports carry the same address,
     * and the switch's link stays pointed at the placeholder because nothing
     * re-evaluates an existing wiring.
     *
     * Safe because Unmanaged means "seen, not identified": only Unmanaged
     * assets are touched, only on an exact MAC match, never a real asset.
     *
     * Skipped when core's MAC rules cannot resolve this itemtype anyway —
     * otherwise the switch simply recreates the placeholder on its next scan
     * and deleting it each time would churn asset ids for no gain. `Phone` is
     * in `$CFG_GLPI['asset_types']` and so always resolvable; `PDU` is not, and
     * depends on the `pdu_in_asset_types` setting.
     */
    public static function retirePlaceholders(string $mac, int $keepPortId): void
    {
        /** @var DBmysql $DB */
        global $DB;
        global $CFG_GLPI;

        if ($mac === '') {
            return;
        }

        foreach ($DB->request([
            'FROM'  => NetworkPort::getTable(),
            'WHERE' => [
                'mac'      => $mac,
                'itemtype' => Unmanaged::class,
                ['NOT' => ['id' => $keepPortId]],
            ],
        ]) as $row) {
            $owner = new NetworkPort();
            if (!$owner->getFromDB($keepPortId)) {
                continue;
            }
            $ownerType = (string) $owner->fields['itemtype'];

            if (!in_array($ownerType, $CFG_GLPI['asset_types'] ?? [], true)) {
                continue;
            }

            $placeholder = new Unmanaged();
            if (!$placeholder->getFromDB((int) $row['items_id'])) {
                continue;
            }
            // Purge rather than soft-delete: a placeholder in the bin still
            // owns the MAC and would keep winning the lookup.
            $placeholder->delete(['id' => $placeholder->getID()], true);
        }
    }
}
