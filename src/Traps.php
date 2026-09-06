<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;

/**
 * SNMP notifications received by a scanner.
 *
 * Two uses, and the second is why this is worth having at all.
 *
 * A trap is a record: linkDown at 03:00 explains a lot the next morning, and
 * nothing else in an asset database can tell you that.
 *
 * A trap is also the best possible input to the discovery/inventory split. The
 * change counters that decide whether a device is worth walking are guesses
 * made from the outside, at whatever interval the sweep happens to run. A trap
 * is the device saying "something changed" the moment it does — so a received
 * trap clears the device's last-inventory stamp and the next discovery pass
 * walks it, without waiting for the interval.
 *
 * What a trap is never allowed to do is *assert* anything. A v1 or v2c trap is
 * an unauthenticated UDP datagram with a community string in it, trivially
 * forged by anything that can route a packet to the listener. So its contents
 * are stored and shown, never written into an asset. The worst a forged trap
 * achieves is an SNMP walk of a device the scanner was already allowed to walk.
 */
final class Traps
{
    public const TABLE = 'glpi_plugin_glpinetscan_traps';

    /** How many notifications to keep per device before the oldest go. */
    public const KEEP_PER_DEVICE = 200;

    /**
     * Record a batch of notifications from one scanner.
     *
     * @param array<int,array<string,mixed>> $notifications
     * @return int how many were stored
     */
    public static function record(Scanner $scanner, array $notifications): int
    {
        /** @var DBmysql $DB */
        global $DB;

        $stored = 0;
        $touched = [];

        foreach ($notifications as $n) {
            if (!is_array($n)) {
                continue;
            }

            $address = trim((string) ($n['address'] ?? ''));
            if ($address === '' || filter_var($address, FILTER_VALIDATE_IP) === false) {
                continue;
            }

            // Resolved through what discovery recorded, so a trap from an
            // address the scanner has never seen is stored but attached to
            // nothing — visible, and unable to affect an asset it may have
            // nothing to do with.
            $seen = self::deviceAt($address);

            $DB->insert(self::TABLE, [
                'plugin_glpinetscan_scanners_id' => $scanner->getID(),
                'address'     => substr($address, 0, 63),
                'deviceid'    => substr((string) ($seen['deviceid'] ?? ''), 0, 255),
                'itemtype'    => substr((string) ($seen['itemtype'] ?? ''), 0, 100),
                'items_id'    => (int) ($seen['items_id'] ?? 0),
                'trap_oid'    => substr((string) ($n['trap_oid'] ?? ''), 0, 255),
                'trap_name'   => substr((string) ($n['trap_name'] ?? ''), 0, 128),
                'version'     => substr((string) ($n['version'] ?? ''), 0, 16),
                'varbinds'    => json_encode($n['varbinds'] ?? [], JSON_THROW_ON_ERROR),
                'received_at' => (int) ($n['received_at'] ?? time()),
            ]);

            $stored++;

            if (($seen['deviceid'] ?? '') !== '') {
                $touched[(string) $seen['deviceid']] = true;
            }
        }

        // One re-inventory per device per batch, not per trap. A flapping link
        // produces hundreds of notifications and warrants exactly one walk.
        foreach (array_keys($touched) as $deviceId) {
            self::requestInventory($deviceId);
        }

        self::prune();

        return $stored;
    }

    /**
     * Ask for this device to be walked on the next discovery pass.
     *
     * Implemented by clearing the last-inventory stamp rather than by queuing
     * anything: the split already walks a device it has no record of walking,
     * so this reuses a rule that is tested instead of adding a second one that
     * would have to agree with it.
     */
    private static function requestInventory(string $deviceId): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->update(Discovery::TABLE, ['last_inventory' => 0], ['deviceid' => $deviceId]);
    }

    /**
     * Which device was last discovered at an address.
     *
     * @return array<string,mixed>
     */
    private static function deviceAt(string $address): array
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($DB->request([
            'FROM'  => Discovery::TABLE,
            'WHERE' => ['address' => $address],
            'ORDER' => ['last_discovery DESC'],
            'LIMIT' => 1,
        ]) as $row) {
            return $row;
        }

        return [];
    }

    /**
     * Keep the table from growing without limit.
     *
     * A trap log is a stream, not an inventory: the useful part is the recent
     * past, and a switch with a flapping port would otherwise fill a disk with
     * copies of the same sentence.
     */
    private static function prune(): void
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($DB->request([
            'SELECT'  => ['address', new \QueryExpression('COUNT(*) AS ' . $DB->quoteName('cpt'))],
            'FROM'    => self::TABLE,
            'GROUPBY' => ['address'],
            'HAVING'  => ['cpt' => ['>', self::KEEP_PER_DEVICE]],
        ]) as $row) {
            $cut = null;
            $offset = 0;
            foreach ($DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::TABLE,
                'WHERE'  => ['address' => $row['address']],
                'ORDER'  => ['id DESC'],
                'LIMIT'  => 1,
                'START'  => self::KEEP_PER_DEVICE,
            ]) as $edge) {
                $cut = (int) $edge['id'];
            }
            unset($offset);

            if ($cut !== null) {
                $DB->delete(self::TABLE, ['address' => $row['address'], 'id' => ['<=', $cut]]);
            }
        }
    }

    /**
     * Notifications for one asset, newest first.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function forItem(string $itemtype, int $items_id, int $limit = 50): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $out = [];
        foreach ($DB->request([
            'FROM'  => self::TABLE,
            'WHERE' => ['itemtype' => $itemtype, 'items_id' => $items_id],
            'ORDER' => ['id DESC'],
            'LIMIT' => $limit,
        ]) as $row) {
            $out[] = $row;
        }

        return $out;
    }
}
