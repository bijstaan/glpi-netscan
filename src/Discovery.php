<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;

/**
 * The discovery/inventory split: deciding which devices are worth walking.
 *
 * A full inventory walk costs between 86 and 157 times what a discovery probe
 * does — measured against the SNMP simulators, with tiny tables over
 * loopback; a 48-port switch across a WAN is far worse. So a sweep's cost is
 * dominated by fully walking the devices that answer, not by probing the
 * addresses that do not, and the saving comes from not re-walking a device that
 * has not changed.
 *
 * The decision lives here, on the server, rather than on the scanner. GLPI is
 * the only party that knows what it already holds, when it last held it, and
 * whether someone has since deleted the asset — a scanner keeping its own notes
 * would happily skip a device whose asset had been removed, and GLPI would stay
 * empty with nothing to explain why.
 *
 * A device is walked when any of these is true:
 *
 *   - it has never been walked, or the asset it produced no longer exists
 *   - it rebooted since the last walk (uptime went backwards)
 *   - a standard change counter moved: an interface was created or deleted,
 *     the layering between interfaces changed, or the physical inventory did
 *   - the last walk is older than the target's inventory interval
 *
 * That last rule is what bounds the staleness the counters cannot see. None of
 * them moves when a port goes down or a MAC moves between ports, and both of
 * those matter to GLPI — so "nothing looks changed" is never allowed to mean
 * "never walk again".
 */
final class Discovery
{
    public const TABLE = 'glpi_plugin_glpinetscan_seen';

    /**
     * Record a discovery submission and decide whether a full walk is wanted.
     *
     * @param array<string,mixed> $payload one discovery submission
     * @return bool whether the scanner should walk this device now
     */
    public static function consider(array $payload, int $targets_id, int $inventoryInterval): bool
    {
        /** @var DBmysql $DB */
        global $DB;

        $deviceId = trim((string) ($payload['deviceid'] ?? ''));
        if ($deviceId === '') {
            return false;
        }

        $markers = (array) ($payload['markers'] ?? []);
        $now     = time();

        $row = null;
        foreach ($DB->request([
            'FROM'  => self::TABLE,
            'WHERE' => ['deviceid' => $deviceId],
            'LIMIT' => 1,
        ]) as $found) {
            $row = $found;
        }

        $wanted = self::shouldInventory($row, $markers, $now, $inventoryInterval)
            || !self::assetStillExists($row);

        $DB->updateOrInsert(self::TABLE, [
            'plugin_glpinetscan_targets_id' => $targets_id,
            'address'                       => substr((string) ($payload['scan_address'] ?? ''), 0, 63),
            'last_discovery'                => $now,
            'uptime_ticks'                  => (int) ($markers['uptime_ticks'] ?? 0),
            'iftable_last_change'           => (int) ($markers['iftable_last_change'] ?? 0),
            'ifstack_last_change'           => (int) ($markers['ifstack_last_change'] ?? 0),
            'entity_last_change'            => (int) ($markers['entity_last_change'] ?? 0),
        ], ['deviceid' => $deviceId]);

        return $wanted;
    }

    /**
     * The decision itself, given what was recorded last time.
     *
     * Public and free of any database access so it can be tested directly —
     * these four rules are the whole feature, and getting one wrong means
     * either a scanner that never refreshes or one that never saves anything.
     *
     * @param array<string,mixed>|null $row     the previous discovery, if any
     * @param array<string,mixed>      $markers the counters just reported
     */
    public static function shouldInventory(?array $row, array $markers, int $now, int $inventoryInterval): bool
    {
        // Never seen, or seen but never walked.
        if ($row === null || (int) $row['last_inventory'] <= 0) {
            return true;
        }

        // Bounded staleness. Zero or less disables the interval rule entirely,
        // leaving only the change counters — which is a deliberate choice an
        // operator can make for a range of appliances that never change, and a
        // bad one for a switch estate.
        if ($inventoryInterval > 0 && ($now - (int) $row['last_inventory']) >= $inventoryInterval) {
            return true;
        }

        $uptime = (int) ($markers['uptime_ticks'] ?? 0);
        $previous = (int) $row['uptime_ticks'];

        // A reboot. Uptime going backwards is the signal, and it matters twice
        // over: the device may have come back different, and every other
        // counter here is measured against sysUpTime, so they are incomparable
        // across the restart and cannot be trusted until after a walk.
        if ($uptime > 0 && $previous > 0 && $uptime < $previous) {
            return true;
        }

        foreach (['iftable_last_change', 'ifstack_last_change', 'entity_last_change'] as $key) {
            $current = (int) ($markers[$key] ?? 0);
            if ($current > 0 && $current !== (int) $row[$key]) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the asset the last full walk produced is still in GLPI.
     *
     * Checked against what that walk actually created, recorded at the time,
     * rather than against `glpi_agents`: GLPI creates no agent row for a device
     * inventoried this way, so a deviceid lookup there never matches and every
     * device would be re-walked on every pass — which is exactly what happened
     * before this was written that way.
     *
     * The case it catches is an operator deleting an asset to force a clean
     * re-import. Without it the scanner would keep discovering the device,
     * decide nothing had changed, and never rebuild what was deleted — the
     * failure mode that makes people stop trusting an inventory tool.
     */
    private static function assetStillExists(?array $row): bool
    {
        if ($row === null) {
            return false;
        }

        $itemtype = (string) ($row['itemtype'] ?? '');
        $items_id = (int) ($row['items_id'] ?? 0);

        // Nothing recorded yet — an older row, or a device never walked. The
        // caller's other rules decide; claiming the asset is missing here would
        // force a walk that may not be needed.
        if ($itemtype === '' || $items_id <= 0) {
            return true;
        }

        if (!class_exists($itemtype) || !is_a($itemtype, \CommonDBTM::class, true)) {
            return false;
        }

        $item = new $itemtype();
        if (!$item->getFromDB($items_id)) {
            return false;
        }

        return (int) ($item->fields['is_deleted'] ?? 0) === 0;
    }

    /** Record that a device was walked in full, and what that produced. */
    public static function recordInventory(string $deviceId, ?string $itemtype, ?int $items_id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        if ($deviceId === '') {
            return;
        }

        $fields = ['last_inventory' => time()];
        if ($itemtype !== null && $itemtype !== '' && $items_id !== null && $items_id > 0) {
            $fields['itemtype'] = $itemtype;
            $fields['items_id'] = $items_id;
        }

        $DB->updateOrInsert(self::TABLE, $fields, ['deviceid' => $deviceId]);
    }

    /**
     * Forget everything known about a target's devices.
     *
     * Used when a target's ranges change: the devices behind it may not be the
     * same devices, and a stale "last walked" would suppress the walk that
     * would have found that out.
     */
    public static function forgetTarget(int $targets_id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->delete(self::TABLE, ['plugin_glpinetscan_targets_id' => $targets_id]);
    }
}
