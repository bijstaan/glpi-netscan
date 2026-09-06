<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use Session;

/**
 * Device control: the only part of this plugin that writes to hardware.
 *
 * Everything else here reads. This does not, and that difference deserves more
 * care than a feature flag, because the same mechanism that reboots a stuck
 * access point can black out a rack or cut the link the scanner itself is
 * reachable through.
 *
 * Four gates, all of which must be open before a single SNMP SET leaves a
 * scanner:
 *
 *  1. **A global setting**, off by default. Installing this plugin does not
 *     make an estate writable.
 *  2. **A separate write credential per target.** Not the community the scanner
 *     reads with — a distinct SNMPCredential an operator chooses deliberately.
 *     Reusing the read credential would mean any community that happened to be
 *     read-write silently made the whole estate controllable.
 *  3. **A right**, checked when the action is queued rather than when it runs.
 *  4. **An expiry.** A queued action that the scanner does not collect within a
 *     few minutes is abandoned, not held. The alternative is a click that gets
 *     forgotten and then power-cycles a rack when a scanner reconnects hours
 *     later, which is the failure people rightly fear from this kind of tool.
 *
 * Actions are queued rather than performed inline because GLPI usually cannot
 * reach the device network at all — the scanner is the thing with a route. That
 * the queue also produces an audit trail, and a place to see what happened, is
 * a consequence worth having.
 */
final class Control
{
    public const TABLE = 'glpi_plugin_glpinetscan_actions';

    public const PENDING = 'pending';
    public const SENT    = 'sent';
    public const DONE    = 'done';
    public const FAILED  = 'failed';
    public const EXPIRED = 'expired';

    /**
     * How long a queued action stays collectable.
     *
     * Deliberately short. A scanner polls on its own interval, so this is
     * "collected on the next poll or two, or not at all" — long enough for the
     * normal case and far too short for an action to surprise anyone later.
     */
    public const TTL_SECONDS = 600;

    /**
     * The controls this plugin knows how to perform.
     *
     * `port_admin` is built in because ifAdminStatus is standard, is indexed by
     * ifIndex like everything else about a port, and means the same thing on
     * every device that implements IF-MIB. Anything vendor-specific — outlet
     * switching, PoE — comes from a profile's `control` section instead, and
     * deliberately so: getting the OID or the index wrong on those does not
     * fail, it turns off the wrong thing.
     *
     * @return array<string,array{label:string,oid:string,values:array<string,int>,confirm:string}>
     */
    public static function builtins(): array
    {
        return [
            'port_admin' => [
                'label'   => __('Port administrative state', 'glpinetscan'),
                'oid'     => '1.3.6.1.2.1.2.2.1.7',
                'values'  => ['up' => 1, 'down' => 2],
                'confirm' => __('This changes the administrative state of a switch port. Shutting the wrong port can cut a site off, including the path this scanner reaches the device by.', 'glpinetscan'),
            ],
        ];
    }

    /** Whether control is enabled at all on this instance. */
    public static function enabled(): bool
    {
        return (bool) Settings::get('allow_control');
    }

    /**
     * Whether the current user may queue an action.
     *
     * Deliberately `config` UPDATE — an administrative right — rather than
     * UPDATE on the asset. Being allowed to correct a switch's serial number in
     * an asset register is not the same as being allowed to shut its ports, and
     * where the two differ the safer reading is the right one. A dedicated
     * plugin right assignable per profile is the natural refinement.
     */
    public static function canControl(): bool
    {
        return (bool) Session::haveRight('config', UPDATE);
    }

    /**
     * Queue an action for a scanner to perform.
     *
     * @return string|null an error message, or null when queued
     */
    public static function queue(
        int $scanners_id,
        int $targets_id,
        string $deviceId,
        string $itemtype,
        int $items_id,
        string $action,
        string $index,
        string $value,
        string $label
    ): ?string {
        /** @var DBmysql $DB */
        global $DB;

        if (!self::enabled()) {
            return __('Device control is switched off. Enable it under Setup > Network scanning.', 'glpinetscan');
        }
        if (!self::canControl()) {
            return __('You do not have the right to control devices.', 'glpinetscan');
        }
        if ($deviceId === '' || $action === '' || $value === '') {
            return __('Incomplete action.', 'glpinetscan');
        }

        $target = new Target();
        if (!$target->getFromDB($targets_id) || !$target->writeCredentialID()) {
            return __('This device belongs to no scan target with a write credential. Set one on the target before controlling it.', 'glpinetscan');
        }

        $now = time();

        // The address discovery last saw this device on. Taken from what the
        // scanner reported rather than from anything a caller supplies: an
        // action is aimed at a device GLPI has actually seen, at the address it
        // was seen on.
        $address = '';
        foreach ($DB->request([
            'SELECT' => ['address'],
            'FROM'   => Discovery::TABLE,
            'WHERE'  => ['deviceid' => $deviceId],
            'LIMIT'  => 1,
        ]) as $seen) {
            $address = (string) $seen['address'];
        }

        if ($address === '') {
            return __('This device has no address on record yet. It must be discovered by a scan before it can be controlled.', 'glpinetscan');
        }

        $DB->insert(self::TABLE, [
            'plugin_glpinetscan_scanners_id' => $scanners_id,
            'plugin_glpinetscan_targets_id'  => $targets_id,
            'deviceid'    => $deviceId,
            'address'     => $address,
            'itemtype'    => $itemtype,
            'items_id'    => $items_id,
            'action'      => $action,
            'target_index' => $index,
            'value'       => $value,
            'label'       => mb_substr($label, 0, 255),
            'state'       => self::PENDING,
            'users_id'    => (int) (Session::getLoginUserID() ?: 0),
            'requested_at' => $now,
            'expires_at'  => $now + self::TTL_SECONDS,
        ]);

        return null;
    }

    /**
     * Hand a scanner the actions it should perform now.
     *
     * Expiring first, in the same call: an action is only ever collected if it
     * is still within its window, and the sweep that would have collected it is
     * the natural moment to notice that it is not.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function claim(int $scanners_id): array
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!self::enabled()) {
            return [];
        }

        self::expireStale();

        $out = [];
        foreach ($DB->request([
            'FROM'  => self::TABLE,
            'WHERE' => [
                // A target may be pinned to one scanner or left at 0 meaning
                // "whichever scanner asks", exactly as scan jobs are. An action
                // queued for an unpinned target is collectable by any scanner.
                'OR'    => [
                    ['plugin_glpinetscan_scanners_id' => $scanners_id],
                    ['plugin_glpinetscan_scanners_id' => 0],
                ],
                'state' => self::PENDING,
            ],
            'ORDER' => ['id ASC'],
            'LIMIT' => 25,
        ]) as $row) {
            $target = new Target();
            if (!$target->getFromDB((int) $row['plugin_glpinetscan_targets_id'])) {
                continue;
            }

            $credential = $target->writeCredential();
            if ($credential === null) {
                // The write credential was removed after the action was queued.
                self::complete((int) $row['id'], false, 'the target no longer has a write credential');
                continue;
            }

            // The OID is resolved by the scanner, not here. A profile's control
            // section is matched on the device's sysObjectID, and the scanner is
            // the only party that knows it — the queue holds the *intent*
            // ("this port, down"), which is also what makes the audit row
            // readable a year later.
            $out[] = [
                'action_id'  => (int) $row['id'],
                'address'    => (string) $row['address'],
                'action'     => (string) $row['action'],
                'index'      => (string) $row['target_index'],
                'value'      => (string) $row['value'],
                'label'      => (string) $row['label'],
                'credential' => $credential,
                'options'    => [
                    'port'       => (int) $target->fields['snmp_port'],
                    'timeout_ms' => (int) $target->fields['timeout_ms'],
                    'retries'    => (int) $target->fields['retries'],
                ],
            ];

            $DB->update(self::TABLE, ['state' => self::SENT], ['id' => (int) $row['id']]);
        }

        return $out;
    }

    /**
     * Whether an action was queued for this scanner.
     *
     * Checked before accepting a result: without it, any enrolled scanner could
     * mark another's actions as done and hide a write that never happened.
     */
    public static function belongsTo(int $id, int $scanners_id): bool
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($DB->request([
            'SELECT' => ['id'],
            'FROM'   => self::TABLE,
            'WHERE'  => [
                'id' => $id,
                'OR' => [
                    ['plugin_glpinetscan_scanners_id' => $scanners_id],
                    ['plugin_glpinetscan_scanners_id' => 0],
                ],
            ],
            'LIMIT'  => 1,
        ]) as $_) {
            return true;
        }

        return false;
    }

    /** Record how an action turned out. */
    public static function complete(int $id, bool $ok, string $result): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->update(self::TABLE, [
            'state'        => $ok ? self::DONE : self::FAILED,
            'result'       => mb_substr($result, 0, 500),
            'completed_at' => time(),
        ], ['id' => $id]);
    }

    /**
     * Abandon actions nobody collected in time.
     *
     * The point of the whole expiry rule: an action that was queued and then
     * not performed must end up visibly abandoned, never quietly performed
     * later against a device whose situation has since changed.
     */
    public static function expireStale(): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->update(self::TABLE, [
            'state'        => self::EXPIRED,
            'result'       => 'not collected before it expired',
            'completed_at' => time(),
        ], [
            'state'      => [self::PENDING, self::SENT],
            'expires_at' => ['<', time()],
        ]);
    }

    /**
     * Which scanner and target know how to reach this asset.
     *
     * Resolved through what discovery recorded rather than through the asset,
     * because the asset says nothing about which scanner can reach it — and on
     * a multi-site estate that is the whole question.
     *
     * @return array<string,mixed>|null
     */
    public static function deviceFor(string $itemtype, int $items_id): ?array
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach ($DB->request([
            'FROM'  => Discovery::TABLE,
            'WHERE' => ['itemtype' => $itemtype, 'items_id' => $items_id],
            'ORDER' => ['last_discovery DESC'],
            'LIMIT' => 1,
        ]) as $seen) {
            $target = new Target();
            if (!$target->getFromDB((int) $seen['plugin_glpinetscan_targets_id'])) {
                return null;
            }

            return [
                'deviceid'         => (string) $seen['deviceid'],
                'address'          => (string) $seen['address'],
                'targets_id'       => $target->getID(),
                'target_name'      => (string) $target->fields['name'],
                'scanners_id'      => (int) $target->fields['plugin_glpinetscan_scanners_id'],
                'write_credential' => $target->writeCredentialID(),
            ];
        }

        return null;
    }

    /**
     * The action history for one asset.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function forItem(string $itemtype, int $items_id, int $limit = 20): array
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
