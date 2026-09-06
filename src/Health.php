<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use SNMPCredential;

/**
 * Readiness checks for the config page.
 *
 * Every check here corresponds to a way the pipeline fails *silently* — the
 * scan runs, the payload is accepted, and no asset appears. Both of the big
 * ones are GLPI configuration rather than plugin bugs, and neither is
 * discoverable from the outside, so they are surfaced where an operator will
 * look before filing the bug.
 */
final class Health
{
    public const OK    = 'ok';
    public const WARN  = 'warn';
    public const ERROR = 'error';

    /**
     * @return array<int,array{state:string,title:string,detail:string}>
     */
    public static function checks(): array
    {
        return [
            self::nativeInventory(),
            self::importRules(),
            self::credentials(),
            self::targets(),
            self::scanners(),
            self::power(),
        ];
    }

    /**
     * Power devices are reported separately because they do not appear in the
     * inventory counts at all — they bypass core's pipeline entirely, so an
     * operator looking for "did my UPSes import?" has nowhere else to look.
     */
    private static function power(): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $ups = 0;
        $pdu = 0;
        $stale = 0;
        $cutoff = time() - Settings::get('stale_after');

        foreach ($DB->request(['FROM' => PowerIngest::DEVICES_TABLE]) as $row) {
            if ((string) $row['kind'] === 'ups') {
                $ups++;
            } else {
                $pdu++;
            }
            if ((int) $row['last_seen'] < $cutoff) {
                $stale++;
            }
        }

        if ($ups + $pdu === 0) {
            return [
                'state'  => self::OK,
                'title'  => __('No power devices discovered yet', 'glpinetscan'),
                'detail' => __('UPSes and rack PDUs become GLPI PDU assets with a Power state tab.', 'glpinetscan'),
            ];
        }

        $detail = $stale > 0
            ? sprintf(__('%d have not reported recently.', 'glpinetscan'), $stale)
            : __('Readings are current.', 'glpinetscan');

        // Worth saying only once power devices actually exist: until then the
        // trade-off is abstract.
        if (!Settings::get('pdu_in_asset_types')) {
            $detail .= ' ' . __(
                'Switch ports facing these devices will link to "Unmanaged" placeholders rather than the assets themselves — see the setting below.',
                'glpinetscan'
            );
        }

        return [
            'state'  => $stale > 0 ? self::WARN : self::OK,
            'title'  => sprintf(
                __('%1$d UPS and %2$d PDU tracked', 'glpinetscan'),
                $ups,
                $pdu
            ),
            'detail' => $detail,
        ];
    }

    private static function nativeInventory(): array
    {
        if (Ingest::nativeInventoryEnabled()) {
            return [
                'state'  => self::OK,
                'title'  => __('GLPI native inventory is enabled', 'glpinetscan'),
                'detail' => __('Scan results are imported by GLPI itself.', 'glpinetscan'),
            ];
        }

        return [
            'state'  => self::ERROR,
            'title'  => __('GLPI native inventory is disabled', 'glpinetscan'),
            'detail' => __(
                'Enable it under Setup > General > Inventory. Until then GLPI accepts scan results and discards them, so scans appear to succeed while no asset is ever created.',
                'glpinetscan'
            ),
        ];
    }

    /**
     * GLPI's stock rules only import a NetworkEquipment that has a serial
     * number: "NetworkEquipment import (by mac)" ships disabled, so anything
     * without a serial falls through to "import denied".
     *
     * Plenty of switches expose no ENTITY-MIB serial, so on a default install
     * this is the single most likely reason a scan finds devices and imports
     * none of them.
     */
    private static function importRules(): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $byMac = false;
        $bySerial = false;

        foreach (
            $DB->request([
                'FROM'  => 'glpi_rules',
                'WHERE' => ['sub_type' => ['LIKE', '%RuleImportAsset%'], 'is_active' => 1],
            ]) as $row
        ) {
            $name = (string) $row['name'];
            if (stripos($name, 'NetworkEquipment import (by mac)') !== false) {
                $byMac = true;
            }
            if (stripos($name, 'NetworkEquipment import (by serial)') !== false) {
                $bySerial = true;
            }
        }

        if ($byMac) {
            return [
                'state'  => self::OK,
                'title'  => __('Network equipment can be imported by MAC address', 'glpinetscan'),
                'detail' => __('Devices without a serial number will still be imported.', 'glpinetscan'),
            ];
        }

        return [
            'state'  => self::WARN,
            'title'  => __('Only network equipment with a serial number will be imported', 'glpinetscan'),
            'detail' => sprintf(
                __(
                    'The rule "NetworkEquipment import (by mac)" is disabled, so a device that exposes no serial via ENTITY-MIB is filed under Administration > Refused equipment instead of being imported. Enable it under Administration > Rules > Rules for asset import. (Import by serial is currently %s.)',
                    'glpinetscan'
                ),
                $bySerial ? __('enabled', 'glpinetscan') : __('also disabled', 'glpinetscan')
            ),
        ];
    }

    private static function credentials(): array
    {
        $count = countElementsInTable(SNMPCredential::getTable(), ['is_deleted' => 0]);

        if ($count > 0) {
            return [
                'state'  => self::OK,
                'title'  => sprintf(__('%d SNMP credential(s) defined', 'glpinetscan'), $count),
                'detail' => __('Managed under Setup > SNMP credentials.', 'glpinetscan'),
            ];
        }

        return [
            'state'  => self::ERROR,
            'title'  => __('No SNMP credentials defined', 'glpinetscan'),
            'detail' => __('Add one under Setup > SNMP credentials, then attach it to a scan target.', 'glpinetscan'),
        ];
    }

    private static function targets(): array
    {
        $count = countElementsInTable(Target::getTable(), ['is_active' => 1, 'is_deleted' => 0]);

        if ($count > 0) {
            return [
                'state'  => self::OK,
                'title'  => sprintf(__('%d active scan target(s)', 'glpinetscan'), $count),
                'detail' => '',
            ];
        }

        return [
            'state'  => self::WARN,
            'title'  => __('No active scan targets', 'glpinetscan'),
            'detail' => __('Scanners will poll and be given nothing to do.', 'glpinetscan'),
        ];
    }

    private static function scanners(): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $total = 0;
        $fresh = 0;
        $cutoff = time() - Settings::get('stale_after');

        foreach (
            $DB->request([
                'FROM'  => Scanner::getTable(),
                'WHERE' => ['is_active' => 1, 'is_deleted' => 0],
            ]) as $row
        ) {
            $total++;
            if ((int) $row['last_seen'] > $cutoff) {
                $fresh++;
            }
        }

        if ($total === 0) {
            return [
                'state'  => self::WARN,
                'title'  => __('No scanners enrolled', 'glpinetscan'),
                'detail' => __('Install the agent and point it at this server with an enrollment secret.', 'glpinetscan'),
            ];
        }

        if ($fresh === 0) {
            return [
                'state'  => self::WARN,
                'title'  => sprintf(__('%d scanner(s), none seen recently', 'glpinetscan'), $total),
                'detail' => __('Check the agent is running and can reach this server.', 'glpinetscan'),
            ];
        }

        return [
            'state'  => self::OK,
            'title'  => sprintf(__('%1$d of %2$d scanner(s) active', 'glpinetscan'), $fresh, $total),
            'detail' => '',
        ];
    }
}
