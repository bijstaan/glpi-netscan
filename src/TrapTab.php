<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use CommonGLPI;

/**
 * Notifications received from one device.
 *
 * The point of showing these next to the asset is that a trap answers a
 * question the asset record cannot: not "what is this device" but "what did it
 * do at 03:00". A linkDown followed by a linkUp four seconds later is a
 * flapping port, and nothing else in an inventory says so.
 *
 * Contents are shown, never trusted. A v1 or v2c trap is an unauthenticated
 * datagram, so what it says is displayed as the device's claim and is not
 * written into any asset field.
 */
final class TrapTab extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('Notifications', 'glpinetscan');
    }

    public static function getIcon()
    {
        return 'ti ti-bell';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || (int) $item->getID() <= 0) {
            return '';
        }

        $count = count(Traps::forItem($item->getType(), (int) $item->getID(), 1));

        // No tab on the many devices that have never sent one, rather than an
        // empty tab on every asset in the estate.
        return $count > 0 ? self::createTabEntry(self::getTypeName()) : '';
    }

    public static function displayTabContentForItem(
        CommonGLPI $item,
        $tabnum = 1,
        $withtemplate = 0
    ) {
        if (!$item instanceof CommonDBTM) {
            return false;
        }

        $rows = Traps::forItem($item->getType(), (int) $item->getID());
        if ($rows === []) {
            return true;
        }

        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='card mb-3 glpinetscan-surface'><div class='card-header'><h3 class='card-title'>"
            . __s('SNMP notifications', 'glpinetscan') . '</h3></div><div class="card-body">';
        echo "<p class='text-muted'>"
            . __s(
                'Sent by the device to a scanner. Shown as received: an SNMPv1 or v2c notification is unauthenticated, so nothing here is written into the asset. A notification does cause the device to be inventoried again on the next pass, where the facts are read from the device itself.',
                'glpinetscan'
            )
            . '</p>';

        echo "<div class='table-responsive'><table class='table table-sm'><thead><tr>"
            . '<th>' . __s('Received', 'glpinetscan') . '</th>'
            . '<th>' . __s('Notification', 'glpinetscan') . '</th>'
            . '<th>' . __s('Version', 'glpinetscan') . '</th>'
            . '<th>' . __s('Values', 'glpinetscan') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $name = (string) $row['trap_name'];
            $oid  = (string) $row['trap_oid'];

            echo '<tr><td>' . $e(date('Y-m-d H:i:s', (int) $row['received_at'])) . '</td>';
            echo '<td>' . ($name !== '' ? $e($name) : "<code class='small'>" . $e($oid) . '</code>');
            if ($name !== '') {
                echo "<div class='small text-muted'><code>" . $e($oid) . '</code></div>';
            }
            echo '</td>';
            echo '<td>' . $e($row['version']) . '</td>';

            $varbinds = json_decode((string) ($row['varbinds'] ?? '{}'), true) ?: [];
            echo "<td class='small'>";
            foreach ($varbinds as $vboid => $value) {
                echo '<div><code>' . $e($vboid) . '</code> = ' . $e($value) . '</div>';
            }
            echo '</td></tr>';
        }

        echo '</tbody></table></div></div></div>';

        return true;
    }
}
