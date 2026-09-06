<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use CommonGLPI;

/**
 * Wireless tab on a network device.
 *
 * Shown on any NetworkEquipment the scanner has recorded wireless state for,
 * which is both halves of the estate: a controller lists the access points it
 * manages, and a standalone AP lists the networks it broadcasts.
 *
 * The access points are also assets in their own right — each row links to one
 * — because this tab answers "what is this controller doing" while the asset
 * answers "what is this box and where is it", and those are different
 * questions asked by different people.
 */
final class WirelessTab extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('Wireless', 'glpinetscan');
    }

    public static function getIcon()
    {
        return 'ti ti-wifi';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || (int) $item->getID() <= 0) {
            return '';
        }

        $state = WirelessIngest::forItem((int) $item->getID(), $item->getType());
        $count = count($state['ssids']) + count($state['aps']);

        // No tab at all on the overwhelming majority of network devices, rather
        // than an empty one on every switch in the estate.
        return $count > 0 ? self::createTabEntry(self::getTypeName(), $count) : '';
    }

    public static function displayTabContentForItem(
        CommonGLPI $item,
        $tabnum = 1,
        $withtemplate = 0
    ) {
        if (!$item instanceof CommonDBTM) {
            return false;
        }

        $state = WirelessIngest::forItem((int) $item->getID(), $item->getType());
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        if ($state['ssids'] !== []) {
            echo "<div class='card mb-3 glpinetscan-surface'><div class='card-header'><h3 class='card-title'>"
                . __s('Networks', 'glpinetscan') . '</h3></div><div class="card-body">';
            echo "<table class='table table-sm'><thead><tr><th>" . __s('SSID', 'glpinetscan')
                . '</th><th>' . __s('Clients', 'glpinetscan') . '</th></tr></thead><tbody>';
            foreach ($state['ssids'] as $ssid) {
                echo '<tr><td>' . $e($ssid['name']) . '</td><td>' . $e($ssid['clients']) . '</td></tr>';
            }
            echo '</tbody></table></div></div>';
        }

        if ($state['aps'] !== []) {
            echo "<div class='card mb-3 glpinetscan-surface'><div class='card-header'><h3 class='card-title'>"
                . __s('Access points', 'glpinetscan') . '</h3></div><div class="card-body">';
            echo "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr>"
                . '<th>' . __s('Name', 'glpinetscan') . '</th>'
                . '<th>' . __s('Model', 'glpinetscan') . '</th>'
                . '<th>' . __s('Serial number', 'glpinetscan') . '</th>'
                . '<th>' . __s('Status', 'glpinetscan') . '</th>'
                . '<th>' . __s('Clients', 'glpinetscan') . '</th>'
                . '<th>' . __s('Radios', 'glpinetscan') . '</th>'
                . '<th>' . __s('Location', 'glpinetscan') . '</th>'
                . '</tr></thead><tbody>';

            foreach ($state['aps'] as $ap) {
                $name = $e($ap['name']);
                // Linked to the asset when it exists. It usually does: the AP is
                // submitted as an ordinary NetworkEquipment in the same run.
                if ((int) $ap['accesspoints_id'] > 0) {
                    $name = "<a href='" . \NetworkEquipment::getFormURLWithID((int) $ap['accesspoints_id'])
                        . "'>" . $name . '</a>';
                }

                echo '<tr><td>' . $name . '</td>';
                echo '<td>' . $e($ap['model']) . '</td>';
                echo '<td>' . $e($ap['serial']) . '</td>';
                echo '<td>' . $e($ap['status']) . '</td>';
                echo '<td>' . $e($ap['clients']) . '</td>';

                // Radio detail as one line each: band, channel, clients. It is
                // the answer to "which band is busy", which the per-AP total
                // cannot give.
                $radios = json_decode((string) ($ap['radio_detail'] ?? '[]'), true) ?: [];
                $lines = [];
                foreach ($radios as $radio) {
                    $bits = array_filter([
                        trim((string) ($radio['band'] ?? '')),
                        ((int) ($radio['channel'] ?? 0)) > 0
                            ? sprintf(__('ch %d', 'glpinetscan'), (int) $radio['channel']) : '',
                        sprintf(__('%d clients', 'glpinetscan'), (int) ($radio['clients'] ?? 0)),
                        trim((string) ($radio['status'] ?? '')),
                    ]);
                    $lines[] = $e(implode(', ', $bits));
                }
                echo "<td class='small'>" . (implode('<br>', $lines) ?: $e($ap['radios'])) . '</td>';
                echo '<td>' . $e($ap['location']) . '</td></tr>';
            }

            echo '</tbody></table></div></div></div>';
        }

        return true;
    }
}
