<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonGLPI;
use Html;
use PDU;

/**
 * "Power state" tab on a PDU asset.
 *
 * Shows the last reading the scanner took: battery, input and output lines,
 * environmental sensors, active alarms and the outlet map. None of this lives
 * in GLPI's asset tables because none of it is inventory — but it is exactly
 * what someone looking at a UPS in GLPI wants to know, and having to open a
 * separate monitoring tool to answer "is it on battery?" is the gap this
 * closes.
 */
final class PowerTab extends CommonGLPI
{
    public static string $rightname = 'config';

    public static function getTypeName($nb = 0)
    {
        return __('Power state', 'glpinetscan');
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!($item instanceof PDU) || $item->isNewItem()) {
            return '';
        }
        if (PowerIngest::forPdu($item->getID()) === null) {
            return '';
        }
        return self::getTypeName();
    }

    public static function displayTabContentForItem(
        CommonGLPI $item,
        $tabnum = 1,
        $withtemplate = 0
    ) {
        if (!($item instanceof PDU)) {
            return false;
        }

        $state = PowerIngest::forPdu($item->getID());
        if ($state === null) {
            return false;
        }

        self::render($state);
        return true;
    }

    private static function render(array $state): void
    {
        $device  = $state['device'];
        $outlets = $state['outlets'];
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        $lastSeen = (int) $device['last_seen'];
        $stale    = $lastSeen > 0 && (time() - $lastSeen) > Settings::get('stale_after');

        echo "<div class='container-fluid glpinetscan-surface'>";

        echo "<p class='text-muted'>";
        if ($lastSeen > 0) {
            printf(
                __s('Last reading %s', 'glpinetscan'),
                Html::convDateTime(date('Y-m-d H:i:s', $lastSeen))
            );
            if ($stale) {
                echo " <span class='badge bg-warning text-white'>" . __s('stale', 'glpinetscan') . '</span>';
            }
        } else {
            echo __s('No reading recorded yet.', 'glpinetscan');
        }
        echo '</p>';

        // --- alarms first: they are the reason someone opened this tab ---
        $alarms = json_decode((string) $device['alarms_json'], true) ?: [];
        if ($alarms !== []) {
            echo "<div class='alert alert-warning'><strong>"
                . __s('Active alarms', 'glpinetscan') . '</strong><ul class="mb-0">';
            foreach ($alarms as $alarm) {
                echo '<li>' . $e($alarm) . '</li>';
            }
            echo '</ul></div>';
        }

        // --- battery ---
        if ($device['kind'] === 'ups') {
            echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
                . __s('Battery', 'glpinetscan') . '</h3></div><div class="card-body">';

            $source = (string) $device['output_source'];
            if ($source !== '') {
                // "battery" here means the UPS is carrying the load — the one
                // state worth making impossible to miss.
                $class = $source === 'battery' ? 'bg-danger' : 'bg-success';
                echo "<p><span class='badge $class text-white'>"
                    . $e(__('Output source', 'glpinetscan') . ': ' . $source)
                    . '</span></p>';
            }

            echo "<div class='row'>";
            self::stat(__s('Charge', 'glpinetscan'), $device['battery_charge'] . ' %');
            self::stat(__s('Runtime', 'glpinetscan'), $device['battery_runtime_min'] . ' min');
            self::stat(__s('Voltage', 'glpinetscan'), rtrim(rtrim((string) $device['battery_voltage'], '0'), '.') . ' V');
            self::stat(__s('Temperature', 'glpinetscan'), $device['battery_temp_c'] . ' °C');
            echo '</div>';

            if ((int) $device['battery_replace'] === 1) {
                echo "<div class='alert alert-danger mb-0'>"
                    . __s('The UPS reports that its battery needs replacing.', 'glpinetscan')
                    . '</div>';
            }
            if ((int) $device['seconds_on_battery'] > 0) {
                echo "<div class='alert alert-warning mb-0'>"
                    . sprintf(
                        __s('Running on battery for %d seconds.', 'glpinetscan'),
                        (int) $device['seconds_on_battery']
                    )
                    . '</div>';
            }
            echo '</div></div>';
        }

        self::lines(__s('Input', 'glpinetscan'), json_decode((string) $device['input_json'], true) ?: []);
        self::lines(__s('Output', 'glpinetscan'), json_decode((string) $device['output_json'], true) ?: []);

        // --- sensors ---
        $sensors = json_decode((string) $device['sensors_json'], true) ?: [];
        if ($sensors !== []) {
            echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
                . __s('Sensors', 'glpinetscan') . '</h3></div><div class="card-body">';
            echo "<table class='table table-sm mb-0'><thead><tr><th>" . __s('Name') . '</th><th>'
                . __s('Type', 'glpinetscan') . '</th><th class="text-end">' . __s('Value', 'glpinetscan')
                . '</th></tr></thead><tbody>';
            foreach ($sensors as $sensor) {
                echo '<tr><td>' . $e($sensor['name'] ?? '') . '</td>';
                echo '<td>' . $e($sensor['type'] ?? '') . '</td>';
                echo "<td class='text-end'>" . $e($sensor['value'] ?? '') . ' '
                    . $e($sensor['units'] ?? '') . '</td></tr>';
            }
            echo '</tbody></table></div></div>';
        }

        // --- outlets ---
        if ($outlets !== []) {
            echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
                . sprintf(__s('Outlets (%d)', 'glpinetscan'), count($outlets)) . '</h3></div>';
            echo '<div class="card-body">';
            echo "<table class='table table-sm mb-0'><thead><tr><th>#</th><th>" . __s('Name')
                . '</th><th>' . __s('State', 'glpinetscan') . '</th><th class="text-end">'
                . __s('Current', 'glpinetscan') . '</th><th class="text-end">'
                . __s('Power', 'glpinetscan') . '</th></tr></thead><tbody>';
            foreach ($outlets as $outlet) {
                $state = (string) $outlet['state'];
                $badge = match ($state) {
                    'on'  => 'bg-success',
                    'off' => 'bg-secondary',
                    default => 'bg-warning',
                };
                echo '<tr>';
                echo '<td>' . (int) $outlet['outlet_index'] . '</td>';
                echo '<td>' . $e($outlet['name']) . '</td>';
                echo "<td><span class='badge $badge text-white'>" . $e($state !== '' ? $state : '?') . '</span></td>';
                echo "<td class='text-end'>"
                    . ((float) $outlet['current_a'] > 0 ? $e($outlet['current_a']) . ' A' : '—') . '</td>';
                echo "<td class='text-end'>"
                    . ((int) $outlet['power_w'] > 0 ? (int) $outlet['power_w'] . ' W' : '—') . '</td>';
                echo '</tr>';
            }
            echo '</tbody></table></div></div>';
        }

        echo '</div>';
    }

    private static function lines(string $title, array $lines): void
    {
        if ($lines === []) {
            return;
        }
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
            . $e($title) . '</h3></div><div class="card-body">';
        echo "<table class='table table-sm mb-0'><thead><tr><th>" . __s('Line', 'glpinetscan')
            . '</th><th class="text-end">' . __s('Voltage', 'glpinetscan')
            . '</th><th class="text-end">' . __s('Current', 'glpinetscan')
            . '</th><th class="text-end">' . __s('Power', 'glpinetscan')
            . '</th><th class="text-end">' . __s('Frequency', 'glpinetscan')
            . '</th><th class="text-end">' . __s('Load', 'glpinetscan')
            . '</th></tr></thead><tbody>';

        foreach ($lines as $line) {
            $cell = static fn($v, $unit) => $v ? $v . ' ' . $unit : '—';
            echo '<tr>';
            echo '<td>' . (int) ($line['index'] ?? 0) . '</td>';
            echo "<td class='text-end'>" . $e($cell($line['voltage_v'] ?? 0, 'V')) . '</td>';
            echo "<td class='text-end'>" . $e($cell($line['current_a'] ?? 0, 'A')) . '</td>';
            echo "<td class='text-end'>" . $e($cell($line['power_w'] ?? 0, 'W')) . '</td>';
            echo "<td class='text-end'>" . $e($cell($line['frequency_hz'] ?? 0, 'Hz')) . '</td>';
            echo "<td class='text-end'>" . $e($cell($line['load_percent'] ?? 0, '%')) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table></div></div>';
    }

    private static function stat(string $label, string $value): void
    {
        echo "<div class='col-6 col-md-3 mb-2'>";
        echo "<div class='text-muted small'>" . $label . '</div>';
        echo "<div class='fs-3'>" . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '</div>';
        echo '</div>';
    }
}
