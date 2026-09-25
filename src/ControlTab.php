<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use CommonGLPI;
use Html;
use NetworkPort;
use Session;
use User;

/**
 * The Control tab: where a device write is asked for, and where it is answered.
 *
 * Both halves are here on purpose. A control that can be issued from one screen
 * and whose outcome has to be hunted for on another is a control people stop
 * trusting, and the history is the only thing that distinguishes "the port is
 * down because I shut it" from "the port is down".
 *
 * The confirmation is a typed one rather than a click-through. Shutting a
 * switch port is exactly the kind of action that gets done to the wrong row of
 * a table, and an "are you sure?" that is dismissed by reflex prevents none of
 * that — typing the port's own name does.
 */
final class ControlTab extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('Control', 'glpinetscan');
    }

    public static function getIcon()
    {
        return 'ti ti-power';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || (int) $item->getID() <= 0) {
            return '';
        }

        // Hidden entirely unless this instance can control anything. A tab that
        // only ever says "switched off" is noise on every asset in the estate.
        if (!Control::enabled() || !Control::canControl()) {
            return '';
        }

        return self::createTabEntry(self::getTypeName());
    }

    public static function displayTabContentForItem(
        CommonGLPI $item,
        $tabnum = 1,
        $withtemplate = 0
    ) {
        if (!$item instanceof CommonDBTM) {
            return false;
        }

        if (!Control::enabled() || !Control::canControl()) {
            echo "<div class='alert alert-info glpinetscan-surface'>"
                . __s('Device control is switched off for this instance.', 'glpinetscan')
                . '</div>';
            return true;
        }

        $itemtype = $item->getType();
        $items_id = (int) $item->getID();

        $device = Control::deviceFor($itemtype, $items_id);
        if ($device === null) {
            echo "<div class='alert alert-warning glpinetscan-surface'>"
                . __s('This asset was not imported by a network scan, so there is no scanner that knows how to reach it.', 'glpinetscan')
                . '</div>';
            self::showHistory($itemtype, $items_id);
            return true;
        }

        if ((int) $device['write_credential'] <= 0) {
            echo "<div class='alert alert-warning glpinetscan-surface'>"
                . sprintf(
                    __s('The scan target %s has no write credential, so nothing on it can be switched. Set one on the target first.', 'glpinetscan'),
                    htmlspecialchars((string) $device['target_name'], ENT_QUOTES, 'UTF-8')
                )
                . '</div>';
            self::showHistory($itemtype, $items_id);
            return true;
        }

        self::showPortControls($itemtype, $items_id, $device);
        self::showHistory($itemtype, $items_id);

        return true;
    }

    /**
     * One row per port, with the state it can be put into.
     *
     * Only ports the scan actually recorded an ifIndex for. A port GLPI knows
     * about from somewhere else has no index to write against, and guessing one
     * would write to whichever interface happened to hold that number.
     *
     * @param array<string,mixed> $device
     */
    private static function showPortControls(string $itemtype, int $items_id, array $device): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $ports = [];
        foreach ($DB->request([
            'FROM'  => NetworkPort::getTable(),
            'WHERE' => ['itemtype' => $itemtype, 'items_id' => $items_id],
            'ORDER' => ['logical_number ASC'],
        ]) as $port) {
            if ((int) $port['logical_number'] > 0) {
                $ports[] = $port;
            }
        }

        echo "<div class='card mb-3 glpinetscan-surface'><div class='card-header'><h3 class='card-title'>"
            . __s('Ports', 'glpinetscan') . '</h3></div><div class="card-body">';

        echo "<p class='text-muted'>"
            . __s(
                'Changing a port to down disables it at the device. Shutting the wrong port can cut a site off — including the path the scanner reaches this device by, which would leave it uncontrollable from here.',
                'glpinetscan'
            )
            . '</p>';

        if ($ports === []) {
            echo "<p class='text-muted'>" . __s('No scanned ports on this asset.', 'glpinetscan') . '</p>';
            echo '</div></div>';
            return;
        }

        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr>"
            . '<th>' . __s('ifIndex', 'glpinetscan') . '</th>'
            . '<th>' . __s('Name', 'glpinetscan') . '</th>'
            . '<th>' . __s('Confirm by typing the port name', 'glpinetscan') . '</th>'
            . '<th></th></tr></thead><tbody>';

        foreach ($ports as $port) {
            $name  = (string) $port['name'];
            $index = (int) $port['logical_number'];

            echo '<tr><td>' . $e($index) . '</td><td>' . $e($name) . '</td>';
            echo "<td colspan='2'>";
            echo "<form method='post' action='"
                . Url::to('front/control.form.php') . "'"
                . " class='d-flex gap-2 align-items-center'>";
            echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
            echo Html::hidden('control_itemtype', ['value' => $itemtype]);
            echo Html::hidden('control_items_id', ['value' => $items_id]);
            echo Html::hidden('control_action', ['value' => 'port_admin']);
            echo Html::hidden('control_index', ['value' => $index]);
            echo Html::hidden('control_label', ['value' => $name]);

            // Typed rather than clicked. The mistake this prevents is acting on
            // the wrong row, and a confirmation the operator has to read the row
            // to satisfy is the only kind that prevents it.
            echo "<input class='form-control form-control-sm' style='max-width:16rem'"
                . " name='control_confirm' autocomplete='off' placeholder='" . $e($name) . "'>";
            echo "<button class='btn btn-sm btn-outline-secondary' name='control_value' value='up'>"
                . __s('Bring up', 'glpinetscan') . '</button>';
            echo "<button class='btn btn-sm btn-outline-danger' name='control_value' value='down'>"
                . __s('Shut down', 'glpinetscan') . '</button>';
            echo '</form></td></tr>';
        }

        echo '</tbody></table></div></div></div>';
    }

    /** What has been asked for, and what came of it. */
    private static function showHistory(string $itemtype, int $items_id): void
    {
        $rows = Control::forItem($itemtype, $items_id);
        if ($rows === []) {
            return;
        }

        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='card mb-3 glpinetscan-surface'><div class='card-header'><h3 class='card-title'>"
            . __s('Control history', 'glpinetscan') . '</h3></div><div class="card-body">';
        echo "<div class='table-responsive'><table class='table table-sm'><thead><tr>"
            . '<th>' . __s('Requested', 'glpinetscan') . '</th>'
            . '<th>' . __s('By', 'glpinetscan') . '</th>'
            . '<th>' . __s('Action', 'glpinetscan') . '</th>'
            . '<th>' . __s('State', 'glpinetscan') . '</th>'
            . '<th>' . __s('Result', 'glpinetscan') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $badge = match ((string) $row['state']) {
                Control::DONE    => 'bg-success',
                Control::FAILED  => 'bg-danger',
                Control::EXPIRED => 'bg-secondary',
                default          => 'bg-warning',
            };

            echo '<tr><td>' . $e(date('Y-m-d H:i:s', (int) $row['requested_at'])) . '</td>';
            echo '<td>' . $e(getUserName((int) $row['users_id'])) . '</td>';
            echo '<td>' . $e($row['label'] . ' → ' . $row['value']) . '</td>';
            echo "<td><span class='badge $badge'>" . $e($row['state']) . '</span></td>';
            echo "<td class='small'>" . $e($row['result']) . '</td></tr>';
        }

        echo '</tbody></table></div></div></div>';
    }
}
