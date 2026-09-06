<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Queue one device write, from the Control tab.
 *
 * A separate script rather than a handler inside the tab: the tab renders
 * inside GLPI's own item form, and posting there would hand the request to
 * GLPI's asset-update machinery, which knows nothing about this and would
 * either ignore it or treat the fields as asset edits.
 */

use GlpiPlugin\Glpinetscan\Control;

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

Session::checkLoginUser();
Html::popHeader(__('Device control', 'glpinetscan'), $_SERVER['PHP_SELF']);

$itemtype = (string) ($_POST['control_itemtype'] ?? '');
$items_id = (int) ($_POST['control_items_id'] ?? 0);

if ($itemtype === '' || $items_id <= 0 || !class_exists($itemtype)) {
    Session::addMessageAfterRedirect(__('Unknown asset.', 'glpinetscan'), false, ERROR);
    Html::back();
}

$device = Control::deviceFor($itemtype, $items_id);
if ($device === null) {
    Session::addMessageAfterRedirect(
        __('This asset was not imported by a network scan, so no scanner knows how to reach it.', 'glpinetscan'),
        false,
        ERROR
    );
    Html::back();
}

$label   = (string) ($_POST['control_label'] ?? '');
$confirm = trim((string) ($_POST['control_confirm'] ?? ''));

// The typed confirmation. Compared against the label of the very row the button
// belonged to, so confirming one port does not authorise another — which is the
// mistake this exists to prevent, and the reason it is not a click-through.
if ($confirm === '' || $confirm !== $label) {
    Session::addMessageAfterRedirect(
        sprintf(
            __('Nothing was changed. To confirm, type %s exactly.', 'glpinetscan'),
            '"' . $label . '"'
        ),
        false,
        ERROR
    );
    Html::back();
}

$error = Control::queue(
    (int) $device['scanners_id'],
    (int) $device['targets_id'],
    (string) $device['deviceid'],
    $itemtype,
    $items_id,
    (string) ($_POST['control_action'] ?? ''),
    (string) ($_POST['control_index'] ?? ''),
    (string) ($_POST['control_value'] ?? ''),
    $label
);

if ($error !== null) {
    Session::addMessageAfterRedirect($error, false, ERROR);
} else {
    Session::addMessageAfterRedirect(
        sprintf(
            __('Queued: %1$s → %2$s. It will be applied on the scanner\'s next poll, and abandoned if that does not happen within ten minutes.', 'glpinetscan'),
            $label,
            (string) ($_POST['control_value'] ?? '')
        )
    );
}

Html::back();
