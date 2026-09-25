<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * "Check with the vendor now", from the Warranty tab on an asset.
 *
 * A page of its own rather than a handler inside the tab: a tab renders inside
 * the asset's own form, so a form posted from there would be answered by
 * core's asset handler, not by this plugin.
 *
 * Nothing is rendered. The lookup runs, a message is queued, and the browser
 * goes back where it came from with the tab still open.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpinetscan\Warranty\Sync;

// GLPI's own financial-information right: this writes the asset's warranty
// fields, which is what that right governs.
Session::checkRight('infocom', READ);

$itemtype = (string) ($_POST['itemtype'] ?? '');
$items_id = (int) ($_POST['items_id'] ?? 0);

if (empty($_POST['check_now']) || $items_id <= 0) {
    Html::back();
}

// No Session::checkCSRF() here on purpose. GLPI 11's CheckCsrfListener already
// validates the token for every non-XHR POST to a legacy script, and it does so
// with preserve_token = false — which *consumes* the token, so checking it a
// second time always fails with a 403 on a request that was perfectly valid.

$item = getItemForItemtype($itemtype);

if (!$item instanceof CommonDBTM || !$item->getFromDB($items_id)) {
    throw new \Glpi\Exception\Http\NotFoundHttpException();
}

// The right that matters is the one on the asset, not a plugin right: spending
// an API call against a vendor quota is a write-shaped act against this
// machine, and `can()` is where the entity restriction lives — canUpdateItem()
// alone would let a read-only technician through.
if (!$item->can($items_id, UPDATE)) {
    throw new \Glpi\Exception\Http\AccessDeniedHttpException();
}

$result = Sync::runItem($itemtype, $items_id);

Session::addMessageAfterRedirect(
    $result['message'],
    false,
    $result['ok'] ? INFO : WARNING
);

Html::back();
