<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Redraw the port map.
 *
 * Returns the same markup the tab rendered, from the same renderer: a
 * faceplate whose refresh path builds the picture differently from its first
 * paint is a faceplate that will eventually disagree with itself, and the
 * disagreement will be about which ports are up.
 *
 * Read-only, so a GET with no CSRF token — but the asset's own read right is
 * re-checked here rather than inherited from the fact that the tab rendered
 * once. Rights and entity can both have changed since, and this endpoint is
 * reachable directly with any items_id somebody cares to type.
 */

use GlpiPlugin\Glpinetscan\PortMapTab;

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

Session::checkLoginUser();
Html::header_nocache();
header('Content-Type: text/html; charset=UTF-8');

$itemtype = (string) ($_GET['itemtype'] ?? '');
$items_id = (int) ($_GET['items_id'] ?? 0);

if ($items_id <= 0 || !is_a($itemtype, CommonDBTM::class, true)) {
    http_response_code(400);
    exit;
}

$item = getItemForItemtype($itemtype);
if (!($item instanceof CommonDBTM) || !$item->can($items_id, READ)) {
    http_response_code(403);
    exit;
}

PortMapTab::content($itemtype, $items_id);
