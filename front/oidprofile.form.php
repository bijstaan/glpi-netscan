<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpinetscan\OidProfile;

Session::checkRight('config', READ);

$item = new OidProfile();
$id   = (int) ($_GET['id'] ?? 0);

if (!empty($_POST['add'])) {
    Session::checkRight('config', UPDATE);
    $item->check(-1, CREATE, $_POST);
    $newid = $item->add($_POST);
    Html::redirect(OidProfile::getFormURLWithID($newid));
} elseif (!empty($_POST['update'])) {
    Session::checkRight('config', UPDATE);
    $item->check($_POST['id'], UPDATE);
    $item->update($_POST);
    Html::back();
} elseif (!empty($_POST['purge'])) {
    Session::checkRight('config', PURGE);
    $item->check($_POST['id'], PURGE);
    $item->delete($_POST, 1);
    Html::redirect(OidProfile::getSearchURL());
}

Html::header(
    OidProfile::getTypeName(1),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector('glpinetscan_oidprofile', 'admin')
        : 'admin',
    'glpinetscan_oidprofile'
);

// display() runs a read check, which a not-yet-existing row can never pass —
// so the "new" form has to go straight to showForm(), which supplies its own
// form header and buttons.
// Scope wrapper: this page is otherwise entirely core-rendered markup,
// which the plugin's dark-theme CSS (public/css/netscan.css) could
// structurally never reach.
echo "<div class='glpinetscan-surface'>";
if ($id > 0) {
    $item->display(['id' => $id]);
} else {
    $item->showForm(0);
}
echo "</div>";

Html::footer();
