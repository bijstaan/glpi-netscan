<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpinetscan\OidProfile;

Session::checkRight('config', READ);

Html::header(
    OidProfile::getTypeName(2),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector('glpinetscan_oidprofile', 'admin')
        : 'admin',
    'glpinetscan_oidprofile'
);

Search::show(OidProfile::class);

Html::footer();
