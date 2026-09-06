<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonGLPI;
use Session;

/**
 * Administration menu entries.
 *
 * Returned as `is_multi_entries`, which is how one class contributes several
 * items to a category: the plugin has three distinct things an operator
 * manages and burying two of them behind a single link makes them unfindable.
 *
 * Scan targets come first deliberately — defining what to scan is the job, and
 * it is the page someone arrives looking for.
 *
 * Configuration is deliberately *not* here. GLPI separates Administration
 * (operational data you work with day to day) from Setup (how the instance is
 * configured), and enrollment keys and TLS policy belong on the latter — see
 * SettingsMenu.
 *
 * The `: bool` return types on canView/canCreate are load-bearing: CommonGLPI
 * declares them, and a signature mismatch here is a fatal error inside menu
 * generation, which takes out every page in GLPI rather than just this one.
 */
final class Menu extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('Network scanning', 'glpinetscan');
    }

    public static function getIcon()
    {
        return 'ti ti-radar';
    }

    public static function canView(): bool
    {
        return (bool) Session::haveRight('config', READ);
    }

    public static function canCreate(): bool
    {
        return (bool) Session::haveRight('config', UPDATE);
    }

    public static function getMenuContent()
    {
        if (!self::canView()) {
            return false;
        }

        $can_write = self::canCreate();

        $entries = ['is_multi_entries' => true];

        // What to scan. The primary page.
        $entries['glpinetscan_target'] = [
            'title' => Target::getTypeName(2),
            'page'  => Target::getSearchURL(false),
            'icon'  => Target::getIcon(),
            'links' => array_filter([
                'search' => Target::getSearchURL(false),
                'add'    => $can_write ? Target::getFormURL(false) : '',
            ]),
        ];

        // Enrolled scanners. No 'add' link at all: a scanner registers itself
        // by running the install command, and there is nothing to create by
        // hand. An empty 'add' is not the same as no 'add' — GLPI renders the
        // button either way and an empty target sends the operator to the
        // dashboard, which is exactly what it used to do here.
        $entries['glpinetscan_scanner'] = [
            'title' => Scanner::getTypeName(2),
            'page'  => Scanner::getSearchURL(false),
            'icon'  => Scanner::getIcon(),
            'links' => ['search' => Scanner::getSearchURL(false)],
        ];

        $entries['glpinetscan_oidprofile'] = [
            'title' => OidProfile::getTypeName(2),
            'page'  => OidProfile::getSearchURL(false),
            'icon'  => OidProfile::getIcon(),
            'links' => array_filter([
                'search' => OidProfile::getSearchURL(false),
                'add'    => $can_write ? OidProfile::getFormURL(false) : '',
            ]),
        ];

        return $entries;
    }
}
