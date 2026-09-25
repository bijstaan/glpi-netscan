<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */
/**
 * GLPI Netscan — SNMP network scanning, configured from GLPI.
 *
 * The scanner binary holds no OID knowledge and no scan policy: ranges,
 * credentials and OID profiles are all defined here and handed to it at job
 * time. Adding a device-specific OID is an edit in this UI, not a new build.
 *
 * Collected data is handed to GLPI's *native* inventory pipeline rather than
 * assembled into assets by this plugin. Core already knows how to turn
 * NETDISCOVERY/NETINVENTORY content into NetworkEquipment, Printer and
 * Unmanaged assets with their ports, IPs and components — reimplementing that
 * would mean maintaining a second, worse copy of it.
 */

use Glpi\Http\Firewall;
use Glpi\Http\SessionManager;
use GlpiPlugin\Glpinetscan\Menu;
use GlpiPlugin\Glpinetscan\PortMapTab;
use GlpiPlugin\Glpinetscan\PowerTab;
use GlpiPlugin\Glpinetscan\ControlTab;
use GlpiPlugin\Glpinetscan\TrapTab;
use GlpiPlugin\Glpinetscan\WirelessTab;
use GlpiPlugin\Glpinetscan\Settings;
use GlpiPlugin\Glpinetscan\OidProfile;
use GlpiPlugin\Glpinetscan\Scanner;
use GlpiPlugin\Glpinetscan\Target;
use GlpiPlugin\Glpinetscan\WarrantyTab;
use Glpi\Plugin\Hooks;

define('PLUGIN_GLPINETSCAN_VERSION', '0.9.1');
define('PLUGIN_GLPINETSCAN_MIN_GLPI', '12.0');
define('PLUGIN_GLPINETSCAN_CONFIG_CONTEXT', 'plugin:glpinetscan');

function plugin_init_glpinetscan()
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['glpinetscan'] = true;

    // The scanner's three endpoints authenticate with their own credentials —
    // an enrollment secret, then a per-scanner bearer token — so they are
    // declared stateless. Without this they would be pushed through GLPI's
    // interactive session and CSRF machinery, which a headless agent has no
    // way to satisfy. Declaring them stateless removes GLPI's checks, not
    // ours: each endpoint authenticates before it does anything.
    $scanner_api = '#^/front/(enroll|job|report|control|trap)\.php#';
    Firewall::addPluginStrategyForLegacyScripts(
        'glpinetscan',
        $scanner_api,
        Firewall::STRATEGY_NO_CHECK
    );
    SessionManager::registerPluginStatelessPath('glpinetscan', $scanner_api);

    Plugin::registerClass(Scanner::class);
    Plugin::registerClass(Target::class);
    Plugin::registerClass(OidProfile::class);

    // Core's MAC-resolution rules search $CFG_GLPI['asset_types'], which does
    // not include PDU — so a switch's forwarding table can never resolve to a
    // UPS or rack strip, and links to an Unmanaged placeholder instead.
    // Adding PDU here is the only lever that changes that, and it is opt-in
    // because asset_types is consulted widely across core.
    if (Settings::get('pdu_in_asset_types')) {
        global $CFG_GLPI;
        if (!in_array('PDU', $CFG_GLPI['asset_types'] ?? [], true)) {
            $CFG_GLPI['asset_types'][] = 'PDU';
        }
    }

    // Power state lives on the native PDU asset, which is where someone
    // looking for a UPS will actually be.
    Plugin::registerClass(PowerTab::class, ['addtabon' => ['PDU']]);
    // Shown only on devices the scanner recorded wireless state for; see
    // WirelessTab::getTabNameForItem.
    Plugin::registerClass(WirelessTab::class, ['addtabon' => ['NetworkEquipment']]);
    // The faceplate. NetworkEquipment only: every other itemtype that can hold
    // ports holds one or two of them, and a picture of two ports is a worse
    // table. Not gated on the asset having been scanned by this plugin —
    // everything it draws is core's own port data, so it works on a switch
    // some other agent inventoried; it only omits the freshness line, which is
    // the one fact that is genuinely ours. See PortMapTab::getTabNameForItem
    // for the empty case.
    Plugin::registerClass(PortMapTab::class, ['addtabon' => ['NetworkEquipment']]);
    // Only ever visible when device control is switched on and the user may use
    // it; see ControlTab::getTabNameForItem.
    Plugin::registerClass(ControlTab::class, ['addtabon' => ['NetworkEquipment', 'PDU', 'Printer']]);
    // Only appears on assets that have actually sent a notification; see
    // TrapTab::getTabNameForItem.
    Plugin::registerClass(TrapTab::class, ['addtabon' => ['NetworkEquipment', 'PDU', 'Printer', 'Phone']]);

    // "Warranty" tab on scanned kit. The dates themselves go into GLPI's own
    // Infocom fields, so this tab carries what Infocom has no room for: the
    // full entitlement list, and why there is no warranty when there is none.
    // Shown only where there is something to say — see
    // WarrantyTab::getTabNameForItem. Unmanaged is absent because it is not in
    // $CFG_GLPI['infocom_types'], so there would be nowhere to write an answer.
    Plugin::registerClass(WarrantyTab::class, [
        'addtabon' => ['NetworkEquipment', 'Printer', 'Phone', 'PDU', 'Computer'],
    ]);

    // Seven hardware vendors' API credentials. Declaring them here is what makes
    // Config::setConfigurationValues() encrypt them on write, mask them in the
    // history log, and re-encrypt them when an administrator runs
    // `glpi:security:changekey` — without which a key rotation silently orphans
    // every one of them at once.
    //
    // SECURED_CONFIGS rather than SECURED_FIELDS: the values live in
    // `glpi_configs.value`, a core column shared with every other setting in
    // GLPI, and naming that column would point the rotation migration at all of
    // them.
    $PLUGIN_HOOKS[Hooks::SECURED_CONFIGS]['glpinetscan'] =
        GlpiPlugin\Glpinetscan\Warranty\Settings::secretKeys();

    // A purged asset takes its warranty lookup with it. The row is keyed on
    // (itemtype, items_id) and GLPI reuses ids, so an orphan would eventually
    // attach one device's warranty history to an unrelated new one.
    $PLUGIN_HOOKS['item_purge']['glpinetscan'] = [
        'NetworkEquipment' => 'plugin_glpinetscan_item_purged',
        'Printer'          => 'plugin_glpinetscan_item_purged',
        'Phone'            => 'plugin_glpinetscan_item_purged',
        'PDU'              => 'plugin_glpinetscan_item_purged',
        'Computer'         => 'plugin_glpinetscan_item_purged',
    ];

    // Operational objects under Administration; configuration under Setup,
    // which is the split GLPI itself makes.
    $PLUGIN_HOOKS['menu_toadd']['glpinetscan'] = [
        // Administration only. The settings page is reached from Setup >
        // Plugins, which already links it — a Setup-menu entry as well would be
        // a second link to the same page.
        'admin'  => Menu::class,
    ];
    $PLUGIN_HOOKS['config_page']['glpinetscan'] = 'front/config.php';

    // Theme conformance for every surface the plugin ships (dark-palette
    // muted-text/badge/button rules, scoped to the plugin's own containers
    // — see public/css/netscan.css). Global on purpose: the plugin's
    // surfaces include tabs on core assets (PDU, NetworkEquipment,
    // Printer, Phone), which a per-page <style> cannot cover.
    $PLUGIN_HOOKS['add_css']['glpinetscan'] = 'css/netscan.css';

    // Moves the "Port map" tab next to core's "Network ports" tab, which is
    // the only way that ordering can be had: defineAllTabs() is final, adds
    // plugin tabs strictly last, and offers no hook. Global for the same
    // reason the stylesheet is — the tab bar it edits is core's, on a core
    // asset form — and it returns immediately on every page that has no tab
    // bar, which is most of them. See public/js/portmap.js.
    $PLUGIN_HOOKS['add_javascript']['glpinetscan'] = 'js/portmap.js';

    /**
     * SNMP findings, offered to glpi-ai's assistant as tools.
     *
     * Registered unconditionally: only glpi-ai reads this hook, so an instance
     * without it pays nothing and the class is never loaded. Deliberately not
     * the port inventory — that lives in GLPI's own tables, and offering a
     * second copy would give the model two sources that can disagree.
     */
    $PLUGIN_HOOKS['glpiai_tools']['glpinetscan'] = [
        GlpiPlugin\Glpinetscan\AiTools::class,
        'all',
    ];
}

function plugin_version_glpinetscan()
{
    return [
        'name'         => 'GLPI Netscan',
        'version'      => PLUGIN_GLPINETSCAN_VERSION,
        'author'       => 'Bijstaan',
        'license'      => 'GPL-3.0-or-later',
        'homepage'     => 'https://github.com/bijstaan/glpi-netscan',
        'requirements' => ['glpi' => ['min' => PLUGIN_GLPINETSCAN_MIN_GLPI]],
    ];
}

function plugin_glpinetscan_check_prerequisites()
{
    return true;
}

function plugin_glpinetscan_check_config($verbose = false)
{
    return true;
}
