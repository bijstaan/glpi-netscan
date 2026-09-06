<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

use GlpiPlugin\Glpinetscan\OidProfile;
use GlpiPlugin\Glpinetscan\Scanner;
use GlpiPlugin\Glpinetscan\Secret;
use GlpiPlugin\Glpinetscan\Target;

/**
 * Install.
 *
 * Credential handling follows the osquery agent's model, because the threat is
 * the same shape: a shared *bootstrap* secret that can be rotated and scoped,
 * exchanged once for a *per-scanner* token that is stored only as a hash. A
 * leaked bootstrap secret lets someone register a visible, revocable scanner;
 * a leaked token exposes one scanner. Neither is stored in a form that lets a
 * database reader impersonate a scanner.
 */
function plugin_glpinetscan_install()
{
    /** @var DBmysql $DB */
    global $DB;

    $charset = 'utf8mb4';
    $collate = 'utf8mb4_unicode_ci';

    // Enrollment secrets. Stored twice on purpose: a SHA-256 for lookup, since
    // GLPIKey encryption is non-deterministic and an encrypted column cannot be
    // matched against, plus the encrypted plaintext so the UI can rebuild the
    // install command without the secret sitting at rest in the clear.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_secrets')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_secrets` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255) NOT NULL DEFAULT '',
                `secret_hash` CHAR(64) NOT NULL,
                `secret` TEXT NOT NULL,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 0,
                `expires_at` INT UNSIGNED NOT NULL DEFAULT 0,
                `enroll_count` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `secret_hash` (`secret_hash`),
                KEY `is_active` (`is_active`),
                KEY `entities_id` (`entities_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // One row per enrolled scanner. `token_hash` is a bearer credential, so
    // the column holds only its SHA-256 — the database should never contain a
    // value that can be replayed against the API.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_scanners')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_scanners` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255) NOT NULL DEFAULT '',
                `token_hash` CHAR(64) NOT NULL,
                `hostname` VARCHAR(255) NOT NULL DEFAULT '',
                `platform` VARCHAR(64) NOT NULL DEFAULT '',
                `agent_version` VARCHAR(64) NOT NULL DEFAULT '',
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 0,
                `agents_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `last_seen` INT UNSIGNED NOT NULL DEFAULT 0,
                `last_address` VARCHAR(64) NOT NULL DEFAULT '',
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `is_deleted` TINYINT NOT NULL DEFAULT 0,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `token_hash` (`token_hash`),
                KEY `entities_id` (`entities_id`),
                KEY `agents_id` (`agents_id`),
                KEY `is_active` (`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // What to scan. Credentials are referenced by id into core's
    // glpi_snmpcredentials rather than duplicated here.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_targets')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_targets` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255) NOT NULL DEFAULT '',
                `ranges` TEXT NOT NULL,
                `snmpcredentials` VARCHAR(255) NOT NULL DEFAULT '',
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 0,
                `scan_interval` INT UNSIGNED NOT NULL DEFAULT 3600,
                `snmp_port` INT UNSIGNED NOT NULL DEFAULT 161,
                `timeout_ms` INT UNSIGNED NOT NULL DEFAULT 2000,
                `retries` INT UNSIGNED NOT NULL DEFAULT 1,
                `concurrency` INT UNSIGNED NOT NULL DEFAULT 32,
                `last_run` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `is_deleted` TINYINT NOT NULL DEFAULT 0,
                `comment` TEXT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `scanner` (`plugin_glpinetscan_scanners_id`),
                KEY `entities_id` (`entities_id`),
                KEY `is_active` (`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Operator-authored OID profiles. Shipped packs live in data/profiles/ and
    // are read from disk; rows here layer on top of them by priority, which is
    // what lets a site add one OID for one switch model without forking the
    // plugin or losing the change on upgrade.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_oidprofiles')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_oidprofiles` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255) NOT NULL DEFAULT '',
                `priority` INT NOT NULL DEFAULT 100,
                `sysobjectid_prefix` TEXT NULL,
                `sysdescr_regex` VARCHAR(255) NULL,
                `itemtype_override` VARCHAR(32) NULL,
                `device_oids` TEXT NULL,
                `port_oids` TEXT NULL,
                `component_oids` TEXT NULL,
                `counter_oids` TEXT NULL,
                `topology_oids` TEXT NULL,
                `features` TEXT NULL,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `is_deleted` TINYINT NOT NULL DEFAULT 0,
                `comment` TEXT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `is_active` (`is_active`),
                KEY `priority` (`priority`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Power devices: the mapping from a scanned device to its GLPI PDU asset,
    // plus the latest state snapshot. One row per device, overwritten each
    // scan — this answers "what does it say now", not "what did it do", which
    // is the inventory-shaped question. Trending belongs in monitoring.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_powerdevices')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_powerdevices` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `deviceid` VARCHAR(255) NOT NULL,
                `pdus_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `kind` VARCHAR(8) NOT NULL DEFAULT 'pdu',
                `battery_status` VARCHAR(16) NOT NULL DEFAULT '',
                `battery_charge` INT NOT NULL DEFAULT 0,
                `battery_runtime_min` INT NOT NULL DEFAULT 0,
                `battery_voltage` DECIMAL(8,2) NOT NULL DEFAULT 0,
                `battery_temp_c` INT NOT NULL DEFAULT 0,
                `seconds_on_battery` INT NOT NULL DEFAULT 0,
                `battery_replace` TINYINT NOT NULL DEFAULT 0,
                `output_source` VARCHAR(16) NOT NULL DEFAULT '',
                `input_json` TEXT NULL,
                `output_json` TEXT NULL,
                `sensors_json` TEXT NULL,
                `alarms_json` TEXT NULL,
                `last_seen` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `deviceid` (`deviceid`),
                KEY `pdus_id` (`pdus_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Per-outlet detail. GLPI's own Item_Plug models outlet *types and counts*
    // only, so individually addressable sockets have to live here.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_outlets')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_outlets` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpinetscan_powerdevices_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `outlet_index` INT UNSIGNED NOT NULL DEFAULT 0,
                `name` VARCHAR(255) NOT NULL DEFAULT '',
                `state` VARCHAR(16) NOT NULL DEFAULT '',
                `current_a` DECIMAL(8,2) NOT NULL DEFAULT 0,
                `power_w` INT NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `outlet` (`plugin_glpinetscan_powerdevices_id`,`outlet_index`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // deviceid -> asset mapping for asset types the plugin creates itself
    // (currently Phone; PDUs carry their mapping on the powerdevices row,
    // which also holds their state).
    if (!$DB->tableExists('glpi_plugin_glpinetscan_assetmap')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_assetmap` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `deviceid` VARCHAR(255) NOT NULL,
                `itemtype` VARCHAR(100) NOT NULL,
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `last_seen` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `device` (`deviceid`,`itemtype`),
                KEY `item` (`itemtype`,`items_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Per-run outcome, so an operator can see what a scan actually did rather
    // than inferring it from whether assets appeared.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_runs')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_runs` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpinetscan_targets_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `started_at` INT UNSIGNED NOT NULL DEFAULT 0,
                `finished_at` INT UNSIGNED NOT NULL DEFAULT 0,
                `discovered` INT UNSIGNED NOT NULL DEFAULT 0,
                `inventoried` INT UNSIGNED NOT NULL DEFAULT 0,
                `failed` INT UNSIGNED NOT NULL DEFAULT 0,
                `message` TEXT NULL,
                PRIMARY KEY (`id`),
                KEY `scanner` (`plugin_glpinetscan_scanners_id`),
                KEY `target` (`plugin_glpinetscan_targets_id`),
                KEY `started_at` (`started_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Packages offered to scanners by self-update. Deliberately not an
    // upload store: GLPI holds the manifest — version, URL, checksum, size —
    // and the bytes are served from wherever the operator already publishes
    // artifacts. The scanner authenticates them by checksum, so where they
    // came from does not have to be trusted.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_packages')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_packages` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `version` VARCHAR(64) NOT NULL DEFAULT '',
                `platform` VARCHAR(32) NOT NULL DEFAULT '',
                `arch` VARCHAR(32) NOT NULL DEFAULT '',
                `url` VARCHAR(1024) NOT NULL DEFAULT '',
                `sha256` CHAR(64) NOT NULL DEFAULT '',
                `size` BIGINT UNSIGNED NOT NULL DEFAULT 0,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `release` (`platform`, `arch`, `version`),
                KEY `offer` (`platform`, `arch`, `is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Added after the first release: a scanner records the architecture it is
    // running on so it is never offered a package that cannot execute.
    if (
        $DB->tableExists('glpi_plugin_glpinetscan_scanners')
        && !$DB->fieldExists('glpi_plugin_glpinetscan_scanners', 'arch')
    ) {
        $DB->doQuery(
            "ALTER TABLE `glpi_plugin_glpinetscan_scanners`
             ADD COLUMN `arch` VARCHAR(32) NOT NULL DEFAULT '' AFTER `platform`"
        );
    }

    // Wireless: what a controller reports about its estate. Not on the asset,
    // because GLPI's inventory format has nowhere for it — see WirelessIngest.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_wifinetworks')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_wifinetworks` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `itemtype` VARCHAR(100) NOT NULL DEFAULT '',
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `name` VARCHAR(255) NOT NULL DEFAULT '',
                `clients` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `last_seen` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `network` (`itemtype`, `items_id`, `name`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists('glpi_plugin_glpinetscan_accesspoints')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_accesspoints` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `itemtype` VARCHAR(100) NOT NULL DEFAULT '',
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `name` VARCHAR(255) NOT NULL DEFAULT '',
                `serial` VARCHAR(255) NOT NULL DEFAULT '',
                `mac` VARCHAR(64) NOT NULL DEFAULT '',
                `ip` VARCHAR(64) NOT NULL DEFAULT '',
                `model` VARCHAR(255) NOT NULL DEFAULT '',
                `location` VARCHAR(255) NOT NULL DEFAULT '',
                `firmware` VARCHAR(128) NOT NULL DEFAULT '',
                `status` VARCHAR(64) NOT NULL DEFAULT '',
                `radios` INT UNSIGNED NOT NULL DEFAULT 0,
                `clients` INT UNSIGNED NOT NULL DEFAULT 0,
                `radio_detail` TEXT NULL,
                `accesspoints_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `last_seen` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `ap` (`itemtype`, `items_id`, `name`),
                KEY `asset` (`accesspoints_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // What the discovery pass learned about each device, and when it was last
    // walked in full. This is the state the inventory decision is made from,
    // and it lives here rather than on the scanner so that deleting an asset in
    // GLPI causes it to be re-walked rather than skipped forever.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_seen')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_seen` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `deviceid` VARCHAR(255) NOT NULL,
                `plugin_glpinetscan_targets_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `address` VARCHAR(64) NOT NULL DEFAULT '',
                `last_discovery` INT UNSIGNED NOT NULL DEFAULT 0,
                `last_inventory` INT UNSIGNED NOT NULL DEFAULT 0,
                `uptime_ticks` BIGINT UNSIGNED NOT NULL DEFAULT 0,
                `iftable_last_change` BIGINT UNSIGNED NOT NULL DEFAULT 0,
                `ifstack_last_change` BIGINT UNSIGNED NOT NULL DEFAULT 0,
                `entity_last_change` BIGINT UNSIGNED NOT NULL DEFAULT 0,
                `itemtype` VARCHAR(100) NOT NULL DEFAULT '',
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `deviceid` (`deviceid`),
                KEY `target` (`plugin_glpinetscan_targets_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // How stale a full walk may get before one is forced, regardless of whether
    // anything looked like it changed. The change markers only catch ports
    // being created or removed and hardware being swapped; a port going down,
    // or a MAC moving, moves nothing they can see.
    if (
        $DB->tableExists('glpi_plugin_glpinetscan_targets')
        && !$DB->fieldExists('glpi_plugin_glpinetscan_targets', 'inventory_interval')
    ) {
        $DB->doQuery(
            "ALTER TABLE `glpi_plugin_glpinetscan_targets`
             ADD COLUMN `inventory_interval` INT UNSIGNED NOT NULL DEFAULT 86400 AFTER `scan_interval`"
        );
    }

    foreach (['itemtype' => "VARCHAR(100) NOT NULL DEFAULT ''", 'items_id' => 'INT UNSIGNED NOT NULL DEFAULT 0'] as $field => $spec) {
        if (
            $DB->tableExists('glpi_plugin_glpinetscan_seen')
            && !$DB->fieldExists('glpi_plugin_glpinetscan_seen', $field)
        ) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_glpinetscan_seen` ADD COLUMN `$field` $spec");
        }
    }

    // The control queue. Every SNMP write this plugin ever performs is a row
    // here first, which is what makes it auditable and what makes the expiry
    // rule enforceable — see Control.
    if (!$DB->tableExists('glpi_plugin_glpinetscan_actions')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_actions` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpinetscan_targets_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `deviceid` VARCHAR(255) NOT NULL DEFAULT '',
                `address` VARCHAR(64) NOT NULL DEFAULT '',
                `itemtype` VARCHAR(100) NOT NULL DEFAULT '',
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `action` VARCHAR(64) NOT NULL DEFAULT '',
                `target_index` VARCHAR(64) NOT NULL DEFAULT '',
                `value` VARCHAR(64) NOT NULL DEFAULT '',
                `label` VARCHAR(255) NOT NULL DEFAULT '',
                `state` VARCHAR(16) NOT NULL DEFAULT 'pending',
                `result` VARCHAR(500) NOT NULL DEFAULT '',
                `users_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `requested_at` INT UNSIGNED NOT NULL DEFAULT 0,
                `expires_at` INT UNSIGNED NOT NULL DEFAULT 0,
                `completed_at` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                KEY `pending` (`plugin_glpinetscan_scanners_id`, `state`),
                KEY `item` (`itemtype`, `items_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // Which credential a scanner may *write* with on this target. Zero means
    // this target cannot be controlled at all, which is the default and stays
    // the default until someone chooses a credential deliberately.
    if (
        $DB->tableExists('glpi_plugin_glpinetscan_targets')
        && !$DB->fieldExists('glpi_plugin_glpinetscan_targets', 'write_snmpcredentials_id')
    ) {
        $DB->doQuery(
            "ALTER TABLE `glpi_plugin_glpinetscan_targets`
             ADD COLUMN `write_snmpcredentials_id` INT UNSIGNED NOT NULL DEFAULT 0 AFTER `snmpcredentials`"
        );
    }

    if (!$DB->tableExists('glpi_plugin_glpinetscan_traps')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpinetscan_traps` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpinetscan_scanners_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `address` VARCHAR(64) NOT NULL DEFAULT '',
                `deviceid` VARCHAR(255) NOT NULL DEFAULT '',
                `itemtype` VARCHAR(100) NOT NULL DEFAULT '',
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `trap_oid` VARCHAR(255) NOT NULL DEFAULT '',
                `trap_name` VARCHAR(128) NOT NULL DEFAULT '',
                `version` VARCHAR(16) NOT NULL DEFAULT '',
                `varbinds` TEXT NULL,
                `received_at` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                KEY `item` (`itemtype`, `items_id`),
                KEY `address` (`address`, `id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    plugin_glpinetscan_enable_lag_ports();

    Secret::ensureDefault();
    plugin_glpinetscan_default_columns();

    return true;
}

/**
 * Global default columns for the plugin's lists.
 *
 * Without these GLPI shows name and entity only, which for a scan target omits
 * the one thing it exists to record — the ranges — and for a scanner omits
 * whether it is alive. `users_id = 0` makes them the instance-wide default
 * that a user can still override for themselves.
 */
/**
 * Let GLPI import aggregated links.
 *
 * `glpi_networkporttypes` ships with ieee8023adLag(161) marked not importable
 * and with no instantiation type, so a port-channel is *silently discarded* by
 * the inventory pipeline before its member list is ever read — verified against
 * this GLPI: submit a LAG port and only its members appear. GLPI models
 * aggregation properly through NetworkPortAggregate; the row simply is not
 * switched on.
 *
 * Narrow on purpose. It changes one reference row, and the only behaviour that
 * changes is whether an aggregated interface is imported at all. Contrast
 * `pdu_in_asset_types`, which is an opt-in setting because `asset_types` is
 * consulted right across core — here there is nothing to weigh up, because
 * without it the collected data has nowhere to go.
 */
function plugin_glpinetscan_enable_lag_ports(): void
{
    /** @var DBmysql $DB */
    global $DB;

    if (!$DB->tableExists('glpi_networkporttypes')) {
        return;
    }

    $DB->update('glpi_networkporttypes', [
        'is_importable'      => 1,
        'instantiation_type' => 'NetworkPortAggregate',
    ], [
        'value_decimal' => 161,
    ]);

    // The type list is cached, and a stale cache means the next scan still
    // drops the port with nothing to indicate why.
    plugin_glpinetscan_forget_port_types();
}

/** Undo the above, leaving GLPI as it shipped. */
function plugin_glpinetscan_disable_lag_ports(): void
{
    /** @var DBmysql $DB */
    global $DB;

    if (!$DB->tableExists('glpi_networkporttypes')) {
        return;
    }

    // Only reverted when it still looks like ours. Someone who enabled this
    // deliberately, or another plugin that needs it, should not have it taken
    // away by an unrelated uninstall.
    $DB->update('glpi_networkporttypes', [
        'is_importable'      => 0,
        'instantiation_type' => null,
    ], [
        'value_decimal'      => 161,
        'instantiation_type' => 'NetworkPortAggregate',
    ]);

    plugin_glpinetscan_forget_port_types();
}

function plugin_glpinetscan_forget_port_types(): void
{
    global $GLPI_CACHE;

    if (isset($GLPI_CACHE)) {
        $GLPI_CACHE->delete('glpi_inventory_ports_types');
    }
}

function plugin_glpinetscan_default_columns(): void
{
    /** @var DBmysql $DB */
    global $DB;

    $defaults = [
        Target::class     => [3, 4, 5, 6],   // ranges, scanner, interval, active
        Scanner::class    => [3, 5, 6, 7],   // hostname, version, last address, active
        OidProfile::class => [3, 4, 5],      // priority, sysobjectid prefixes, active
    ];

    foreach ($defaults as $itemtype => $columns) {
        $rank = 1;
        foreach ($columns as $num) {
            if (countElementsInTable('glpi_displaypreferences', [
                'itemtype' => $itemtype,
                'num'      => $num,
                'users_id' => 0,
            ]) > 0) {
                continue;
            }
            $DB->insert('glpi_displaypreferences', [
                'itemtype' => $itemtype,
                'num'      => $num,
                'rank'     => $rank++,
                'users_id' => 0,
            ]);
        }
    }
}

function plugin_glpinetscan_uninstall()
{
    /** @var DBmysql $DB */
    global $DB;

    foreach (['secrets', 'scanners', 'targets', 'oidprofiles', 'runs', 'powerdevices', 'outlets', 'assetmap', 'packages', 'wifinetworks', 'accesspoints', 'seen', 'actions', 'traps'] as $suffix) {
        $table = "glpi_plugin_glpinetscan_$suffix";
        if ($DB->tableExists($table)) {
            $DB->doQuery("DROP TABLE `$table`");
        }
    }

    plugin_glpinetscan_disable_lag_ports();

    $DB->delete('glpi_displaypreferences', [
        'itemtype' => [Target::class, Scanner::class, OidProfile::class],
    ]);

    Config::deleteConfigurationValues(
        PLUGIN_GLPINETSCAN_CONFIG_CONTEXT,
        array_keys(\GlpiPlugin\Glpinetscan\Settings::DEFAULTS)
    );

    return true;
}
