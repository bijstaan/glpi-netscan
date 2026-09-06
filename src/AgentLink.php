<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use Agent;
use AgentType;
use DBmysql;

/**
 * Registers each scanner as a native GLPI inventory Agent.
 *
 * Without this a scanner exists only in the plugin's own table, so it is
 * invisible on *Administration → Inventory → Agents* — the page an
 * administrator actually goes to when asking "what is collecting for me, when
 * did it last check in, and what can it do?". Every other inventory agent in
 * the instance appears there; a scanner that does not looks like it is not
 * really part of the system.
 *
 * The fields that matter are the ones that page renders:
 *
 *  - `version` is not a plain string. GLPI reads it with `importArrayFromDB()`
 *    and renders one line per module, so it must be written with
 *    `exportArrayToDB()` — a bare "0.1.0" falls back to an unexplained blob.
 *  - `use_module_*` are the supported tasks. A netscan scanner does network
 *    discovery and network inventory and nothing else, so the rest are set to
 *    0 explicitly rather than left at their defaults: an agent that claims a
 *    task it cannot do is worse than one that claims none.
 *  - `threads_*` and `timeout_*` mirror what the scanner is actually told to
 *    do, so the figures on that page are the real ones rather than defaults.
 */
final class AgentLink
{
    /** Agent type shown in GLPI, distinct from glpi-agent's own "Core". */
    public const AGENT_TYPE = 'GLPI Netscan';

    /** Tasks this agent implements, in GLPI's vocabulary. */
    public const TASKS = ['netdiscovery', 'netinventory'];

    /**
     * Create or refresh the GLPI Agent row for a scanner.
     *
     * @return int The glpi_agents id, or 0 when it could not be written.
     */
    public static function sync(Scanner $scanner, string $agentVersion = ''): int
    {
        /** @var DBmysql $DB */
        global $DB;

        $deviceid = self::deviceId($scanner);

        $agent = new Agent();
        $agents_id = 0;
        if ($agent->getFromDBByCrit(['deviceid' => $deviceid])) {
            $agents_id = $agent->getID();
        }

        if ($agentVersion === '') {
            $agentVersion = (string) $scanner->fields['agent_version'];
        }

        $input = [
            'deviceid'      => $deviceid,
            'name'          => (string) $scanner->fields['name'],
            'entities_id'   => (int) $scanner->fields['entities_id'],
            'agenttypes_id' => self::agentTypeId(),
            'last_contact'  => date('Y-m-d H:i:s', max(1, (int) $scanner->fields['last_seen'])),
            'version'       => self::versionBlob($agentVersion),
            'useragent'     => 'glpi-netscan/' . ($agentVersion !== '' ? $agentVersion : 'unknown'),
            'remote_addr'   => (string) $scanner->fields['last_address'],

            // Supported tasks. Declared exhaustively so the agent never claims
            // something it cannot do.
            'use_module_network_discovery'      => 1,
            'use_module_network_inventory'      => 1,
            'use_module_computer_inventory'     => 0,
            'use_module_esx_remote_inventory'   => 0,
            'use_module_remote_inventory'       => 0,
            'use_module_package_deployment'     => 0,
            'use_module_collect_data'           => 0,
            'use_module_wake_on_lan'            => 0,
        ];

        // Concurrency and timeout come from the targets this scanner is
        // actually given, so the page shows what it will really do rather than
        // GLPI's defaults.
        [$threads, $timeout] = self::workload($scanner->getID());
        $input['threads_networkdiscovery'] = $threads;
        $input['threads_networkinventory'] = $threads;
        $input['timeout_networkdiscovery'] = $timeout;
        $input['timeout_networkinventory'] = $timeout;

        if ($agents_id > 0) {
            $input['id'] = $agents_id;
            $agent->update($input);
        } else {
            // A scanner is not an inventoried device: it collects *for* GLPI
            // rather than being collected. GLPI still wants an itemtype, so it
            // is left pointing at nothing rather than inventing a Computer that
            // does not exist.
            $input['itemtype'] = 'Computer';
            $input['items_id'] = 0;
            $agents_id = (int) $agent->add($input);
        }

        if ($agents_id > 0 && (int) $scanner->fields['agents_id'] !== $agents_id) {
            $DB->update(Scanner::getTable(), ['agents_id' => $agents_id], ['id' => $scanner->getID()]);
        }

        return $agents_id;
    }

    /** Remove the Agent row when a scanner is deleted. */
    public static function forget(Scanner $scanner): void
    {
        $agents_id = (int) $scanner->fields['agents_id'];
        if ($agents_id <= 0) {
            return;
        }

        $agent = new Agent();
        if ($agent->getFromDB($agents_id)) {
            $agent->delete(['id' => $agents_id], true);
        }
    }

    /**
     * A stable device id.
     *
     * Prefixed so it is obvious in GLPI's agent list which plugin owns it, and
     * keyed on the scanner id rather than its name so a rename does not orphan
     * the agent row.
     */
    public static function deviceId(Scanner $scanner): string
    {
        $host = trim((string) $scanner->fields['hostname']);
        if ($host === '') {
            $host = trim((string) $scanner->fields['name']);
        }
        return sprintf('netscan-%s-%d', $host !== '' ? $host : 'scanner', $scanner->getID());
    }

    /**
     * The per-task version map GLPI's agent page renders.
     *
     * Both tasks ship in the one binary, so they carry its version; listing
     * them separately is what makes the page state which tasks exist.
     */
    private static function versionBlob(string $agentVersion): string
    {
        $version = $agentVersion !== '' ? $agentVersion : 'unknown';

        return exportArrayToDB([
            'NETSCAN'      => $version,
            'NETDISCOVERY' => $version,
            'NETINVENTORY' => $version,
        ]);
    }

    /** Find or create the agent type. */
    private static function agentTypeId(): int
    {
        $type = new AgentType();
        if ($type->getFromDBByCrit(['name' => self::AGENT_TYPE])) {
            return $type->getID();
        }

        $id = $type->add(['name' => self::AGENT_TYPE]);
        return $id ? (int) $id : 0;
    }

    /**
     * Concurrency and timeout across this scanner's targets.
     *
     * @return array{0:int,1:int} threads, timeout in seconds
     */
    private static function workload(int $scanners_id): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $threads = 0;
        $timeout = 0;

        foreach ($DB->request([
            'FROM'  => Target::getTable(),
            'WHERE' => [
                'is_active'  => 1,
                'is_deleted' => 0,
                'OR'         => [
                    ['plugin_glpinetscan_scanners_id' => $scanners_id],
                    ['plugin_glpinetscan_scanners_id' => 0],
                ],
            ],
        ]) as $row) {
            $threads = max($threads, (int) $row['concurrency']);
            $timeout = max($timeout, (int) ceil(((int) $row['timeout_ms']) / 1000));
        }

        return [$threads, $timeout];
    }
}
