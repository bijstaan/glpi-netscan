<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use GLPIKey;
use SNMPCredential;

/**
 * Builds the work assignment a scanner receives when it polls.
 *
 * This is the point where SNMP credentials leave GLPI, so it is also the reason
 * `require_tls` defaults to on: the response carries live community strings and
 * v3 passphrases, decrypted, to a scanner that may be across a WAN.
 */
final class Job
{
    public const RUNS_TABLE = 'glpi_plugin_glpinetscan_runs';

    /**
     * Assemble every due job for a scanner.
     *
     * @return array<string,mixed>
     */
    public static function forScanner(Scanner $scanner, string $platform = '', string $arch = ''): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $now      = time();
        $settings = Settings::all();
        $jobs     = [];

        $criteria = [
            'FROM'  => Target::getTable(),
            'WHERE' => [
                'is_active'  => 1,
                'is_deleted' => 0,
                // A target may be pinned to one scanner, or left at 0 meaning
                // "whichever scanner asks" — useful when a site runs a single
                // scanner and pinning is just ceremony.
                'OR'         => [
                    ['plugin_glpinetscan_scanners_id' => $scanner->getID()],
                    ['plugin_glpinetscan_scanners_id' => 0],
                ],
            ],
            'ORDER' => 'id ASC',
        ];

        foreach ($DB->request($criteria) as $row) {
            $target = new Target();
            $target->getFromResultSet($row);

            $due = (int) $row['last_run'] + (int) $row['scan_interval'];
            if ($due > $now) {
                continue;
            }

            $ranges = $target->rangeList();
            if ($ranges === []) {
                continue;
            }

            $creds = self::credentials($target->credentialIds());
            if ($creds === []) {
                // Dispatching a target with no usable credential would burn a
                // full sweep to learn nothing; make it visible instead.
                self::recordRun($scanner->getID(), (int) $row['id'], $now, $now, 0, 0, 0, 'no usable SNMP credential');
                continue;
            }

            $runId = self::recordRun($scanner->getID(), (int) $row['id'], $now, 0, 0, 0, 0, '');

            // Claim the target immediately. Two scanners polling at once would
            // otherwise both be handed the same sweep.
            $DB->update(Target::getTable(), ['last_run' => $now], ['id' => (int) $row['id']]);

            $jobs[] = [
                'job_id'      => $runId,
                'target_id'   => (int) $row['id'],
                'target_name' => (string) $row['name'],
                'ranges'      => $ranges,
                'credentials' => $creds,
                'options'     => [
                    'port'        => (int) $row['snmp_port'],
                    'timeout_ms'  => (int) $row['timeout_ms'],
                    'retries'     => (int) $row['retries'],
                    'concurrency' => (int) $row['concurrency'],
                ],
            ];
        }

        // Device writes queued for this scanner, if any. Claimed here rather
        // than on an endpoint of its own because the poll already happens on a
        // short interval and a second one would be a second thing to secure.
        $actions = Control::claim($scanner->getID());

        $out = [
            'scanner_invalid' => false,
            'poll_interval'   => (int) $settings['poll_interval'],
            'jobs'            => $jobs,
            // Carried on the poll the scanner already makes rather than on an
            // endpoint of its own. Unlike the osquery agent — which needs a
            // separate channel because osqueryd's protocol is fixed and knows
            // nothing about updating itself — this protocol is ours end to end,
            // and the poll already reports the running version.
            'update'          => Update::offerFor($scanner, $platform, $arch),
        ];

        if ($actions !== []) {
            $out['actions'] = $actions;
        }

        // Trap policy. Sent on every poll — including idle ones — because it is
        // how a scanner learns that listening has been switched off as well as
        // on, and a listener that only ever hears about being enabled is one
        // nobody can turn off without visiting the machine.
        $out['traps'] = self::trapPolicy($scanner);

        // Profiles are only worth sending when there is work; they are the
        // bulkiest part of the response and the idle poll should stay cheap.
        //
        // Queued actions count as work: a control declared by a profile — an
        // outlet, a PoE port — cannot be resolved without them, and those
        // arrive on polls that have no scanning to do at all.
        if ($jobs !== [] || $actions !== []) {
            $out['profiles'] = OidProfile::forJob();
        }

        return $out;
    }

    /**
     * What this scanner should do about SNMP notifications.
     *
     * The permitted source ranges are the scanner's own targets, so a trap is
     * only accepted from an address it was already told to scan. That is the
     * same rule inventory submissions follow, and it is what makes an
     * unauthenticated v1/v2c trap tolerable: the worst a forged one achieves is
     * an SNMP walk of a device the scanner may already walk.
     *
     * @return array<string,mixed>
     */
    private static function trapPolicy(Scanner $scanner): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $settings = Settings::all();

        if (empty($settings['allow_traps'])) {
            return ['enabled' => false];
        }

        $ranges = [];
        foreach ($DB->request([
            'FROM'  => Target::getTable(),
            'WHERE' => [
                'is_active'  => 1,
                'is_deleted' => 0,
                'OR'         => [
                    ['plugin_glpinetscan_scanners_id' => $scanner->getID()],
                    ['plugin_glpinetscan_scanners_id' => 0],
                ],
            ],
        ]) as $row) {
            $target = new Target();
            $target->getFromResultSet($row);
            foreach ($target->rangeList() as $range) {
                $ranges[] = $range;
            }
        }

        $ranges = array_values(array_unique($ranges));

        // No ranges means no permitted sources, and the scanner refuses to
        // listen rather than listening to everything. A configuration mistake
        // should close a listening port, not open it.
        return [
            'enabled' => $ranges !== [],
            'port'    => (int) $settings['trap_port'],
            'ranges'  => $ranges,
        ];
    }

    /**
     * Decrypt the referenced SNMP credentials into the scanner's wire format.
     *
     * @param int[] $ids
     * @return array<int,array<string,mixed>>
     */
    public static function credentials(array $ids): array
    {
        $key = new GLPIKey();
        $out = [];

        foreach ($ids as $id) {
            $cred = new SNMPCredential();
            if (!$cred->getFromDB($id) || (int) $cred->fields['is_deleted'] === 1) {
                continue;
            }

            $version = $cred->getRealVersion();
            if ($version === '') {
                continue;
            }

            $entry = [
                'id'      => (int) $cred->fields['id'],
                'name'    => (string) $cred->fields['name'],
                'version' => $version,
            ];

            if ($version === '3') {
                $entry['username']        = (string) $cred->fields['username'];
                $entry['auth_protocol']   = $cred->getAuthProtocol();
                $entry['auth_passphrase'] = (string) $key->decrypt($cred->fields['auth_passphrase'] ?? '');
                $entry['priv_protocol']   = $cred->getEncryption();
                $entry['priv_passphrase'] = (string) $key->decrypt($cred->fields['priv_passphrase'] ?? '');
            } else {
                $entry['community'] = (string) $cred->fields['community'];
                if ($entry['community'] === '') {
                    continue;
                }
            }

            $out[] = $entry;
        }

        return $out;
    }

    public static function recordRun(
        int $scannerId,
        int $targetId,
        int $startedAt,
        int $finishedAt,
        int $discovered,
        int $inventoried,
        int $failed,
        string $message
    ): int {
        /** @var DBmysql $DB */
        global $DB;

        $DB->insert(self::RUNS_TABLE, [
            'plugin_glpinetscan_scanners_id' => $scannerId,
            'plugin_glpinetscan_targets_id'  => $targetId,
            'started_at'                     => $startedAt,
            'finished_at'                    => $finishedAt,
            'discovered'                     => $discovered,
            'inventoried'                    => $inventoried,
            'failed'                         => $failed,
            'message'                        => $message,
        ]);

        return (int) $DB->insertId();
    }

    /** Fold a scanner's reported outcome into an open run row. */
    public static function closeRun(
        int $runId,
        int $scannerId,
        int $discovered,
        int $inventoried,
        int $failed,
        string $message
    ): void {
        /** @var DBmysql $DB */
        global $DB;

        if ($runId <= 0) {
            return;
        }

        $DB->update(
            self::RUNS_TABLE,
            [
                'finished_at' => time(),
                'discovered'  => $discovered,
                'inventoried' => $inventoried,
                'failed'      => $failed,
                'message'     => $message,
            ],
            // Scoped to the reporting scanner so one scanner cannot rewrite
            // another's run history.
            ['id' => $runId, 'plugin_glpinetscan_scanners_id' => $scannerId]
        );
    }

    /**
     * The target a run belongs to, used to check reported addresses against
     * the ranges that were actually assigned.
     */
    public static function targetForRun(int $runId, int $scannerId): ?Target
    {
        /** @var DBmysql $DB */
        global $DB;

        $rows = $DB->request([
            'FROM'  => self::RUNS_TABLE,
            'WHERE' => ['id' => $runId, 'plugin_glpinetscan_scanners_id' => $scannerId],
            'LIMIT' => 1,
        ]);

        foreach ($rows as $row) {
            $target = new Target();
            if ($target->getFromDB((int) $row['plugin_glpinetscan_targets_id'])) {
                return $target;
            }
        }

        return null;
    }
}
