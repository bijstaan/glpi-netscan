<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use CronTask;
use Throwable;

/**
 * The scheduled half: decide what to ask, ask it, write down the answer.
 *
 * Everything about this loop is shaped by the fact that the resource being
 * spent is somebody else's rate limit, and the punishment for spending it
 * carelessly is an API key suspended by a vendor — which takes a support case
 * to undo and is not something a plugin should be able to do to an
 * administrator by accident.
 *
 * So: a bounded number of assets per run; a per-vendor interval floor inside
 * the transport; batching wherever the vendor supports it (a hundred Dell
 * service tags is one request); a long schedule for answers that will not
 * change; and a vendor that has just answered "your credentials are wrong" or
 * "slow down" is dropped for the rest of the run rather than asked another
 * ninety times.
 *
 * Failures are recorded against the asset rather than only raised, because
 * the question an administrator asks is "why has this laptop got no warranty",
 * and the answer has to be somewhere they will look.
 */
final class Sync
{
    /** How long an asset nothing can be done about waits before being reconsidered. */
    private const SKIP_DAYS = 30;

    /** Ditto, when the only reason is that its vendor is not switched on yet. */
    private const NOT_CONFIGURED_DAYS = 1;

    /** A transient failure is worth another go within the hour. */
    private const RETRY_MINUTES = 60;

    /**
     * One pass.
     *
     * @param array<string,int|string>|null $settings override, for tests that
     *        need to exercise the loop without writing to the instance's
     *        configuration. Production always passes null.
     * @return array<string,int> counters, for the cron volume and the tests
     */
    public static function run(?int $limit = null, ?array $settings = null): array
    {
        $stats = [
            'considered' => 0,
            'looked_up'  => 0,
            'covered'    => 0,
            'not_found'  => 0,
            'skipped'    => 0,
            'errors'     => 0,
            'applied'    => 0,
        ];

        $settings ??= Settings::all();

        if ((int) $settings['warranty_enabled'] !== 1) {
            return $stats;
        }

        $usable = array_flip(Registry::usableKeys($settings));

        $limit      = $limit ?? (int) $settings['warranty_run_limit'];
        $candidates = Scope::due(max(1, $limit));

        /** @var array<string,Subject[]> $queue */
        $queue = [];

        foreach ($candidates as $candidate) {
            $stats['considered']++;

            $subject = Scope::subjectFor($candidate['itemtype'], $candidate['items_id'], $settings);

            if ($subject === null) {
                self::skip(
                    $candidate['itemtype'],
                    $candidate['items_id'],
                    'No usable serial number on this asset.',
                    self::SKIP_DAYS
                );
                $stats['skipped']++;
                continue;
            }

            $vendor = Detector::detect($subject);

            if ($vendor === null) {
                Record::store($subject, Record::failure(
                    '',
                    Record::SKIPPED,
                    $subject->manufacturer === ''
                        ? 'No manufacturer recorded, so no vendor could be identified.'
                        : sprintf('No warranty API is available for "%s".', $subject->manufacturer),
                    self::SKIP_DAYS
                ));
                $stats['skipped']++;
                continue;
            }

            if (!isset($usable[$vendor])) {
                Record::store($subject, Record::failure(
                    $vendor,
                    Record::SKIPPED,
                    sprintf(
                        '%s lookups are not switched on, or are missing credentials.',
                        Registry::classFor($vendor)::label()
                    ),
                    self::NOT_CONFIGURED_DAYS
                ));
                $stats['skipped']++;
                continue;
            }

            $queue[$vendor][] = $subject;
        }

        foreach ($queue as $vendor => $subjects) {
            self::runVendor($vendor, $subjects, $settings, $stats);
        }

        return $stats;
    }

    /**
     * Every batch for one vendor, stopping early when the vendor tells us to.
     *
     * @param Subject[]            $subjects
     * @param array<string,mixed>  $settings
     * @param array<string,int>    $stats
     */
    private static function runVendor(string $vendor, array $subjects, array $settings, array &$stats): void
    {
        $class  = Registry::classFor($vendor);
        $client = Registry::make($vendor, $settings);

        if ($class === null || $client === null) {
            return;
        }

        foreach (array_chunk($subjects, max(1, $class::batchSize())) as $batch) {
            try {
                $results = $client->lookup($batch);
            } catch (WarrantyException $e) {
                self::recordBatchFailure($batch, $vendor, $e, $stats);

                // A credential problem, a quota refusal or a misconfiguration
                // will greet every remaining batch identically. Carrying on
                // would turn one bad setting into several hundred rejected
                // requests, which is how an API key gets suspended.
                if (!$e->isRetryable() || $e->kind === WarrantyException::THROTTLED) {
                    return;
                }

                continue;
            } catch (Throwable $e) {
                self::recordBatchFailure(
                    $batch,
                    $vendor,
                    new WarrantyException(WarrantyException::RESPONSE, $e->getMessage()),
                    $stats
                );
                continue;
            }

            foreach ($batch as $subject) {
                $stats['looked_up']++;

                $coverage = $results[$subject->key()] ?? null;

                if ($coverage === null || $coverage->isEmpty()) {
                    // A vendor that answered *something* usually said why — an
                    // ambiguous serial, a decommissioned unit, a response shape
                    // nothing matched. Its own words beat the generic message.
                    $why = $coverage !== null && $coverage->note !== ''
                        ? $coverage->note
                        : sprintf(
                            '%s has no warranty record for this serial. Kit registered to a '
                                . 'reseller rather than to your account looks like this.',
                            $class::label()
                        );

                    Record::store($subject, Record::failure(
                        $vendor,
                        Record::NOT_FOUND,
                        $why,
                        (int) $settings['warranty_unknown_interval_days']
                    ));
                    $stats['not_found']++;
                    continue;
                }

                $applied = Writer::apply($subject, $coverage, $settings);

                $due = $coverage->isCovered()
                    ? (int) $settings['warranty_interval_days']
                    : (int) $settings['warranty_expired_interval_days'];

                Record::store($subject, Record::fromCoverage($coverage, $applied, $due));

                $stats['covered']++;
                if ($applied['outcome'] === Writer::APPLIED) {
                    $stats['applied']++;
                }
            }
        }
    }

    /**
     * @param Subject[]         $batch
     * @param array<string,int> $stats
     */
    private static function recordBatchFailure(array $batch, string $vendor, WarrantyException $e, array &$stats): void
    {
        $next = $e->isRetryable()
            ? Record::inMinutes(self::RETRY_MINUTES)
            : Record::in(self::NOT_CONFIGURED_DAYS);

        foreach ($batch as $subject) {
            Record::store($subject, [
                'vendor'        => $vendor,
                'status'        => Record::ERROR,
                'message'       => mb_substr($e->getMessage(), 0, 500),
                'next_check_at' => $next,
            ]);
            $stats['errors']++;
        }

        trigger_error('glpinetscan warranty: ' . $e->getMessage(), E_USER_WARNING);
    }

    private static function skip(string $itemtype, int $items_id, string $message, int $days): void
    {
        Record::store(
            new Subject(itemtype: $itemtype, items_id: $items_id, serial: ''),
            Record::failure('', Record::SKIPPED, $message, $days)
        );
    }

    /**
     * Look one asset up now, regardless of its schedule.
     *
     * This is what the button on the asset's tab calls. It bypasses the due
     * check and the scope check — an operator asking about the machine in
     * front of them is a deliberate act, and refusing it because the asset was
     * checked yesterday would be obtuse — but it still respects the master
     * switch and the vendor switches, because those are the decisions about
     * what may leave the building at all.
     *
     * @return array{ok:bool, message:string}
     */
    public static function runItem(string $itemtype, int $items_id): array
    {
        $settings = Settings::all();

        if ((int) $settings['warranty_enabled'] !== 1) {
            return ['ok' => false, 'message' => __('Warranty lookups are switched off.', 'glpinetscan')];
        }

        $subject = Scope::subjectFor($itemtype, $items_id, $settings);

        if ($subject === null) {
            return ['ok' => false, 'message' => __('This asset has no usable serial number.', 'glpinetscan')];
        }

        $vendor = Detector::detect($subject);

        if ($vendor === null) {
            return [
                'ok'      => false,
                'message' => __('No vendor warranty API matches this asset\'s manufacturer.', 'glpinetscan'),
            ];
        }

        if (!Registry::isUsable($vendor, $settings)) {
            return [
                'ok'      => false,
                'message' => sprintf(
                    __('%s lookups are not switched on, or are missing credentials.', 'glpinetscan'),
                    Registry::classFor($vendor)::label()
                ),
            ];
        }

        $stats = ['looked_up' => 0, 'covered' => 0, 'not_found' => 0, 'errors' => 0, 'applied' => 0];

        self::runVendor($vendor, [$subject], $settings, $stats);

        if ($stats['errors'] > 0) {
            $row = Record::for($itemtype, $items_id);

            return ['ok' => false, 'message' => (string) ($row['message'] ?? __('The lookup failed.', 'glpinetscan'))];
        }

        if ($stats['not_found'] > 0) {
            return [
                'ok'      => false,
                'message' => sprintf(
                    __('%s has no warranty record for this serial number.', 'glpinetscan'),
                    Registry::classFor($vendor)::label()
                ),
            ];
        }

        return ['ok' => true, 'message' => __('Warranty updated from the vendor.', 'glpinetscan')];
    }

    /**
     * Put every skipped asset back in the queue.
     *
     * Called when the settings are saved: an administrator who has just
     * switched a vendor on should not wait a day to see anything happen, and
     * the skipped rows are precisely the ones that were waiting for exactly
     * this change.
     */
    public static function requeueSkipped(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($DB->tableExists(Record::TABLE)) {
            $DB->update(Record::TABLE, ['next_check_at' => null], ['status' => Record::SKIPPED]);
        }
    }

    // ------------------------------------------------------------------- cron

    /**
     * @return array<string,string>
     */
    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'warrantyLookup' => [
                'description' => __('Look up hardware warranties with the vendors', 'glpinetscan'),
            ],
            default => [],
        };
    }

    /** @return int 1 when something happened, 0 when the run was quiet */
    public static function cronWarrantyLookup(CronTask $task): int
    {
        $stats = self::run();

        $task->addVolume($stats['looked_up']);

        if ($stats['errors'] > 0) {
            $task->log(sprintf('%d warranty lookups failed', $stats['errors']));
        }

        return $stats['looked_up'] > 0 || $stats['skipped'] > 0 ? 1 : 0;
    }
}
