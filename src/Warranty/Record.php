<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use DBmysql;

/**
 * One row per asset: what the vendor said, when, and what was done with it.
 *
 * Deliberately *not* where the warranty lives — that is the asset's Infocom,
 * and this exists alongside it for the three things Infocom has no room for:
 *
 * - **the full entitlement list.** A machine routinely has three or four
 *   overlapping lines of cover and Infocom holds one span, so without this the
 *   reason a particular date was chosen is unrecoverable;
 * - **the failures.** "This asset has no warranty data" and "Dell has been
 *   answering 401 for a fortnight" look identical from an empty Infocom, and
 *   only one of them is something an administrator can fix;
 * - **the schedule.** When each asset is next due, so a nightly cron over a
 *   large estate is a trickle rather than a stampede against a rate limit.
 *
 * Plain static database access rather than a CommonDBTM. Registering an
 * itemtype would put this in the search engine, and a second searchable
 * warranty alongside the native one is exactly the duplication this feature
 * was asked to avoid.
 */
final class Record
{
    public const TABLE = 'glpi_plugin_glpinetscan_warranties';

    /** The vendor answered and the dates are on the asset. */
    public const OK = 'ok';

    /** The vendor has no record of this serial. Not a failure. */
    public const NOT_FOUND = 'notfound';

    /** The lookup failed. `message` says how. */
    public const ERROR = 'error';

    /** Nothing was asked: no serial, or no vendor matched, or the vendor is off. */
    public const SKIPPED = 'skipped';

    /**
     * @return array<string,mixed>|null
     */
    public static function for(string $itemtype, int $items_id): ?array
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!$DB->tableExists(self::TABLE)) {
            return null;
        }

        foreach (
            $DB->request([
                'FROM'  => self::TABLE,
                'WHERE' => ['itemtype' => $itemtype, 'items_id' => $items_id],
                'LIMIT' => 1,
            ]) as $row
        ) {
            return $row;
        }

        return null;
    }

    /** What this plugin last wrote onto the asset's warranty fields. */
    public static function signatureFor(string $itemtype, int $items_id): string
    {
        return (string) (self::for($itemtype, $items_id)['applied_signature'] ?? '');
    }

    /**
     * @return Entitlement[]
     */
    public static function entitlements(array $row): array
    {
        $decoded = json_decode((string) ($row['entitlements'] ?? ''), true);

        if (!is_array($decoded)) {
            return [];
        }

        return array_map(
            static fn(array $e): Entitlement => Entitlement::fromArray($e),
            array_values(array_filter($decoded, 'is_array'))
        );
    }

    /**
     * Record the outcome of one lookup, creating or replacing the asset's row.
     *
     * @param array<string,mixed> $fields
     */
    public static function store(Subject $subject, array $fields): void
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!$DB->tableExists(self::TABLE)) {
            return;
        }

        $now = date('Y-m-d H:i:s');

        $row = $fields + [
            'itemtype'   => $subject->itemtype,
            'items_id'   => $subject->items_id,
            'serial'     => mb_substr($subject->serial, 0, 255),
            'checked_at' => $now,
            'date_mod'   => $now,
        ];

        $existing = self::for($subject->itemtype, $subject->items_id);

        if ($existing !== null) {
            $DB->update(self::TABLE, $row, ['id' => (int) $existing['id']]);
            return;
        }

        $row['date_creation'] = $now;
        $DB->insert(self::TABLE, $row);
    }

    /**
     * The fields describing a successful lookup.
     *
     * @param array{outcome:string,signature:string,message:string} $applied
     * @return array<string,mixed>
     */
    public static function fromCoverage(Coverage $coverage, array $applied, int $due_days): array
    {
        $principal = $coverage->principal();

        return [
            'vendor'            => $coverage->vendor,
            'status'            => self::OK,
            'message'           => mb_substr(trim($applied['message'] . ' ' . $coverage->note), 0, 500),
            'product'           => mb_substr($coverage->product, 0, 255),
            'service_level'     => mb_substr($coverage->level(), 0, 255),
            'start_date'        => $coverage->start(),
            'end_date'          => $coverage->end(),
            'is_lifetime'       => $coverage->isLifetime() ? 1 : 0,
            'is_covered'        => $coverage->isCovered() ? 1 : 0,
            'ship_date'         => $coverage->ship_date,
            'purchase_date'     => $coverage->purchase_date,
            'country'           => mb_substr($coverage->country, 0, 8),
            'entitlements'      => json_encode(
                array_map(static fn(Entitlement $e): array => $e->toArray(), $coverage->entitlements),
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            ),
            'applied'           => $applied['outcome'] === Writer::APPLIED
                || $applied['outcome'] === Writer::UNCHANGED ? 1 : 0,
            'applied_signature' => $applied['signature'],
            'next_check_at'     => self::in($due_days),
            'entitlement_count' => count($coverage->entitlements),
            'principal_type'    => $principal?->type ?? '',
        ];
    }

    /** @return array<string,mixed> */
    public static function failure(string $vendor, string $status, string $message, int $due_days): array
    {
        return [
            'vendor'        => $vendor,
            'status'        => $status,
            'message'       => mb_substr($message, 0, 500),
            'next_check_at' => self::in($due_days),
        ];
    }

    public static function in(int $days): string
    {
        return date('Y-m-d H:i:s', time() + max(1, $days) * 86400);
    }

    /** Minutes rather than days, for a transient failure worth retrying soon. */
    public static function inMinutes(int $minutes): string
    {
        return date('Y-m-d H:i:s', time() + max(1, $minutes) * 60);
    }

    /**
     * Counts by status, for the settings page.
     *
     * @return array<string,int>
     */
    public static function summary(): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $out = [self::OK => 0, self::NOT_FOUND => 0, self::ERROR => 0, self::SKIPPED => 0];

        if (!$DB->tableExists(self::TABLE)) {
            return $out;
        }

        foreach (
            $DB->request([
                'SELECT' => ['status', new \QueryExpression('COUNT(*) AS ' . $DB->quoteName('cnt'))],
                'FROM'   => self::TABLE,
                'GROUPBY' => ['status'],
            ]) as $row
        ) {
            $out[(string) $row['status']] = (int) $row['cnt'];
        }

        return $out;
    }

    /**
     * The most recent failures, newest first — the settings page's diagnostic.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function recentFailures(int $limit = 10): array
    {
        /** @var DBmysql $DB */
        global $DB;

        if (!$DB->tableExists(self::TABLE)) {
            return [];
        }

        $out = [];

        foreach (
            $DB->request([
                'FROM'    => self::TABLE,
                'WHERE'   => ['status' => self::ERROR],
                'ORDER'   => ['checked_at DESC'],
                'LIMIT'   => max(1, $limit),
            ]) as $row
        ) {
            $out[] = $row;
        }

        return $out;
    }

    /** Forget every lookup for an asset that has gone away. */
    public static function purgeItem(string $itemtype, int $items_id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        if ($DB->tableExists(self::TABLE)) {
            $DB->delete(self::TABLE, ['itemtype' => $itemtype, 'items_id' => $items_id]);
        }
    }
}
