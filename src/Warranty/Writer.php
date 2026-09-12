<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use CommonDBTM;
use DateTimeImmutable;
use Infocom;
use Supplier;
use Throwable;

/**
 * Projects a vendor's answer onto GLPI's own warranty fields.
 *
 * The instruction this feature was built to satisfy is that warranty data
 * lives in the *native* asset fields rather than in a plugin table nobody else
 * can report on — so this writes `glpi_infocoms`, and everything downstream
 * (the Financial tab, the warranty-expiry search options, GLPI's own expiry
 * alert cron, the dashboards, CSV export) works with no further help.
 *
 * ### The shape mismatch, and how it is resolved
 *
 * GLPI stores a warranty as **a start date plus a number of months**, and
 * computes the expiry as `warranty_date + warranty_duration months`. Vendors
 * report **a start date and an end date**, several of them at once, and one of
 * the seven reports an end date with no start at all.
 *
 * Three rules follow, and each of them is a decision rather than an obvious
 * translation:
 *
 * 1. **The entitlement that ends last wins.** A machine with a base warranty
 *    and a ProSupport extension is covered until the extension ends; that is
 *    the date the field is asked about. The whole list is kept on the lookup
 *    record so the choice can be audited.
 *
 * 2. **The duration is whole months, rounded down, and the exact end date goes
 *    into `warranty_info`.** A three-year warranty is thirty-six months on the
 *    nose, so this is exact in almost every real case. Where a vendor's span
 *    is not a whole number of months, GLPI's computed expiry lands a few days
 *    early — which errs towards warning sooner, and the true date is still on
 *    the record and in the info string.
 *
 *    Worth knowing, because it looks like an off-by-one bug and is not ours:
 *    **GLPI computes this expiry two different ways and they differ by a day.**
 *    The search option "Warranty expiration date" and the warranty-alert cron
 *    both use `DATE_ADD(warranty_date, INTERVAL warranty_duration MONTH)`, which
 *    lands exactly on the vendor's end date. The Financial information tab
 *    subtracts one day from that, to show the last day that is still covered.
 *    Reporting and alerting — the two that matter operationally — are therefore
 *    exact, and the tab reads one day earlier by GLPI's own convention.
 *
 * 3. **A coverage with no start is written as a zero-month span ending on the
 *    right day.** Cisco reports expiry without a start. Writing
 *    `warranty_date = <end>, duration = 0` makes every expiry view and every
 *    alert correct. It does leave the "start" column holding the end date,
 *    which is why the info string says so explicitly — the alternative was to
 *    invent a purchase date for every switch in the estate.
 *
 * ### What it will not do
 *
 * It does not touch a warranty somebody typed in. The signature of what this
 * plugin last wrote is kept on the lookup record; if the Infocom no longer
 * matches it, a human has edited those fields and the lookup is recorded but
 * not applied, unless an administrator has explicitly allowed overwriting.
 * The same goes for the purchase date and the supplier, which are finance's
 * fields and are only ever filled in when empty.
 */
final class Writer
{
    /** GLPI's own marker for cover that never expires. */
    public const LIFETIME = -1;

    public const APPLIED    = 'applied';
    public const UNCHANGED  = 'unchanged';
    public const SKIPPED    = 'skipped';
    public const DISABLED   = 'disabled';
    public const NO_DATES   = 'nodates';

    /**
     * Write one coverage onto one asset.
     *
     * @param array<string,int|string> $settings
     * @return array{outcome:string, signature:string, message:string}
     */
    public static function apply(Subject $subject, Coverage $coverage, array $settings): array
    {
        $plan = self::plan($coverage);

        if ($plan === null) {
            return [
                'outcome'   => self::NO_DATES,
                'signature' => '',
                'message'   => 'The vendor reported no usable dates.',
            ];
        }

        $signature = self::signature($plan);

        if ((int) ($settings['warranty_write_infocom'] ?? 1) !== 1) {
            return [
                'outcome'   => self::DISABLED,
                'signature' => '',
                'message'   => 'Writing to the asset is switched off; the result is recorded only.',
            ];
        }

        $infocom = new Infocom();
        $exists  = (bool) $infocom->getFromDBforDevice($subject->itemtype, $subject->items_id);

        if ($exists && !self::mayWrite($infocom, $subject, $settings)) {
            return [
                'outcome'   => self::SKIPPED,
                'signature' => '',
                'message'   => 'The warranty fields on this asset were edited by hand, so they were '
                    . 'left alone. Switch on "Overwrite manually edited warranties" to replace them.',
            ];
        }

        $input = [
            'warranty_date'     => $plan['start'],
            'warranty_duration' => $plan['duration'],
            'warranty_info'     => $plan['info'],
        ];

        if ((int) ($settings['warranty_set_buy_date'] ?? 1) === 1) {
            $purchase = $coverage->purchase_date ?? $coverage->ship_date;
            // Only when GLPI has nothing. A purchase date is finance's field
            // and a ship date is an approximation of it.
            if ($purchase !== null && ($exists ? trim((string) $infocom->fields['buy_date']) === '' : true)) {
                $input['buy_date'] = $purchase;
            }
        }

        if ((int) ($settings['warranty_set_supplier'] ?? 0) === 1) {
            if (!$exists || (int) $infocom->fields['suppliers_id'] === 0) {
                $suppliers_id = self::supplier($coverage->vendor, $subject);
                if ($suppliers_id > 0) {
                    $input['suppliers_id'] = $suppliers_id;
                }
            }
        }

        if ($exists) {
            if (self::isUnchanged($infocom, $input)) {
                return [
                    'outcome'   => self::UNCHANGED,
                    'signature' => $signature,
                    'message'   => '',
                ];
            }

            $input['id'] = (int) $infocom->fields['id'];
            $infocom->update($input);
        } else {
            $input['itemtype'] = $subject->itemtype;
            $input['items_id'] = $subject->items_id;
            $infocom->add($input);
        }

        return [
            'outcome'   => self::APPLIED,
            'signature' => $signature,
            'message'   => '',
        ];
    }

    /**
     * The three field values a coverage implies, or null when it implies none.
     *
     * @return array{start:string, duration:int, info:string, end:?string}|null
     */
    public static function plan(Coverage $coverage): ?array
    {
        $principal = $coverage->principal();

        if ($principal === null) {
            return null;
        }

        $level  = $principal->level !== '' ? $principal->level : $coverage->product;
        $vendor = self::vendorLabel($coverage->vendor);

        if ($principal->lifetime) {
            $start = $coverage->start() ?? $principal->start;

            if ($start === null) {
                return null;
            }

            return [
                'start'    => $start,
                'duration' => self::LIFETIME,
                'info'     => self::info($vendor, $level, 'never expires'),
                'end'      => null,
            ];
        }

        $end = $principal->end;

        if ($end === null) {
            return null;
        }

        $start = $principal->start ?? $coverage->start();

        if ($start === null || $start > $end) {
            // No start, or a start the vendor's own end date contradicts.
            // Anchoring on the end date keeps the expiry exactly right; the
            // info string says the start is not from the vendor so nobody
            // reads the column as a purchase date.
            return [
                'start'    => $end,
                'duration' => 0,
                'info'     => self::info($vendor, $level, 'expires ' . $end . '; start not reported'),
                'end'      => $end,
            ];
        }

        return [
            'start'    => $start,
            'duration' => self::monthsBetween($start, $end),
            'info'     => self::info($vendor, $level, 'expires ' . $end),
            'end'      => $end,
        ];
    }

    /**
     * Whole months from one date to another.
     *
     * Counted in calendar months rather than divided out of a day count: a
     * three-year warranty is thirty-six months whether or not a leap day fell
     * inside it, and `(end - start) / 30` makes it thirty-six and a bit.
     */
    public static function monthsBetween(string $start, string $end): int
    {
        $from = new DateTimeImmutable($start);
        $to   = new DateTimeImmutable($end);

        if ($to <= $from) {
            return 0;
        }

        $months = ((int) $to->format('Y') - (int) $from->format('Y')) * 12
                + ((int) $to->format('n') - (int) $from->format('n'));

        // The final month is only complete once the day of the month has come
        // round again.
        if ((int) $to->format('j') < (int) $from->format('j')) {
            $months--;
        }

        return max(0, $months);
    }

    /**
     * The expiry GLPI's search options and warranty-alert cron will compute.
     *
     * `DATE_ADD(warranty_date, INTERVAL n MONTH)` in SQL, which *clamps* the
     * day of the month rather than overflowing it — 31 January plus one month
     * is 28 February, where PHP's own `+1 month` would say 3 March. The
     * difference only shows up on month-end start dates, and it shows up as a
     * warranty appearing to expire in the wrong month, so it is reproduced
     * here rather than approximated.
     */
    public static function addMonths(string $date, int $months): string
    {
        $from = new DateTimeImmutable($date);

        if ($months === 0) {
            return $from->format('Y-m-d');
        }

        $target = $from->modify(($months > 0 ? '+' : '-') . abs($months) . ' month');

        // PHP overflows into the following month; MySQL clamps to the last day
        // of the target month. Detect the overflow by the day of month changing
        // and walk back to the end of the intended month.
        if ((int) $target->format('j') !== (int) $from->format('j')) {
            $target = $target->modify('first day of this month')->modify('-1 day');
        }

        return $target->format('Y-m-d');
    }

    /**
     * The expiry the Financial information tab will *display*.
     *
     * One day earlier than {@see addMonths()}, because GLPI shows the last day
     * still covered rather than the first day not covered. Here so the tests
     * can assert what a person actually sees, which is the number that gets
     * queried when somebody thinks the plugin is wrong.
     */
    public static function displayedExpiry(string $start, int $months): string
    {
        if ($months <= 0) {
            return (new DateTimeImmutable($start))->format('Y-m-d');
        }

        return (new DateTimeImmutable(self::addMonths($start, $months)))
            ->modify('-1 day')
            ->format('Y-m-d');
    }

    /** "Dell — ProSupport Next Business Day (expires 2027-03-14)", clipped to the column. */
    private static function info(string $vendor, string $level, string $suffix): string
    {
        $text = $vendor;

        if ($level !== '') {
            $text .= ' — ' . $level;
        }

        $text .= ' (' . $suffix . ')';

        return mb_substr($text, 0, 255);
    }

    private static function vendorLabel(string $key): string
    {
        $class = Registry::classFor($key);

        return $class !== null ? $class::label() : ucfirst($key);
    }

    /** A fingerprint of what was written, so a later edit by a person is visible. */
    public static function signature(array $plan): string
    {
        return sha1(implode('|', [
            (string) $plan['start'],
            (string) $plan['duration'],
            (string) $plan['info'],
        ]));
    }

    /**
     * May this plugin write the warranty fields on this asset?
     *
     * Yes when they are empty, yes when they still hold exactly what this
     * plugin last wrote, and otherwise only with explicit permission. The
     * previous signature comes from the lookup record; an asset with no record
     * yet and a warranty already filled in is treated as somebody else's data,
     * which is the safe reading on a first sync over an estate that has been
     * maintained by hand for years.
     */
    private static function mayWrite(Infocom $infocom, Subject $subject, array $settings): bool
    {
        if ((int) ($settings['warranty_overwrite_manual'] ?? 0) === 1) {
            return true;
        }

        $date     = trim((string) ($infocom->fields['warranty_date'] ?? ''));
        $duration = (int) ($infocom->fields['warranty_duration'] ?? 0);
        $info     = trim((string) ($infocom->fields['warranty_info'] ?? ''));

        if ($date === '' && $duration === 0 && $info === '') {
            return true;
        }

        $previous = Record::signatureFor($subject->itemtype, $subject->items_id);

        return $previous !== '' && $previous === sha1(implode('|', [$date, (string) $duration, $info]));
    }

    /** @param array<string,mixed> $input */
    private static function isUnchanged(Infocom $infocom, array $input): bool
    {
        foreach ($input as $field => $value) {
            $current = $infocom->fields[$field] ?? null;

            if ((string) $current !== (string) $value) {
                return false;
            }
        }

        return true;
    }

    /**
     * The manufacturer as a GLPI Supplier, created if need be.
     *
     * Only reached when the administrator asked for it. Entity comes from the
     * asset rather than the session, because this runs in cron where there is
     * no session and every supplier would otherwise land in the root entity.
     */
    private static function supplier(string $vendor, Subject $subject): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $name = self::vendorLabel($vendor);

        try {
            $item = getItemForItemtype($subject->itemtype);
            if (!$item instanceof CommonDBTM || !$item->getFromDB($subject->items_id)) {
                return 0;
            }

            $entities_id = (int) ($item->fields['entities_id'] ?? 0);

            $supplier = new Supplier();
            foreach (
                $DB->request([
                    'SELECT' => ['id'],
                    'FROM'   => Supplier::getTable(),
                    'WHERE'  => [
                        'name'        => $name,
                        'entities_id' => $entities_id,
                        'is_deleted'  => 0,
                    ],
                    'LIMIT'  => 1,
                ]) as $row
            ) {
                return (int) $row['id'];
            }

            $id = $supplier->add([
                'name'         => $name,
                'entities_id'  => $entities_id,
                'is_recursive' => 1,
                'comment'      => 'Created by the warranty lookup.',
            ]);

            return is_int($id) ? $id : 0;
        } catch (Throwable) {
            // A supplier is a convenience; failing to create one must never
            // cost the warranty dates that were the point of the lookup.
            return 0;
        }
    }
}
