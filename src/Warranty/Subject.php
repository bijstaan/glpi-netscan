<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * One asset, reduced to what a vendor will accept.
 *
 * The serial is the only field every vendor needs; the rest are there because
 * three of the seven cannot answer without them. HP resolves an ambiguous
 * serial with the product number, HPE requires a country because its
 * entitlements are sold per region, and Apple and Lenovo both key on a
 * machine-type suffix for models whose serial is not unique on its own.
 *
 * Kept separate from the GLPI item so a vendor client never touches the
 * database, which is what makes them testable and what stops a lookup path
 * from growing the ability to write to an asset.
 */
final class Subject
{
    public function __construct(
        public readonly string $itemtype,
        public readonly int $items_id,
        public readonly string $serial,
        public readonly string $manufacturer = '',
        public readonly string $model = '',
        /** HP product number / HPE product number, from the model dropdown. */
        public readonly string $part_number = '',
        /** ISO 3166-1 alpha-2, for the vendors that sell entitlements per region. */
        public readonly string $country = '',
        public readonly string $name = ''
    ) {
    }

    /**
     * The serial as vendors index it.
     *
     * Upper-cased and stripped of the spaces that creep in when a serial has
     * been typed rather than inventoried. Case matters: Dell's asset endpoint
     * matches a lower-case service tag but returns it upper-cased, so keying a
     * result map on the sent value silently loses every row.
     */
    public function key(): string
    {
        return self::normalise($this->serial);
    }

    public static function normalise(string $serial): string
    {
        return strtoupper(preg_replace('/\s+/', '', trim($serial)) ?? $serial);
    }

    /**
     * Is this worth sending at all?
     *
     * GLPI is full of placeholder serials — inventory agents write these when
     * the firmware has none, and sending them is a guaranteed miss that still
     * costs a call against the quota. The list is the set actually seen in
     * DMI, not a guess.
     */
    public function isLookupable(): bool
    {
        $serial = $this->key();

        if (mb_strlen($serial) < 4 || mb_strlen($serial) > 64) {
            return false;
        }

        static $placeholders = [
            'NOTSPECIFIED', 'TOBEFILLEDBYOEM', 'TOBEFILLEDBYO.E.M.', 'SYSTEMSERIALNUMBER',
            'DEFAULTSTRING', 'NONE', 'N/A', 'NA', 'UNKNOWN', 'INVALID', 'EMPTY',
            'SERIALNUMBER', 'CHASSISSERIALNUMBER', 'OEM', '0123456789', 'XXXXXXX',
        ];

        $flat = str_replace(['-', '_', '.', '/'], '', $serial);

        if (in_array($flat, $placeholders, true)) {
            return false;
        }

        // All one character ("000000", "XXXXXXXX") is never a real serial.
        return count(array_unique(str_split($flat))) > 1;
    }
}
