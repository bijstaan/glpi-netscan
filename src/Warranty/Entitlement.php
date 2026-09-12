<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use DateTimeImmutable;
use Throwable;

/**
 * One line of cover, as the vendor describes it.
 *
 * Every vendor here returns several of these for a machine that has ever been
 * sold an upgrade: a base hardware warranty, a ProSupport or Care Pack that
 * extends it, accidental-damage cover, sometimes a software subscription with
 * its own clock. They overlap, they start on different days, and the one that
 * ends last is not always the one a technician cares about.
 *
 * GLPI's Infocom has room for exactly one span, so the projection has to pick
 * (see {@see Coverage} and {@see Writer}). Keeping the full list here is what
 * makes that choice inspectable afterwards instead of a number nobody can
 * account for.
 */
final class Entitlement
{
    /** The hardware warranty the machine shipped with. */
    public const BASE = 'base';

    /** A purchased extension: ProSupport, Care Pack, Premier Support, SmartNet. */
    public const EXTENDED = 'extended';

    /** A support contract line rather than a warranty. */
    public const CONTRACT = 'contract';

    /** Reported, but the vendor did not say which of the above it is. */
    public const OTHER = 'other';

    public function __construct(
        public readonly string $type,
        /** The vendor's own words: "ProSupport Next Business Day", "SNTC 8x5xNBD". */
        public readonly string $level,
        /** Y-m-d, or null when the vendor did not say. */
        public readonly ?string $start,
        /** Y-m-d, or null for cover with no end date. */
        public readonly ?string $end,
        /** True when the vendor says the cover never expires. */
        public readonly bool $lifetime = false,
        /** A contract or agreement number, where the vendor gives one. */
        public readonly string $reference = ''
    ) {
    }

    /**
     * Build one from whatever shape the vendor used.
     *
     * Dates arrive as ISO 8601 with a timezone (Dell), as `Y-m-d` (Lenovo),
     * as `Y-m-d\TH:i:s` (Cisco) and occasionally as an empty string that is
     * not null. One parser, applied everywhere, rather than seven.
     */
    public static function make(
        string $type,
        string $level,
        mixed $start,
        mixed $end,
        bool $lifetime = false,
        string $reference = ''
    ): self {
        return new self(
            in_array($type, [self::BASE, self::EXTENDED, self::CONTRACT, self::OTHER], true) ? $type : self::OTHER,
            trim(mb_substr(trim($level), 0, 200)),
            self::date($start),
            self::date($end),
            $lifetime,
            trim(mb_substr(trim((string) $reference), 0, 100))
        );
    }

    /**
     * A vendor date as Y-m-d, or null.
     *
     * Deliberately strict about the year. A vendor that has no date for a
     * field sometimes sends `0001-01-01` or `1900-01-01` rather than omitting
     * it, and those parse perfectly well — then become an asset bought in the
     * year 1 with a warranty that expired two millennia ago, which is much
     * harder to notice than a blank.
     */
    public static function date(mixed $value): ?string
    {
        if (!is_string($value) && !is_int($value)) {
            return null;
        }

        $value = trim((string) $value);
        if ($value === '' || $value === '0' || str_starts_with($value, '0000')) {
            return null;
        }

        try {
            $date = new DateTimeImmutable($value);
        } catch (Throwable) {
            return null;
        }

        $year = (int) $date->format('Y');
        if ($year < 1990 || $year > 2100) {
            return null;
        }

        return $date->format('Y-m-d');
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'type'      => $this->type,
            'level'     => $this->level,
            'start'     => $this->start,
            'end'       => $this->end,
            'lifetime'  => $this->lifetime,
            'reference' => $this->reference,
        ];
    }

    /** @param array<string,mixed> $row */
    public static function fromArray(array $row): self
    {
        return new self(
            (string) ($row['type'] ?? self::OTHER),
            (string) ($row['level'] ?? ''),
            isset($row['start']) ? (string) $row['start'] : null,
            isset($row['end']) ? (string) $row['end'] : null,
            (bool) ($row['lifetime'] ?? false),
            (string) ($row['reference'] ?? '')
        );
    }

    public function isActive(?string $today = null): bool
    {
        $today ??= date('Y-m-d');

        if ($this->start !== null && $this->start > $today) {
            return false;
        }

        return $this->lifetime || $this->end === null || $this->end >= $today;
    }
}
