<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * Everything one vendor knows about one serial, normalised.
 *
 * Seven vendors, seven vocabularies: Dell calls it an entitlement, HP an
 * offer, HPE a support level, Cisco a coverage summary, Fortinet an
 * entitlement with a separate warranty list, Lenovo splits warranties from
 * contracts, and Apple reports one coverage block. They are all reduced to
 * this before anything else in the plugin sees them, so the projection onto
 * GLPI's fields is written once and the vendor clients stay dumb.
 */
final class Coverage
{
    /**
     * @param Entitlement[] $entitlements
     */
    public function __construct(
        public readonly string $serial,
        public readonly string $vendor,
        public readonly array $entitlements = [],
        /** The vendor's product description: "Latitude 7440", "Catalyst 9300-48P". */
        public readonly string $product = '',
        /** When the vendor shipped it. */
        public readonly ?string $ship_date = null,
        /** When the customer bought it, where the vendor distinguishes the two. */
        public readonly ?string $purchase_date = null,
        public readonly string $country = '',
        /** Anything the vendor said that does not fit a field, for the tab. */
        public readonly string $note = ''
    ) {
    }

    public function isEmpty(): bool
    {
        return $this->entitlements === [];
    }

    /**
     * The entitlement the asset's warranty fields should reflect.
     *
     * The one that ends last, because that is the date on which the machine
     * genuinely stops being covered — which is the question Infocom's warranty
     * fields are asked. Lifetime cover wins outright. Among entitlements with
     * no end date at all, the first is taken; the alternative, treating "no
     * end" as "ends now", would report a covered machine as expired.
     */
    public function principal(): ?Entitlement
    {
        $best = null;

        foreach ($this->entitlements as $entitlement) {
            if ($entitlement->lifetime) {
                return $entitlement;
            }

            if ($best === null) {
                $best = $entitlement;
                continue;
            }

            if ($entitlement->end === null) {
                continue;
            }

            if ($best->end === null || $entitlement->end > $best->end) {
                $best = $entitlement;
            }
        }

        return $best;
    }

    /** The earliest start any entitlement reports, falling back to the ship date. */
    public function start(): ?string
    {
        $earliest = null;

        foreach ($this->entitlements as $entitlement) {
            if ($entitlement->start === null) {
                continue;
            }
            if ($earliest === null || $entitlement->start < $earliest) {
                $earliest = $entitlement->start;
            }
        }

        return $earliest ?? $this->purchase_date ?? $this->ship_date;
    }

    /** The last day the asset is covered by anything, or null for lifetime cover. */
    public function end(): ?string
    {
        $principal = $this->principal();

        if ($principal === null || $principal->lifetime) {
            return null;
        }

        return $principal->end;
    }

    public function isLifetime(): bool
    {
        $principal = $this->principal();

        return $principal !== null && $principal->lifetime;
    }

    /** Is anything still in force today? */
    public function isCovered(?string $today = null): bool
    {
        foreach ($this->entitlements as $entitlement) {
            if ($entitlement->isActive($today)) {
                return true;
            }
        }

        return false;
    }

    /** The service level to record, from the entitlement that ends last. */
    public function level(): string
    {
        return $this->principal()?->level ?? '';
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'serial'        => $this->serial,
            'vendor'        => $this->vendor,
            'product'       => $this->product,
            'ship_date'     => $this->ship_date,
            'purchase_date' => $this->purchase_date,
            'country'       => $this->country,
            'note'          => $this->note,
            'entitlements'  => array_map(static fn(Entitlement $e): array => $e->toArray(), $this->entitlements),
        ];
    }

    /** @param array<string,mixed> $row */
    public static function fromArray(array $row): self
    {
        return new self(
            (string) ($row['serial'] ?? ''),
            (string) ($row['vendor'] ?? ''),
            array_map(
                static fn(array $e): Entitlement => Entitlement::fromArray($e),
                array_values((array) ($row['entitlements'] ?? []))
            ),
            (string) ($row['product'] ?? ''),
            isset($row['ship_date']) ? (string) $row['ship_date'] : null,
            isset($row['purchase_date']) ? (string) $row['purchase_date'] : null,
            (string) ($row['country'] ?? ''),
            (string) ($row['note'] ?? '')
        );
    }
}
