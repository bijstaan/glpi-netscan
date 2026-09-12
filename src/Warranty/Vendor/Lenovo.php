<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty\Vendor;

use GlpiPlugin\Glpinetscan\Warranty\AbstractVendor;
use GlpiPlugin\Glpinetscan\Warranty\Coverage;
use GlpiPlugin\Glpinetscan\Warranty\Entitlement;
use GlpiPlugin\Glpinetscan\Warranty\Subject;

/**
 * Lenovo — Support Warranty & Contract API v2.5.
 *
 * The simplest of the seven: no OAuth dance, just a ClientID header on every
 * call. The token is issued by a Lenovo account representative or through the
 * partner programme; there is no self-service portal.
 *
 * Covers ThinkPad, ThinkCentre, ThinkStation, Yoga and the ThinkSystem and
 * ThinkAgile server lines, including the ex-IBM System x machine types Lenovo
 * acquired in 2014 — which is why IBM is one of the manufacturer aliases here.
 *
 * **The machine type matters for older kit.** Lenovo serials are unique per
 * machine type, not globally, and the API answers an ambiguous serial with
 * error 101 rather than guessing. Where GLPI's model carries a product number
 * that looks like a machine type, it is sent as the documented `SERIAL.MT`
 * form so the answer is unambiguous.
 */
final class Lenovo extends AbstractVendor
{
    private const WARRANTY_URL = 'https://supportapi.lenovo.com/v2.5/warranty';

    /** Lenovo's own code for "no warranty record for this serial". */
    private const ERROR_NOT_FOUND = 100;

    /** "Several machines share this serial; send SERIAL.MT." */
    private const ERROR_AMBIGUOUS = 101;

    public static function key(): string
    {
        return 'lenovo';
    }

    public static function label(): string
    {
        return 'Lenovo';
    }

    public static function credentials(): array
    {
        return [
            'client_id' => [
                'label'    => 'ClientID',
                'type'     => 'secret',
                'required' => true,
                'hint'     => 'Issued by a Lenovo account representative or the partner programme. '
                    . 'Sent as the ClientID header on every request.',
            ],
        ];
    }

    public static function aliases(): array
    {
        return ['lenovo', 'ibm', 'thinkpad', 'thinkcentre', 'thinksystem'];
    }

    public static function batchSize(): int
    {
        return 50;
    }

    public static function minInterval(): float
    {
        return 0.5;
    }

    public function lookup(array $subjects): array
    {
        if ($subjects === []) {
            return [];
        }

        $query = [];
        foreach ($subjects as $subject) {
            $query[] = self::queryFor($subject);
        }

        $reply = $this->http->send('POST', self::WARRANTY_URL, [
            'form'    => ['Serial' => implode(',', $query)],
            'headers' => ['ClientID' => $this->credential('client_id')],
        ]);

        // A serial Lenovo has no record of comes back as a 404 for a
        // single-serial call. That is an answer, not a failure, so it must not
        // become a retryable error that the sync keeps re-queueing.
        if ($reply->status === 404) {
            return [];
        }

        $this->assertOk($reply, 'warranty');

        $payload = $reply->json(self::label());

        // One serial returns an object; several return a list. Normalising
        // here keeps the loop below from having to care.
        $rows = array_is_list($payload) ? $payload : [$payload];

        $subjects_by_serial = self::bySerial($subjects);
        $out                = [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $code = (int) (self::pick($row, 'Code', 'ErrorCode', 'code') ?? 0);
            if ($code === self::ERROR_NOT_FOUND) {
                continue;
            }

            $serial = Subject::normalise((string) (self::pick($row, 'Serial', 'serial') ?? ''));

            // The `.MT` suffix is a query form, not part of the serial, but
            // Lenovo has echoed it back on some responses.
            $serial = explode('.', $serial)[0];

            if ($serial === '' || !isset($subjects_by_serial[$serial])) {
                continue;
            }

            if ($code === self::ERROR_AMBIGUOUS) {
                // Recorded rather than dropped: the fix is for someone to put
                // the machine type on the model, and an empty result gives
                // them nothing to act on.
                $out[$serial] = new Coverage(
                    serial: $serial,
                    vendor: self::key(),
                    product: (string) (self::pick($row, 'Product', 'product') ?? ''),
                    note: 'Lenovo holds several machines with this serial. Set the machine type '
                        . '(four characters, e.g. 20U9) as the product number on this asset\'s model '
                        . 'so the lookup can be resolved.'
                );
                continue;
            }

            $entitlements = [];

            foreach ((array) (self::pick($row, 'Warranty', 'Warranties') ?? []) as $warranty) {
                if (!is_array($warranty)) {
                    continue;
                }

                $entitlements[] = Entitlement::make(
                    self::typeFor((string) ($warranty['Type'] ?? '')),
                    self::describe($warranty),
                    self::pick($warranty, 'Start', 'start'),
                    self::pick($warranty, 'End', 'end'),
                    false,
                    (string) (self::pick($warranty, 'ID', 'Id') ?? '')
                );
            }

            // Support contracts are a separate list with their own clock. An
            // expired one is skipped: Lenovo keeps historical contract lines,
            // and letting one of those win the "ends last" comparison would
            // report cover the customer no longer has.
            foreach ((array) (self::pick($row, 'Contract', 'Contracts') ?? []) as $contract) {
                if (!is_array($contract)) {
                    continue;
                }

                $status = strtoupper((string) ($contract['Status'] ?? ''));
                if ($status === 'EXPIRED' || $status === 'CANCELLED') {
                    continue;
                }

                $entitlements[] = Entitlement::make(
                    Entitlement::CONTRACT,
                    (string) (self::pick($contract, 'SLA', 'EntitlementCode', 'ItemNumber') ?? 'Support contract'),
                    self::pick($contract, 'Start', 'start'),
                    self::pick($contract, 'End', 'end'),
                    false,
                    (string) (self::pick($contract, 'Contract', 'ItemNumber') ?? '')
                );
            }

            $out[$serial] = new Coverage(
                serial: $serial,
                vendor: self::key(),
                entitlements: $entitlements,
                product: (string) (self::pick($row, 'Product', 'product') ?? ''),
                ship_date: Entitlement::date(self::pick($row, 'Shipped', 'Shiped')),
                purchase_date: Entitlement::date(self::pick($row, 'Purchased', 'purchased')),
                country: strtoupper((string) (self::pick($row, 'Country', 'country') ?? ''))
            );
        }

        return $out;
    }

    /**
     * The query term for one asset.
     *
     * `SERIAL.MT` where a machine type is known, plain serial otherwise. A
     * machine type is four alphanumerics; anything else on the model's product
     * number is some other identifier and sending it would make a resolvable
     * serial unresolvable.
     */
    private static function queryFor(Subject $subject): string
    {
        $machine_type = strtoupper(trim($subject->part_number));

        if (preg_match('/^[A-Z0-9]{4}$/', $machine_type) === 1) {
            return $subject->key() . '.' . $machine_type;
        }

        return $subject->key();
    }

    /** The most descriptive of the several names Lenovo puts on a warranty. */
    private static function describe(array $warranty): string
    {
        $name     = trim((string) ($warranty['Name'] ?? ''));
        $delivery = trim((string) ($warranty['Delivery'] ?? ''));

        if ($name !== '' && $delivery !== '' && stripos($name, $delivery) === false) {
            // "3Y Premier Support" plus "ON_SITE" reads better as one line than
            // as a name that omits how the service is actually delivered.
            return $name . ' (' . str_replace('_', ' ', strtolower($delivery)) . ')';
        }

        return $name !== '' ? $name : trim((string) ($warranty['Description'] ?? ''));
    }

    private static function typeFor(string $type): string
    {
        return match (strtoupper($type)) {
            'BASE'               => Entitlement::BASE,
            'UPGRADE', 'EXTENDED' => Entitlement::EXTENDED,
            default              => Entitlement::OTHER,
        };
    }
}
