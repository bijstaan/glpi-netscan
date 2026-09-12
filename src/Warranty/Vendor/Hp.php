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
 * HP Inc. — Product Warranty API v2.
 *
 * This is HP Inc.: laptops, desktops, workstations, printers and displays.
 * Hewlett Packard Enterprise split off in 2015 and has an entirely separate
 * API, account and support organisation — see {@see Hpe}. The two are told
 * apart by asset type rather than by name, because an estate's ProCurve
 * switches and its EliteBooks both report a manufacturer of "HP".
 *
 * Access is requested at developers.hp.com; the credentials are an OAuth2
 * client ID and secret tied to a warranty-scope subscription.
 *
 * **The product number is worth supplying.** HP's serials are not globally
 * unique on their own — the same string is issued against different product
 * lines — so a lookup without a product number can return the warranty of a
 * different machine. GLPI keeps that number on the model dropdown
 * (`glpi_computermodels.product_number`), which is where it is read from; when
 * it is blank the call is still made, because HP resolves most serials without
 * it, but the result is less trustworthy and the tab says so.
 */
final class Hp extends AbstractVendor
{
    private const TOKEN_URL = 'https://warranty.api.hp.com/oauth/v1/token';
    private const QUERY_URL = 'https://warranty.api.hp.com/productwarranty/v2/queries';

    public static function key(): string
    {
        return 'hp';
    }

    public static function label(): string
    {
        return 'HP Inc.';
    }

    public static function credentials(): array
    {
        return [
            'client_id' => [
                'label'    => 'Client ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'From developers.hp.com, on a subscription to the Product Warranty API.',
            ],
            'client_secret' => [
                'label'    => 'Client secret',
                'type'     => 'secret',
                'required' => true,
                'hint'     => '',
            ],
        ];
    }

    public static function aliases(): array
    {
        // Compaq is still what some firmware reports on older business
        // desktops, and it is HP Inc.'s line, not HPE's.
        return ['hp', 'hewlett-packard', 'hewlett packard', 'hp inc', 'compaq'];
    }

    /**
     * Ten rather than the API's ceiling.
     *
     * The response is a flat array with no guaranteed order, so results are
     * matched back by serial. A large batch that comes back missing the serial
     * field would be unattributable in bulk; ten keeps the blast radius of
     * that small while still cutting the request count by an order of
     * magnitude.
     */
    public static function batchSize(): int
    {
        return 10;
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

        $token = $this->bearer(self::TOKEN_URL, [
            'client_id'     => $this->credential('client_id'),
            'client_secret' => $this->credential('client_secret'),
        ]);

        $body = [];
        foreach ($subjects as $subject) {
            $entry = ['sn' => $subject->key()];
            if ($subject->part_number !== '') {
                $entry['pn'] = $subject->part_number;
            }
            $body[] = $entry;
        }

        $reply = $this->http->send('POST', self::QUERY_URL, [
            'json'    => $body,
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/json',
            ],
        ]);

        $this->assertOk($reply, 'product warranty');

        $subjects_by_serial = self::bySerial($subjects);
        $rows               = $reply->json(self::label());
        $out                = [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $serial = Subject::normalise((string) (self::pick($row, 'sn', 'serialNumber', 'serial') ?? ''));

            // A single-serial batch whose response omits the serial is still
            // unambiguous, and HP does omit it on some product lines. Any
            // larger batch is not, and guessing would attach one machine's
            // warranty to another.
            if ($serial === '' && count($subjects) === 1) {
                $serial = array_key_first($subjects_by_serial);
            }

            if ($serial === '' || !isset($subjects_by_serial[$serial])) {
                continue;
            }

            $entitlements = [];
            foreach ((array) (self::pick($row, 'offers', 'entitlements') ?? []) as $offer) {
                if (!is_array($offer)) {
                    continue;
                }

                $start = self::pick($offer, 'serviceObligationLineItemStartDate', 'startDate', 'obligationStartDate');
                $end   = self::pick($offer, 'serviceObligationLineItemEndDate', 'endDate', 'obligationEndDate');

                if ($start === null && $end === null) {
                    continue;
                }

                $entitlements[] = Entitlement::make(
                    self::typeFor((string) ($offer['serviceObligationTypeCode'] ?? '')),
                    (string) (self::pick($offer, 'offerDescription', 'serviceLevelDescription', 'offerId') ?? ''),
                    $start,
                    $end,
                    false,
                    (string) (self::pick($offer, 'obligationKey', 'offerId') ?? '')
                );
            }

            $out[$serial] = new Coverage(
                serial: $serial,
                vendor: self::key(),
                entitlements: $entitlements,
                product: trim((string) (self::pick($row, 'productDescription', 'productName', 'pn') ?? '')),
                ship_date: Entitlement::date(self::pick($row, 'shipDate', 'warrantyStartDate')),
                country: strtoupper((string) (self::pick($row, 'countryCode', 'country') ?? '')),
                note: $subjects_by_serial[$serial]->part_number === ''
                    ? 'Looked up without a product number; HP serials are not unique on their own, '
                        . 'so set the product number on the model to be certain of this result.'
                    : ''
            );
        }

        return $out;
    }

    /**
     * HP's service-obligation type code.
     *
     * HP publishes the code list only to API subscribers. In every payload
     * seen, "C" is the contracted maintenance line — a Care Pack or an onsite
     * support agreement — and the remaining codes are the base warranty the
     * unit shipped with. Anything unrecognised is left as the base warranty
     * rather than discarded, because dropping a line loses cover; mislabelling
     * one only changes a word on a tab.
     */
    private static function typeFor(string $code): string
    {
        return strtoupper($code) === 'C' ? Entitlement::CONTRACT : Entitlement::BASE;
    }
}
