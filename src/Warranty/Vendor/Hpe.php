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
 * Hewlett Packard Enterprise — Support Entitlement (warranty check) API.
 *
 * HPE, not HP Inc.: ProLiant and Synergy servers, Nimble and Alletra storage,
 * FlexNetwork and Aruba networking. Separate company, separate support
 * organisation, separate credentials. {@see Hp} covers the client and printer
 * side.
 *
 * Access is not self-service. HPE issues the client ID and secret against a
 * support agreement after a request through support.hpe.com; there is no
 * developer portal to sign up on, which is also why the request and response
 * shapes below are matched leniently — HPE documents them to entitled accounts
 * rather than publicly, and a field rename would otherwise read as every HPE
 * asset losing its warranty overnight.
 *
 * **A country code is required.** HPE sells entitlements per region and the
 * API will not answer without one, so the plugin's configured default is used
 * whenever the asset's entity does not supply one.
 */
final class Hpe extends AbstractVendor
{
    private const TOKEN_URL    = 'https://api-gw.support.hpe.com/apigwext/services/oauth/token';
    private const WARRANTY_URL = 'https://api-gw.support.hpe.com/apigwext/support/entitlement/v1/warrantyCheck/';

    public static function key(): string
    {
        return 'hpe';
    }

    public static function label(): string
    {
        return 'HPE';
    }

    public static function credentials(): array
    {
        return [
            'client_id' => [
                'label'    => 'API client ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'Requested through support.hpe.com; issued against a support agreement.',
            ],
            'client_secret' => [
                'label'    => 'API client secret',
                'type'     => 'secret',
                'required' => true,
                'hint'     => '',
            ],
            'country' => [
                'label'    => 'Default country code',
                'type'     => 'text',
                'required' => false,
                'hint'     => 'ISO two-letter code. HPE entitlements are regional and the API requires one.',
                'default'  => 'US',
            ],
        ];
    }

    public static function aliases(): array
    {
        // Aruba is HPE's networking brand and its switches report themselves
        // that way; 3Com and H3C kit that came through the same acquisition
        // reports its own names and is supported on the same agreements.
        return [
            'hewlett packard enterprise', 'hewlett-packard enterprise', 'hpe',
            'aruba', 'aruba networks', '3com', 'h3c',
        ];
    }

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

        $default_country = strtoupper($this->credential('country'));

        // Basic authentication on the token call rather than the credentials
        // in the body: this gateway rejects the form-encoded form with a 400
        // that says nothing useful.
        $token = $this->bearer(self::TOKEN_URL, [], [
            'Authorization' => 'Basic ' . base64_encode(
                $this->credential('client_id') . ':' . $this->credential('client_secret')
            ),
        ]);

        $body = [];
        foreach ($subjects as $subject) {
            $body[] = [
                'serialNumber'  => $subject->key(),
                'productNumber' => $subject->part_number,
                'countryCode'   => $subject->country !== '' ? strtoupper($subject->country) : $default_country,
            ];
        }

        $reply = $this->http->send('POST', self::WARRANTY_URL, [
            'json'    => $body,
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/json',
            ],
        ]);

        $this->assertOk($reply, 'warranty check');

        $payload = $reply->json(self::label());

        // The documented envelope, with a bare list accepted as well: the
        // gateway has returned both shapes depending on the account's
        // subscription.
        $rows = $payload['entitlementBySnPnInstanceHSLList']
            ?? $payload['entitlements']
            ?? (array_is_list($payload) ? $payload : []);

        $subjects_by_serial = self::bySerial($subjects);
        $out                = [];

        foreach ((array) $rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $serial = Subject::normalise((string) (self::pick($row, 'serialNumber', 'serial', 'sn') ?? ''));
            if ($serial === '' || !isset($subjects_by_serial[$serial])) {
                continue;
            }

            $levels = (array) (self::pick($row, 'supportLevels', 'offers', 'entitlements') ?? []);

            $entitlements = [];
            foreach ($levels as $level) {
                if (!is_array($level)) {
                    continue;
                }

                $start = self::pick($level, 'startDate', 'obligationStartDate', 'serviceStartDate');
                $end   = self::pick($level, 'endDate', 'obligationEndDate', 'serviceEndDate');

                if ($start === null && $end === null) {
                    continue;
                }

                // HPE distinguishes the warranty a unit shipped with from a
                // contracted support level by whether contractLevel is set.
                $contract = trim((string) ($level['contractLevel'] ?? ''));

                $entitlements[] = Entitlement::make(
                    $contract !== '' ? Entitlement::CONTRACT : Entitlement::BASE,
                    (string) (self::pick($level, 'serviceLevel', 'serviceLevelDescription', 'offerDescription') ?? $contract),
                    $start,
                    $end,
                    false,
                    (string) (self::pick($level, 'contractNumber', 'contractId') ?? '')
                );
            }

            $highest = trim((string) (self::pick($row, 'currentHighestSupportLevel', 'highestSupportLevel') ?? ''));

            $out[$serial] = new Coverage(
                serial: $serial,
                vendor: self::key(),
                entitlements: $entitlements,
                product: trim((string) (self::pick($row, 'productDescription', 'productNumber') ?? '')),
                ship_date: Entitlement::date(self::pick($row, 'shipDate', 'productShipDate')),
                country: strtoupper((string) (self::pick($row, 'countryCode', 'country') ?? '')),
                note: $highest !== '' ? 'Highest active support level: ' . $highest : ''
            );
        }

        return $out;
    }
}
