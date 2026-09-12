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
 * Juniper Networks — Service Asset API v1.0.
 *
 * `POST /queryAssetsDetails` takes a list of serial numbers and returns, per
 * asset, a `warranty` list and a `serviceContract` list with their own line
 * items — which is almost exactly the shape this plugin wants, and makes
 * Juniper one of the better-fitting of the ten.
 *
 * Credentials come from Juniper's onboarding form (onboarding-form-app.juniper.net)
 * against a support agreement; the portal issues an application id, a customer
 * source id and either an API key or OAuth2 client credentials. There is no
 * self-service tier.
 *
 * **The `Authorization` header is sent exactly as configured.** Juniper's
 * gateway declares an API-key scheme on that header, and different onboarding
 * packs hand out the value with and without a `Bearer ` prefix. Rather than
 * guess for an API that cannot be called from here, whatever the administrator
 * pastes is what is sent — the settings hint says so.
 *
 * Every request carries a `customerUniqueTransactionID`; Juniper uses it to
 * correlate a call in their logs when something needs chasing, so it is a
 * fresh UUID per request rather than a constant.
 */
final class Juniper extends AbstractVendor
{
    private const ASSETS_URL = 'https://apigw.juniper.net/css-asset/1.0/queryAssetsDetails';

    public static function key(): string
    {
        return 'juniper';
    }

    public static function label(): string
    {
        return 'Juniper Networks';
    }

    public static function credentials(): array
    {
        return [
            'api_key' => [
                'label'    => 'Authorization header value',
                'type'     => 'secret',
                'required' => true,
                'hint'     => 'Sent verbatim as the Authorization header. Include the "Bearer " '
                    . 'prefix if your onboarding pack shows one.',
            ],
            'app_id' => [
                'label'    => 'Application ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'The appId Juniper assigned during onboarding.',
            ],
            'customer_source_id' => [
                'label'    => 'Customer source ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'The customerSourceID Juniper assigned during onboarding.',
            ],
        ];
    }

    public static function aliases(): array
    {
        // Mist is Juniper's, but a Mist access point is claimed by a code
        // rather than registered as a support asset, so it is left out.
        return ['juniper', 'juniper networks'];
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

        $reply = $this->http->send('POST', self::ASSETS_URL, [
            'json' => [
                'queryAssetsDetailsRequest' => [
                    'appId'                       => $this->credential('app_id'),
                    'requestDateTime'             => gmdate('Y-m-d\TH:i:s\Z'),
                    'customerUniqueTransactionID' => self::transactionId(),
                    'customerSourceID'            => $this->credential('customer_source_id'),
                    'serialNumbersOrSSRNs'        => self::serials($subjects),
                ],
            ],
            'headers' => [
                'Authorization' => $this->credential('api_key'),
                'Content-Type'  => 'application/json',
            ],
        ]);

        $this->assertOk($reply, 'asset details');

        $payload            = $reply->json(self::label());
        $subjects_by_serial = self::bySerial($subjects);
        $out                = [];

        foreach ((array) (self::pick($payload, 'assets', 'Assets') ?? []) as $asset) {
            if (!is_array($asset)) {
                continue;
            }

            // Juniper indexes on the serial *or* the software support reference
            // number, and echoes back whichever it matched. Both are mapped, so
            // an estate that records SSRNs still lands on the right asset.
            $serial = Subject::normalise((string) (self::pick($asset, 'serialNumber', 'serialNumberOrSSRN') ?? ''));

            if (!isset($subjects_by_serial[$serial])) {
                $ssrn = Subject::normalise((string) (self::pick($asset, 'softwareSupportReferenceNumber') ?? ''));
                if ($ssrn !== '' && isset($subjects_by_serial[$ssrn])) {
                    $serial = $ssrn;
                }
            }

            if ($serial === '' || !isset($subjects_by_serial[$serial])) {
                continue;
            }

            $entitlements = [];

            foreach ((array) ($asset['warranty'] ?? []) as $warranty) {
                if (!is_array($warranty)) {
                    continue;
                }

                $entitlements[] = Entitlement::make(
                    Entitlement::BASE,
                    (string) (self::pick($warranty, 'warrantyDescription') ?? 'Hardware warranty'),
                    self::pick($warranty, 'warrantyStartDate'),
                    self::pick($warranty, 'warrantyEndDate')
                );
            }

            // A service contract is a header with its own line items, and the
            // dates are on the line items rather than the header.
            foreach ((array) ($asset['serviceContract'] ?? []) as $contract) {
                if (!is_array($contract)) {
                    continue;
                }

                foreach ((array) ($contract['contractDetails'] ?? []) as $line) {
                    if (!is_array($line)) {
                        continue;
                    }

                    $status = strtoupper((string) ($line['contractStatus'] ?? ''));
                    if ($status === 'EXPIRED' || $status === 'CANCELLED' || $status === 'TERMINATED') {
                        continue;
                    }

                    $entitlements[] = Entitlement::make(
                        Entitlement::CONTRACT,
                        (string) (self::pick($line, 'serviceSKUDescription', 'serviceType', 'serviceSKU') ?? 'Service contract'),
                        self::pick($line, 'contractStartDate'),
                        self::pick($line, 'contractEndDate'),
                        false,
                        (string) (self::pick($contract, 'contractNumber') ?? '')
                    );
                }
            }

            $out[$serial] = new Coverage(
                serial: $serial,
                vendor: self::key(),
                entitlements: $entitlements,
                product: trim((string) (self::pick($asset, 'productSKUDescription', 'productSKU') ?? '')),
                ship_date: Entitlement::date(self::pick($asset, 'shipDate')),
                purchase_date: Entitlement::date(self::pick($asset, 'registrationDate')),
                country: strtoupper((string) (self::pick($asset, 'installedAtCountry') ?? '')),
                note: self::note($asset)
            );
        }

        return $out;
    }

    /**
     * Anything Juniper said that changes how the dates should be read.
     *
     * An asset Juniper considers ineligible for service, or one somebody has
     * declined cover on, is not the same as an asset with no cover — and the
     * difference is the whole answer when a technician is asking why they
     * cannot open a case.
     */
    private static function note(array $asset): string
    {
        $notes = [];

        if (isset($asset['serviceEligible']) && !self::truthy($asset['serviceEligible'])) {
            $notes[] = 'Juniper marks this asset as not eligible for service.';
        }

        if (self::truthy($asset['isServiceDeclinedOnAsset'] ?? false)) {
            $reason = trim((string) ($asset['serviceDeclineReason'] ?? ''));
            $notes[] = 'Service was declined on this asset' . ($reason !== '' ? ': ' . $reason : '.');
        }

        $status = trim((string) ($asset['assetStatus'] ?? ''));
        if ($status !== '' && strtoupper($status) !== 'ACTIVE') {
            $notes[] = 'Asset status: ' . $status . '.';
        }

        return implode(' ', $notes);
    }

    /** Juniper sends booleans as booleans, as "Y"/"N" and as "true"/"false". */
    private static function truthy(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        return in_array(strtoupper(trim((string) $value)), ['Y', 'YES', 'TRUE', '1'], true);
    }

    /**
     * A correlation id for one call.
     *
     * Juniper's support uses this to find a request in their logs, so it has to
     * be unique per call rather than per install. `random_bytes` rather than
     * `uniqid`, because two GLPI servers behind the same account would
     * otherwise collide on a shared clock.
     */
    private static function transactionId(): string
    {
        $bytes = random_bytes(16);

        // RFC 4122 version 4.
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
