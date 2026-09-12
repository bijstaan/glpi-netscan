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
 * Dell TechDirect — Asset Entitlements API v5.
 *
 * Credentials come from the API tab of a TechDirect account
 * (techdirect.dell.com), where the key is issued against a customer or partner
 * number; there is no anonymous tier. The same credentials cover Dell client
 * hardware, PowerEdge servers, PowerSwitch networking and Alienware, because
 * Dell keys everything on the service tag.
 *
 * The service tag *is* GLPI's serial for Dell kit — seven alphanumerics, and
 * the inventory agent reports it as the serial — so nothing has to be derived.
 * The Express Service Code, which some sites record in the asset number, is the
 * same tag in base 36 and is not accepted here.
 *
 * Batching is what makes this vendor cheap: a hundred tags per call means a
 * thousand-machine estate is ten requests.
 */
final class Dell extends AbstractVendor
{
    private const TOKEN_PATH  = '/auth/oauth/v2/token';
    private const ASSETS_PATH = '/PROD/sbil/eapi/v5/asset-entitlements';

    public static function key(): string
    {
        return 'dell';
    }

    public static function label(): string
    {
        return 'Dell';
    }

    public static function credentials(): array
    {
        return [
            'client_id' => [
                'label'    => 'API key (client ID)',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'From techdirect.dell.com → APIs → Warranty Status.',
            ],
            'client_secret' => [
                'label'    => 'API secret (client secret)',
                'type'     => 'secret',
                'required' => true,
                'hint'     => 'Shown once when the key is created.',
            ],
            'api_base' => [
                'label'    => 'API host',
                'type'     => 'text',
                'required' => false,
                'hint'     => 'Only change this if Dell issued your account a regional gateway.',
                'default'  => 'https://apigtwb2c.us.dell.com',
            ],
        ];
    }

    public static function aliases(): array
    {
        // "EMC" and "Dell EMC" are the storage and networking lines; their
        // service tags go through the same endpoint. Alienware is Dell's
        // gaming brand and reports itself by name in DMI.
        return ['dell', 'alienware', 'dell emc', 'emc corporation'];
    }

    public static function batchSize(): int
    {
        return 100;
    }

    public static function minInterval(): float
    {
        return 0.25;
    }

    public function lookup(array $subjects): array
    {
        if ($subjects === []) {
            return [];
        }

        $base    = rtrim($this->credential('api_base'), '/');
        $serials = self::serials($subjects);

        $token = $this->bearer($base . self::TOKEN_PATH, [
            'client_id'     => $this->credential('client_id'),
            'client_secret' => $this->credential('client_secret'),
        ]);

        $reply = $this->http->send('GET', $base . self::ASSETS_PATH, [
            'query'   => ['servicetags' => implode(',', $serials)],
            'headers' => ['Authorization' => 'Bearer ' . $token],
        ]);

        $this->assertOk($reply, 'asset entitlements');

        $out = [];

        foreach ($reply->json(self::label()) as $asset) {
            if (!is_array($asset)) {
                continue;
            }

            // Dell answers for every tag sent, marking the ones it does not
            // know rather than omitting them. Treating those as a result would
            // stamp "no warranty" onto assets Dell simply has no record of.
            if (!empty($asset['invalid'])) {
                continue;
            }

            $serial = Subject::normalise((string) self::pick($asset, 'serviceTag', 'id'));
            if ($serial === '') {
                continue;
            }

            $entitlements = [];
            foreach ((array) ($asset['entitlements'] ?? []) as $row) {
                if (!is_array($row)) {
                    continue;
                }

                $entitlements[] = Entitlement::make(
                    self::typeFor((string) ($row['entitlementType'] ?? '')),
                    (string) self::pick($row, 'serviceLevelDescription', 'serviceLevelCode', 'itemNumber'),
                    $row['startDate'] ?? null,
                    $row['endDate'] ?? null,
                    false,
                    (string) ($row['itemNumber'] ?? '')
                );
            }

            $out[$serial] = new Coverage(
                serial: $serial,
                vendor: self::key(),
                entitlements: $entitlements,
                product: trim((string) self::pick($asset, 'productLineDescription', 'systemDescription', 'productLobDescription')),
                ship_date: Entitlement::date($asset['shipDate'] ?? null),
                country: strtoupper((string) ($asset['countryCode'] ?? '')),
                note: !empty($asset['duplicated'])
                    ? 'Dell reports this service tag against more than one record.'
                    : ''
            );
        }

        return $out;
    }

    /**
     * Dell's entitlementType, in its vocabulary.
     *
     * INITIAL is what shipped with the machine and EXTENDED is what was bought
     * afterwards. Dell also emits EXPIRED for cover that has lapsed, which is
     * a state rather than a kind — it still describes a real warranty and is
     * kept, because "this machine had ProSupport until March" is exactly the
     * fact a technician is looking for.
     */
    private static function typeFor(string $type): string
    {
        return match (strtoupper($type)) {
            'INITIAL'  => Entitlement::BASE,
            'EXTENDED' => Entitlement::EXTENDED,
            default    => Entitlement::OTHER,
        };
    }
}
