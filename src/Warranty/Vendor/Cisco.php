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
 * Cisco — Support API, Serial Number to Information (SN2INFO) v2.
 *
 * Credentials are an OAuth2 client ID and secret registered at
 * apiconsole.cisco.com against a Cisco.com account with a support contract.
 * Applications registered from March 2023 onwards use id.cisco.com rather than
 * the retired cloudsso.cisco.com, which is what this uses.
 *
 * **Cisco reports an end date and no start date.** The coverage summary gives
 * `warranty_end_date` and `covered_product_line_end_date` with nothing to say
 * when either began — Cisco's own portal shows it the same way. {@see Writer}
 * handles that: GLPI stores a start plus a duration, so a coverage with no
 * start is written as a zero-length span ending on the right day, which makes
 * every expiry view and every warranty alert correct even though the start
 * column is not meaningful. The alternative — inventing a start from the
 * warranty type — would put a fabricated purchase date on every switch in the
 * estate.
 *
 * **Meraki is deliberately excluded.** Meraki serials (Q2xx-xxxx-xxxx) are not
 * in SN2INFO; they live in the Dashboard API, which is a per-organisation
 * credential and a different product entirely. Sending them here returns
 * "serial number does not exist" for every access point a site owns.
 */
final class Cisco extends AbstractVendor
{
    private const TOKEN_URL    = 'https://id.cisco.com/oauth2/default/v1/token';
    private const COVERAGE_URL = 'https://apix.cisco.com/sn2info/v2/coverage/summary/serial_numbers/';

    public static function key(): string
    {
        return 'cisco';
    }

    public static function label(): string
    {
        return 'Cisco';
    }

    public static function credentials(): array
    {
        return [
            'client_id' => [
                'label'    => 'Client ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'From apiconsole.cisco.com, on an application subscribed to the Support APIs.',
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
        // "Meraki" is absent on purpose — see the class docblock.
        return ['cisco', 'cisco systems', 'linksys'];
    }

    /** Cisco's documented ceiling for this endpoint. */
    public static function batchSize(): int
    {
        return 75;
    }

    public static function minInterval(): float
    {
        // Cisco publishes 5 requests per second across the Support APIs.
        return 0.25;
    }

    public function lookup(array $subjects): array
    {
        if ($subjects === []) {
            return [];
        }

        $serials = self::serials($subjects);

        $token = $this->bearer(self::TOKEN_URL, [
            'client_id'     => $this->credential('client_id'),
            'client_secret' => $this->credential('client_secret'),
        ], ['Content-Type' => 'application/x-www-form-urlencoded']);

        // The serials are path segments, not a query string. Each is encoded
        // individually so the comma separating them survives.
        $path = implode(',', array_map('rawurlencode', $serials));

        $reply = $this->http->send('GET', self::COVERAGE_URL . $path, [
            'headers' => ['Authorization' => 'Bearer ' . $token],
        ]);

        $this->assertOk($reply, 'coverage summary');

        $payload            = $reply->json(self::label());
        $subjects_by_serial = self::bySerial($subjects);
        $out                = [];

        foreach ((array) ($payload['serial_numbers'] ?? []) as $row) {
            if (!is_array($row)) {
                continue;
            }

            // Cisco reports a per-serial error inside a successful response —
            // an unknown serial does not fail the batch, and must not be
            // allowed to look like a machine with no cover.
            if (!empty($row['ErrorResponse'])) {
                continue;
            }

            $serial = Subject::normalise((string) ($row['sr_no'] ?? ''));
            if ($serial === '' || !isset($subjects_by_serial[$serial])) {
                continue;
            }

            $entitlements = [];

            $warranty_end = Entitlement::date($row['warranty_end_date'] ?? null);
            if ($warranty_end !== null) {
                $entitlements[] = Entitlement::make(
                    Entitlement::BASE,
                    trim((string) (self::pick($row, 'warranty_type_description', 'warranty_type') ?? 'Hardware warranty')),
                    null,
                    $warranty_end
                );
            }

            $contract_end = Entitlement::date($row['covered_product_line_end_date'] ?? null);
            if ($contract_end !== null) {
                $entitlements[] = Entitlement::make(
                    Entitlement::CONTRACT,
                    trim((string) (self::pick($row, 'service_line_descr', 'service_contract_number') ?? 'Service contract')),
                    null,
                    $contract_end,
                    false,
                    (string) ($row['service_contract_number'] ?? '')
                );
            }

            $out[$serial] = new Coverage(
                serial: $serial,
                vendor: self::key(),
                entitlements: $entitlements,
                product: self::product($row),
                country: strtoupper((string) ($row['contract_site_country'] ?? '')),
                note: strtoupper((string) ($row['is_covered'] ?? '')) === 'NO'
                    ? 'Cisco reports this device as not currently covered.'
                    : ''
            );
        }

        return $out;
    }

    /**
     * The most useful product name in the coverage record.
     *
     * The orderable PID list is what a human recognises ("C9300-48P-A"); the
     * base PID is the platform underneath it. Either beats leaving the product
     * blank, which is what happens on kit bought as part of a bundle.
     */
    private static function product(array $row): string
    {
        foreach ((array) ($row['orderable_pid_list'] ?? []) as $pid) {
            if (!is_array($pid)) {
                continue;
            }
            $name = trim((string) (self::pick($pid, 'orderable_pid', 'item_description') ?? ''));
            if ($name !== '') {
                return $name;
            }
        }

        $base = $row['base_pid_list'] ?? [];
        if (is_array($base)) {
            // Cisco sends this as an object on some records and a list on
            // others, so both shapes are unwrapped.
            $first = array_is_list($base) ? ($base[0] ?? []) : $base;
            if (is_array($first)) {
                return trim((string) (self::pick($first, 'base_pid', 'item_description') ?? ''));
            }
        }

        return '';
    }
}
