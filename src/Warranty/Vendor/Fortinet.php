<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty\Vendor;

use GlpiPlugin\Glpinetscan\Warranty\AbstractVendor;
use GlpiPlugin\Glpinetscan\Warranty\Coverage;
use GlpiPlugin\Glpinetscan\Warranty\Entitlement;
use GlpiPlugin\Glpinetscan\Warranty\Reply;
use GlpiPlugin\Glpinetscan\Warranty\Subject;
use GlpiPlugin\Glpinetscan\Warranty\WarrantyException;

/**
 * Fortinet — FortiCare Asset Management (Registration API v3).
 *
 * Credentials are an **IAM API user**, created in the FortiCloud Identity and
 * Access Management portal, not an ordinary support login. The portal issues
 * an API username and password; those are exchanged for a token at
 * FortiAuthenticator and the token is then used against support.fortinet.com.
 *
 * Two things about this API differ from the other six and both are load-bearing:
 *
 * **The token grant is `password`, not `client_credentials`**, and the request
 * is JSON rather than form-encoded — so the shared OAuth helper cannot be used
 * and the exchange is done here.
 *
 * **It only knows assets registered to the account the credentials belong to.**
 * Fortinet hardware bought through a reseller that registered it under their
 * own account is genuinely invisible, which is a different thing from being
 * out of warranty and is reported as "not found" rather than "expired".
 */
final class Fortinet extends AbstractVendor
{
    private const TOKEN_URL = 'https://customerapiauth.fortinet.com/api/v1/oauth/token/';
    private const LIST_URL  = 'https://support.fortinet.com/ES/api/registration/v3/products/list';

    public static function key(): string
    {
        return 'fortinet';
    }

    public static function label(): string
    {
        return 'Fortinet';
    }

    public static function credentials(): array
    {
        return [
            'api_username' => [
                'label'    => 'IAM API username',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'From FortiCloud → IAM → API Users. Not a support portal login.',
            ],
            'api_password' => [
                'label'    => 'IAM API password',
                'type'     => 'secret',
                'required' => true,
                'hint'     => 'Shown once when the API user is created.',
            ],
            'client_id' => [
                'label'    => 'Client ID',
                'type'     => 'text',
                'required' => false,
                'hint'     => 'The FortiCloud service being called. Leave as assetmanagement.',
                'default'  => 'assetmanagement',
            ],
        ];
    }

    public static function aliases(): array
    {
        return ['fortinet', 'fortigate', 'fortiswitch', 'fortiap', 'forti'];
    }

    /** The endpoint takes one serial per call. */
    public static function batchSize(): int
    {
        return 1;
    }

    public static function minInterval(): float
    {
        // Fortinet publishes 100 calls a minute and 1000 an hour. 0.7s keeps
        // a long sync inside the per-minute ceiling without ever bursting.
        return 0.7;
    }

    public function lookup(array $subjects): array
    {
        if ($subjects === []) {
            return [];
        }

        $token = $this->fortiToken();
        $out   = [];

        foreach ($subjects as $subject) {
            $reply = $this->http->send('POST', self::LIST_URL, [
                'json'    => ['serialNumber' => $subject->key()],
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Content-Type'  => 'application/json',
                ],
            ]);

            // An unregistered serial is a 404 here; that is an answer about
            // one device and must not abandon the rest of the batch.
            if ($reply->status === 404) {
                continue;
            }

            $this->assertOk($reply, 'product list');

            $payload = $reply->json(self::label());

            foreach ((array) ($payload['assets'] ?? []) as $asset) {
                if (!is_array($asset)) {
                    continue;
                }

                $serial = Subject::normalise((string) (self::pick($asset, 'serialNumber', 'serial') ?? ''));
                if ($serial === '') {
                    continue;
                }

                $entitlements = [];

                // Fortinet splits the same shape across two lists: the support
                // services bought (entitlements) and the hardware warranty
                // (warrantySupports). Both are cover and both belong here.
                foreach (['entitlements', 'warrantySupports'] as $field) {
                    $is_warranty = $field === 'warrantySupports';

                    foreach ((array) ($asset[$field] ?? []) as $line) {
                        if (!is_array($line)) {
                            continue;
                        }

                        $start = self::pick($line, 'startDate', 'start');
                        $end   = self::pick($line, 'endDate', 'end');

                        if ($start === null && $end === null) {
                            continue;
                        }

                        $entitlements[] = Entitlement::make(
                            $is_warranty ? Entitlement::BASE : Entitlement::CONTRACT,
                            (string) (self::pick($line, 'levelDesc', 'typeDesc', 'level') ?? ''),
                            $start,
                            $end
                        );
                    }
                }

                foreach ((array) ($asset['contracts'] ?? []) as $contract) {
                    if (!is_array($contract)) {
                        continue;
                    }

                    foreach ((array) ($contract['terms'] ?? []) as $term) {
                        if (!is_array($term)) {
                            continue;
                        }

                        $entitlements[] = Entitlement::make(
                            Entitlement::CONTRACT,
                            (string) (self::pick($term, 'supportType', 'typeDesc') ?? ''),
                            self::pick($term, 'startDate', 'start'),
                            self::pick($term, 'endDate', 'end'),
                            false,
                            (string) (self::pick($contract, 'contractNumber', 'sku') ?? '')
                        );
                    }
                }

                $out[$serial] = new Coverage(
                    serial: $serial,
                    vendor: self::key(),
                    entitlements: $entitlements,
                    product: trim((string) (self::pick($asset, 'productModel', 'description') ?? '')),
                    purchase_date: Entitlement::date(self::pick($asset, 'registrationDate')),
                    note: !empty($asset['isDecommissioned'])
                        ? 'Fortinet has this unit marked decommissioned.'
                        : ''
                );
            }
        }

        return $out;
    }

    /**
     * The FortiCloud token.
     *
     * Not {@see AbstractVendor::bearer()}: this grant is `password` over JSON,
     * where every other vendor here is `client_credentials` over a form.
     */
    private function fortiToken(): string
    {
        if ($this->token !== null && $this->token_expires > time()) {
            return $this->token;
        }

        $reply = $this->http->send('POST', self::TOKEN_URL, [
            'json' => [
                'username'   => $this->credential('api_username'),
                'password'   => $this->credential('api_password'),
                'client_id'  => $this->credential('client_id'),
                'grant_type' => 'password',
            ],
            'headers' => ['Content-Type' => 'application/json'],
        ]);

        if (!$reply->ok()) {
            throw new WarrantyException(
                WarrantyException::AUTH,
                sprintf(
                    'Fortinet rejected the IAM API credentials (HTTP %d): %s',
                    $reply->status,
                    Reply::clip($reply->body, 160)
                ),
                $reply->status
            );
        }

        $body  = $reply->json(self::label());
        $token = (string) ($body['access_token'] ?? '');

        if ($token === '') {
            throw new WarrantyException(
                WarrantyException::AUTH,
                'Fortinet returned no access_token: ' . Reply::clip($reply->body, 160)
            );
        }

        $this->token         = $token;
        $this->token_expires = time() + max(60, (int) ($body['expires_in'] ?? 14400)) - 60;

        return $token;
    }
}
