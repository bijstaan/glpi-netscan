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
use GlpiPlugin\Glpinetscan\Warranty\TokenStore;
use GlpiPlugin\Glpinetscan\Warranty\Transport;
use GlpiPlugin\Glpinetscan\Warranty\WarrantyException;

/**
 * Apple — Global Service Exchange (GSX) REST API v2.
 *
 * The hardest of the seven to set up and the only one that cannot be turned on
 * from a web form. GSX access requires an Apple Authorised Service Provider or
 * Self-Servicing Account agreement, a GSX account with the "Web Services"
 * privilege granted in MyAccess, a client certificate signed by Apple, and the
 * static IP of this GLPI server allowlisted by Apple. There is no evaluation
 * tier and no way around any of it — Apple has published no serial-number
 * warranty API for anyone else since the public coverage check was closed.
 *
 * Three consequences are visible in the code:
 *
 * **Mutual TLS.** The certificate is a PEM bundle with the private key
 * appended, held on disk on the GLPI server. The plugin stores its path and
 * passphrase, never the file, because the file is per-partner and has to be
 * renewed with Apple annually.
 *
 * **A single-use activation token.** Apple issues an activation token; the
 * first authentication exchanges it for a session token and the activation
 * token is then spent. That session token is what every later call uses, so it
 * has to outlive the process — see {@see TokenStore}. Getting this wrong is
 * not a retryable error; it means asking Apple for a new activation token.
 *
 * **The auth endpoint and the data endpoints are on different paths.**
 * Authentication is under `/api`, everything else under `/gsx/api`, on a base
 * URL that is issued per partner in eServiceCentral rather than being a single
 * public hostname.
 *
 * Apple documents the response body only to partners under agreement, so the
 * field names below are read through aliases and the raw payload keys are kept
 * on the lookup record when nothing matches — a renamed field then shows up as
 * something an administrator can act on rather than as silence.
 */
final class Apple extends AbstractVendor
{
    private const AUTH_PATH    = '/api/authenticate/token';
    private const DETAILS_PATH = '/gsx/api/repair/product/details';

    public function __construct(
        Transport $http,
        array $credentials = [],
        private readonly ?TokenStore $tokens = null
    ) {
        parent::__construct($http, $credentials);
    }

    public static function key(): string
    {
        return 'apple';
    }

    public static function label(): string
    {
        return 'Apple';
    }

    public static function credentials(): array
    {
        return [
            'base_url' => [
                'label'    => 'GSX base URL',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'The partner base URL from eServiceCentral. No trailing path.',
            ],
            'sold_to' => [
                'label'    => 'Sold-To account number',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'Your Apple Sold-To, sent as X-Apple-SoldTo.',
            ],
            'ship_to' => [
                'label'    => 'Ship-To account number',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'The service location, sent as X-Apple-ShipTo.',
            ],
            'operator_apple_id' => [
                'label'    => 'Operator Apple ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'The GSX user with the "Web Services" privilege.',
            ],
            'activation_token' => [
                'label'    => 'Activation token',
                'type'     => 'secret',
                'required' => true,
                'hint'     => 'Issued by Apple. Spent on first use and exchanged for a session '
                    . 'token, which the plugin then keeps.',
            ],
            'cert_path' => [
                'label'    => 'Client certificate path',
                'type'     => 'path',
                'required' => true,
                'hint'     => 'Absolute path on this server to the Apple-signed .pem chain with '
                    . 'your private key appended. Keep it outside the web root.',
            ],
            'cert_password' => [
                'label'    => 'Certificate passphrase',
                'type'     => 'secret',
                'required' => false,
                'hint'     => 'Leave empty if the private key is not encrypted.',
            ],
            'accept_language' => [
                'label'    => 'Accept-Language',
                'type'     => 'text',
                'required' => false,
                'hint'     => 'As listed in eServiceCentral.',
                'default'  => 'en_US',
            ],
        ];
    }

    public static function aliases(): array
    {
        return ['apple'];
    }

    /** GSX answers about one device per call. */
    public static function batchSize(): int
    {
        return 1;
    }

    public static function minInterval(): float
    {
        return 1.0;
    }

    public function lookup(array $subjects): array
    {
        if ($subjects === []) {
            return [];
        }

        $out = [];

        foreach ($subjects as $subject) {
            $reply = $this->details($subject->key(), false);

            // A session token that has lapsed answers 401. One re-authentication
            // is worth attempting because GSX expires these on idle time as
            // well as age, and an estate checked nightly will hit that
            // routinely; a second failure is a credential problem.
            if ($reply->status === 401 || $reply->status === 403) {
                $reply = $this->details($subject->key(), true);
            }

            if ($reply->status === 404) {
                continue;
            }

            $this->assertOk($reply, 'product details');

            $payload = $reply->json(self::label());
            $device  = self::device($payload);

            if ($device === []) {
                continue;
            }

            $serial = Subject::normalise(
                (string) (self::pick($device, 'serialNumber', 'id', 'identifier') ?? $subject->key())
            );

            $out[$serial] = $this->coverage($serial, $device);
        }

        return $out;
    }

    /** One product-details call, optionally forcing a fresh session token first. */
    private function details(string $serial, bool $reauthenticate): Reply
    {
        $base  = rtrim($this->credential('base_url'), '/');
        $token = $this->sessionToken($reauthenticate);

        return $this->http->send('POST', $base . self::DETAILS_PATH, [
            'json' => [
                // GSX requires a received timestamp on this call even when
                // nothing is being received; it dates the entitlement answer.
                'unitReceivedDateTime' => gmdate('Y-m-d\TH:i:s\Z'),
                'device'               => ['id' => $serial],
            ],
            'headers' => $this->headers($token) + ['Content-Type' => 'application/json'],
        ]);
    }

    /**
     * @return array<string,string>
     */
    private function headers(string $token): array
    {
        return [
            'X-Apple-SoldTo'          => $this->credential('sold_to'),
            'X-Apple-ShipTo'          => $this->credential('ship_to'),
            'X-Operator-User-ID'      => $this->credential('operator_apple_id'),
            'X-Apple-Service-Version' => 'v2',
            'X-Apple-Auth-Token'      => $token,
            'Accept-Language'         => $this->credential('accept_language'),
        ];
    }

    /**
     * The session token, from the store or by exchanging what we have.
     *
     * The stored token is presented for renewal in preference to the
     * activation token, because the activation token only works once. Losing
     * the stored one therefore costs a call to Apple to be issued another.
     */
    private function sessionToken(bool $force): string
    {
        $stored = $this->tokens?->get('apple_session_token') ?? '';

        if (!$force && $stored !== '') {
            return $stored;
        }

        $base    = rtrim($this->credential('base_url'), '/');
        $present = $stored !== '' ? $stored : $this->credential('activation_token');

        $reply = $this->http->send('POST', $base . self::AUTH_PATH, [
            'json' => [
                'userAppleId' => $this->credential('operator_apple_id'),
                'authToken'   => $present,
            ],
            'headers' => [
                'X-Apple-SoldTo'          => $this->credential('sold_to'),
                'X-Apple-ShipTo'          => $this->credential('ship_to'),
                'X-Apple-Service-Version' => 'v2',
                'Accept-Language'         => $this->credential('accept_language'),
                'Content-Type'            => 'application/json',
            ],
        ]);

        if (!$reply->ok()) {
            throw new WarrantyException(
                WarrantyException::AUTH,
                sprintf(
                    'Apple GSX refused authentication (HTTP %d): %s. If the activation token has '
                        . 'already been used and the session token is lost, Apple must issue a new '
                        . 'activation token.',
                    $reply->status,
                    Reply::clip($reply->body, 160)
                ),
                $reply->status
            );
        }

        $token = (string) (self::pick($reply->json(self::label()), 'authToken', 'auth_token') ?? '');

        if ($token === '') {
            throw new WarrantyException(
                WarrantyException::AUTH,
                'Apple GSX returned no authToken: ' . Reply::clip($reply->body, 160)
            );
        }

        $this->tokens?->put('apple_session_token', $token);

        return $token;
    }

    /**
     * The device object, wherever GSX put it this time.
     *
     * Responses have carried the device at the root, under `device`, and
     * inside a single-element `devices` list. All three are unwrapped rather
     * than assuming one.
     */
    private static function device(array $payload): array
    {
        foreach (['device', 'productDetails', 'product'] as $key) {
            if (is_array($payload[$key] ?? null)) {
                return $payload[$key];
            }
        }

        foreach (['devices', 'products'] as $key) {
            $list = $payload[$key] ?? null;
            if (is_array($list) && is_array($list[0] ?? null)) {
                return $list[0];
            }
        }

        return isset($payload['warrantyInfo']) || isset($payload['serialNumber']) ? $payload : [];
    }

    private function coverage(string $serial, array $device): Coverage
    {
        $warranty = [];
        foreach (['warrantyInfo', 'warranty', 'coverage', 'coverageDetails'] as $key) {
            if (is_array($device[$key] ?? null)) {
                $warranty = $device[$key];
                break;
            }
        }

        // Apple reports coverage as one block rather than a list, so the block
        // is split into the hardware warranty and, where present, the AppleCare
        // agreement — which have different end dates and which a technician
        // needs to tell apart.
        $entitlements = [];

        $status = trim((string) (self::pick($warranty, 'warrantyStatusDescription', 'warrantyStatus', 'warrantyStatusCode') ?? ''));

        $start = self::pick($warranty, 'startDate', 'coverageStartDate', 'warrantyStartDate');
        $end   = self::pick($warranty, 'endDate', 'coverageEndDate', 'warrantyEndDate');

        if ($start !== null || $end !== null) {
            $entitlements[] = Entitlement::make(
                Entitlement::BASE,
                $status !== '' ? $status : 'Apple Limited Warranty',
                $start,
                $end
            );
        }

        $contract_start = self::pick($warranty, 'contractCoverageStartDate', 'appleCareStartDate');
        $contract_end   = self::pick($warranty, 'contractCoverageEndDate', 'appleCareEndDate');

        if ($contract_start !== null || $contract_end !== null) {
            $entitlements[] = Entitlement::make(
                Entitlement::CONTRACT,
                trim((string) (self::pick($warranty, 'contractType', 'agreementType') ?? 'AppleCare')),
                $contract_start,
                $contract_end
            );
        }

        // Nothing matched. Recording which keys were actually present is the
        // difference between an administrator seeing "Apple changed a field
        // name" and seeing a machine that silently never gets a warranty.
        $note = '';
        if ($entitlements === []) {
            $keys = array_slice(array_keys($warranty !== [] ? $warranty : $device), 0, 12);
            $note = $keys === []
                ? 'Apple returned no coverage block for this serial.'
                : 'No coverage dates recognised. Fields returned: ' . implode(', ', $keys);
        }

        return new Coverage(
            serial: $serial,
            vendor: self::key(),
            entitlements: $entitlements,
            product: trim((string) (self::pick($device, 'productDescription', 'configDescription', 'productName') ?? '')),
            purchase_date: Entitlement::date(
                self::pick($device, 'purchaseDate', 'estimatedPurchaseDate')
                    ?? self::pick($warranty, 'purchaseDate', 'estimatedPurchaseDate')
            ),
            country: strtoupper((string) (self::pick($device, 'purchaseCountryCode', 'countryCode') ?? '')),
            note: $note
        );
    }
}
