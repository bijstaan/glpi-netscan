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
use GlpiPlugin\Glpinetscan\Warranty\WarrantyException;

/**
 * Pure Storage — Pure1 public REST API, support contracts.
 *
 * Like Microsoft, this answers about a *fleet*: `/arrays/support-contracts`
 * returns the contract on every array in the Pure1 organisation, so it is
 * fetched once per run and every subject is answered from it.
 *
 * **It matches on name, not serial, and that is a real limitation.** Pure1's
 * array records carry an id, a name, an FQDN and a model — and no serial
 * number anywhere in the public API. An asset discovered over SNMP is matched
 * against the Pure1 array whose name or FQDN equals its GLPI name (the SNMP
 * sysName, in practice), and the result says so on the tab. A site that renames
 * an array in Pure1 without renaming it in GLPI will stop matching; that is
 * visible as "not found" rather than as a wrong date, which is the right way
 * round for a weaker join.
 *
 * Authentication is the odd one out too: RFC 8693 **token exchange**, not
 * client credentials. An RS256 JWT signed with a private key whose public half
 * was uploaded to Pure1 is presented as the subject token and traded for a
 * bearer token. The claim set is deliberately minimal — `iss`, `iat`, `exp`,
 * in *seconds* — matching Pure's own client. Pure's reference documentation
 * describes a fuller set (`kid`, `aud`, `sub`) with millisecond timestamps;
 * their shipped PowerShell module sends neither, and a working client beats a
 * spec when the two disagree.
 */
final class PureStorage extends AbstractVendor
{
    private const BASE_URL  = 'https://api.pure1.purestorage.com';
    private const TOKEN_URL = self::BASE_URL . '/oauth2/1.0/token';
    private const API_ROOT  = self::BASE_URL . '/api/1.latest';

    /** @var array<string,Coverage>|null the fleet, keyed by lower-cased name */
    private ?array $fleet = null;

    public static function key(): string
    {
        return 'pure';
    }

    public static function label(): string
    {
        return 'Pure Storage';
    }

    public static function credentials(): array
    {
        return [
            'app_id' => [
                'label'    => 'Pure1 application ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'Shown in Pure1 when the public key is registered. Looks like '
                    . 'pure1:apikey:xxxxxxxxxxxxxxxx.',
            ],
            'private_key_path' => [
                'label'    => 'Private key path',
                'type'     => 'path',
                'required' => true,
                'hint'     => 'Absolute path on this server to the RSA private key whose public '
                    . 'half is registered in Pure1. Keep it outside the web root.',
            ],
            'private_key_password' => [
                'label'    => 'Private key passphrase',
                'type'     => 'secret',
                'required' => false,
                'hint'     => 'Leave empty if the key is not encrypted.',
            ],
        ];
    }

    public static function aliases(): array
    {
        return ['pure storage', 'purestorage', 'pure'];
    }

    public static function batchSize(): int
    {
        return 500;
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

        $fleet = $this->fleet();
        $out   = [];

        foreach ($subjects as $subject) {
            $coverage = $this->match($subject, $fleet);

            if ($coverage !== null) {
                // Re-keyed onto the subject's serial so the rest of the
                // pipeline is unaffected by the name-based join.
                $out[$subject->key()] = new Coverage(
                    serial: $subject->key(),
                    vendor: self::key(),
                    entitlements: $coverage->entitlements,
                    product: $coverage->product,
                    note: trim($coverage->note . ' Matched to the Pure1 array by name, not by '
                        . 'serial number: Pure1 does not publish one.')
                );
            }
        }

        return $out;
    }

    /**
     * The Pure1 array this asset is, if any.
     *
     * Name first, then the FQDN, then the FQDN's first label — an SNMP sysName
     * is sometimes the bare host and sometimes fully qualified, and the two
     * should not be different answers.
     *
     * @param array<string,Coverage> $fleet
     */
    private function match(Subject $subject, array $fleet): ?Coverage
    {
        foreach (self::candidates($subject) as $candidate) {
            if (isset($fleet[$candidate])) {
                return $fleet[$candidate];
            }
        }

        return null;
    }

    /** @return string[] */
    private static function candidates(Subject $subject): array
    {
        $name = strtolower(trim($subject->name));

        if ($name === '') {
            return [];
        }

        $out = [$name];

        if (str_contains($name, '.')) {
            $out[] = explode('.', $name)[0];
        }

        return array_values(array_unique(array_filter($out)));
    }

    /**
     * Every array in the Pure1 organisation and its support contract.
     *
     * Two calls: the arrays give the model, the support contracts give the
     * dates. Keyed by every name an asset might be discovered under.
     *
     * @return array<string,Coverage>
     */
    private function fleet(): array
    {
        if ($this->fleet !== null) {
            return $this->fleet;
        }

        $token = $this->bearer(self::TOKEN_URL, [
            'grant_type'         => 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token'      => $this->jwt(),
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:jwt',
        ]);

        $headers = ['Authorization' => 'Bearer ' . $token];

        $models = [];
        foreach ($this->items(self::API_ROOT . '/arrays', $headers, 'arrays') as $array) {
            $id = trim((string) ($array['id'] ?? ''));
            if ($id !== '') {
                $models[$id] = trim((string) (self::pick($array, 'model', 'os') ?? ''));
            }
        }

        $fleet = [];

        foreach ($this->items(self::API_ROOT . '/arrays/support-contracts', $headers, 'support contracts') as $contract) {
            $resource = $contract['resource'] ?? [];

            if (!is_array($resource)) {
                continue;
            }

            $start = self::epoch($contract['start_date'] ?? null);
            $end   = self::epoch($contract['end_date'] ?? null);

            if ($start === null && $end === null) {
                continue;
            }

            $coverage = new Coverage(
                serial: '',
                vendor: self::key(),
                entitlements: [
                    Entitlement::make(Entitlement::CONTRACT, 'Pure1 support contract', $start, $end),
                ],
                product: $models[trim((string) ($resource['id'] ?? ''))] ?? ''
            );

            foreach ([$resource['name'] ?? '', $resource['fqdn'] ?? ''] as $name) {
                $name = strtolower(trim((string) $name));

                if ($name === '') {
                    continue;
                }

                $fleet[$name] = $coverage;

                if (str_contains($name, '.')) {
                    $fleet[explode('.', $name)[0]] ??= $coverage;
                }
            }
        }

        return $this->fleet = $fleet;
    }

    /**
     * Every page of a Pure1 collection.
     *
     * Pure1 pages with a continuation token and defaults to 1000 items. A
     * fleet larger than that is rare and entirely possible, and silently
     * reading only the first page would leave exactly those sites with
     * warranties on some arrays and not others.
     *
     * @param array<string,string> $headers
     * @return array<int,array<string,mixed>>
     */
    private function items(string $url, array $headers, string $what): array
    {
        $out    = [];
        $cursor = null;

        // A hard ceiling as well as the cursor: a server that keeps handing
        // back the same token would otherwise loop until the request times out.
        for ($page = 0; $page < 50; $page++) {
            $query = $cursor === null ? [] : ['continuation_token' => $cursor];

            $reply = $this->http->send('GET', $url, ['query' => $query, 'headers' => $headers]);

            $this->assertOk($reply, $what);

            $body = $reply->json(self::label());

            foreach ((array) ($body['items'] ?? []) as $item) {
                if (is_array($item)) {
                    $out[] = $item;
                }
            }

            $cursor = $body['continuation_token'] ?? null;

            if (!is_string($cursor) || $cursor === '') {
                break;
            }
        }

        return $out;
    }

    /**
     * The signed subject token.
     *
     * A minute of validity: it is exchanged immediately and never stored, so a
     * longer-lived one is only a longer-lived credential on disk if anything
     * ever logged it.
     */
    private function jwt(): string
    {
        $path = $this->credential('private_key_path');

        if (!is_readable($path)) {
            throw new WarrantyException(
                WarrantyException::CONFIG,
                sprintf('Pure Storage private key is not readable at %s.', $path)
            );
        }

        $key = openssl_pkey_get_private(
            (string) file_get_contents($path),
            $this->credential('private_key_password')
        );

        if ($key === false) {
            throw new WarrantyException(
                WarrantyException::CONFIG,
                'Pure Storage private key could not be read. Check the passphrase, and that the '
                    . 'file is an RSA private key in PEM form.'
            );
        }

        $now = time();

        $segments = [
            self::base64url((string) json_encode(['alg' => 'RS256', 'typ' => 'JWT'])),
            self::base64url((string) json_encode([
                'iss' => $this->credential('app_id'),
                'iat' => $now,
                'exp' => $now + 60,
            ])),
        ];

        $signing_input = implode('.', $segments);
        $signature     = '';

        if (!openssl_sign($signing_input, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new WarrantyException(
                WarrantyException::CONFIG,
                'Pure Storage token could not be signed with the configured private key.'
            );
        }

        return $signing_input . '.' . self::base64url($signature);
    }

    private static function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /** Pure1 timestamps are milliseconds since the epoch. */
    private static function epoch(mixed $value): ?string
    {
        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            return null;
        }

        $seconds = intdiv((int) $value, 1000);

        return $seconds > 0 ? Entitlement::date(gmdate('Y-m-d', $seconds)) : null;
    }
}
