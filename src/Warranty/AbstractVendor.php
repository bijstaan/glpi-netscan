<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * The parts every vendor client repeats.
 *
 * Five of the seven are OAuth2 client-credentials behind a different hostname,
 * so the token dance lives here. The token is held for the life of the object
 * and never stored: a cron run is seconds long, the shortest-lived of these
 * tokens is an hour, and a bearer token written to the database is a
 * credential at rest that buys nothing. Apple is the exception and says so in
 * its own class.
 */
abstract class AbstractVendor implements Vendor
{
    protected ?string $token = null;

    /** Unix time the cached token stops being usable. */
    protected int $token_expires = 0;

    /**
     * @param array<string,string> $credentials as configured, already decrypted
     */
    public function __construct(
        protected readonly Transport $http,
        protected readonly array $credentials = []
    ) {
    }

    public static function minInterval(): float
    {
        return 0.0;
    }

    /**
     * Nothing to set up, which is true of nine of the ten.
     *
     * @return array<string,array{label:string,hint:string}>
     */
    public static function setupActions(): array
    {
        return [];
    }

    public function runSetupAction(string $action): string
    {
        throw new WarrantyException(
            WarrantyException::CONFIG,
            sprintf('%s has no setup action "%s".', static::label(), $action)
        );
    }

    /**
     * A configured credential.
     *
     * @throws WarrantyException when a required one is missing, which is a
     *         configuration fault and must not be retried on a timer.
     */
    protected function credential(string $name): string
    {
        $value = trim((string) ($this->credentials[$name] ?? ''));

        if ($value !== '') {
            return $value;
        }

        $spec = static::credentials()[$name] ?? null;

        if ($spec !== null && ($spec['default'] ?? '') !== '') {
            return (string) $spec['default'];
        }

        if ($spec === null || $spec['required']) {
            throw new WarrantyException(
                WarrantyException::CONFIG,
                sprintf(
                    '%s is not configured: %s is required',
                    static::label(),
                    $spec['label'] ?? $name
                )
            );
        }

        return '';
    }

    /** True when every required credential is present. */
    public static function isConfigured(array $credentials): bool
    {
        foreach (static::credentials() as $name => $spec) {
            if (!$spec['required']) {
                continue;
            }
            if (trim((string) ($credentials[$name] ?? '')) === '' && ($spec['default'] ?? '') === '') {
                return false;
            }
        }

        return true;
    }

    /**
     * An OAuth2 token, fetched once per object.
     *
     * Defaults to the client-credentials grant, which is what six of the ten
     * use. A caller may override `grant_type` — Pure Storage uses RFC 8693
     * token exchange — which is why the default is merged rather than unioned:
     * PHP's `+` keeps the left-hand value on a key collision, so `['grant_type'
     * => 'client_credentials'] + $form` would silently ignore an override and
     * send the wrong grant.
     *
     * @param array<string,string> $form  body fields; may override grant_type
     * @param array<string,string> $headers
     */
    protected function bearer(string $token_url, array $form, array $headers = []): string
    {
        if ($this->token !== null && $this->token_expires > time()) {
            return $this->token;
        }

        $reply = $this->http->send('POST', $token_url, [
            'form'    => array_merge(['grant_type' => 'client_credentials'], $form),
            'headers' => $headers + ['Accept' => 'application/json'],
        ]);

        if (!$reply->ok()) {
            // A token endpoint refusing the credentials is the single most
            // common failure here, and it is always the same fix, so it is
            // named as such rather than reported as "HTTP 400".
            throw new WarrantyException(
                WarrantyException::AUTH,
                sprintf(
                    '%s rejected the API credentials (HTTP %d): %s',
                    static::label(),
                    $reply->status,
                    Reply::clip($reply->body, 160)
                ),
                $reply->status
            );
        }

        $body  = $reply->json(static::label());
        $token = (string) ($body['access_token'] ?? '');

        if ($token === '') {
            throw new WarrantyException(
                WarrantyException::AUTH,
                static::label() . ' returned no access_token: ' . Reply::clip($reply->body, 160)
            );
        }

        // A minute of margin, so a token cannot expire between being checked
        // and being used on a slow batch.
        $lifetime = (int) ($body['expires_in'] ?? 3600);
        $this->token         = $token;
        $this->token_expires = time() + max(60, $lifetime) - 60;

        return $token;
    }

    /**
     * Turn a non-2xx into the right kind of failure.
     *
     * The mapping is the same for every vendor and getting it wrong is
     * expensive in both directions: treating an auth failure as retryable
     * hammers a vendor with bad credentials until the key is suspended, and
     * treating a 503 as permanent leaves an estate with no warranty data
     * because of one bad afternoon.
     */
    protected function assertOk(Reply $reply, string $context = ''): void
    {
        if ($reply->ok()) {
            return;
        }

        $who    = static::label() . ($context !== '' ? ' (' . $context . ')' : '');
        $detail = Reply::clip($reply->body, 160);

        throw match (true) {
            $reply->status === 401, $reply->status === 403 => new WarrantyException(
                WarrantyException::AUTH,
                sprintf('%s refused the request (HTTP %d): %s', $who, $reply->status, $detail),
                $reply->status
            ),
            $reply->status === 429 => new WarrantyException(
                WarrantyException::THROTTLED,
                sprintf('%s asked us to slow down (HTTP 429): %s', $who, $detail),
                $reply->status
            ),
            $reply->status >= 500 => new WarrantyException(
                WarrantyException::TRANSPORT,
                sprintf('%s is having trouble (HTTP %d): %s', $who, $reply->status, $detail),
                $reply->status
            ),
            default => new WarrantyException(
                WarrantyException::RESPONSE,
                sprintf('%s returned HTTP %d: %s', $who, $reply->status, $detail),
                $reply->status
            ),
        };
    }

    /**
     * Serials from a batch, deduplicated and in the order given.
     *
     * @param Subject[] $subjects
     * @return string[]
     */
    protected static function serials(array $subjects): array
    {
        $out = [];
        foreach ($subjects as $subject) {
            $out[$subject->key()] = $subject->key();
        }

        return array_values($out);
    }

    /**
     * @param Subject[] $subjects
     * @return array<string,Subject> keyed by serial
     */
    protected static function bySerial(array $subjects): array
    {
        $out = [];
        foreach ($subjects as $subject) {
            $out[$subject->key()] = $subject;
        }

        return $out;
    }

    /**
     * Read the first present key from a payload.
     *
     * Vendors rename fields between minor versions without announcing it, and
     * several of these APIs are documented only to their own partners. Reading
     * a list of aliases rather than one name is what stops a rename showing up
     * as every asset silently losing its warranty.
     */
    protected static function pick(array $row, string ...$keys): mixed
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $row) && $row[$key] !== null && $row[$key] !== '') {
                return $row[$key];
            }
        }

        return null;
    }
}
