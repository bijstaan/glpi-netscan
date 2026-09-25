<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\TransferException;
use Toolbox;

/**
 * The only place this plugin talks to a hardware vendor.
 *
 * Guzzle out of GLPI's own vendor tree, obtained through
 * {@see Toolbox::getGuzzleClient()} rather than constructed directly so that
 * an instance behind a corporate proxy works without a second proxy setting
 * nobody would think to look for. That matters more here than for most
 * outbound traffic: a GLPI that inventories an estate is usually on the
 * management network, and the management network is usually the one that has
 * no direct route out.
 *
 * Four behaviours are deliberate.
 *
 * **`http_errors` is off.** Several of these APIs use status codes for
 * ordinary answers — Dell returns 401 for an expired token that simply needs
 * refreshing, Lenovo answers an unknown serial with a 404 carrying a reason
 * code, Cisco answers an exhausted quota with 403 — so the status and the body
 * are read together by the caller rather than turned into an exception class
 * hierarchy that hides the body.
 *
 * **A floor on the interval between requests.** Fortinet publishes 100 calls
 * per minute, Cisco 5 per second, Dell 50 per minute on most contracts. A
 * shared clock inside the transport means a vendor client cannot forget, and
 * an operator who presses "Check now" twenty times cannot get the instance's
 * API key suspended.
 *
 * **Client certificates.** Apple's GSX is mutual-TLS; the certificate is per
 * partner and cannot be shared, so it is a path on disk rather than anything
 * this plugin stores.
 *
 * **Only the serial leaves.** No hostname, no user, no entity, no instance
 * URL. A serial number is the whole of what a warranty lookup needs, and the
 * vendor already knows it — they sold the machine. The User-Agent names the
 * plugin and its version, because a service being called on a schedule is
 * entitled to know by what.
 */
final class HttpTransport implements Transport
{
    private ?GuzzleClient $client = null;

    /** microtime of the last request, for the interval floor. */
    private float $last_request = 0.0;

    public function __construct(
        private readonly int $timeout = 30,
        private float $min_interval = 0.0,
        /** Path to a PEM bundle for mutual TLS, and its passphrase. */
        private readonly ?string $cert_path = null,
        private readonly ?string $cert_password = null
    ) {
    }

    public function setMinInterval(float $seconds): void
    {
        $this->min_interval = max(0.0, $seconds);
    }

    public function send(string $method, string $url, array $options = []): Reply
    {
        $this->waitForSlot();

        $request = [
            'headers'     => ($options['headers'] ?? []) + [
                'Accept'     => 'application/json',
                'User-Agent' => self::userAgent(),
            ],
            'timeout'     => $this->timeout,
            'http_errors' => false,
        ];

        if (!empty($options['query'])) {
            $request['query'] = $options['query'];
        }
        if (array_key_exists('json', $options)) {
            $request['json'] = $options['json'];
        }
        if (!empty($options['form'])) {
            $request['form_params'] = $options['form'];
        }
        if (isset($options['body'])) {
            $request['body'] = $options['body'];
        }

        if ($this->cert_path !== null && $this->cert_path !== '') {
            // Guzzle wants [path] or [path, passphrase]; handing it a null
            // passphrase makes cURL prompt on stdin and hang the cron.
            $request['cert'] = ($this->cert_password === null || $this->cert_password === '')
                ? $this->cert_path
                : [$this->cert_path, $this->cert_password];
        }

        try {
            $response = $this->client()->request($method, $url, $request);
        } catch (ConnectException $e) {
            throw new WarrantyException(
                WarrantyException::TRANSPORT,
                'Could not reach ' . self::host($url) . ': ' . $e->getMessage()
            );
        } catch (TransferException $e) {
            // Read timeouts arrive here rather than as ConnectException. A slow
            // vendor is the ordinary cause, so this is transport (retryable)
            // and not the vendor answering badly.
            throw new WarrantyException(
                WarrantyException::TRANSPORT,
                self::host($url) . ' request failed: ' . $e->getMessage()
            );
        } finally {
            $this->last_request = microtime(true);
        }

        $headers = [];
        foreach ($response->getHeaders() as $name => $values) {
            $headers[strtolower((string) $name)] = implode(', ', $values);
        }

        return new Reply($response->getStatusCode(), (string) $response->getBody(), $headers);
    }

    private function waitForSlot(): void
    {
        if ($this->min_interval <= 0.0 || $this->last_request === 0.0) {
            return;
        }

        $elapsed = microtime(true) - $this->last_request;
        if ($elapsed >= $this->min_interval) {
            return;
        }

        usleep((int) round(($this->min_interval - $elapsed) * 1_000_000));
    }

    private function client(): GuzzleClient
    {
        if ($this->client === null) {
            $this->client = method_exists(Toolbox::class, 'getGuzzleClient')
                ? Toolbox::getGuzzleClient()
                : new GuzzleClient(self::proxyOptions() + ['connect_timeout' => 5]);
        }

        return $this->client;
    }

    /**
     * GLPI 12 removed Toolbox::getGuzzleClient(); this is what it added, so the
     * instance's outbound proxy still applies. Guzzle itself still ships with
     * core (league/oauth2-client depends on it).
     *
     * @return array{proxy?:string}
     */
    private static function proxyOptions(): array
    {
        global $CFG_GLPI;

        if (empty($CFG_GLPI['proxy_name'])) {
            return [];
        }

        $credentials = '';
        if (!empty($CFG_GLPI['proxy_user'])) {
            $credentials = rawurlencode((string) $CFG_GLPI['proxy_user']) . ':'
                . rawurlencode((string) (new \GLPIKey())->decrypt((string) $CFG_GLPI['proxy_passwd'])) . '@';
        }

        return ['proxy' => 'http://' . $credentials . $CFG_GLPI['proxy_name'] . ':' . $CFG_GLPI['proxy_port']];
    }

    private static function userAgent(): string
    {
        $version = defined('PLUGIN_GLPINETSCAN_VERSION') ? PLUGIN_GLPINETSCAN_VERSION : 'dev';

        return 'glpi-netscan/' . $version . ' (GLPI plugin; warranty lookup)';
    }

    /** Only the host, so an error message never carries a token or a serial. */
    public static function host(string $url): string
    {
        return (string) (parse_url($url, PHP_URL_HOST) ?: $url);
    }
}
