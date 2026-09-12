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
 * Microsoft Surface — Surface API Management Service, Warranty and Coverage API.
 *
 * The one vendor here that answers about a *fleet* rather than a serial. There
 * is no per-device endpoint: the tenant is enrolled for scanning, Microsoft
 * scans it, and the API then hands back a CSV of every Intune-enrolled Surface
 * with its coverage. So one export is fetched per sync run, cached for the life
 * of this object, and every serial in the batch is answered from it.
 *
 * That shape has three consequences worth knowing:
 *
 * - **Only devices in the configured Intune tenant are visible.** A Surface
 *   that is not Intune-enrolled, or is in a different tenant, is reported as
 *   not found, which is accurate — Microsoft genuinely has nothing to say
 *   about it here.
 * - **The data is refreshed by Microsoft biweekly**, not on demand. Pressing
 *   "Check now" re-reads the same export.
 * - **The tenant must be enrolled once before anything exists**, and the first
 *   scan takes up to five business days. Enrolment is a state change inside the
 *   customer's own tenant, so it is a button on the settings page rather than
 *   something a cron does the first time it runs — see {@see setupActions()}.
 *
 * Access is not self-service: Microsoft grants it per tenant by email, with a
 * minimum of fifty Intune-registered Surface devices.
 *
 * Two credentials are needed at once, and they are different kinds of thing: an
 * Entra application token proves *who the tenant is*, and the subscription key
 * proves *the subscription to this API*. Missing either gives a 401 that names
 * neither.
 */
final class Microsoft extends AbstractVendor
{
    private const BASE_URL = 'https://surface.ams.microsoft.com';

    /** Microsoft's own app id for the service; the token must be scoped to it. */
    private const SCOPE = '76bd8628-ca60-441c-9d83-06503cbfd9c5/.default';

    /** @var array<string,Coverage>|null the export, parsed, for this run */
    private ?array $fleet = null;

    public static function key(): string
    {
        return 'microsoft';
    }

    public static function label(): string
    {
        return 'Microsoft Surface';
    }

    public static function credentials(): array
    {
        return [
            'tenant_id' => [
                'label'    => 'Entra tenant ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'The tenant registered with the Surface API Management Service.',
            ],
            'client_id' => [
                'label'    => 'Application (client) ID',
                'type'     => 'text',
                'required' => true,
                'hint'     => 'The Entra app registration you gave Microsoft at onboarding.',
            ],
            'client_secret' => [
                'label'    => 'Client secret',
                'type'     => 'secret',
                'required' => true,
                'hint'     => '',
            ],
            'subscription_key' => [
                'label'    => 'Subscription key',
                'type'     => 'secret',
                'required' => true,
                'hint'     => 'From your profile in the Surface API Management developer portal. '
                    . 'Sent as Ocp-Apim-Subscription-Key.',
            ],
        ];
    }

    public static function aliases(): array
    {
        return ['microsoft', 'surface'];
    }

    /**
     * Large, because the cost is one export per run rather than per serial.
     *
     * The batch size only decides how many subjects are handed over at a time;
     * the export is fetched once and reused, so this is really just "do not
     * build an enormous array".
     */
    public static function batchSize(): int
    {
        return 500;
    }

    public static function setupActions(): array
    {
        return [
            'enrol' => [
                'label' => 'Enrol this tenant for scanning',
                'hint'  => 'Microsoft only produces warranty data for tenants that have opted in. '
                    . 'This is a change inside your Microsoft tenant, so it is not done '
                    . 'automatically. The first scan can take up to five business days.',
            ],
        ];
    }

    public function runSetupAction(string $action): string
    {
        if ($action !== 'enrol') {
            return parent::runSetupAction($action);
        }

        $reply = $this->http->send('PUT', self::BASE_URL . '/api/external/warranty/enrollment', [
            'headers' => $this->headers(),
        ]);

        $this->assertOk($reply, 'warranty enrollment');

        return 'Tenant enrolled for Surface warranty scanning. Data appears once Microsoft has '
             . 'scanned the tenant, which can take up to five business days.';
    }

    public function lookup(array $subjects): array
    {
        if ($subjects === []) {
            return [];
        }

        $fleet = $this->fleet();
        $out   = [];

        foreach ($subjects as $subject) {
            if (isset($fleet[$subject->key()])) {
                $out[$subject->key()] = $fleet[$subject->key()];
            }
        }

        return $out;
    }

    /**
     * The tenant's warranty export, fetched once.
     *
     * @return array<string,Coverage>
     */
    private function fleet(): array
    {
        if ($this->fleet !== null) {
            return $this->fleet;
        }

        $reply = $this->http->send('GET', self::BASE_URL . '/api/external/warranty/export', [
            'headers' => $this->headers(),
        ]);

        // Documented: a tenant that has not been scanned yet answers 404. That
        // is a setup state, not a fault, and saying so is the difference
        // between an administrator waiting and an administrator debugging.
        if ($reply->status === 404) {
            throw new WarrantyException(
                WarrantyException::CONFIG,
                'Microsoft has no warranty export for this tenant yet. Enrol the tenant for '
                    . 'scanning on the settings page; the first scan can take up to five '
                    . 'business days.',
                404
            );
        }

        $this->assertOk($reply, 'warranty export');

        $url = trim((string) (self::pick($reply->json(self::label()), 'downloadUrl', 'downloadURL') ?? ''));

        if ($url === '') {
            throw new WarrantyException(
                WarrantyException::RESPONSE,
                'Microsoft returned no downloadUrl: ' . Reply::clip($reply->body, 160)
            );
        }

        // Deliberately no headers on this one. The download is a pre-signed
        // storage URL that carries its own authorisation; sending the Entra
        // token and the subscription key to it would hand both to a host that
        // has no business seeing them, and some storage front ends reject a
        // request that carries a second Authorization header anyway.
        $csv = $this->http->send('GET', $url);

        $this->assertOk($csv, 'warranty export download');

        return $this->fleet = self::parse($csv->body);
    }

    /** @return array<string,string> */
    private function headers(): array
    {
        return [
            'Authorization'             => 'Bearer ' . $this->token(),
            'Ocp-Apim-Subscription-Key' => $this->credential('subscription_key'),
        ];
    }

    /** An Entra client-credentials token scoped to the Surface service. */
    private function token(): string
    {
        return $this->bearer(
            'https://login.microsoftonline.com/' . rawurlencode($this->credential('tenant_id')) . '/oauth2/v2.0/token',
            [
                'client_id'     => $this->credential('client_id'),
                'client_secret' => $this->credential('client_secret'),
                'scope'         => self::SCOPE,
            ]
        );
    }

    /**
     * Turn the export into coverages, keyed by serial.
     *
     * Columns are matched by *name*, not position: Microsoft documents the
     * export only as "the same data as the Surface Management Portal", and a
     * column inserted upstream would silently shift every field if this read
     * by index. A row whose serial or dates cannot be found is skipped rather
     * than guessed at.
     *
     * @return array<string,Coverage>
     */
    public static function parse(string $csv): array
    {
        $rows = self::rows($csv);

        if ($rows === []) {
            return [];
        }

        $header = array_map(
            static fn(string $name): string => strtolower(preg_replace('/[^a-z0-9]+/i', '', $name) ?? $name),
            array_shift($rows)
        );

        $index = static function (array $names) use ($header): ?int {
            foreach ($names as $name) {
                $at = array_search($name, $header, true);
                if ($at !== false) {
                    return (int) $at;
                }
            }

            return null;
        };

        $serial_at = $index(['serialnumber', 'serial', 'devicserialnumber', 'deviceserialnumber']);
        $start_at  = $index(['warrantystartdate', 'coveragestartdate', 'startdate', 'warrantystart']);
        $end_at    = $index(['warrantyenddate', 'coverageenddate', 'enddate', 'warrantyend', 'expirationdate']);
        $model_at  = $index(['model', 'devicemodel', 'productname', 'skudisplayname']);
        $type_at   = $index(['warrantytype', 'coveragetype', 'serviceplan', 'warrantyname']);
        $status_at = $index(['warrantystatus', 'coveragestatus', 'status']);

        if ($serial_at === null || ($start_at === null && $end_at === null)) {
            return [];
        }

        $out = [];

        foreach ($rows as $row) {
            $serial = Subject::normalise((string) ($row[$serial_at] ?? ''));

            if ($serial === '') {
                continue;
            }

            $start = $start_at === null ? null : Entitlement::date($row[$start_at] ?? null);
            $end   = $end_at === null ? null : Entitlement::date($row[$end_at] ?? null);

            if ($start === null && $end === null) {
                continue;
            }

            $level = $type_at !== null ? trim((string) ($row[$type_at] ?? '')) : '';

            $entitlement = Entitlement::make(
                Entitlement::BASE,
                $level !== '' ? $level : 'Surface warranty',
                $start,
                $end
            );

            // Several rows per device are possible when a device carries both
            // its original warranty and an extended protection plan. Keep them
            // all; the projection picks the one that ends last.
            $existing = $out[$serial] ?? null;

            $out[$serial] = new Coverage(
                serial: $serial,
                vendor: self::key(),
                entitlements: array_merge($existing?->entitlements ?? [], [$entitlement]),
                product: $existing?->product
                    ?: ($model_at !== null ? trim((string) ($row[$model_at] ?? '')) : ''),
                note: $existing?->note
                    ?: ($status_at !== null ? trim((string) ($row[$status_at] ?? '')) : '')
            );
        }

        return $out;
    }

    /**
     * Parse the CSV.
     *
     * `str_getcsv` line by line rather than writing the body to a temporary
     * file: an export of a large estate is a few megabytes, and a cron that
     * needs a writable temp directory is a cron that fails on a hardened host.
     * A UTF-8 BOM is stripped — Microsoft sends one, and it would otherwise
     * become part of the first column's name and lose the serial column.
     *
     * @return array<int,array<int,string>>
     */
    private static function rows(string $csv): array
    {
        $csv = preg_replace('/^\xEF\xBB\xBF/', '', $csv) ?? $csv;

        $rows = [];
        foreach (preg_split('/\r\n|\r|\n/', $csv) ?: [] as $line) {
            if (trim($line) === '') {
                continue;
            }
            $rows[] = str_getcsv($line, ',', '"', '\\');
        }

        return $rows;
    }
}
