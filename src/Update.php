<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;

/**
 * Scanner self-update.
 *
 * GLPI is the authority on what version the fleet should run; scanners ask, on
 * the poll they already make, and are told. Two things make it safe to do that
 * to machines nobody is going to drive to:
 *
 * **Staged rollout.** Each scanner belongs to a stable ring derived from its
 * own identity, so raising the rollout percentage always reaches the same
 * machines first and in the same order. A bad build is found on 5% of the
 * estate rather than all of it, and a scanner never oscillates between "update"
 * and "don't" as the percentage moves up and down.
 *
 * **Verified payloads.** Every package carries a SHA-256 the scanner checks
 * before it executes anything. A self-updater that installs whatever it
 * downloads is a remote code execution channel into every machine running it,
 * and speaking TLS to its own GLPI is not sufficient — that proves where the
 * bytes came from, not that they are the bytes the administrator published.
 *
 * The manifest is deliberately not an upload store. GLPI records where a
 * release lives and what it should hash to; the bytes stay wherever the
 * operator already publishes artifacts. Since the scanner authenticates the
 * download by checksum, the host serving it does not have to be trusted, and
 * GLPI does not become a binary distribution point with the storage and
 * access-control questions that would bring.
 */
final class Update
{
    public const TABLE = 'glpi_plugin_glpinetscan_packages';

    /**
     * Platforms and architectures a package may be published for.
     *
     * Linux and Windows only. macOS is deliberately absent rather than merely
     * unbuilt: offering a platform the scanner has no installer or service
     * integration for would let an operator publish a package that no machine
     * can ever be told about, with nothing to explain why.
     */
    public const PLATFORMS = ['linux', 'windows'];
    public const ARCHES    = ['amd64', 'arm64'];

    /**
     * Which rollout ring a scanner falls in (0–99).
     *
     * Hashed rather than taken modulo directly: `id % 100` would put scanners
     * enrolled together into the same ring, so a site that installed its whole
     * estate in one afternoon would see the rollout arrive all at once — which
     * is the failure mode staging exists to prevent.
     *
     * Keyed on the row id rather than the hostname or the token, because it has
     * to be stable for the life of the machine: a hostname changes on a rename
     * and the token changes on every re-enrolment, and either would silently
     * re-roll a scanner into a different ring.
     */
    public static function ringFor(int $scanners_id): int
    {
        return (int) (hexdec(substr(hash('sha256', 'glpinetscan-scanner-' . $scanners_id), 0, 8)) % 100);
    }

    /**
     * What to tell a polling scanner about its version.
     *
     * Ring and rollout percentage are reported even when nothing is offered.
     * "This scanner is in ring 71 and the rollout is at 20%" is the answer to
     * the question an operator actually asks — why has that one not updated —
     * and without it the only observable state is an unexplained old version.
     *
     * @return array<string,mixed>
     */
    public static function offerFor(Scanner $scanner, string $platform, string $arch): array
    {
        $settings = Settings::all();

        $ring    = self::ringFor($scanner->getID());
        $percent = max(0, min(100, (int) $settings['rollout_percent']));

        $offer = [
            'available'       => false,
            'package'         => null,
            'ring'            => $ring,
            'rollout_percent' => $percent,
        ];

        if (empty($settings['update_enabled'])) {
            return $offer;
        }

        // Fall back to what was recorded at enrolment when a scanner is too old
        // to report its platform on every poll — otherwise enabling updates
        // would strand exactly the scanners that most need one.
        [$platform, $arch] = self::resolveTarget($scanner, $platform, $arch);
        if ($platform === '' || $arch === '') {
            return $offer;
        }

        // Outside the current wave. Answered honestly as "nothing for you"
        // rather than by withholding the fields, so the scanner can say why.
        if ($ring >= $percent) {
            return $offer;
        }

        $package = self::activePackage($platform, $arch);
        if ($package === null) {
            return $offer;
        }

        $running = (string) $scanner->fields['agent_version'];
        if ($running !== '' && self::sameVersion($running, (string) $package['version'])) {
            return $offer;
        }

        $offer['available'] = true;
        $offer['package']   = [
            'version' => (string) $package['version'],
            'url'     => (string) $package['url'],
            'sha256'  => (string) $package['sha256'],
            'size'    => (int) $package['size'],
        ];

        return $offer;
    }

    /**
     * Decide which package a scanner should be matched against.
     *
     * @return array{0:string,1:string}
     */
    private static function resolveTarget(Scanner $scanner, string $platform, string $arch): array
    {
        $platform = strtolower(trim($platform));
        $arch     = strtolower(trim($arch));

        if ($platform === '' || $arch === '') {
            // Enrolment records the pair as "linux/amd64" in one column.
            $stored = strtolower(trim((string) $scanner->fields['platform']));
            $parts  = explode('/', $stored, 2);
            if ($platform === '') {
                $platform = trim($parts[0] ?? '');
            }
            if ($arch === '') {
                $arch = trim($parts[1] ?? (string) $scanner->fields['arch']);
            }
        }

        if (!in_array($platform, self::PLATFORMS, true) || !in_array($arch, self::ARCHES, true)) {
            return ['', ''];
        }

        return [$platform, $arch];
    }

    /** The package currently offered for a platform and architecture. */
    public static function activePackage(string $platform, string $arch): ?array
    {
        /** @var DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'FROM'  => self::TABLE,
                'WHERE' => ['platform' => $platform, 'arch' => $arch, 'is_active' => 1],
                'ORDER' => ['id DESC'],
                'LIMIT' => 1,
            ]) as $row
        ) {
            return $row;
        }

        return null;
    }

    /**
     * Publish a release so scanners can be offered it.
     *
     * Publishing the same platform/arch/version again replaces the existing row
     * rather than adding a second: re-publishing after a rebuild is the normal
     * way to correct a wrong checksum, and a table that grew a row each time
     * would leave the truth decided by insertion order.
     *
     * Only one package per platform/arch is ever offered — the newest active
     * one — so publishing a new version supersedes the old without needing the
     * old one withdrawn first.
     *
     * @param array<string,mixed> $fields
     * @return string|null an error message, or null on success
     */
    public static function publish(array $fields): ?string
    {
        /** @var DBmysql $DB */
        global $DB;

        $version  = ltrim(trim((string) ($fields['version'] ?? '')), 'v');
        // Matched exactly rather than normalised to a default. A typo folded to
        // "linux" would be published as a Linux package and offered to Linux
        // machines, which is a far worse outcome than a rejected form.
        $platform = strtolower(trim((string) ($fields['platform'] ?? '')));
        $arch     = strtolower(trim((string) ($fields['arch'] ?? '')));
        $url      = trim((string) ($fields['url'] ?? ''));
        $sha256   = strtolower(trim((string) ($fields['sha256'] ?? '')));
        $size     = (int) ($fields['size'] ?? 0);

        if ($version === '') {
            return __('A version is required.', 'glpinetscan');
        }
        if (!in_array($platform, self::PLATFORMS, true)) {
            return __('Platform must be linux or windows.', 'glpinetscan');
        }
        if (!in_array($arch, self::ARCHES, true)) {
            return __('Architecture must be amd64 or arm64.', 'glpinetscan');
        }
        // HTTPS only. The scanner verifies the checksum after downloading, so a
        // plaintext URL could not let an attacker plant a payload — but it would
        // let anyone on the path see exactly which version every machine is
        // fetching, which is reconnaissance given away for nothing.
        if (!preg_match('#^https://#i', $url)) {
            return __('The package URL must be https.', 'glpinetscan');
        }
        if (!preg_match('/^[0-9a-f]{64}$/', $sha256)) {
            return __('The SHA-256 must be 64 hexadecimal characters.', 'glpinetscan');
        }
        if ($size <= 0) {
            return __('The package size is required, in bytes.', 'glpinetscan');
        }

        $row = [
            'version'   => $version,
            'platform'  => $platform,
            'arch'      => $arch,
            'url'       => $url,
            'sha256'    => $sha256,
            'size'      => $size,
            'is_active' => 1,
        ];

        $existing = null;
        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::TABLE,
                'WHERE'  => ['platform' => $platform, 'arch' => $arch, 'version' => $version],
                'LIMIT'  => 1,
            ]) as $found
        ) {
            $existing = (int) $found['id'];
        }

        if ($existing !== null) {
            $DB->update(self::TABLE, $row, ['id' => $existing]);
            return null;
        }

        $row['date_creation'] = $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s');
        $DB->insert(self::TABLE, $row);

        return null;
    }

    /** Stop offering a package. */
    public static function withdraw(int $id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->delete(self::TABLE, ['id' => $id]);
    }

    /**
     * Every published package, newest first.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function all(): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $out = [];
        foreach ($DB->request(['FROM' => self::TABLE, 'ORDER' => ['id DESC']]) as $row) {
            $out[] = $row;
        }
        return $out;
    }

    /**
     * Version spread across the fleet.
     *
     * Version drift is the thing an operator most needs to see about a fleet
     * that updates itself: it is how a rollout is watched, and how a stuck
     * scanner is noticed at all.
     *
     * @return array<int,array{version:string,cpt:int}>
     */
    public static function versionSpread(): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'SELECT'  => [
                    'agent_version',
                    new \Glpi\DBAL\QueryExpression('COUNT(*) AS ' . $DB->quoteName('cpt')),
                ],
                'FROM'    => Scanner::getTable(),
                'WHERE'   => ['is_deleted' => 0],
                'GROUPBY' => ['agent_version'],
                'ORDER'   => ['cpt DESC'],
            ]) as $row
        ) {
            $out[] = [
                'version' => (string) ($row['agent_version'] ?? ''),
                'cpt'     => (int) $row['cpt'],
            ];
        }

        return $out;
    }

    private static function sameVersion(string $a, string $b): bool
    {
        return ltrim(trim($a), 'v') === ltrim(trim($b), 'v');
    }
}
