<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use DBmysql;
use GLPIKey;
use QueryExpression;

/**
 * Enrollment secrets: the bootstrap credential a fresh scanner presents once,
 * in exchange for its own token.
 *
 * A secret is shared by every scanner installed from one command line, so it
 * is treated as low-trust. It buys exactly one thing — the right to obtain a
 * scanner token — and can be scoped to an entity, expired, and revoked without
 * touching scanners that already enrolled.
 *
 * Storage keeps **both** forms, which is not redundancy:
 *
 *  - `secret_hash` is a SHA-256 used for lookup. GLPIKey encryption is
 *    non-deterministic, so an encrypted column cannot be matched against —
 *    without the hash, verifying a presented secret means decrypting every row
 *    on every enrollment attempt.
 *  - `secret` is the GLPIKey-encrypted plaintext, so the UI can rebuild the
 *    install command later without the plaintext ever sitting at rest.
 */
final class Secret
{
    public const TABLE = 'glpi_plugin_glpinetscan_secrets';

    /**
     * Create a secret.
     *
     * The plaintext is returned once, here, because it is needed to build the
     * install command; afterwards it exists only encrypted.
     *
     * @return array{id:int,secret:string}
     */
    public static function create(string $name, int $entities_id = 0, int $expires_at = 0): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $plain = bin2hex(random_bytes(24));

        $DB->insert(self::TABLE, [
            'name'          => $name,
            'secret_hash'   => hash('sha256', $plain),
            'secret'        => (new GLPIKey())->encrypt($plain),
            'entities_id'   => $entities_id,
            'expires_at'    => $expires_at,
            'is_active'     => 1,
            'enroll_count'  => 0,
            'date_creation' => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
        ]);

        return ['id' => (int) $DB->insertId(), 'secret' => $plain];
    }

    /** Create a first secret on install so the plugin is usable immediately. */
    public static function ensureDefault(): void
    {
        if (countElementsInTable(self::TABLE) > 0) {
            return;
        }

        self::create(__('Default enrollment secret', 'glpinetscan'), 0);
    }

    /**
     * Resolve a presented secret to its row.
     *
     * A single indexed hit on the hash, regardless of how many secrets exist.
     *
     * @return array<string,mixed>|null
     */
    public static function match(string $presented): ?array
    {
        /** @var DBmysql $DB */
        global $DB;

        $presented = trim($presented);
        if ($presented === '') {
            return null;
        }

        $rows = $DB->request([
            'FROM'  => self::TABLE,
            'WHERE' => ['secret_hash' => hash('sha256', $presented), 'is_active' => 1],
            'LIMIT' => 1,
        ]);

        foreach ($rows as $row) {
            $expires = (int) $row['expires_at'];
            if ($expires > 0 && $expires < time()) {
                return null;
            }
            return $row;
        }

        return null;
    }

    /**
     * Recover the plaintext, for redisplay in the install command.
     *
     * Returns null when the GLPI encryption key has been rotated since the
     * secret was issued. That is recoverable — issue a new secret — so it must
     * not be fatal, and the UI says so rather than showing a broken command.
     */
    public static function reveal(array $row): ?string
    {
        if (empty($row['secret'])) {
            return null;
        }

        try {
            $plain = (new GLPIKey())->decrypt($row['secret']);
        } catch (\Throwable) {
            return null;
        }

        return $plain !== '' ? $plain : null;
    }

    /** Record that a scanner enrolled with this secret. */
    public static function countEnrolment(int $id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->update(
            self::TABLE,
            ['enroll_count' => new QueryExpression('enroll_count + 1')],
            ['id' => $id]
        );
    }

    /**
     * All secrets, active first.
     *
     * Revoked ones stay listed: their enrolment counts are the record of what
     * was installed with them, and deleting the row would lose that.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function all(): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $out = [];
        foreach ($DB->request([
            'FROM'  => self::TABLE,
            'ORDER' => ['is_active DESC', 'name'],
        ]) as $row) {
            $out[] = $row;
        }
        return $out;
    }

    public static function revoke(int $id): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $DB->update(self::TABLE, ['is_active' => 0], ['id' => $id]);
    }
}
