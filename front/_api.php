<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Shared bootstrap for the scanner-facing endpoints.
 *
 * These are declared stateless in setup.php, so GLPI performs no auth of its
 * own here — everything below is the plugin's own boundary.
 */

use GlpiPlugin\Glpinetscan\Scanner;
use GlpiPlugin\Glpinetscan\Settings;

/** Emit JSON and stop. */
function glpinetscan_respond(array $payload, int $status = 200): never
{
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    http_response_code($status);
    echo json_encode($payload, JSON_THROW_ON_ERROR);
    exit;
}

/** Decode a JSON request body, or fail cleanly. */
function glpinetscan_body(): array
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        glpinetscan_respond(['error' => 'method_not_allowed'], 405);
    }

    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        glpinetscan_respond(['error' => 'empty_body'], 400);
    }

    // Bound the body. Inventory submissions are the large ones and a 48-port
    // switch is comfortably under this; the limit exists so an unauthenticated
    // caller cannot make the server buffer arbitrary memory before auth runs.
    if (strlen($raw) > 8 * 1024 * 1024) {
        glpinetscan_respond(['error' => 'body_too_large'], 413);
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        glpinetscan_respond(['error' => 'invalid_json'], 400);
    }

    return $decoded;
}

/**
 * Refuse plaintext when configured to.
 *
 * The job response carries decrypted SNMP community strings and v3
 * passphrases, so serving this API over plain HTTP hands the whole estate's
 * SNMP credentials to anyone on the path.
 */
function glpinetscan_require_tls(): void
{
    if (!Settings::get('require_tls')) {
        return;
    }

    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443')
        // Set by a terminating proxy; GLPI is commonly deployed behind one.
        || (strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

    if (!$https) {
        glpinetscan_respond(['error' => 'tls_required'], 403);
    }
}

/** The caller's address, for the scanner's last-seen record. */
function glpinetscan_client_address(): string
{
    return substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 63);
}

/**
 * Authenticate a scanner from the request body's token.
 *
 * A token that does not resolve gets `scanner_invalid`, which is the agent's
 * cue to discard its credentials and re-enroll — the same revocation signal
 * osquery uses, and the reason deactivating a scanner in the UI is sufficient
 * to cut it off.
 */
function glpinetscan_authenticate(array $body): Scanner
{
    $token = (string) ($body['scanner_token'] ?? '');
    $scanner = Scanner::authenticate($token);

    if ($scanner === null) {
        glpinetscan_respond(['scanner_invalid' => true, 'error' => 'invalid_token'], 401);
    }

    $scanner->touch(
        glpinetscan_client_address(),
        substr((string) ($body['agent_version'] ?? ''), 0, 64),
        substr((string) ($body['arch'] ?? ''), 0, 32)
    );

    return $scanner;
}
