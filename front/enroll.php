<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Exchange an enrollment secret for a per-scanner token.
 *
 * The token is returned exactly once and stored only as a hash, so this is the
 * only moment it exists in a recoverable form.
 */

use GlpiPlugin\Glpinetscan\Scanner;

require_once __DIR__ . '/_api.php';

glpinetscan_require_tls();
$body = glpinetscan_body();

$secret = (string) ($body['enroll_secret'] ?? '');
if ($secret === '') {
    glpinetscan_respond(['error' => 'missing_secret'], 400);
}

$result = Scanner::enroll(
    $secret,
    substr(trim((string) ($body['hostname'] ?? '')), 0, 255),
    substr(trim((string) ($body['platform'] ?? '')), 0, 64),
    substr(trim((string) ($body['agent_version'] ?? '')), 0, 64),
    glpinetscan_client_address()
);

if ($result === null) {
    // Deliberately identical for "wrong secret", "expired" and "revoked": the
    // caller is unauthenticated, and distinguishing them would let someone
    // enumerate which secrets exist.
    glpinetscan_respond(['error' => 'enrollment_refused'], 403);
}

glpinetscan_respond([
    'scanner_token' => $result['token'],
    'scanner_id'    => $result['scanner']->getID(),
    'entities_id'   => (int) $result['scanner']->fields['entities_id'],
], 201);
