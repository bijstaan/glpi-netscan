<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Receive the outcome of queued device writes.
 *
 * Separate from the scan report because the timing is different: an operator
 * who has just asked for a port to be shut is watching for the result, and
 * folding it into the next sweep's report would make them wait for the sweep.
 *
 * Body: `{scanner_token, results: [{action_id, ok, result}, …]}`
 */

use GlpiPlugin\Glpinetscan\Control;

require_once __DIR__ . '/_api.php';

glpinetscan_require_tls();
$body    = glpinetscan_body();
$scanner = glpinetscan_authenticate($body);

$results = $body['results'] ?? [];
if (!is_array($results)) {
    glpinetscan_respond(['error' => 'invalid_results'], 400);
}

$recorded = 0;
foreach ($results as $result) {
    if (!is_array($result)) {
        continue;
    }

    $id = (int) ($result['action_id'] ?? 0);
    if ($id <= 0) {
        continue;
    }

    // Only the scanner the action was queued for may report on it. Without
    // this, any enrolled scanner could mark another's actions as done and hide
    // a write that never happened.
    if (!Control::belongsTo($id, $scanner->getID())) {
        continue;
    }

    Control::complete($id, (bool) ($result['ok'] ?? false), (string) ($result['result'] ?? ''));
    $recorded++;
}

glpinetscan_respond(['recorded' => $recorded]);
