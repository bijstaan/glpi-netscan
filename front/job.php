<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Hand a scanner its due work: ranges, credentials, tuning and OID profiles.
 */

use GlpiPlugin\Glpinetscan\Job;

require_once __DIR__ . '/_api.php';

glpinetscan_require_tls();
$body    = glpinetscan_body();
$scanner = glpinetscan_authenticate($body);

glpinetscan_respond(Job::forScanner(
    $scanner,
    substr((string) ($body['platform'] ?? ''), 0, 32),
    substr((string) ($body['arch'] ?? ''), 0, 32)
));
