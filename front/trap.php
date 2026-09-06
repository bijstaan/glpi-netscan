<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Receive SNMP notifications a scanner has collected.
 *
 * Body: `{scanner_token, notifications: [ {address, trap_oid, varbinds, …}, … ]}`
 *
 * Batched by the scanner rather than forwarded one at a time: traps arrive in
 * bursts by nature — a switch reloading emits one per port — and a submission
 * per trap would turn a link flap into a denial of service against GLPI.
 */

use GlpiPlugin\Glpinetscan\Settings;
use GlpiPlugin\Glpinetscan\Traps;

require_once __DIR__ . '/_api.php';

glpinetscan_require_tls();
$body    = glpinetscan_body();
$scanner = glpinetscan_authenticate($body);

// Checked again here, not only when the policy was handed out. A scanner that
// was told to listen and then had the setting turned off underneath it should
// stop being listened to immediately, without waiting for it to poll again.
if (!Settings::get('allow_traps')) {
    glpinetscan_respond(['error' => 'traps_disabled'], 403);
}

$notifications = $body['notifications'] ?? [];
if (!is_array($notifications)) {
    glpinetscan_respond(['error' => 'invalid_notifications'], 400);
}

// Bounded so one submission cannot be made arbitrarily large. The scanner
// already drops its own excess; this is the server not taking the scanner's
// word for how much it should accept.
if (count($notifications) > 500) {
    $notifications = array_slice($notifications, 0, 500);
}

glpinetscan_respond(['recorded' => Traps::record($scanner, $notifications)]);
