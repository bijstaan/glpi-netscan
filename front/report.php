<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Receive scan results and hand them to GLPI's native inventory pipeline.
 *
 * Body: `{scanner_token, job_id, payloads: [ {deviceid, action, content}, … ]}`
 */

use Glpi\Agent\Communication\AbstractRequest;
use GlpiPlugin\Glpinetscan\Discovery;
use GlpiPlugin\Glpinetscan\Ingest;
use GlpiPlugin\Glpinetscan\Job;

require_once __DIR__ . '/_api.php';

glpinetscan_require_tls();
$body    = glpinetscan_body();
$scanner = glpinetscan_authenticate($body);

$jobId    = (int) ($body['job_id'] ?? 0);
$payloads = $body['payloads'] ?? [];

if (!is_array($payloads)) {
    glpinetscan_respond(['error' => 'invalid_payloads'], 400);
}

// Resolved from the run row rather than taken from the request, so a scanner
// cannot nominate the ranges it will be checked against.
$target = $jobId > 0 ? Job::targetForRun($jobId, $scanner->getID()) : null;

// Ingest referenced devices before the devices that reference them.
//
// A switch's forwarding table names the MACs of everything behind it. If the
// switch is imported first, GLPI has no asset carrying those MACs and invents
// an Unmanaged placeholder for each — and the resulting link then survives,
// because nothing re-evaluates an existing wiring. Importing endpoints and
// power devices first means the real ports already exist when the switch
// arrives, so it wires to them directly.
//
// The original index is preserved in the result so a caller can still match
// outcomes to what it sent.
$ordered = [];
foreach ($payloads as $index => $payload) {
    $isNetwork = is_array($payload)
        && (($payload['itemtype'] ?? '') === 'NetworkEquipment');
    $ordered[] = ['index' => $index, 'payload' => $payload, 'last' => $isNetwork ? 1 : 0];
}
usort($ordered, static fn(array $a, array $b): int => $a['last'] <=> $b['last']);

$phase = (string) ($body['phase'] ?? '');

$accepted = 0;
$rejected = 0;
$results  = [];

// Which devices the scanner should walk in full, answered back to a discovery
// batch. The decision is made here because this is where the knowledge is: what
// GLPI already holds, when it last held it, and whether the asset still exists.
$inventoryWanted = [];

foreach ($ordered as $entry) {
    $index   = $entry['index'];
    $payload = $entry['payload'];
    if (!is_array($payload)) {
        $rejected++;
        $results[] = ['index' => $index, 'ok' => false, 'errors' => ['not an object']];
        continue;
    }


    // Contained per device. The whole batch arrives in one request, so an
    // uncaught core Error (GLPI rolls its transaction back and rethrows) used
    // to 500 every device in the batch, and the run came back empty.
    try {
        $outcome = Ingest::submit($scanner, $payload, $target);
    } catch (\Throwable $e) {
        trigger_error('glpinetscan: ingest failed: ' . $e->getMessage(), E_USER_WARNING);
        $outcome = [
            'ok'       => false,
            'errors'   => [sprintf('GLPI could not import this device: %s', $e->getMessage())],
            'itemtype' => null,
            'items_id' => null,
        ];
    }
    if ($outcome['ok']) {
        $accepted++;
    } else {
        $rejected++;
    }

    $deviceId = (string) ($payload['deviceid'] ?? '');

    if ($phase === 'discovery') {
        // Considered even when the ingest rejected the submission: a device
        // GLPI refused to import is precisely one that should be walked in
        // full, since a discovery carries too little to satisfy the import
        // rules on its own.
        if (Discovery::consider($payload, $target?->getID() ?? 0, $target?->inventoryInterval() ?? 0)) {
            $inventoryWanted[] = $deviceId;
        }
    } elseif ($outcome['ok'] && ($payload['action'] ?? '') === AbstractRequest::NETINV_ACTION) {
        Discovery::recordInventory($deviceId, $outcome['itemtype'], $outcome['items_id']);
    }

    $results[] = [
        'index'    => $index,
        'deviceid' => (string) ($payload['deviceid'] ?? ''),
        'ok'       => $outcome['ok'],
        'errors'   => $outcome['errors'],
        'itemtype' => $outcome['itemtype'],
        'items_id' => $outcome['items_id'],
    ];
}

// The run row is closed by whichever phase finishes the job. A discovery batch
// that wants nothing walked is the end of that sweep, so it closes the run
// itself; otherwise the inventory batch that follows does, with the real
// numbers.
if ($jobId > 0 && ($phase !== 'discovery' || $inventoryWanted === [])) {
    Job::closeRun(
        $jobId,
        $scanner->getID(),
        (int) ($body['discovered'] ?? 0),
        $phase === 'discovery' ? 0 : $accepted,
        $rejected + (int) ($body['failed'] ?? 0),
        substr((string) ($body['message'] ?? ''), 0, 2000)
    );
}

$response = [
    'accepted' => $accepted,
    'rejected' => $rejected,
    'results'  => $results,
];

// Only ever sent in reply to a discovery batch. An absent field is what an
// older scanner sees, and what tells a newer one that this plugin does not know
// about the split — so the two disagreeing degrades to walking everything,
// which is what happened before any of this existed.
if ($phase === 'discovery') {
    $response['inventory_wanted'] = $inventoryWanted;
}

glpinetscan_respond($response);
