<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The discovery/inventory decision rules, tested without GLPI.
 *
 *   php plugin/tests/discovery-rules.php
 *
 * Discovery::shouldInventory takes no database and no GLPI bootstrap, which is
 * deliberate: these four rules decide whether every device in an estate gets
 * walked or skipped, and a rule that is wrong in one direction means an
 * inventory that never refreshes while a rule wrong in the other gives back
 * everything the split was for.
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/Discovery.php';

use GlpiPlugin\Glpinetscan\Discovery;

$pass = 0;
$fail = 0;

function check(string $label, bool $got, bool $want): void
{
    global $pass, $fail;

    if ($got === $want) {
        $pass++;
        printf("PASS  %s\n", $label);
        return;
    }

    $fail++;
    printf("FAIL  %s (got %s, want %s)\n", $label, var_export($got, true), var_export($want, true));
}

const HOUR = 3600;
const DAY  = 86400;

$now = 1_700_000_000;

/** A device walked an hour ago, with counters that have not moved. */
$settled = [
    'last_inventory'      => $now - HOUR,
    'uptime_ticks'        => 500_000,
    'iftable_last_change' => 1_000,
    'ifstack_last_change' => 1_100,
    'entity_last_change'  => 1_200,
    'itemtype'            => 'NetworkEquipment',
    'items_id'            => 7,
];
$unchanged = [
    'uptime_ticks'        => 860_000,   // still climbing
    'iftable_last_change' => 1_000,
    'ifstack_last_change' => 1_100,
    'entity_last_change'  => 1_200,
];

check('never seen is walked', Discovery::shouldInventory(null, $unchanged, $now, DAY), true);

check(
    'seen but never walked is walked',
    Discovery::shouldInventory(['last_inventory' => 0] + $settled, $unchanged, $now, DAY),
    true
);

check(
    'nothing changed within the interval is skipped',
    Discovery::shouldInventory($settled, $unchanged, $now, DAY),
    false
);

check(
    'stale beyond the interval is walked',
    Discovery::shouldInventory(['last_inventory' => $now - (2 * DAY)] + $settled, $unchanged, $now, DAY),
    true
);

// Zero disables the interval rule: for a range of appliances that genuinely
// never change, the counters alone are the operator's deliberate choice.
check(
    'a zero interval leaves only the change signals',
    Discovery::shouldInventory(['last_inventory' => $now - (30 * DAY)] + $settled, $unchanged, $now, 0),
    false
);

// A reboot. Uptime going backwards matters twice over: the device may have come
// back different, and every other counter is measured against sysUpTime so none
// of them is comparable across the restart.
check(
    'uptime going backwards is a reboot and is walked',
    Discovery::shouldInventory($settled, ['uptime_ticks' => 2_000] + $unchanged, $now, DAY),
    true
);

check(
    'uptime climbing normally is not a reboot',
    Discovery::shouldInventory($settled, ['uptime_ticks' => 900_000] + $unchanged, $now, DAY),
    false
);

// A device that reports no uptime at all offers no evidence either way, and
// must not be mistaken for one that rebooted to tick zero.
check(
    'a device reporting no uptime is not treated as rebooted',
    Discovery::shouldInventory($settled, ['uptime_ticks' => 0] + $unchanged, $now, DAY),
    false
);

foreach (['iftable_last_change', 'ifstack_last_change', 'entity_last_change'] as $counter) {
    $moved = $unchanged;
    $moved[$counter] = 9_999;
    check("a moved $counter is walked", Discovery::shouldInventory($settled, $moved, $now, DAY), true);
}

// Hardware that does not implement a counter reports zero every time. That is
// an absence of evidence, not evidence of change — treating it as a change
// would walk such a device on every single pass and defeat the split entirely.
$noCounters = ['uptime_ticks' => 900_000, 'iftable_last_change' => 0,
               'ifstack_last_change' => 0, 'entity_last_change' => 0];
check(
    'a device implementing no counters is not walked every pass',
    Discovery::shouldInventory($settled, $noCounters, $now, DAY),
    false
);

// The inverse: a device that used to report a counter and now reports zero has
// most likely just stopped answering that scalar, not changed.
check(
    'a counter dropping to zero is not read as a change',
    Discovery::shouldInventory($settled, ['iftable_last_change' => 0] + $unchanged, $now, DAY),
    false
);

printf("\n%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
