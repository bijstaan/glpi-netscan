<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * The faceplate's layout and status rules, tested without GLPI.
 *
 *   php plugin/tests/portmap-layout.php
 *
 * Everything else the port map draws is read straight out of core's tables and
 * is only as right as core is. These three rules are the plugin's own, and
 * each is wrong in a way that is easy to miss by looking:
 *
 *  - the position rule decides where a port is drawn. Split at the wrong run
 *    of digits and a stacked switch draws one row with two port 1s in it,
 *    which looks like a faceplate and is not one.
 *  - the status rule decides what colour it is drawn in. Read a missing
 *    ifOperStatus as 0 and every port from an inventory source that omits the
 *    field goes red.
 *  - the speed band decides the third mode's colouring, and the boundary
 *    cases are exactly the speeds real hardware reports.
 */

declare(strict_types=1);

// PortMap's own vocabulary calls GLPI's translation function. Stubbed rather
// than avoided, so the labels are exercised too.
if (!function_exists('__')) {
    function __($str, $domain = 'GLPI')
    {
        return $str;
    }
}

require_once __DIR__ . '/../src/PortMap.php';

use GlpiPlugin\Glpinetscan\PortMap;

$pass = 0;
$fail = 0;

function check(string $label, mixed $got, mixed $want): void
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

// --- where a port is drawn ------------------------------------------------
// One case per vendor naming scheme actually met in the field. The module is
// whatever precedes the LAST run of digits, which is what keeps a stack's
// members apart.
$place = static fn(string $name) => PortMap::facePosition($name);

check('Cisco IOS', $place('GigabitEthernet0/1'), ['prefix' => 'GigabitEthernet0', 'position' => 1]);
check('Cisco IOS-XE stack', $place('GigabitEthernet1/0/24'), ['prefix' => 'GigabitEthernet1/0', 'position' => 24]);
check('Cisco ten-gig', $place('Te1/1/4'), ['prefix' => 'Te1/1', 'position' => 4]);
check('Nexus / Arista', $place('Ethernet1/48'), ['prefix' => 'Ethernet1', 'position' => 48]);
check('Juniper', $place('ge-0/0/7'), ['prefix' => 'ge-0/0', 'position' => 7]);
check('Fortinet', $place('port12'), ['prefix' => 'port', 'position' => 12]);
check('Cumulus', $place('swp3'), ['prefix' => 'swp', 'position' => 3]);
check('Linux-style', $place('eth0'), ['prefix' => 'eth', 'position' => 0]);
check('bare number', $place('7'), ['prefix' => '', 'position' => 7]);
check('trailing space is not a name', $place('  Gi0/2  '), ['prefix' => 'Gi0', 'position' => 2]);

// The whole point of splitting at the last run: two stack members' port 1s
// must land in different modules, or they are drawn on top of each other.
check(
    'stack members are separate modules',
    $place('GigabitEthernet1/0/1')['prefix'] === $place('GigabitEthernet2/0/1')['prefix'],
    false
);

// A name with no trailing number has no position, and the caller files it
// among the logical interfaces rather than inventing one.
foreach (['Management', 'Loopback', 'Null', 'Vlan', ''] as $name) {
    check("no position for '$name'", $place($name), null);
}

// A separator left dangling on the prefix would split one module in two the
// moment a device names a port without it.
check('separator is trimmed off the module', $place('Gi-0-4')['prefix'], 'Gi-0');
check('dot separator is trimmed too', $place('1.2')['prefix'], '1');

// --- what colour it is drawn in -------------------------------------------
// IF-MIB codes: 1 up, 2 down, 3 testing, 4 unknown, 5 dormant, 6 notPresent,
// 7 lowerLayerDown. Administrative state is the second argument.
check('up', PortMap::stateOf(1, 1), 'up');
check('down with no link', PortMap::stateOf(2, 1), 'down');
check('testing', PortMap::stateOf(3, 1), 'testing');
check('dormant', PortMap::stateOf(5, 1), 'dormant');
check('not present', PortMap::stateOf(6, 1), 'absent');
check('lower layer down', PortMap::stateOf(7, 1), 'lowerdown');

// The distinction the whole colouring exists for: a shut port reports oper
// down as well, and calling that "down" sends somebody to check a patch lead.
check('shut wins over down', PortMap::stateOf(2, 2), 'disabled');
check('shut wins even while the link is still up', PortMap::stateOf(1, 2), 'disabled');

// Core writes these into varchar columns, and not every inventory source
// fills them. An absent status is unknown — never 0, which is not a state
// any MIB defines and would paint a whole device red.
check('missing status is unknown, not down', PortMap::stateOf(null, null), 'unknown');
check('empty string is unknown', PortMap::stateOf('', ''), 'unknown');
check('a numeric string is read as its code', PortMap::stateOf('1', '1'), 'up');
check('an unknown admin value does not shut the port', PortMap::stateOf(1, ''), 'up');

check('unknown has a label', PortMap::stateLabel('unknown'), 'Unknown');
check('a state with no label falls back', PortMap::stateLabel('nonsense'), 'Unknown');

// --- speed ----------------------------------------------------------------
check('gigabit band', PortMap::speedBand(1000000000), '1g');
check('just under gigabit is fast ethernet', PortMap::speedBand(999999999), '100m');
check('ten gigabit', PortMap::speedBand(10000000000), '10g');
check('forty gigabit still bands as ten-plus', PortMap::speedBand(40000000000), '10g');
check('hundred meg', PortMap::speedBand(100000000), '100m');
check('ten meg', PortMap::speedBand(10000000), '10m');
// A port whose speed is not reported must not be drawn as the slowest one:
// "no answer" and "10 Mb/s" are different facts about the switch.
check('unreported speed has no band', PortMap::speedBand(0), 'none');

check('gigabit reads as gigabit', PortMap::speedLabel(1000000000), '1 Gb/s');
check('two and a half gig keeps its half', PortMap::speedLabel(2500000000), '2.5 Gb/s');
check('bundle speeds do not grow a decimal', PortMap::speedLabel(2000000000), '2 Gb/s');
check('hundred meg', PortMap::speedLabel(100000000), '100 Mb/s');
check('sub-megabit links still read', PortMap::speedLabel(64000), '64 kb/s');
check('no speed reported is blank, not zero', PortMap::speedLabel(0), '');

printf("\n%d passed, %d failed\n", $pass, $fail);
exit($fail === 0 ? 0 : 1);
