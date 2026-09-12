<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Dependency-free tests for the warranty lookup.
 *
 * Run:  php plugin/tests/warranty.php
 *
 * Every one of these vendors is behind a paid support agreement, an NDA, or
 * both, so none of them can be exercised from a test environment and the seven
 * clients would otherwise have no coverage at all. The fake transport below
 * replays response bodies in the shape each vendor documents, and asserts the
 * *requests* as well — the URL, the headers and the body — because with an API
 * nobody here can call, sending the wrong thing is the failure mode that would
 * otherwise only show up in a customer's log.
 *
 * What is NOT asserted, and cannot be: that these are the shapes the vendors
 * actually return today. The payloads are modelled on each vendor's published
 * schema; a field rename upstream shows up as a lookup that finds nothing, not
 * as a failing test here. That is why the clients read aliases rather than one
 * field name, and why an unrecognised response is recorded with the keys it
 * did contain.
 */

declare(strict_types=1);

define('PLUGIN_GLPINETSCAN_VERSION', 'test');

if (!function_exists('__')) {
    function __(string $text, string $domain = 'glpi'): string
    {
        return $text;
    }
}

$base = __DIR__ . '/../src/Warranty';

require_once $base . '/WarrantyException.php';
require_once $base . '/Reply.php';
require_once $base . '/Transport.php';
require_once $base . '/TokenStore.php';
require_once $base . '/Subject.php';
require_once $base . '/Entitlement.php';
require_once $base . '/Coverage.php';
require_once $base . '/Vendor.php';
require_once $base . '/AbstractVendor.php';
require_once $base . '/Vendor/Dell.php';
require_once $base . '/Vendor/Hp.php';
require_once $base . '/Vendor/Hpe.php';
require_once $base . '/Vendor/Lenovo.php';
require_once $base . '/Vendor/Apple.php';
require_once $base . '/Vendor/Cisco.php';
require_once $base . '/Vendor/Fortinet.php';
require_once $base . '/Vendor/Juniper.php';
require_once $base . '/Vendor/Microsoft.php';
require_once $base . '/Vendor/PureStorage.php';
require_once $base . '/Registry.php';
require_once $base . '/Detector.php';
require_once $base . '/Writer.php';

use GlpiPlugin\Glpinetscan\Warranty\Coverage;
use GlpiPlugin\Glpinetscan\Warranty\Detector;
use GlpiPlugin\Glpinetscan\Warranty\Entitlement;
use GlpiPlugin\Glpinetscan\Warranty\Registry;
use GlpiPlugin\Glpinetscan\Warranty\Reply;
use GlpiPlugin\Glpinetscan\Warranty\Subject;
use GlpiPlugin\Glpinetscan\Warranty\TokenStore;
use GlpiPlugin\Glpinetscan\Warranty\Transport;
use GlpiPlugin\Glpinetscan\Warranty\WarrantyException;
use GlpiPlugin\Glpinetscan\Warranty\Writer;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Apple;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Cisco;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Dell;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Fortinet;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Hp;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Hpe;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Juniper;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Lenovo;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\Microsoft;
use GlpiPlugin\Glpinetscan\Warranty\Vendor\PureStorage;

$passed = 0;
$failed = 0;

function check(string $what, $actual, $expected): void
{
    global $passed, $failed;

    if ($actual === $expected) {
        $passed++;
        return;
    }

    $failed++;
    printf(
        "FAIL %s\n     expected: %s\n     actual:   %s\n",
        $what,
        var_export($expected, true),
        var_export($actual, true)
    );
}

function section(string $name): void
{
    echo "\n== $name\n";
}

/**
 * Replays canned replies and records what was asked for.
 */
final class FakeTransport implements Transport
{
    /** @var array<int,array{method:string,url:string,options:array}> */
    public array $sent = [];

    /** @param array<int,Reply|WarrantyException> $replies */
    public function __construct(private array $replies)
    {
    }

    public function send(string $method, string $url, array $options = []): Reply
    {
        $this->sent[] = ['method' => $method, 'url' => $url, 'options' => $options];

        $next = array_shift($this->replies);

        if ($next === null) {
            throw new RuntimeException('FakeTransport: unexpected request to ' . $url);
        }

        if ($next instanceof WarrantyException) {
            throw $next;
        }

        return $next;
    }

    public function last(): array
    {
        return $this->sent[array_key_last($this->sent)] ?? [];
    }
}

final class MemoryTokenStore implements TokenStore
{
    /** @param array<string,string> $values */
    public function __construct(public array $values = [])
    {
    }

    public function get(string $name): string
    {
        return $this->values[$name] ?? '';
    }

    public function put(string $name, string $value): void
    {
        $this->values[$name] = $value;
    }
}

function json_reply(array $body, int $status = 200): Reply
{
    return new Reply($status, json_encode($body, JSON_THROW_ON_ERROR));
}

function token_reply(string $token = 'test-token'): Reply
{
    return json_reply(['access_token' => $token, 'expires_in' => 3600]);
}

// ------------------------------------------------------------------ serials
section('serial hygiene');

check('upper-cases and strips spaces', Subject::normalise(' 7fk l2m3 '), '7FKL2M3');

$lookupable = static fn(string $serial): bool => (new Subject('Computer', 1, $serial))->isLookupable();

check('a real service tag is looked up', $lookupable('7FKL2M3'), true);
check('an Apple serial is looked up', $lookupable('C02XY1234ABC'), true);
// These are what DMI actually contains on hardware with no serial programmed.
check('To be filled by O.E.M. is not', $lookupable('To Be Filled By O.E.M.'), false);
check('System Serial Number is not', $lookupable('System Serial Number'), false);
check('Default string is not', $lookupable('Default string'), false);
check('all zeroes is not', $lookupable('00000000'), false);
check('all X is not', $lookupable('XXXXXXXX'), false);
check('too short is not', $lookupable('ABC'), false);
check('empty is not', $lookupable(''), false);

// ------------------------------------------------------------------- dates
section('vendor date parsing');

check('ISO 8601 with a zone', Entitlement::date('2024-05-12T00:00:00Z'), '2024-05-12');
check('plain Y-m-d', Entitlement::date('2024-05-12'), '2024-05-12');
check('US-style', Entitlement::date('05/12/2024'), '2024-05-12');
check('empty string', Entitlement::date(''), null);
check('null', Entitlement::date(null), null);
check('nonsense', Entitlement::date('not a date'), null);
// Vendors send these instead of omitting a field; they parse perfectly well and
// would otherwise become a machine bought in the year 1.
check('the zero date is rejected', Entitlement::date('0000-00-00'), null);
check('year 1 is rejected', Entitlement::date('0001-01-01'), null);
check('1900 is rejected', Entitlement::date('1900-01-01'), null);

// --------------------------------------------------------------- coverage
section('picking the entitlement that counts');

$coverage = new Coverage(
    serial: 'ABC1234',
    vendor: 'dell',
    entitlements: [
        Entitlement::make(Entitlement::BASE, 'Basic Onsite', '2021-05-11', '2024-05-11'),
        Entitlement::make(Entitlement::EXTENDED, 'ProSupport NBD', '2021-05-11', '2026-05-11'),
        Entitlement::make(Entitlement::OTHER, 'Accidental damage', '2021-05-11', '2023-05-11'),
    ],
    ship_date: '2021-05-01'
);

check('the last-ending entitlement wins', $coverage->end(), '2026-05-11');
check('its service level is the one recorded', $coverage->level(), 'ProSupport NBD');
check('the earliest start is the start', $coverage->start(), '2021-05-11');
check('covered today', $coverage->isCovered('2025-01-01'), true);
check('not covered afterwards', $coverage->isCovered('2027-01-01'), false);
check('not covered beforehand', $coverage->isCovered('2020-01-01'), false);

$lifetime = new Coverage('X', 'cisco', [
    Entitlement::make(Entitlement::BASE, 'Limited lifetime', '2019-01-01', null, true),
    Entitlement::make(Entitlement::CONTRACT, 'SNTC 8x5xNBD', '2019-01-01', '2024-01-01'),
]);

check('lifetime cover wins outright', $lifetime->isLifetime(), true);
check('lifetime cover has no end date', $lifetime->end(), null);
check('lifetime cover is always current', $lifetime->isCovered('2099-01-01'), true);

// An entitlement with no end date must not be read as "ended today" — that
// would report a covered machine as expired.
$open = new Coverage('X', 'hp', [
    Entitlement::make(Entitlement::BASE, 'Open', '2020-01-01', null),
]);
check('an open-ended entitlement is still cover', $open->isCovered('2030-01-01'), true);

check('an empty coverage is empty', (new Coverage('X', 'dell'))->isEmpty(), true);
check('an empty coverage has no principal', (new Coverage('X', 'dell'))->principal(), null);

// A round trip through the record's JSON column must not lose anything.
$restored = Coverage::fromArray($coverage->toArray());
check('survives a round trip: end', $restored->end(), '2026-05-11');
check('survives a round trip: level', $restored->level(), 'ProSupport NBD');
check('survives a round trip: count', count($restored->entitlements), 3);

// -------------------------------------------------------------- detection
section('vendor detection');

$vendor = static fn(string $m, string $model = '', string $type = 'Computer'): ?string
    => Detector::vendorFor($m, $model, $type);

check('Dell Inc.', $vendor('Dell Inc.'), 'dell');
check('Dell Computer Corporation', $vendor('Dell Computer Corporation'), 'dell');
check('bare Dell', $vendor('Dell'), 'dell');
check('Alienware is Dell', $vendor('Alienware'), 'dell');
check('LENOVO', $vendor('LENOVO'), 'lenovo');
check('IBM machine types are Lenovo now', $vendor('IBM'), 'lenovo');
check('Apple Inc.', $vendor('Apple Inc.'), 'apple');
check('Cisco Systems, Inc.', $vendor('Cisco Systems, Inc.', '', 'NetworkEquipment'), 'cisco');
check('Fortinet', $vendor('Fortinet, Inc.', '', 'NetworkEquipment'), 'fortinet');

// The 2015 split: same name, two companies, two APIs.
check('HP on a laptop is HP Inc.', $vendor('HP', '', 'Computer'), 'hp');
check('Hewlett-Packard on a laptop is HP Inc.', $vendor('Hewlett-Packard', '', 'Computer'), 'hp');
check('HP on a printer is HP Inc.', $vendor('HP', '', 'Printer'), 'hp');
check('HP on a switch is HPE', $vendor('HP', '', 'NetworkEquipment'), 'hpe');
check('Hewlett Packard Enterprise is always HPE', $vendor('Hewlett Packard Enterprise', '', 'Computer'), 'hpe');
check('Aruba is HPE', $vendor('Aruba Networks', '', 'NetworkEquipment'), 'hpe');
check('3Com is HPE', $vendor('3Com', '', 'NetworkEquipment'), 'hpe');

// Meraki serials are not in Cisco's support API; sending them would fail on
// every access point in an estate, every night.
check('Meraki is excluded', $vendor('Cisco Meraki', '', 'NetworkEquipment'), null);

// Short aliases are destructive without word boundaries.
check('Sharp is not HP', $vendor('Sharp Corporation', '', 'Printer'), null);
check('Semcon is not Dell EMC', $vendor('Semcon', '', 'Computer'), null);

check('unknown manufacturer', $vendor('Raspberry Pi Foundation'), null);
check('no manufacturer and no model', $vendor(''), null);

// SNMP kit often has no manufacturer in GLPI at all, because the enterprise
// OID never mapped to one. The model string is the fallback.
check('model says Catalyst', $vendor('', 'Catalyst 9300-48P', 'NetworkEquipment'), 'cisco');
check('model says FortiGate', $vendor('', 'FortiGate-60F', 'NetworkEquipment'), 'fortinet');
check('model says ProCurve', $vendor('', 'ProCurve 2920-48G', 'NetworkEquipment'), 'hpe');
check('model says ThinkPad', $vendor('', 'ThinkPad T14 Gen 3'), 'lenovo');
check('model says Latitude', $vendor('', 'Latitude 7440'), 'dell');
check('model says MacBook', $vendor('', 'MacBook Pro'), 'apple');

// Cisco access points land in GLPI with no manufacturer at all — the enterprise
// OID never mapped to one — and a model that is a bare product identifier. Both
// of these were sitting unmatched in a real inventory.
check('a bare Aironet product id', $vendor('', 'AIR-AP2802I-E-K9', 'NetworkEquipment'), 'cisco');
check('a bare Catalyst AP product id', $vendor('', 'C9120AXI-E', 'NetworkEquipment'), 'cisco');
check('a Catalyst switch product id', $vendor('', 'WS-C2960X-24TS-L', 'NetworkEquipment'), 'cisco');
check('a Nexus product id', $vendor('', 'N9K-C93180YC-EX', 'NetworkEquipment'), 'cisco');
check('a Catalyst 9800 controller', $vendor('', 'C9800-CL-K9', 'NetworkEquipment'), 'cisco');

// A model that names its maker outright is settled by the same alias rules the
// manufacturer column uses.
check('the model names the maker', $vendor('', 'Cisco C9130AXI-E', 'NetworkEquipment'), 'cisco');
check('the model names Fortinet', $vendor('', 'Fortinet FG-100F', 'NetworkEquipment'), 'fortinet');
check('the model names HP on a switch', $vendor('', 'HP 2530-48G', 'NetworkEquipment'), 'hpe');
check('the model names HP on a laptop', $vendor('', 'HP 250 G8', 'Computer'), 'hp');
check('a Meraki model is still excluded', $vendor('', 'Cisco Meraki MR46', 'NetworkEquipment'), null);

check('Juniper Networks', $vendor('Juniper Networks', '', 'NetworkEquipment'), 'juniper');
check('a Juniper chassis id', $vendor('', 'EX4300-48T', 'NetworkEquipment'), 'juniper');
check('an SRX', $vendor('', 'SRX345', 'NetworkEquipment'), 'juniper');
// Anchored and digit-bearing, so ordinary words starting "ex" or "mx" are safe.
check('exagrid is not a Juniper switch', $vendor('', 'ExaGrid EX21', 'Computer'), null);
check('Microsoft Surface', $vendor('Microsoft Corporation', 'Surface Laptop 5', 'Computer'), 'microsoft');
check('a Surface model alone', $vendor('', 'Surface Pro 9', 'Computer'), 'microsoft');
check('Pure Storage', $vendor('Pure Storage', '', 'NetworkEquipment'), 'pure');
check('a FlashArray model alone', $vendor('', 'FlashArray//X70 R3', 'NetworkEquipment'), 'pure');

// Still absent, and checked: these have no serial-number warranty API.
check('Arista has no API', $vendor('Arista Networks', 'DCS-7050SX3-48YC8', 'NetworkEquipment'), null);
check('Supermicro has no API', $vendor('Supermicro', 'SYS-1029U-TRT', 'Computer'), null);

// The patterns are anchored: an unanchored c9[0-9]{3} would claim half the
// world's part numbers.
check('a part number that merely contains c9xxx is not Cisco', $vendor('', 'TASKalfa C9130ci', 'Printer'), null);

// Kit whose vendor genuinely has no warranty API stays unmatched, so it is
// recorded as "not applicable" rather than failing every night.
check('APC has no API', $vendor('', 'Smart-UPS SRT 3000', 'PDU'), null);
check('Ubiquiti has no API', $vendor('Ubiquiti Networks', 'UAP-AC-PRO', 'NetworkEquipment'), null);
check('Polycom has no API', $vendor('Polycom', 'VVX 411', 'Phone'), null);
check('Kyocera has no API', $vendor('Kyocera', 'TASKalfa 3554ci', 'Printer'), null);

check('corporate suffixes are dropped', Detector::normalise('Dell Inc.'), 'dell');
check('punctuation is dropped', Detector::normalise('Cisco Systems, Inc.'), 'cisco systems');

// ------------------------------------------------------------------- Dell
section('Dell');

$http = new FakeTransport([
    token_reply(),
    json_reply([[
        'id'                     => 1,
        'serviceTag'             => '7FKL2M3',
        'shipDate'               => '2021-05-11T00:00:00Z',
        'productLineDescription' => 'LATITUDE 7420',
        'countryCode'            => 'US',
        'invalid'                => false,
        'duplicated'             => false,
        'entitlements'           => [
            [
                'itemNumber'              => '990-1234',
                'startDate'               => '2021-05-11T00:00:00Z',
                'endDate'                 => '2024-05-12T00:00:00Z',
                'entitlementType'         => 'INITIAL',
                'serviceLevelDescription' => 'Next Business Day Onsite',
            ],
            [
                'itemNumber'              => '990-5678',
                'startDate'               => '2024-05-12T00:00:00Z',
                'endDate'                 => '2026-05-12T00:00:00Z',
                'entitlementType'         => 'EXTENDED',
                'serviceLevelDescription' => 'ProSupport Next Business Day',
            ],
        ],
    ], [
        'serviceTag' => 'NOTMINE',
        'invalid'    => true,
    ]]),
]);

$dell    = new Dell($http, ['client_id' => 'id', 'client_secret' => 'secret']);
$results = $dell->lookup([
    new Subject('Computer', 1, '7fkl2m3', 'Dell Inc.'),
    new Subject('Computer', 2, 'NOTMINE', 'Dell Inc.'),
]);

check('Dell token is a client-credentials form post', $http->sent[0]['options']['form']['grant_type'] ?? null, 'client_credentials');
check('Dell token URL', $http->sent[0]['url'], 'https://apigtwb2c.us.dell.com/auth/oauth/v2/token');
check('Dell asset URL', $http->sent[1]['url'], 'https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements');
check('Dell batches service tags in one query', $http->sent[1]['options']['query']['servicetags'] ?? null, '7FKL2M3,NOTMINE');
check('Dell sends the bearer token', $http->sent[1]['options']['headers']['Authorization'] ?? null, 'Bearer test-token');

// The tag was sent lower-case and Dell echoed it upper-case; keying on what we
// sent would silently lose every row.
check('Dell result is keyed on the normalised tag', isset($results['7FKL2M3']), true);
check('Dell reads two entitlements', count($results['7FKL2M3']->entitlements), 2);
check('Dell end date', $results['7FKL2M3']->end(), '2026-05-12');
check('Dell service level', $results['7FKL2M3']->level(), 'ProSupport Next Business Day');
check('Dell ship date', $results['7FKL2M3']->ship_date, '2021-05-11');
check('Dell product', $results['7FKL2M3']->product, 'LATITUDE 7420');
check('Dell base entitlement is typed', $results['7FKL2M3']->entitlements[0]->type, Entitlement::BASE);
check('Dell extension is typed', $results['7FKL2M3']->entitlements[1]->type, Entitlement::EXTENDED);

// Dell answers for every tag sent, flagging the ones it does not know. Treating
// those as results would stamp "no warranty" on assets Dell has no record of.
check('an invalid tag produces no result', isset($results['NOTMINE']), false);

check('Dell batch size', Dell::batchSize(), 100);

// ------------------------------------------------------------------- HP Inc.
section('HP Inc.');

$http = new FakeTransport([
    token_reply(),
    json_reply([[
        'sn'     => '5CG1234ABC',
        'pn'     => 'T6F46UT',
        'offers' => [
            [
                'offerDescription'                   => 'HP 3y Next Business Day Onsite',
                'serviceObligationTypeCode'          => 'W',
                'serviceObligationLineItemStartDate' => '2022-03-01',
                'serviceObligationLineItemEndDate'   => '2025-03-01',
            ],
            [
                'offerDescription'                   => 'HP Care Pack 5y Onsite',
                'serviceObligationTypeCode'          => 'C',
                'serviceObligationLineItemStartDate' => '2022-03-01',
                'serviceObligationLineItemEndDate'   => '2027-03-01',
                'obligationKey'                      => 'OBL-9',
            ],
        ],
    ]]),
]);

$hp      = new Hp($http, ['client_id' => 'id', 'client_secret' => 'secret']);
$results = $hp->lookup([new Subject('Computer', 1, '5CG1234ABC', 'HP', 'EliteBook 840', 'T6F46UT')]);

check('HP token URL', $http->sent[0]['url'], 'https://warranty.api.hp.com/oauth/v1/token');
check('HP query URL', $http->sent[1]['url'], 'https://warranty.api.hp.com/productwarranty/v2/queries');
check('HP posts a list of sn/pn objects', $http->sent[1]['options']['json'][0] ?? null, ['sn' => '5CG1234ABC', 'pn' => 'T6F46UT']);
check('HP end date is the Care Pack', $results['5CG1234ABC']->end(), '2027-03-01');
check('HP level', $results['5CG1234ABC']->level(), 'HP Care Pack 5y Onsite');
check('HP care pack is a contract line', $results['5CG1234ABC']->entitlements[1]->type, Entitlement::CONTRACT);
check('HP base warranty is a base line', $results['5CG1234ABC']->entitlements[0]->type, Entitlement::BASE);
check('HP with a product number carries no caveat', $results['5CG1234ABC']->note, '');

// Without a product number HP may answer about a different machine, and the
// result says so rather than looking equally trustworthy.
$http = new FakeTransport([
    token_reply(),
    json_reply([['sn' => '5CG1234ABC', 'offers' => [[
        'offerDescription'                   => 'HP 1y',
        'serviceObligationLineItemStartDate' => '2022-03-01',
        'serviceObligationLineItemEndDate'   => '2023-03-01',
    ]]]]),
]);
$hp      = new Hp($http, ['client_id' => 'id', 'client_secret' => 'secret']);
$results = $hp->lookup([new Subject('Computer', 1, '5CG1234ABC', 'HP')]);
check('HP omits pn when there is none', array_key_exists('pn', $http->sent[1]['options']['json'][0]), false);
check('HP without a product number is flagged', str_contains($results['5CG1234ABC']->note, 'product number'), true);

// --------------------------------------------------------------------- HPE
section('HPE');

$http = new FakeTransport([
    token_reply(),
    json_reply(['entitlementBySnPnInstanceHSLList' => [[
        'serialNumber'               => 'CZ12345678',
        'productNumber'              => 'P19562-B21',
        'countryCode'                => 'US',
        'currentHighestSupportLevel' => 'Foundation Care 24x7',
        'supportLevels'              => [
            [
                'serviceLevel' => 'HPE Hardware Warranty',
                'startDate'    => '2020-06-01',
                'endDate'      => '2023-06-01',
            ],
            [
                'serviceLevel'   => 'Foundation Care 24x7',
                'contractLevel'  => 'FC24',
                'contractNumber' => 'CTR-77',
                'startDate'      => '2020-06-01',
                'endDate'        => '2025-06-01',
            ],
        ],
    ]]]),
]);

$hpe     = new Hpe($http, ['client_id' => 'id', 'client_secret' => 'secret', 'country' => 'GB']);
$results = $hpe->lookup([new Subject('NetworkEquipment', 1, 'CZ12345678', 'HPE', '', 'P19562-B21')]);

check('HPE token URL', $http->sent[0]['url'], 'https://api-gw.support.hpe.com/apigwext/services/oauth/token');
// This gateway rejects the credentials in the body with an unhelpful 400.
check('HPE authenticates with Basic', $http->sent[0]['options']['headers']['Authorization'] ?? null, 'Basic ' . base64_encode('id:secret'));
check('HPE warranty URL', $http->sent[1]['url'], 'https://api-gw.support.hpe.com/apigwext/support/entitlement/v1/warrantyCheck/');
check('HPE sends the serial', $http->sent[1]['options']['json'][0]['serialNumber'] ?? null, 'CZ12345678');
check('HPE sends the product number', $http->sent[1]['options']['json'][0]['productNumber'] ?? null, 'P19562-B21');
// HPE prices entitlements per region and will not answer without a country.
check('HPE falls back to the configured country', $http->sent[1]['options']['json'][0]['countryCode'] ?? null, 'GB');
check('HPE end date', $results['CZ12345678']->end(), '2025-06-01');
check('HPE contract line is typed', $results['CZ12345678']->entitlements[1]->type, Entitlement::CONTRACT);
check('HPE warranty line is typed', $results['CZ12345678']->entitlements[0]->type, Entitlement::BASE);
check('HPE highest level is noted', str_contains($results['CZ12345678']->note, 'Foundation Care 24x7'), true);

// The same gateway has returned a bare list depending on the subscription.
$http = new FakeTransport([
    token_reply(),
    json_reply([[
        'serialNumber'  => 'CZ12345678',
        'supportLevels' => [['serviceLevel' => 'Warranty', 'startDate' => '2020-06-01', 'endDate' => '2023-06-01']],
    ]]),
]);
$hpe     = new Hpe($http, ['client_id' => 'id', 'client_secret' => 'secret']);
$results = $hpe->lookup([new Subject('NetworkEquipment', 1, 'CZ12345678', 'HPE')]);
check('HPE bare-list envelope is accepted', $results['CZ12345678']->end(), '2023-06-01');
check('HPE default country', $http->sent[1]['options']['json'][0]['countryCode'] ?? null, 'US');

// ------------------------------------------------------------------ Lenovo
section('Lenovo');

$http = new FakeTransport([
    json_reply([
        'Serial'    => 'PF0ABCDE',
        'Product'   => '20U9/ThinkPad T14',
        'InWarranty' => true,
        'Shipped'   => '2021-02-10',
        'Purchased' => '2021-03-01',
        'Country'   => 'US',
        'Warranty'  => [
            ['ID' => '3EZ', 'Name' => '3Y Premier Support', 'Type' => 'BASE', 'Delivery' => 'ON_SITE',
                'Start' => '2021-03-01', 'End' => '2024-03-01'],
            ['ID' => '5WS', 'Name' => '5Y Premier Support', 'Type' => 'UPGRADE', 'Delivery' => 'ON_SITE',
                'Start' => '2021-03-01', 'End' => '2026-03-01'],
        ],
        'Contract' => [
            // Lenovo keeps historic contract lines. Letting an expired one win
            // the "ends last" comparison would report cover nobody has.
            ['Contract' => 'OLD-1', 'SLA' => 'Lapsed', 'Status' => 'EXPIRED',
                'Start' => '2015-01-01', 'End' => '2030-01-01'],
        ],
    ]),
]);

$lenovo  = new Lenovo($http, ['client_id' => 'clientid']);
$results = $lenovo->lookup([new Subject('Computer', 1, 'PF0ABCDE', 'LENOVO', 'ThinkPad T14', '20U9')]);

check('Lenovo URL', $http->sent[0]['url'], 'https://supportapi.lenovo.com/v2.5/warranty');
check('Lenovo sends the ClientID header', $http->sent[0]['options']['headers']['ClientID'] ?? null, 'clientid');
// A four-character product number is a machine type; Lenovo serials are unique
// per machine type and the API refuses to guess.
check('Lenovo sends SERIAL.MT when the machine type is known', $http->sent[0]['options']['form']['Serial'] ?? null, 'PF0ABCDE.20U9');
check('Lenovo end date', $results['PF0ABCDE']->end(), '2026-03-01');
check('Lenovo names the delivery method', $results['PF0ABCDE']->level(), '5Y Premier Support (on site)');
check('Lenovo skips expired contracts', count($results['PF0ABCDE']->entitlements), 2);
check('Lenovo purchase date', $results['PF0ABCDE']->purchase_date, '2021-03-01');
check('Lenovo ship date', $results['PF0ABCDE']->ship_date, '2021-02-10');
check('Lenovo upgrade is typed', $results['PF0ABCDE']->entitlements[1]->type, Entitlement::EXTENDED);

// A serial with no machine type is sent bare, and a list comes back.
$http = new FakeTransport([
    json_reply([
        ['Serial' => 'AAA1111', 'Warranty' => [['Name' => '1Y', 'Type' => 'BASE', 'Start' => '2023-01-01', 'End' => '2024-01-01']]],
        ['Serial' => 'BBB2222', 'Code' => 100],
        ['Serial' => 'CCC3333', 'Code' => 101, 'Product' => 'ThinkCentre'],
    ]),
]);
$lenovo  = new Lenovo($http, ['client_id' => 'clientid']);
$results = $lenovo->lookup([
    new Subject('Computer', 1, 'AAA1111', 'Lenovo'),
    new Subject('Computer', 2, 'BBB2222', 'Lenovo'),
    new Subject('Computer', 3, 'CCC3333', 'Lenovo'),
]);
check('Lenovo sends a bare serial without a machine type', $http->sent[0]['options']['form']['Serial'] ?? null, 'AAA1111,BBB2222,CCC3333');
check('Lenovo found the first', $results['AAA1111']->end(), '2024-01-01');
check('Lenovo error 100 produces no result', isset($results['BBB2222']), false);
// Error 101 is actionable — somebody has to put the machine type on the model —
// so it is reported rather than dropped.
check('Lenovo error 101 is reported', isset($results['CCC3333']), true);
check('Lenovo error 101 explains the fix', str_contains($results['CCC3333']->note, 'machine type'), true);

// An unknown serial is a 404 for a single-serial call. That is an answer, not a
// failure, and must not be re-queued as a retryable error.
$http    = new FakeTransport([new Reply(404, '{"Code":100}')]);
$lenovo  = new Lenovo($http, ['client_id' => 'clientid']);
check('Lenovo 404 is an empty answer', $lenovo->lookup([new Subject('Computer', 1, 'ZZZ9999', 'Lenovo')]), []);

// ------------------------------------------------------------------- Cisco
section('Cisco');

$http = new FakeTransport([
    token_reply(),
    json_reply(['serial_numbers' => [
        [
            'sr_no'                         => 'FOC1234X5YZ',
            'is_covered'                    => 'YES',
            'warranty_end_date'             => '2023-08-31',
            'warranty_type'                 => 'W-LTD-HW',
            'warranty_type_description'     => 'Limited Lifetime Hardware Warranty',
            'covered_product_line_end_date' => '2027-01-31',
            'service_contract_number'       => 'SC-4242',
            'service_line_descr'            => 'SNTC-8X5XNBD Catalyst 9300',
            'contract_site_country'         => 'US',
            'orderable_pid_list'            => [['orderable_pid' => 'C9300-48P-A', 'item_description' => 'Catalyst 9300']],
        ],
        [
            'sr_no'         => 'BADSERIAL1',
            'ErrorResponse' => ['APIError' => ['ErrorCode' => 'CWS002', 'ErrorDescription' => 'Serial Number Does Not Exist']],
        ],
    ]]),
]);

$cisco   = new Cisco($http, ['client_id' => 'id', 'client_secret' => 'secret']);
$results = $cisco->lookup([
    new Subject('NetworkEquipment', 1, 'FOC1234X5YZ', 'Cisco Systems'),
    new Subject('NetworkEquipment', 2, 'BADSERIAL1', 'Cisco Systems'),
]);

// Applications registered from March 2023 use id.cisco.com, not the retired
// cloudsso.cisco.com.
check('Cisco token URL', $http->sent[0]['url'], 'https://id.cisco.com/oauth2/default/v1/token');
check('Cisco token is form-encoded', $http->sent[0]['options']['headers']['Content-Type'] ?? null, 'application/x-www-form-urlencoded');
// The serials are path segments, not a query string.
check('Cisco serials go in the path', $http->sent[1]['url'], 'https://apix.cisco.com/sn2info/v2/coverage/summary/serial_numbers/FOC1234X5YZ,BADSERIAL1');
check('Cisco end date is the contract, not the warranty', $results['FOC1234X5YZ']->end(), '2027-01-31');
check('Cisco product', $results['FOC1234X5YZ']->product, 'C9300-48P-A');
// Cisco reports an end date and no start; the writer turns that into a
// zero-length span rather than inventing a purchase date.
check('Cisco reports no start date', $results['FOC1234X5YZ']->entitlements[0]->start, null);
check('Cisco contract is typed', $results['FOC1234X5YZ']->entitlements[1]->type, Entitlement::CONTRACT);
// A per-serial error inside a successful response must not look like a machine
// with no cover.
check('a per-serial error produces no result', isset($results['BADSERIAL1']), false);
check('Cisco batch size is its documented ceiling', Cisco::batchSize(), 75);

// --------------------------------------------------------------- Fortinet
section('Fortinet');

$http = new FakeTransport([
    json_reply(['access_token' => 'forti-token', 'expires_in' => 14400]),
    json_reply(['assets' => [[
        'serialNumber'     => 'FGT60FTK20001234',
        'productModel'     => 'FortiGate 60F',
        'registrationDate' => '2021-09-15',
        'isDecommissioned' => false,
        'warrantySupports' => [
            ['levelDesc' => 'Hardware Warranty', 'startDate' => '2021-09-15', 'endDate' => '2022-09-15'],
        ],
        'entitlements'     => [
            ['levelDesc' => 'FortiCare Premium', 'typeDesc' => 'Hardware', 'startDate' => '2021-09-15', 'endDate' => '2026-09-15'],
        ],
        'contracts'        => [
            ['contractNumber' => '1234AB', 'terms' => [
                ['supportType' => 'Advanced Hardware Replacement', 'startDate' => '2021-09-15', 'endDate' => '2026-09-15'],
            ]],
        ],
    ]]]),
]);

$forti   = new Fortinet($http, ['api_username' => 'user', 'api_password' => 'pass', 'client_id' => 'assetmanagement']);
$results = $forti->lookup([new Subject('NetworkEquipment', 1, 'FGT60FTK20001234', 'Fortinet')]);

check('Fortinet token URL', $http->sent[0]['url'], 'https://customerapiauth.fortinet.com/api/v1/oauth/token/');
// This grant is `password` over JSON, where every other vendor here is
// client_credentials over a form.
check('Fortinet uses the password grant', $http->sent[0]['options']['json']['grant_type'] ?? null, 'password');
check('Fortinet sends the client id', $http->sent[0]['options']['json']['client_id'] ?? null, 'assetmanagement');
check('Fortinet list URL', $http->sent[1]['url'], 'https://support.fortinet.com/ES/api/registration/v3/products/list');
check('Fortinet sends one serial', $http->sent[1]['options']['json']['serialNumber'] ?? null, 'FGT60FTK20001234');
check('Fortinet end date', $results['FGT60FTK20001234']->end(), '2026-09-15');
check('Fortinet reads all three lists', count($results['FGT60FTK20001234']->entitlements), 3);
check('Fortinet warranty line is typed', $results['FGT60FTK20001234']->entitlements[0]->type, Entitlement::CONTRACT);
check('Fortinet product', $results['FGT60FTK20001234']->product, 'FortiGate 60F');
check('Fortinet registration date is the purchase date', $results['FGT60FTK20001234']->purchase_date, '2021-09-15');

// Hardware registered to a reseller is genuinely invisible, which is different
// from being out of warranty.
$http  = new FakeTransport([json_reply(['access_token' => 't', 'expires_in' => 100]), new Reply(404, '{}')]);
$forti = new Fortinet($http, ['api_username' => 'u', 'api_password' => 'p']);
check('Fortinet 404 is an empty answer', $forti->lookup([new Subject('NetworkEquipment', 1, 'FGT999', 'Fortinet')]), []);

// ------------------------------------------------------------------- Apple
section('Apple GSX');

$store = new MemoryTokenStore();
$http  = new FakeTransport([
    json_reply(['authToken' => 'session-abc']),
    json_reply(['device' => [
        'id'                 => 'C02XY1234ABC',
        'serialNumber'       => 'C02XY1234ABC',
        'productDescription' => 'MacBook Pro (14-inch, 2021)',
        'purchaseDate'       => '2022-01-20',
        'purchaseCountryCode' => 'US',
        'warrantyInfo'       => [
            'warrantyStatusDescription' => 'Apple Limited Warranty',
            'startDate'                 => '2022-01-20',
            'endDate'                   => '2023-01-20',
            'contractType'              => 'AppleCare+ for Mac',
            'contractCoverageStartDate' => '2022-01-20',
            'contractCoverageEndDate'   => '2025-01-20',
        ],
    ]]),
]);

$apple = new Apple($http, [
    'base_url'          => 'https://partner.example.apple.com',
    'sold_to'           => '0000123456',
    'ship_to'           => '0000123457',
    'operator_apple_id' => 'ops@example.com',
    'activation_token'  => 'activation-xyz',
    'cert_path'         => '/etc/gsx/chain.pem',
    'accept_language'   => 'en_US',
], $store);

$results = $apple->lookup([new Subject('Computer', 1, 'C02XY1234ABC', 'Apple Inc.')]);

// Authentication is under /api and everything else under /gsx/api.
check('Apple auth path', $http->sent[0]['url'], 'https://partner.example.apple.com/api/authenticate/token');
check('Apple presents the activation token first', $http->sent[0]['options']['json']['authToken'] ?? null, 'activation-xyz');
check('Apple details path', $http->sent[1]['url'], 'https://partner.example.apple.com/gsx/api/repair/product/details');
check('Apple sends Sold-To', $http->sent[1]['options']['headers']['X-Apple-SoldTo'] ?? null, '0000123456');
check('Apple sends Ship-To', $http->sent[1]['options']['headers']['X-Apple-ShipTo'] ?? null, '0000123457');
check('Apple sends the operator', $http->sent[1]['options']['headers']['X-Operator-User-ID'] ?? null, 'ops@example.com');
check('Apple sends the service version', $http->sent[1]['options']['headers']['X-Apple-Service-Version'] ?? null, 'v2');
check('Apple sends the session token', $http->sent[1]['options']['headers']['X-Apple-Auth-Token'] ?? null, 'session-abc');
check('Apple sends the serial as the device id', $http->sent[1]['options']['json']['device']['id'] ?? null, 'C02XY1234ABC');

// The activation token is spent on first use; losing the session token means
// asking Apple for a new activation token, so it has to be persisted.
check('Apple keeps the session token', $store->get('apple_session_token'), 'session-abc');
check('Apple end date is the AppleCare contract', $results['C02XY1234ABC']->end(), '2025-01-20');
check('Apple splits warranty from AppleCare', count($results['C02XY1234ABC']->entitlements), 2);
check('Apple purchase date', $results['C02XY1234ABC']->purchase_date, '2022-01-20');
check('Apple product', $results['C02XY1234ABC']->product, 'MacBook Pro (14-inch, 2021)');

// A stored token is reused rather than re-authenticating on every call.
$http  = new FakeTransport([json_reply(['device' => ['serialNumber' => 'C02A', 'warrantyInfo' => [
    'startDate' => '2023-01-01', 'endDate' => '2024-01-01',
]]])]);
$apple = new Apple($http, [
    'base_url' => 'https://partner.example.apple.com', 'sold_to' => '1', 'ship_to' => '2',
    'operator_apple_id' => 'o@e.com', 'activation_token' => 'a', 'cert_path' => '/x.pem',
], new MemoryTokenStore(['apple_session_token' => 'kept']));
$apple->lookup([new Subject('Computer', 1, 'C02A', 'Apple')]);
check('Apple reuses a stored session token', count($http->sent), 1);

// A lapsed session token is worth one re-authentication: GSX expires these on
// idle time, so a nightly estate hits it routinely.
$http  = new FakeTransport([
    new Reply(401, '{"error":"token expired"}'),
    json_reply(['authToken' => 'fresh']),
    json_reply(['device' => ['serialNumber' => 'C02B', 'warrantyInfo' => ['startDate' => '2023-01-01', 'endDate' => '2024-01-01']]]),
]);
$store = new MemoryTokenStore(['apple_session_token' => 'stale']);
$apple = new Apple($http, [
    'base_url' => 'https://partner.example.apple.com', 'sold_to' => '1', 'ship_to' => '2',
    'operator_apple_id' => 'o@e.com', 'activation_token' => 'a', 'cert_path' => '/x.pem',
], $store);
$results = $apple->lookup([new Subject('Computer', 1, 'C02B', 'Apple')]);
check('Apple re-authenticates once on 401', $results['C02B']->end(), '2024-01-01');
check('Apple renews with the stored token, not the spent activation one', $http->sent[1]['options']['json']['authToken'] ?? null, 'stale');
check('Apple stores the renewed token', $store->get('apple_session_token'), 'fresh');

// Apple documents the response only to partners. An unrecognised shape must
// leave something an administrator can act on.
$http  = new FakeTransport([json_reply(['device' => ['serialNumber' => 'C02C', 'warrantyInfo' => ['someNewField' => 'x', 'anotherOne' => 'y']]])]);
$apple = new Apple($http, [
    'base_url' => 'https://p.example.com', 'sold_to' => '1', 'ship_to' => '2',
    'operator_apple_id' => 'o@e.com', 'activation_token' => 'a', 'cert_path' => '/x.pem',
], new MemoryTokenStore(['apple_session_token' => 'kept']));
$results = $apple->lookup([new Subject('Computer', 1, 'C02C', 'Apple')]);
check('an unrecognised Apple payload names its fields', str_contains($results['C02C']->note, 'someNewField'), true);

// ----------------------------------------------------------------- Juniper
section('Juniper');

$http = new FakeTransport([
    json_reply(['assets' => [[
        'assetRecordId'        => 'A-1',
        'assetStatus'          => 'Active',
        'serialNumber'         => 'JN123456ABC',
        'shipDate'             => '2020-04-02',
        'registrationDate'     => '2020-05-01',
        'productSKU'           => 'EX4300-48T',
        'productSKUDescription' => 'EX4300 48-port switch',
        'serviceEligible'      => true,
        'installedAtCountry'   => 'GB',
        'warranty'             => [
            ['index' => 1, 'warrantyDescription' => 'Standard Hardware Warranty',
                'warrantyStartDate' => '2020-04-02', 'warrantyEndDate' => '2021-04-02'],
        ],
        'serviceContract'      => [[
            'index' => 1,
            'contractNumber'  => 'JNPR-98765',
            'contractDetails' => [
                ['contractLineItemNumber' => '1', 'contractStartDate' => '2020-04-02',
                    'contractEndDate' => '2026-04-02', 'contractStatus' => 'Active',
                    'serviceSKU' => 'SVC-NDCE-EX4300', 'serviceSKUDescription' => 'JNPR CARE NDCE Support'],
                // Historic line: keeping it would win the "ends last" comparison
                // and report cover the customer no longer has.
                ['contractLineItemNumber' => '2', 'contractStartDate' => '2015-01-01',
                    'contractEndDate' => '2030-01-01', 'contractStatus' => 'Expired',
                    'serviceSKUDescription' => 'Old plan'],
            ],
        ]],
    ]]]),
]);

$juniper = new Juniper($http, [
    'api_key' => 'jnpr-key', 'app_id' => 'APP1', 'customer_source_id' => 'CS1',
]);
$results = $juniper->lookup([new Subject('NetworkEquipment', 1, 'JN123456ABC', 'Juniper Networks')]);

check('Juniper asset URL', $http->sent[0]['url'], 'https://apigw.juniper.net/css-asset/1.0/queryAssetsDetails');
// Juniper's gateway declares an API-key scheme on Authorization, and different
// onboarding packs include the "Bearer " prefix in the value itself.
check('Juniper sends the key verbatim', $http->sent[0]['options']['headers']['Authorization'] ?? null, 'jnpr-key');
$request = $http->sent[0]['options']['json']['queryAssetsDetailsRequest'] ?? [];
check('Juniper sends the app id', $request['appId'] ?? null, 'APP1');
check('Juniper sends the customer source id', $request['customerSourceID'] ?? null, 'CS1');
check('Juniper sends the serials', $request['serialNumbersOrSSRNs'] ?? null, ['JN123456ABC']);
// Juniper correlates support cases on this, so it must differ per call.
check('Juniper sends a transaction id', strlen((string) ($request['customerUniqueTransactionID'] ?? '')), 36);
check('Juniper end date is the live contract', $results['JN123456ABC']->end(), '2026-04-02');
check('Juniper skips expired contract lines', count($results['JN123456ABC']->entitlements), 2);
check('Juniper warranty line is typed', $results['JN123456ABC']->entitlements[0]->type, Entitlement::BASE);
check('Juniper contract line is typed', $results['JN123456ABC']->entitlements[1]->type, Entitlement::CONTRACT);
check('Juniper product', $results['JN123456ABC']->product, 'EX4300 48-port switch');
check('Juniper ship date', $results['JN123456ABC']->ship_date, '2020-04-02');
check('an eligible active asset carries no caveat', $results['JN123456ABC']->note, '');

// "Not eligible for service" is the whole answer when somebody asks why they
// cannot open a case, so it is reported rather than dropped.
$http = new FakeTransport([
    json_reply(['assets' => [[
        'serialNumber'    => 'JN999',
        'serviceEligible' => 'N',
        'isServiceDeclinedOnAsset' => true,
        'serviceDeclineReason'     => 'End of support',
        'assetStatus'     => 'Inactive',
        'warranty'        => [['warrantyDescription' => 'Standard', 'warrantyStartDate' => '2016-01-01', 'warrantyEndDate' => '2017-01-01']],
    ]]]),
]);
$juniper = new Juniper($http, ['api_key' => 'k', 'app_id' => 'a', 'customer_source_id' => 'c']);
$results = $juniper->lookup([new Subject('NetworkEquipment', 1, 'JN999', 'Juniper')]);
check('Juniper reports service ineligibility', str_contains($results['JN999']->note, 'not eligible'), true);
check('Juniper reports a declined service', str_contains($results['JN999']->note, 'declined'), true);
check('Juniper reports a non-active asset status', str_contains($results['JN999']->note, 'Inactive'), true);

// An estate that records software support reference numbers instead of serials
// still lands on the right asset.
$http = new FakeTransport([
    json_reply(['assets' => [[
        'serialNumber' => 'OTHER1',
        'softwareSupportReferenceNumber' => 'SSRN-7',
        'warranty' => [['warrantyDescription' => 'W', 'warrantyStartDate' => '2021-01-01', 'warrantyEndDate' => '2024-01-01']],
    ]]]),
]);
$juniper = new Juniper($http, ['api_key' => 'k', 'app_id' => 'a', 'customer_source_id' => 'c']);
$results = $juniper->lookup([new Subject('NetworkEquipment', 1, 'SSRN-7', 'Juniper')]);
check('Juniper matches on the SSRN too', isset($results['SSRN-7']), true);

// ------------------------------------------------------- Microsoft Surface
section('Microsoft Surface');

$export_csv = "\xEF\xBB\xBFSerial Number,Model,Warranty Type,Warranty Start Date,Warranty End Date,Warranty Status\n"
    . "012345678901,Surface Laptop 5,Standard Limited Warranty,2023-06-01,2024-06-01,Expired\n"
    . "012345678901,Surface Laptop 5,Extended Protection Plan,2023-06-01,2027-06-01,Active\n"
    . "098765432109,Surface Pro 9,Standard Limited Warranty,2024-02-15,2025-02-15,Active\n";

$http = new FakeTransport([
    token_reply('entra-token'),
    json_reply(['downloadUrl' => 'https://surfaceexport.blob.core.windows.net/x/y.csv?sig=abc',
        'expiresOn' => '2026-09-13T00:00:00Z']),
    new Reply(200, $export_csv),
]);

$ms = new Microsoft($http, [
    'tenant_id' => 'contoso.onmicrosoft.com', 'client_id' => 'app-1',
    'client_secret' => 'shh', 'subscription_key' => 'sub-key',
]);
$results = $ms->lookup([
    new Subject('Computer', 1, '012345678901', 'Microsoft'),
    new Subject('Computer', 2, '098765432109', 'Microsoft'),
    new Subject('Computer', 3, 'NOTINTENANT1', 'Microsoft'),
]);

check('Surface token URL is the tenant endpoint', $http->sent[0]['url'],
    'https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token');
check('Surface token is scoped to the service app id', $http->sent[0]['options']['form']['scope'] ?? null,
    '76bd8628-ca60-441c-9d83-06503cbfd9c5/.default');
check('Surface export URL', $http->sent[1]['url'], 'https://surface.ams.microsoft.com/api/external/warranty/export');
check('Surface sends the subscription key', $http->sent[1]['options']['headers']['Ocp-Apim-Subscription-Key'] ?? null, 'sub-key');
check('Surface sends the bearer token', $http->sent[1]['options']['headers']['Authorization'] ?? null, 'Bearer entra-token');
// The download is a pre-signed storage URL. Sending the Entra token and the
// subscription key to it would hand both to a host with no business seeing them.
check('the CSV download carries no credentials', $http->sent[2]['options'], []);

check('Surface reads the export', $results['012345678901']->end(), '2027-06-01');
// Two rows for one device: original warranty plus an extended plan.
check('Surface keeps both rows for a device', count($results['012345678901']->entitlements), 2);
check('Surface level', $results['012345678901']->level(), 'Extended Protection Plan');
check('Surface model', $results['012345678901']->product, 'Surface Laptop 5');
check('Surface second device', $results['098765432109']->end(), '2025-02-15');
// Only Intune-enrolled devices in the configured tenant are in the export.
check('a device outside the tenant is absent', isset($results['NOTINTENANT1']), false);

// One export per run, not one per batch.
$again = $ms->lookup([new Subject('Computer', 1, '012345678901', 'Microsoft')]);
check('the export is fetched once per run', count($http->sent), 3);
check('and still answers', $again['012345678901']->end(), '2027-06-01');

// A tenant that has never been scanned answers 404. That is a setup state, and
// telling the administrator to wait is the entire useful response.
$http = new FakeTransport([token_reply(), new Reply(404, '{"error":"not found"}')]);
$ms   = new Microsoft($http, ['tenant_id' => 't', 'client_id' => 'c', 'client_secret' => 's', 'subscription_key' => 'k']);
try {
    $ms->lookup([new Subject('Computer', 1, 'ABC12345', 'Microsoft')]);
    check('an unenrolled tenant raises', true, false);
} catch (WarrantyException $e) {
    check('an unenrolled tenant is a config state', $e->kind, WarrantyException::CONFIG);
    check('and says to enrol', str_contains($e->getMessage(), 'Enrol the tenant'), true);
}

// Enrolment changes state inside the customer's Microsoft tenant, so it is a
// button rather than something the cron does on its own.
check('Surface declares a setup action', array_key_exists('enrol', Microsoft::setupActions()), true);
check('no other vendor declares one', Dell::setupActions(), []);

$http = new FakeTransport([token_reply(), new Reply(200, '{}')]);
$ms   = new Microsoft($http, ['tenant_id' => 't', 'client_id' => 'c', 'client_secret' => 's', 'subscription_key' => 'k']);
$message = $ms->runSetupAction('enrol');
check('enrolment is a PUT', $http->sent[1]['method'], 'PUT');
check('enrolment URL', $http->sent[1]['url'], 'https://surface.ams.microsoft.com/api/external/warranty/enrollment');
check('enrolment explains the delay', str_contains($message, 'five business days'), true);

// Column order is not contractual, so the parser reads names. A BOM would
// otherwise become part of the first column name and lose the serial.
$reordered = "Model,Warranty End Date,Serial Number,Warranty Start Date\n"
    . "Surface Go 3,2026-01-01,AAA111222333,2023-01-01\n";
$parsed = Microsoft::parse($reordered);
check('columns are matched by name, not position', $parsed['AAA111222333']->end(), '2026-01-01');
check('an export with no recognisable serial column yields nothing',
    Microsoft::parse("Foo,Bar\n1,2\n"), []);
check('an empty export yields nothing', Microsoft::parse(''), []);

// --------------------------------------------------------- Pure Storage
section('Pure Storage');

$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($key, $pem);
$key_path = sys_get_temp_dir() . '/glpi-warranty-test-key.pem';
file_put_contents($key_path, $pem);

$http = new FakeTransport([
    token_reply('pure-token'),
    json_reply(['items' => [
        ['id' => 'arr-1', 'name' => 'flash01', 'fqdn' => 'flash01.example.com', 'model' => 'FA-X70R3'],
    ], 'continuation_token' => null]),
    json_reply(['items' => [
        ['start_date' => 1609459200000, 'end_date' => 1893456000000,
            'resource' => ['id' => 'arr-1', 'name' => 'flash01', 'fqdn' => 'flash01.example.com']],
    ], 'continuation_token' => null]),
]);

$pure    = new PureStorage($http, ['app_id' => 'pure1:apikey:abc', 'private_key_path' => $key_path]);
$results = $pure->lookup([new Subject('NetworkEquipment', 1, 'PURESN0001', 'Pure Storage', '', '', '', 'flash01')]);

check('Pure token URL', $http->sent[0]['url'], 'https://api.pure1.purestorage.com/oauth2/1.0/token');
// RFC 8693 token exchange, not client credentials — and the default must not
// win the array union, which is what `+` would have done.
check('Pure uses token exchange', $http->sent[0]['options']['form']['grant_type'] ?? null,
    'urn:ietf:params:oauth:grant-type:token-exchange');
check('Pure sends a subject token type', $http->sent[0]['options']['form']['subject_token_type'] ?? null,
    'urn:ietf:params:oauth:token-type:jwt');
check('Pure arrays URL', $http->sent[1]['url'], 'https://api.pure1.purestorage.com/api/1.latest/arrays');
check('Pure contracts URL', $http->sent[2]['url'], 'https://api.pure1.purestorage.com/api/1.latest/arrays/support-contracts');

// The subject token is a real RS256 JWT: header, claims and a verifiable
// signature. Getting any of that wrong fails at Pure with an opaque 400.
$jwt = (string) ($http->sent[0]['options']['form']['subject_token'] ?? '');
$parts = explode('.', $jwt);
check('the subject token has three segments', count($parts), 3);
$b64 = static fn(string $v): array => (array) json_decode(
    base64_decode(strtr($v, '-_', '+/') . str_repeat('=', (4 - strlen($v) % 4) % 4)), true);
check('JWT algorithm is RS256', $b64($parts[0])['alg'] ?? null, 'RS256');
check('JWT issuer is the application id', $b64($parts[1])['iss'] ?? null, 'pure1:apikey:abc');
// Pure's reference docs say milliseconds; their shipped client sends seconds,
// and a working client beats a spec when the two disagree.
check('JWT timestamps are seconds, not milliseconds',
    ($b64($parts[1])['iat'] ?? 0) > 1600000000 && ($b64($parts[1])['iat'] ?? 0) < 4000000000, true);
$signature  = base64_decode(strtr($parts[2], '-_', '+/') . str_repeat('=', (4 - strlen($parts[2]) % 4) % 4));
$public_key = openssl_pkey_get_details($key)['key'];
check('the signature verifies against the public half',
    openssl_verify($parts[0] . '.' . $parts[1], $signature, $public_key, OPENSSL_ALGO_SHA256), 1);
// A tampered payload must not verify — otherwise the check above proves nothing.
check('a tampered payload does not verify',
    openssl_verify($parts[0] . '.' . $parts[1] . 'x', $signature, $public_key, OPENSSL_ALGO_SHA256), 0);

// Pure1 timestamps are milliseconds since the epoch.
check('Pure contract end date', $results['PURESN0001']->end(), '2030-01-01');
check('Pure contract start date', $results['PURESN0001']->start(), '2021-01-01');
check('Pure product comes from the arrays call', $results['PURESN0001']->product, 'FA-X70R3');
// Pure1 publishes no serial, so the join is on the name — and the tab says so
// rather than letting it look as trustworthy as a serial match.
check('Pure says how it matched', str_contains($results['PURESN0001']->note, 'by name'), true);
check('the result is keyed on the asset serial', array_key_first($results), 'PURESN0001');

// An asset whose name is fully qualified must match an array named for the host.
$http = new FakeTransport([
    token_reply('t'),
    json_reply(['items' => []]),
    json_reply(['items' => [['start_date' => 1609459200000, 'end_date' => 1893456000000,
        'resource' => ['id' => 'a', 'name' => 'flash02']]]]),
]);
$pure = new PureStorage($http, ['app_id' => 'x', 'private_key_path' => $key_path]);
$found = $pure->lookup([new Subject('NetworkEquipment', 2, 'SN2', 'Pure Storage', '', '', '', 'flash02.dc.example.com')]);
check('an FQDN asset name matches a bare array name', isset($found['SN2']), true);

// An array nobody in GLPI is named after is simply not matched.
$http = new FakeTransport([
    token_reply('t'),
    json_reply(['items' => []]),
    json_reply(['items' => [['start_date' => 1609459200000, 'end_date' => 1893456000000,
        'resource' => ['id' => 'a', 'name' => 'somethingelse']]]]),
]);
$pure = new PureStorage($http, ['app_id' => 'x', 'private_key_path' => $key_path]);
check('an unmatched name yields nothing',
    $pure->lookup([new Subject('NetworkEquipment', 3, 'SN3', 'Pure Storage', '', '', '', 'flash03')]), []);

// A missing key file is a configuration fault, not something to retry hourly.
$pure = new PureStorage(new FakeTransport([]), ['app_id' => 'x', 'private_key_path' => '/nonexistent.pem']);
try {
    $pure->lookup([new Subject('NetworkEquipment', 4, 'SN4', 'Pure Storage', '', '', '', 'flash04')]);
    check('a missing Pure key raises', true, false);
} catch (WarrantyException $e) {
    check('a missing Pure key is a config fault', $e->kind, WarrantyException::CONFIG);
}

@unlink($key_path);

// ------------------------------------------------------------ failure kinds"""
section('failure classification');

// Getting this wrong is expensive in both directions: retrying an auth failure
// hammers a vendor until the key is suspended, and giving up on a 503 leaves an
// estate with no warranty data because of one bad afternoon.
$kind = static function (int $status): string {
    $http = new FakeTransport([token_reply(), new Reply($status, '{"message":"nope"}')]);
    $dell = new Dell($http, ['client_id' => 'a', 'client_secret' => 'b']);

    try {
        $dell->lookup([new Subject('Computer', 1, 'ABC1234', 'Dell')]);
    } catch (WarrantyException $e) {
        return $e->kind;
    }

    return 'none';
};

check('401 is an auth failure', $kind(401), WarrantyException::AUTH);
check('403 is an auth failure', $kind(403), WarrantyException::AUTH);
check('429 is a throttle', $kind(429), WarrantyException::THROTTLED);
check('500 is transport', $kind(500), WarrantyException::TRANSPORT);
check('503 is transport', $kind(503), WarrantyException::TRANSPORT);
check('400 is a response failure', $kind(400), WarrantyException::RESPONSE);

check('transport failures are retried', (new WarrantyException(WarrantyException::TRANSPORT, ''))->isRetryable(), true);
check('throttles are retried', (new WarrantyException(WarrantyException::THROTTLED, ''))->isRetryable(), true);
check('auth failures are not', (new WarrantyException(WarrantyException::AUTH, ''))->isRetryable(), false);
check('config failures are not', (new WarrantyException(WarrantyException::CONFIG, ''))->isRetryable(), false);

// A token endpoint that refuses is always the same fix, so it is named as such.
$http = new FakeTransport([new Reply(400, '{"error":"invalid_client"}')]);
$dell = new Dell($http, ['client_id' => 'a', 'client_secret' => 'b']);
try {
    $dell->lookup([new Subject('Computer', 1, 'ABC1234', 'Dell')]);
    check('bad credentials raise', true, false);
} catch (WarrantyException $e) {
    check('bad credentials are an auth failure, not a response failure', $e->kind, WarrantyException::AUTH);
}

// A missing credential is a configuration fault and must not be retried on a timer.
$dell = new Dell(new FakeTransport([]), []);
try {
    $dell->lookup([new Subject('Computer', 1, 'ABC1234', 'Dell')]);
    check('a missing credential raises', true, false);
} catch (WarrantyException $e) {
    check('a missing credential is a config fault', $e->kind, WarrantyException::CONFIG);
}

// An HTML error page from a proxy is a common and baffling failure; say so.
$http = new FakeTransport([token_reply(), new Reply(200, '<html>Gateway</html>')]);
$dell = new Dell($http, ['client_id' => 'a', 'client_secret' => 'b']);
try {
    $dell->lookup([new Subject('Computer', 1, 'ABC1234', 'Dell')]);
    check('a non-JSON body raises', true, false);
} catch (WarrantyException $e) {
    check('a non-JSON body is a response failure', $e->kind, WarrantyException::RESPONSE);
    check('and says what it got', str_contains($e->getMessage(), 'not JSON'), true);
}

// ------------------------------------------------------------------ writing
section('projection onto GLPI fields');

check('three whole years', Writer::monthsBetween('2021-05-11', '2024-05-11'), 36);
check('one month', Writer::monthsBetween('2021-05-11', '2021-06-11'), 1);
check('a day short of a month', Writer::monthsBetween('2021-05-11', '2021-06-10'), 0);
check('a day over three years', Writer::monthsBetween('2021-05-11', '2024-05-12'), 36);
check('backwards is zero', Writer::monthsBetween('2024-05-11', '2021-05-11'), 0);
check('same day is zero', Writer::monthsBetween('2024-05-11', '2024-05-11'), 0);
// A leap day inside the span must not turn 36 months into 36 and a bit.
check('leap years do not matter', Writer::monthsBetween('2019-02-28', '2021-02-28'), 24);

// MySQL clamps the day of the month; PHP's own "+1 month" overflows into the
// next one. The difference shows up as a warranty expiring in the wrong month,
// so the SQL behaviour is the one reproduced.
check('month end clamps rather than overflowing', Writer::addMonths('2021-01-31', 1), '2021-02-28');
check('month end clamps in a leap year', Writer::addMonths('2020-01-31', 1), '2020-02-29');
check('a normal date is unaffected', Writer::addMonths('2021-03-15', 12), '2022-03-15');
check('zero months is the date itself', Writer::addMonths('2021-03-15', 0), '2021-03-15');

$plan = Writer::plan(new Coverage('ABC', 'dell', [
    Entitlement::make(Entitlement::BASE, 'Basic', '2021-05-11', '2024-05-11'),
    Entitlement::make(Entitlement::EXTENDED, 'ProSupport NBD', '2021-05-11', '2026-05-11'),
]));

check('warranty_date is the start', $plan['start'], '2021-05-11');
check('warranty_duration is whole months to the last end', $plan['duration'], 60);
// GLPI computes this expiry two ways and they differ by a day. The search
// option and the warranty-alert cron use DATE_ADD(warranty_date, INTERVAL n
// MONTH) and land exactly on the vendor's date; the Financial tab shows the
// last covered day, one earlier. Both are asserted so a change to either is
// visible here rather than in a support case.
check('reporting and alerts land on the vendor end date', Writer::addMonths($plan['start'], $plan['duration']), '2026-05-11');
check('the Financial tab shows the last covered day', Writer::displayedExpiry($plan['start'], $plan['duration']), '2026-05-10');
check('warranty_info names the vendor', str_contains($plan['info'], 'Dell'), true);
check('warranty_info names the service level', str_contains($plan['info'], 'ProSupport NBD'), true);
check('warranty_info carries the exact expiry', str_contains($plan['info'], '2026-05-11'), true);

// -1 is GLPI's own marker for cover that never expires; it renders as "Never".
$plan = Writer::plan(new Coverage('X', 'cisco', [
    Entitlement::make(Entitlement::BASE, 'Limited lifetime', '2019-01-01', null, true),
]));
check('lifetime cover uses GLPI -1', $plan['duration'], Writer::LIFETIME);
check('lifetime cover keeps its start', $plan['start'], '2019-01-01');
check('lifetime cover says so', str_contains($plan['info'], 'never expires'), true);

// Cisco reports an expiry with no start. A zero-month span ending on the right
// day keeps every expiry view and every alert correct.
$plan = Writer::plan(new Coverage('X', 'cisco', [
    Entitlement::make(Entitlement::CONTRACT, 'SNTC 8x5xNBD', null, '2027-01-31'),
]));
check('no start: the span is anchored on the end', $plan['start'], '2027-01-31');
check('no start: the duration is zero', $plan['duration'], 0);
// A zero-month span gets no day subtracted, so the tab shows the exact date too.
check('no start: GLPI still shows the right expiry', Writer::addMonths($plan['start'], $plan['duration']), '2027-01-31');
check('no start: and the tab agrees', Writer::displayedExpiry($plan['start'], $plan['duration']), '2027-01-31');
// So nobody reads the start column as a purchase date.
check('no start: the info string says so', str_contains($plan['info'], 'start not reported'), true);

check('nothing to write when there are no entitlements', Writer::plan(new Coverage('X', 'dell')), null);
check('nothing to write when there is no end date', Writer::plan(new Coverage('X', 'dell', [
    Entitlement::make(Entitlement::BASE, 'Open', '2020-01-01', null),
])), null);

// The signature is what tells a later run whether a person has edited the
// fields since.
$a = Writer::signature(['start' => '2021-05-11', 'duration' => 60, 'info' => 'Dell — x']);
$b = Writer::signature(['start' => '2021-05-11', 'duration' => 60, 'info' => 'Dell — x']);
$c = Writer::signature(['start' => '2021-05-11', 'duration' => 36, 'info' => 'Dell — x']);
check('the same plan signs the same', $a, $b);
check('a different duration signs differently', $a === $c, false);

// -------------------------------------------------------------- the registry
section('registry');

check('ten vendors', count(Registry::vendorClasses()), 10);
check('every vendor has a distinct key', count(Registry::byKey()), 10);
check('an unknown key resolves to nothing', Registry::classFor('acme'), null);

foreach (Registry::vendorClasses() as $class) {
    check($class::label() . ' has a non-empty key', $class::key() !== '', true);
    check($class::label() . ' batches at least one serial', $class::batchSize() >= 1, true);
    check($class::label() . ' claims at least one manufacturer name', $class::aliases() !== [], true);

    foreach ($class::credentials() as $name => $spec) {
        check(
            $class::label() . '/' . $name . ' declares a known field type',
            in_array($spec['type'], ['text', 'secret', 'path'], true),
            true
        );
    }
}

check('Dell needs credentials', Dell::isConfigured([]), false);
check('Dell is configured with both halves', Dell::isConfigured(['client_id' => 'a', 'client_secret' => 'b']), true);
// The API host has a default, so it is not part of being configured.
check('Dell does not need the optional host', Dell::isConfigured(['client_id' => 'a', 'client_secret' => 'b', 'api_base' => '']), true);
check('Lenovo needs only its ClientID', Lenovo::isConfigured(['client_id' => 'x']), true);
check('Apple needs the whole GSX set', Apple::isConfigured(['base_url' => 'x']), false);
check('Juniper needs all three', Juniper::isConfigured(['api_key' => 'a']), false);
check('Juniper configured', Juniper::isConfigured(['api_key' => 'a', 'app_id' => 'b', 'customer_source_id' => 'c']), true);
check('Microsoft needs a subscription key as well as the app', Microsoft::isConfigured([
    'tenant_id' => 't', 'client_id' => 'c', 'client_secret' => 's']), false);
check('Microsoft configured', Microsoft::isConfigured([
    'tenant_id' => 't', 'client_id' => 'c', 'client_secret' => 's', 'subscription_key' => 'k']), true);
// The key passphrase is optional; an unencrypted key is normal.
check('Pure configured without a passphrase', PureStorage::isConfigured([
    'app_id' => 'a', 'private_key_path' => '/k.pem']), true);

// Credentials are secrets and must be declared as such, or they would be
// written to glpi_configs in the clear.
$secret_fields = ['client_secret', 'api_password', 'activation_token', 'cert_password', 'client_id',
    'api_key', 'subscription_key', 'private_key_password'];
foreach (Registry::vendorClasses() as $class) {
    foreach ($class::credentials() as $name => $spec) {
        if ($name === 'client_id' && $class !== Lenovo::class) {
            // An OAuth client id is not a secret; Lenovo's ClientID is the
            // whole credential and is.
            continue;
        }
        if (in_array($name, $secret_fields, true)) {
            check($class::label() . '/' . $name . ' is stored as a secret', $spec['type'], 'secret');
        }
    }
}

// ------------------------------------------------------------------ summary
printf("\n%d passed, %d failed\n", $passed, $failed);

exit($failed === 0 ? 0 : 1);
