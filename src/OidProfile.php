<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use Dropdown;
use Html;
use Session;

/**
 * An OID profile: which OIDs to read for which devices.
 *
 * Two sources, merged at job time:
 *
 *  - **Shipped packs** — versioned JSON under `data/profiles/`, diffable in
 *    git, upgraded with the plugin. This is where broad vendor coverage lives.
 *  - **Rows of this table** — authored in the GLPI UI, layered on top by
 *    priority. This is what lets a site add one OID for one switch model
 *    without forking the plugin or losing the change on the next upgrade.
 *
 * Profiles are authored as `field = OID` lines rather than raw JSON: the field
 * names are a closed vocabulary (they map onto the inventory schema), so the
 * form can validate them and reject a typo instead of shipping a profile that
 * silently collects nothing.
 */
final class OidProfile extends CommonDBTM
{
    public static string $rightname = 'config';

    public bool $dohistory = true;

    /** Where shipped packs live, relative to the plugin root. */
    private const PACK_DIR = '/data/profiles';

    /**
     * Field names the scanner knows how to apply, per section.
     *
     * These mirror `collect.applyDeviceField` and friends in the scanner. A
     * name outside these sets would be accepted, sent, and silently ignored —
     * so the form rejects it up front.
     */
    public const FIELDS = [
        'device' => [
            'name', 'description', 'serial', 'manufacturer', 'model', 'location',
            'contact', 'firmware', 'assettag', 'mac', 'uptime', 'ram', 'memory', 'cpu',
        ],
        'ports' => [
            'ifname', 'ifdescr', 'ifalias', 'iftype', 'ifmtu', 'ifspeed', 'ifstatus',
            'ifinternalstatus', 'ifportduplex', 'iflastchange', 'ifinbytes',
            'ifoutbytes', 'ifinerrors', 'ifouterrors', 'mac',
        ],
        'components' => [
            'name', 'description', 'serial', 'model', 'manufacturer', 'firmware',
            'type', 'fru', 'contained_index', 'stack_number',
        ],
        'pagecounters' => [
            'total', 'black', 'color', 'printtotal', 'printblack', 'printcolor',
            'copytotal', 'copyblack', 'copycolor', 'scanned', 'faxtotal', 'rectoverso',
        ],
        // Standard topology and metric tables. These have defaults compiled
        // into the scanner; overriding one is only for a device that puts the
        // table somewhere non-standard.
        'topology' => [
            'dot1d_base_port_ifindex', 'dot1d_fdb_port', 'dot1d_fdb_status',
            'dot1q_fdb_port', 'dot1q_fdb_status',
            'vlan_static_name', 'vlan_egress_ports', 'vlan_untagged_ports', 'vlan_pvid',
            'lldp_loc_port_id', 'lldp_loc_port_subtype', 'lldp_rem_chassis_id',
            'lldp_rem_port_id', 'lldp_rem_port_desc', 'lldp_rem_sys_name',
            'lldp_rem_sys_desc', 'lldp_rem_man_addr',
            'cdp_device_id', 'cdp_device_port', 'cdp_platform', 'cdp_address',
            'if_hc_in_octets', 'if_hc_out_octets', 'if_high_speed',
            // Link aggregation. `aggregate_iftypes` is a comma-separated list
            // of IANAifType values rather than an OID: it is what separates a
            // port-channel from an SVI in ifStackTable, and hardware that
            // reports a bundle as plain ethernet needs it widened.
            'stack_status', 'lag_attached_agg', 'aggregate_iftypes',
        ],
        // Device control: the only section whose OIDs are *written*. Each entry
        // is an OID plus a value map, e.g.
        //   outlet_power = 1.3.6.1.4.1.318.1.1.26.9.2.4.1.5 on=1,off=2,cycle=3
        // Nothing here is written unless device control is enabled globally and
        // the target has a write credential of its own.
        'control' => [
            'port_admin', 'poe_port', 'outlet_power', 'device_reset',
        ],
        // Access points behind a controller. Every vendor puts these in a
        // different table, so the collector owns the mechanism — walk these
        // columns, correlate rows by table index — and the profile owns the
        // OIDs. Adding Aruba or UniFi is a row here, not a release.
        'wireless' => [
            'ap_name', 'ap_model', 'ap_serial', 'ap_mac', 'ap_ip', 'ap_location',
            'ap_status', 'ap_status_map', 'ap_firmware', 'ap_radios', 'ap_clients',
            'radio_band', 'radio_band_map', 'radio_channel', 'radio_clients',
            'radio_status', 'radio_status_map',
            'ssid', 'ssid_clients',
        ],
    ];

    /**
     * Collectors that can be switched off per device family.
     *
     * All are on unless a profile turns one off, so a new device works with no
     * configuration; this exists for hardware that implements a table badly
     * enough to produce wrong data rather than no data.
     */
    public const FEATURES = ['fdb', 'lldp', 'cdp', 'vlans', 'hc_counters'];

    private const COLUMNS = [
        'device'       => 'device_oids',
        'ports'        => 'port_oids',
        'components'   => 'component_oids',
        'pagecounters' => 'counter_oids',
        'topology'     => 'topology_oids',
    ];

    public static function getTypeName($nb = 0)
    {
        return _n('OID profile', 'OID profiles', $nb, 'glpinetscan');
    }

    // GLPI's `config` right has READ and UPDATE but no CREATE or PURGE, so the
    // inherited checks would 403 on the "new item" form and on deletion. These
    // map the object's lifecycle onto the right that actually exists.
    public static function canCreate(): bool
    {
        return \Session::haveRight('config', UPDATE);
    }

    public static function canUpdate(): bool
    {
        return \Session::haveRight('config', UPDATE);
    }

    public static function canPurge(): bool
    {
        return \Session::haveRight('config', UPDATE);
    }

    public static function canDelete(): bool
    {
        return \Session::haveRight('config', UPDATE);
    }

    public static function getIcon()
    {
        return 'ti ti-list-details';
    }

    /**
     * Every profile the scanner should receive: shipped packs first, then
     * active database rows.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function forJob(): array
    {
        return array_map(
            [self::class, 'normaliseForWire'],
            array_merge(self::shipped(), self::stored())
        );
    }

    /**
     * Force the map-valued members to serialise as JSON objects.
     *
     * PHP cannot tell an empty map from an empty list, so `"match": {}` decodes
     * to `[]` and re-encodes as `[]` — which is a JSON *array*, and fails to
     * unmarshal into the scanner's struct. A base profile matching everything
     * is exactly the case that hits this, so it would break every scan.
     *
     * @param array<string,mixed> $profile
     * @return array<string,mixed>
     */
    private static function normaliseForWire(array $profile): array
    {
        foreach (['match', 'device', 'ports', 'components', 'pagecounters'] as $key) {
            if (!array_key_exists($key, $profile)) {
                continue;
            }
            if (is_array($profile[$key]) && $profile[$key] === []) {
                $profile[$key] = new \stdClass();
            }
        }
        return $profile;
    }

    /**
     * Load the shipped JSON packs.
     *
     * A malformed pack is skipped rather than fatal — one bad file must not
     * take the whole fleet's scanning offline.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function shipped(): array
    {
        $dir = self::packDir();
        if (!is_dir($dir)) {
            return [];
        }

        $files = glob($dir . '/*.json') ?: [];
        sort($files);

        $out = [];
        foreach ($files as $file) {
            $raw = @file_get_contents($file);
            if ($raw === false) {
                continue;
            }
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                continue;
            }

            // A pack file may hold one profile or a list of them. Vendor packs
            // are naturally a list: each vendor needs its own match rule, and
            // one file per vendor would be dozens of near-empty files.
            $profiles = isset($decoded['name']) ? [$decoded] : $decoded;

            foreach ($profiles as $profile) {
                if (!is_array($profile) || !isset($profile['name'])) {
                    continue;
                }
                unset($profile['_comment']);
                $out[] = $profile;
            }
        }

        return $out;
    }

    /** @return array<int,array<string,mixed>> */
    public static function stored(): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => self::getTable(),
                'WHERE' => ['is_active' => 1, 'is_deleted' => 0],
                'ORDER' => 'priority ASC',
            ]) as $row
        ) {
            $prefixes = array_values(array_filter(array_map(
                'trim',
                preg_split('/[\s,]+/', (string) $row['sysobjectid_prefix']) ?: []
            )));

            $profile = [
                'name'     => (string) $row['name'],
                'priority' => (int) $row['priority'],
                'match'    => [],
            ];
            if ($prefixes !== []) {
                $profile['match']['sysobjectid_prefix'] = $prefixes;
            }
            if (trim((string) $row['sysdescr_regex']) !== '') {
                $profile['match']['sysdescr_regex'] = (string) $row['sysdescr_regex'];
            }
            if (trim((string) $row['itemtype_override']) !== '') {
                $profile['itemtype'] = (string) $row['itemtype_override'];
            }

            foreach (self::COLUMNS as $section => $column) {
                $map = self::parseOidLines((string) $row[$column], $section)['valid'];
                if ($map !== []) {
                    $profile[$section] = $map;
                }
            }

            $features = self::parseFeatures((string) $row['features']);
            if ($features !== []) {
                $profile['features'] = $features;
            }

            $out[] = $profile;
        }

        return $out;
    }

    /**
     * Parse `field = OID` lines.
     *
     * An empty OID is meaningful and preserved: it is how a vendor profile
     * suppresses a base OID that a device answers wrongly. There is no other
     * way to express "stop reading this".
     *
     * @return array{valid:array<string,string>,invalid:string[]}
     */
    public static function parseOidLines(string $raw, string $section): array
    {
        $allowed = self::FIELDS[$section] ?? [];
        $valid = [];
        $invalid = [];

        foreach (preg_split('/\r?\n/', trim($raw)) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (!str_contains($line, '=')) {
                $invalid[] = $line;
                continue;
            }

            [$field, $oid] = array_map('trim', explode('=', $line, 2));
            $field = strtolower($field);

            if (!in_array($field, $allowed, true)) {
                $invalid[] = $line;
                continue;
            }
            if ($oid !== '' && !self::isOid($oid)) {
                $invalid[] = $line;
                continue;
            }

            $valid[$field] = $oid;
        }

        return ['valid' => $valid, 'invalid' => $invalid];
    }

    /**
     * Parse `feature = true|false` lines.
     *
     * @return array<string,bool>
     */
    public static function parseFeatures(string $raw): array
    {
        $out = [];
        foreach (preg_split('/\r?\n/', trim($raw)) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || !str_contains($line, '=')) {
                continue;
            }
            [$name, $value] = array_map('trim', explode('=', $line, 2));
            $name = strtolower($name);
            if (!in_array($name, self::FEATURES, true)) {
                continue;
            }
            $out[$name] = filter_var($value, FILTER_VALIDATE_BOOLEAN);
        }
        return $out;
    }

    /**
     * OIDs are dotted decimal, nothing else.
     *
     * This is a security boundary as much as a correctness one: the value is
     * forwarded to the scanner and used to build SNMP requests, so it must not
     * be a place to smuggle arbitrary text.
     */
    public static function isOid(string $oid): bool
    {
        $oid = trim($oid);

        // A literal value, e.g. `manufacturer = =Cisco`. Used where a device
        // exposes no OID for a field but its sysObjectID identifies it.
        if (str_starts_with($oid, '=')) {
            return trim(substr($oid, 1)) !== '';
        }

        // Alternatives: several OIDs separated by "|", tried in order. Every
        // candidate must still be a real OID.
        foreach (explode('|', $oid) as $candidate) {
            if (!preg_match('/^\.?\d+(\.\d+)*$/', trim($candidate))) {
                return false;
            }
        }

        return true;
    }

    public static function formatOidLines(?string $stored): string
    {
        return (string) $stored;
    }

    public function prepareInputForAdd($input)
    {
        return $this->prepareNumbers($this->validateSections($input));
    }

    public function prepareInputForUpdate($input)
    {
        return $this->prepareNumbers($this->validateSections($input));
    }

    /** See Target::prepareNumbers(): '' is not a valid integer to MySQL. */
    private function prepareNumbers(array $input): array
    {
        if (array_key_exists('priority', $input)) {
            $raw = trim((string) $input['priority']);
            $input['priority'] = $raw === '' ? 100 : (int) $raw;
        }
        return $input;
    }

    private function validateSections($input)
    {
        foreach (self::COLUMNS as $section => $column) {
            if (!isset($input[$column])) {
                continue;
            }
            $parsed = self::parseOidLines((string) $input[$column], $section);
            if ($parsed['invalid'] !== []) {
                Session::addMessageAfterRedirect(
                    sprintf(
                        __('%1$s: ignored unrecognised line(s): %2$s', 'glpinetscan'),
                        $section,
                        htmlspecialchars(implode(' | ', $parsed['invalid']))
                    ),
                    false,
                    WARNING
                );
            }
            $lines = [];
            foreach ($parsed['valid'] as $field => $oid) {
                $lines[] = $field . ' = ' . $oid;
            }
            $input[$column] = implode("\n", $lines);
        }

        if (isset($input['features']) && is_array($input['features'])) {
            // The form posts only the boxes that are ticked, so an absent key
            // means "off" — but only for the features the form actually
            // offers, which is why the disabled set is written explicitly
            // rather than inferred later.
            $lines = [];
            foreach (self::FEATURES as $feature) {
                $lines[] = $feature . ' = '
                    . (in_array($feature, $input['features'], true) ? 'true' : 'false');
            }
            $input['features'] = implode("\n", $lines);
        }

        if (isset($input['sysobjectid_prefix'])) {
            $prefixes = [];
            foreach (preg_split('/[\s,]+/', (string) $input['sysobjectid_prefix']) ?: [] as $p) {
                $p = trim($p);
                if ($p !== '' && self::isOid($p)) {
                    $prefixes[] = $p;
                }
            }
            $input['sysobjectid_prefix'] = implode("\n", $prefixes);
        }

        return $input;
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Name') . "</td><td>";
        echo Html::input('name', ['value' => $this->fields['name'] ?? '']);
        echo "</td>";
        echo "<td>" . __('Priority', 'glpinetscan') . "</td><td>";
        echo Html::input('priority', [
            'type' => 'number',
            'value' => ($this->fields['priority'] ?? '') !== '' ? $this->fields['priority'] : 100,
        ]);
        echo "<div class='text-muted'>"
            . __('Applied in ascending order; higher wins. Shipped base is 0.', 'glpinetscan')
            . "</div>";
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('sysObjectID prefixes', 'glpinetscan') . "</td><td>";
        echo "<textarea class='form-control' name='sysobjectid_prefix' rows='2' "
            . "placeholder='1.3.6.1.4.1.9.1'>"
            . htmlspecialchars((string) ($this->fields['sysobjectid_prefix'] ?? '')) . "</textarea>";
        echo "<div class='text-muted'>"
            . __('Empty means this profile applies to every device.', 'glpinetscan')
            . "</div>";
        echo "</td>";
        echo "<td>" . __('sysDescr regex', 'glpinetscan') . "</td><td>";
        echo Html::input('sysdescr_regex', [
            'value' => $this->fields['sysdescr_regex'] ?? '',
        ]);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Force asset type', 'glpinetscan') . "</td><td>";
        Dropdown::showFromArray('itemtype_override', [
            ''            => __('Automatic', 'glpinetscan'),
            'Networking'  => 'Networking',
            'Printer'     => 'Printer',
            'Storage'     => 'Storage',
            'Power'       => 'Power',
            'Phone'       => 'Phone',
            'Video'       => 'Video',
            'KVM'         => 'KVM',
            'Computer'    => 'Computer',
            'Unmanaged'   => 'Unmanaged',
        ], ['value' => $this->fields['itemtype_override'] ?? '']);
        echo "</td>";
        echo "<td>" . __('Active') . "</td><td>";
        Dropdown::showYesNo('is_active', $this->fields['is_active'] ?? 1);
        echo "</td></tr>";

        // Feature toggles come before the OID boxes: switching a collector off
        // is the common adjustment, overriding a standard OID is the rare one.
        $enabled = self::parseFeatures((string) ($this->fields['features'] ?? ''));
        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Collectors', 'glpinetscan') . "</td><td colspan='3'>";
        foreach (self::FEATURES as $feature) {
            // Absent means enabled, which is what makes a new device work with
            // no configuration at all.
            $checked = ($enabled[$feature] ?? true) ? "checked='checked'" : '';
            echo "<label class='form-check form-check-inline'>";
            echo "<input type='checkbox' class='form-check-input' name='features[]' value='"
                . htmlspecialchars($feature) . "' $checked>";
            echo "<span class='form-check-label'>" . htmlspecialchars($feature) . '</span>';
            echo '</label>';
        }
        echo "<div class='text-muted mt-1'>"
            . __('Unticking one stops that table being walked for matching devices. Use it for hardware that answers a table with wrong data rather than no data.', 'glpinetscan')
            . '</div>';
        echo '</td></tr>';

        foreach (self::COLUMNS as $section => $column) {
            $isTopology = $section === 'topology';

            echo "<tr class='tab_bg_1'>";
            echo "<td>" . htmlspecialchars(ucfirst($section)) . " "
                . ($isTopology ? __('overrides', 'glpinetscan') : __('OIDs', 'glpinetscan')) . "</td>";
            echo "<td colspan='3'>";
            echo "<textarea class='form-control' name='" . $column . "' rows='4' "
                . "placeholder='" . ($isTopology
                    ? 'dot1d_fdb_port = 1.3.6.1.4.1.9.9.999.1'
                    : 'serial = 1.3.6.1.4.1.9.3.6.3.0')
                . "'>"
                . htmlspecialchars((string) ($this->fields[$column] ?? '')) . "</textarea>";

            if ($isTopology) {
                echo "<div class='text-muted mt-1'>"
                    . __('These already have standard defaults; set one only for a device that puts the table somewhere non-standard.', 'glpinetscan')
                    . '</div>';
            }

            echo "<div class='text-muted mt-1'>" . __('Fields:', 'glpinetscan') . ' '
                . htmlspecialchars(implode(', ', self::FIELDS[$section]))
                . "</div>";
            echo "</td></tr>";
        }

        echo "<tr class='tab_bg_1'><td colspan='4' class='text-muted'>";
        echo __(
            'A value may list several OIDs separated by "|", tried in order until one answers — use this when overriding a field a broader profile also sets, so the fallback is not lost. A value starting with "=" is a literal, e.g. "manufacturer = =Cisco". An empty value removes a field inherited from a lower-priority profile.',
            'glpinetscan'
        );
        echo '</td></tr>';

        $this->showFormButtons($options);

        return true;
    }

    public function rawSearchOptions()
    {
        $opts = [];
        $opts[] = ['id' => 'common', 'name' => self::getTypeName(2)];
        $opts[] = [
            'id' => '1', 'table' => self::getTable(), 'field' => 'name',
            'name' => __('Name'), 'datatype' => 'itemlink', 'massiveaction' => false,
        ];
        $opts[] = [
            'id' => '2', 'table' => self::getTable(), 'field' => 'id',
            'name' => __('ID'), 'datatype' => 'number',
        ];
        $opts[] = [
            'id' => '3', 'table' => self::getTable(), 'field' => 'priority',
            'name' => __('Priority', 'glpinetscan'), 'datatype' => 'number',
        ];
        $opts[] = [
            'id' => '4', 'table' => self::getTable(), 'field' => 'sysobjectid_prefix',
            'name' => __('sysObjectID prefixes', 'glpinetscan'), 'datatype' => 'text',
        ];
        $opts[] = [
            'id' => '5', 'table' => self::getTable(), 'field' => 'is_active',
            'name' => __('Active'), 'datatype' => 'bool',
        ];
        return $opts;
    }

    private static function packDir(): string
    {
        return \Plugin::getPhpDir('glpinetscan') . self::PACK_DIR;
    }
}
