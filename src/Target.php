<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use Dropdown;
use Html;
use SNMPCredential;

/**
 * A scan target: what to sweep, with which credentials, how often, and by which
 * scanner.
 *
 * Credentials are referenced by id into core's `glpi_snmpcredentials`. GLPI
 * already manages SNMP v1/v2c/v3 credentials in its own UI with GLPIKey
 * encryption behind them; a second store here would be one more place for a
 * community string to rot.
 */
final class Target extends CommonDBTM
{
    public static string $rightname = 'config';

    public bool $dohistory = true;

    public static function getTypeName($nb = 0)
    {
        return _n('Scan target', 'Scan targets', $nb, 'glpinetscan');
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
        return 'ti ti-network';
    }

    /**
     * Validate and normalise the range list before it is stored.
     *
     * Ranges are checked here rather than in the scanner because a malformed
     * range is an operator mistake that should surface while they are looking
     * at the form, not silently produce a scan that covers nothing.
     */
    public function prepareInputForAdd($input)
    {
        return $this->prepareNumbers($this->prepareRanges($input));
    }

    /**
     * The last few scans of this target.
     *
     * The numbers an operator actually needs to tune the two intervals: how
     * many addresses were probed, how many answered, and how many were worth
     * walking. A sweep that probes everything and walks nothing is the split
     * doing its job; one that walks everything every time means the change
     * signals are not reaching this hardware and the interval is carrying the
     * whole load.
     *
     * These rows were recorded from the first version of the plugin and shown
     * nowhere, which was tolerable when every scan did the same work and is not
     * now that they differ.
     */
    private function showRecentRuns(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ((int) $this->getID() <= 0) {
            return;
        }

        $rows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_glpinetscan_runs',
            'WHERE' => ['plugin_glpinetscan_targets_id' => $this->getID()],
            'ORDER' => ['id DESC'],
            'LIMIT' => 10,
        ]) as $row) {
            $rows[] = $row;
        }

        if ($rows === []) {
            return;
        }

        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='card mt-3'><div class='card-header'><h3 class='card-title'>"
            . __s('Recent scans', 'glpinetscan') . '</h3></div><div class="card-body">';
        echo "<div class='table-responsive'><table class='table table-sm'><thead><tr>"
            . '<th>' . __s('Started', 'glpinetscan') . '</th>'
            . '<th>' . __s('Answered', 'glpinetscan') . '</th>'
            . '<th>' . __s('Walked in full', 'glpinetscan') . '</th>'
            . '<th>' . __s('Failed', 'glpinetscan') . '</th>'
            . '<th>' . __s('Detail', 'glpinetscan') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $started = (int) $row['started_at'];
            echo '<tr><td>' . $e($started > 0 ? date('Y-m-d H:i:s', $started) : '') . '</td>';
            echo '<td>' . $e($row['discovered']) . '</td>';
            echo '<td>' . $e($row['inventoried']) . '</td>';
            echo '<td>' . $e($row['failed']) . '</td>';
            echo "<td class='small'>" . $e($row['message']) . '</td></tr>';
        }

        echo '</tbody></table></div></div></div>';
    }

    /**
     * How stale a full walk may get on this target, in seconds.
     *
     * Zero means the interval rule is off and only the change signals decide.
     */
    /**
     * Forget what was learned about this target's devices when its ranges move.
     *
     * The devices behind a changed range may not be the same devices, and a
     * stale "last walked at" would suppress exactly the full walk that would
     * have found that out.
     */
    public function post_updateItem($history = true)
    {
        if (in_array('ranges', $this->updates ?? [], true)) {
            Discovery::forgetTarget($this->getID());
        }

        parent::post_updateItem($history);
    }

    public function inventoryInterval(): int
    {
        return (int) ($this->fields['inventory_interval'] ?? 86400);
    }

    public function prepareInputForUpdate($input)
    {
        return $this->prepareNumbers($this->prepareRanges($input));
    }

    /**
     * Numeric columns, coerced and bounded.
     *
     * GLPI's getEmpty() seeds a new item's fields with empty strings, and MySQL
     * in strict mode rejects '' for an integer column — so a form submitted
     * without touching these dies with a SQL error rather than saving. Coercing
     * here means neither an untouched form nor a hand-crafted POST can produce
     * one.
     */
    private const NUMERIC_DEFAULTS = [
        'scan_interval' => [3600, 60, 604800],
        // How stale a full walk may get before one is forced anyway. Defaults
        // to a day: the change counters catch ports and hardware appearing or
        // disappearing, but nothing catches a port going down or a MAC moving,
        // so something has to bound how long that can go unnoticed.
        'inventory_interval' => [86400, 0, 2592000],
        'snmp_port'     => [161, 1, 65535],
        'timeout_ms'    => [2000, 100, 60000],
        'retries'       => [1, 0, 10],
        'concurrency'   => [32, 1, 512],
    ];

    private function prepareNumbers(array $input): array
    {
        foreach (self::NUMERIC_DEFAULTS as $field => [$default, $min, $max]) {
            if (!array_key_exists($field, $input)) {
                continue;
            }
            $raw = trim((string) $input[$field]);
            $value = $raw === '' ? $default : (int) $raw;
            $input[$field] = max($min, min($max, $value));
        }
        return $input;
    }

    private function prepareRanges($input)
    {
        if (isset($input['ranges'])) {
            $parsed = self::parseRanges((string) $input['ranges']);
            if ($parsed['invalid'] !== []) {
                \Session::addMessageAfterRedirect(
                    sprintf(
                        __('Ignored invalid range(s): %s', 'glpinetscan'),
                        htmlspecialchars(implode(', ', $parsed['invalid']))
                    ),
                    false,
                    WARNING
                );
            }
            $input['ranges'] = implode("\n", $parsed['valid']);
        }

        if (isset($input['snmpcredentials']) && is_array($input['snmpcredentials'])) {
            $ids = array_values(array_filter(array_map('intval', $input['snmpcredentials'])));
            $input['snmpcredentials'] = implode(',', $ids);
        }

        return $input;
    }

    /**
     * Split a newline/comma separated range list into valid and invalid parts.
     *
     * Accepts a single address, CIDR, or `start-end`.
     *
     * @return array{valid:string[],invalid:string[]}
     */
    public static function parseRanges(string $raw): array
    {
        $valid = [];
        $invalid = [];

        foreach (preg_split('/[\s,]+/', trim($raw)) ?: [] as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (self::isValidRange($entry)) {
                $valid[] = $entry;
            } else {
                $invalid[] = $entry;
            }
        }

        return ['valid' => array_values(array_unique($valid)), 'invalid' => $invalid];
    }

    private static function isValidRange(string $entry): bool
    {
        // CIDR
        if (str_contains($entry, '/')) {
            [$addr, $bits] = explode('/', $entry, 2);
            if (!filter_var($addr, FILTER_VALIDATE_IP)) {
                return false;
            }
            if (!ctype_digit($bits)) {
                return false;
            }
            $max = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 128 : 32;
            return (int) $bits >= 0 && (int) $bits <= $max;
        }

        // start-end
        if (str_contains($entry, '-')) {
            [$from, $to] = explode('-', $entry, 2);
            return (bool) filter_var(trim($from), FILTER_VALIDATE_IP)
                && (bool) filter_var(trim($to), FILTER_VALIDATE_IP);
        }

        return (bool) filter_var($entry, FILTER_VALIDATE_IP);
    }

    /** @return string[] */
    public function rangeList(): array
    {
        return self::parseRanges((string) ($this->fields['ranges'] ?? ''))['valid'];
    }

    /** @return int[] */
    /**
     * The credential this target may be *written* with, if any.
     *
     * Separate from the read credentials on purpose. Reusing them would mean a
     * community string that happened to be read-write silently made every
     * device it reached controllable, which is precisely the accident this
     * plugin should not enable. Zero — the default — means this target cannot
     * be controlled at all.
     */
    public function writeCredentialID(): int
    {
        return (int) ($this->fields['write_snmpcredentials_id'] ?? 0);
    }

    /**
     * The decrypted write credential, in the scanner's wire format.
     *
     * @return array<string,mixed>|null
     */
    public function writeCredential(): ?array
    {
        $id = $this->writeCredentialID();
        if ($id <= 0) {
            return null;
        }

        $creds = Job::credentials([$id]);

        return $creds[0] ?? null;
    }

    public function credentialIds(): array
    {
        $raw = (string) ($this->fields['snmpcredentials'] ?? '');
        return array_values(array_filter(array_map('intval', explode(',', $raw))));
    }

    /**
     * Does this target's range list cover an address?
     *
     * Used to reject inventory for addresses a scanner was never asked to
     * look at. Comparison is done on packed binary addresses so that IPv4 and
     * IPv6 share one code path and a textual near-miss cannot pass.
     */
    public function coversAddress(string $ip): bool
    {
        $needle = @inet_pton(trim($ip));
        if ($needle === false) {
            return false;
        }

        foreach ($this->rangeList() as $range) {
            if (self::rangeCovers($range, $needle)) {
                return true;
            }
        }

        return false;
    }

    private static function rangeCovers(string $range, string $needle): bool
    {
        if (str_contains($range, '/')) {
            [$addr, $bits] = explode('/', $range, 2);
            $base = @inet_pton($addr);
            if ($base === false || strlen($base) !== strlen($needle)) {
                return false;
            }
            return self::inPrefix($needle, $base, (int) $bits);
        }

        if (str_contains($range, '-')) {
            [$from, $to] = array_map('trim', explode('-', $range, 2));
            $lo = @inet_pton($from);
            $hi = @inet_pton($to);
            if ($lo === false || $hi === false
                || strlen($lo) !== strlen($needle) || strlen($hi) !== strlen($needle)) {
                return false;
            }
            // Written low..high regardless of how the operator typed it.
            if (strcmp($lo, $hi) > 0) {
                [$lo, $hi] = [$hi, $lo];
            }
            return strcmp($needle, $lo) >= 0 && strcmp($needle, $hi) <= 0;
        }

        $single = @inet_pton($range);
        return $single !== false && $single === $needle;
    }

    /** Compare the first $bits bits of two packed addresses. */
    private static function inPrefix(string $needle, string $base, int $bits): bool
    {
        $len = strlen($base) * 8;
        if ($bits < 0 || $bits > $len) {
            return false;
        }

        $wholeBytes = intdiv($bits, 8);
        if ($wholeBytes > 0 && strncmp($needle, $base, $wholeBytes) !== 0) {
            return false;
        }

        $remainder = $bits % 8;
        if ($remainder === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainder) & 0xFF;
        return (ord($needle[$wholeBytes]) & $mask) === (ord($base[$wholeBytes]) & $mask);
    }

    /** Field value with a fallback for both null and the empty string. */
    private function value(string $field, $default)
    {
        $v = $this->fields[$field] ?? null;
        return ($v === null || $v === '') ? $default : $v;
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Name') . "</td><td>";
        echo Html::input('name', ['value' => $this->value('name', '')]);
        echo "</td>";
        echo "<td>" . __('Active') . "</td><td>";
        Dropdown::showYesNo('is_active', $this->value('is_active', 1));
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Ranges', 'glpinetscan') . "</td>";
        echo "<td colspan='3'>";
        echo "<textarea class='form-control' name='ranges' rows='4' "
            . "placeholder='10.0.0.0/24&#10;192.168.1.5&#10;172.16.0.10-172.16.0.50'>"
            . htmlspecialchars((string) ($this->fields['ranges'] ?? '')) . "</textarea>";
        echo "<div class='text-muted mt-1'>"
            . __('One per line: CIDR, single address, or start-end.', 'glpinetscan')
            . "</div>";
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('SNMP credentials', 'glpinetscan') . "</td>";
        echo "<td colspan='3'>";
        self::showCredentialPicker($this->credentialIds());
        echo "<div class='text-muted mt-1'>"
            . __('Tried in order until one answers. Managed under Setup > SNMP credentials.', 'glpinetscan')
            . "</div>";
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Scanner', 'glpinetscan') . "</td><td>";
        Scanner::dropdown([
            'name'  => 'plugin_glpinetscan_scanners_id',
            'value' => $this->fields['plugin_glpinetscan_scanners_id'] ?? 0,
        ]);
        echo "</td>";
        echo "<td>" . __('Discovery interval (seconds)', 'glpinetscan') . "</td><td>";
        echo Html::input('scan_interval', [
            'type'  => 'number',
            'min'   => 60,
            'value' => $this->value('scan_interval', 3600),
        ]);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Write credential (device control)', 'glpinetscan') . "</td><td>";
        SNMPCredential::dropdown([
            'name'   => 'write_snmpcredentials_id',
            'value'  => $this->fields['write_snmpcredentials_id'] ?? 0,
            'display_emptychoice' => true,
            'emptylabel' => __('None — this target cannot be controlled', 'glpinetscan'),
        ]);
        echo "<div class='form-text'>"
            . __s(
                'Deliberately separate from the credentials used to read. Leave it empty and nothing on this target can be switched, whatever else is enabled. Setting it does not by itself allow control: device control must also be switched on under Setup > Network scanning.',
                'glpinetscan'
            )
            . '</div>';
        echo "</td><td></td><td></td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Full inventory at least every (seconds)', 'glpinetscan') . "</td><td>";
        echo Html::input('inventory_interval', [
            'type'  => 'number',
            'min'   => 0,
            'value' => $this->value('inventory_interval', 86400),
        ]);
        echo "<div class='form-text'>"
            . __s(
                'Every discovery pass probes the whole range cheaply. A full walk is far more expensive, so one is only done when a device is new, has rebooted, reports that its interfaces or hardware changed — or has not been walked for this long. Zero leaves only the change signals, which suits appliances that never change and not a switch estate.',
                'glpinetscan'
            )
            . '</div>';
        echo "</td><td></td><td></td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('SNMP port', 'glpinetscan') . "</td><td>";
        echo Html::input('snmp_port', [
            'type' => 'number', 'min' => 1, 'max' => 65535,
            'value' => $this->value('snmp_port', 161),
        ]);
        echo "</td>";
        echo "<td>" . __('Timeout (ms)', 'glpinetscan') . "</td><td>";
        echo Html::input('timeout_ms', [
            'type' => 'number', 'min' => 100, 'max' => 60000,
            'value' => $this->value('timeout_ms', 2000),
        ]);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Retries', 'glpinetscan') . "</td><td>";
        echo Html::input('retries', [
            'type' => 'number', 'min' => 0, 'max' => 10,
            'value' => $this->value('retries', 1),
        ]);
        echo "</td>";
        echo "<td>" . __('Concurrency', 'glpinetscan') . "</td><td>";
        echo Html::input('concurrency', [
            'type' => 'number', 'min' => 1, 'max' => 512,
            'value' => $this->value('concurrency', 32),
        ]);
        echo "</td></tr>";

        $this->showFormButtons($options);

        $this->showRecentRuns();

        return true;
    }

    /** Multi-select over core's SNMP credentials. */
    public static function showCredentialPicker(array $selected): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $values = [];
        foreach (
            $DB->request([
                'FROM'  => SNMPCredential::getTable(),
                'WHERE' => ['is_deleted' => 0],
                'ORDER' => 'name ASC',
            ]) as $row
        ) {
            $values[(int) $row['id']] = sprintf(
                '%s (v%s)',
                $row['name'] !== '' ? $row['name'] : ('#' . $row['id']),
                $row['snmpversion']
            );
        }

        if ($values === []) {
            echo "<em>" . __('No SNMP credentials defined yet.', 'glpinetscan') . "</em>";
            return;
        }

        Dropdown::showFromArray('snmpcredentials', $values, [
            'values'   => $selected,
            'multiple' => true,
            'width'    => '100%',
        ]);
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
            'id' => '3', 'table' => self::getTable(), 'field' => 'ranges',
            'name' => __('Ranges', 'glpinetscan'), 'datatype' => 'text',
        ];
        $opts[] = [
            'id' => '4', 'table' => Scanner::getTable(), 'field' => 'name',
            'name' => __('Scanner', 'glpinetscan'), 'datatype' => 'dropdown',
        ];
        $opts[] = [
            'id' => '5', 'table' => self::getTable(), 'field' => 'scan_interval',
            'name' => __('Interval (seconds)', 'glpinetscan'), 'datatype' => 'number',
        ];
        $opts[] = [
            'id' => '6', 'table' => self::getTable(), 'field' => 'is_active',
            'name' => __('Active'), 'datatype' => 'bool',
        ];
        $opts[] = [
            'id' => '80', 'table' => 'glpi_entities', 'field' => 'completename',
            'name' => __('Entity'), 'datatype' => 'dropdown',
        ];
        return $opts;
    }
}
