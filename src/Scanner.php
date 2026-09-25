<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use DBmysql;

/**
 * An enrolled scanner.
 *
 * The token is a bearer credential and is stored only as a SHA-256 digest, so
 * a database read cannot be replayed against the API. It is shown exactly once,
 * in the enrollment response — there is no path to recover it afterwards, only
 * to revoke the scanner and enroll again.
 */
final class Scanner extends CommonDBTM
{
    public static string $rightname = 'config';

    public bool $dohistory = true;

    public static function getTypeName($nb = 0)
    {
        return _n('Scanner', 'Scanners', $nb, 'glpinetscan');
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
        return 'ti ti-radar';
    }

    /**
     * Exchange a valid enrollment secret for a fresh scanner token.
     *
     * @return array{token:string,scanner:self}|null Null when the secret is not valid.
     */
    public static function enroll(
        string $secret,
        string $hostname,
        string $platform,
        string $agentVersion,
        string $address
    ): ?array {
        $matched = Secret::match($secret);
        if ($matched === null) {
            return null;
        }

        $token = bin2hex(random_bytes(32));

        $scanner = new self();
        $id = $scanner->add([
            'name'          => $hostname !== '' ? $hostname : __('Unnamed scanner', 'glpinetscan'),
            'token_hash'    => self::hashToken($token),
            'hostname'      => $hostname,
            'platform'      => $platform,
            'agent_version' => $agentVersion,
            'entities_id'   => $matched['entities_id'],
            'last_seen'     => time(),
            'last_address'  => $address,
            'is_active'     => 1,
        ]);

        if (!$id || !$scanner->getFromDB($id)) {
            return null;
        }

        // Lets an operator see which secret is actually in use, and which was
        // issued and never touched.
        Secret::countEnrolment((int) $matched['id']);

        // Publish it on Administration > Inventory > Agents, where an admin
        // looks to see what is collecting for them.
        AgentLink::sync($scanner, $agentVersion);
        $scanner->getFromDB($scanner->getID());

        return ['token' => $token, 'scanner' => $scanner];
    }

    /**
     * Resolve a presented token to its scanner.
     *
     * The lookup is by digest, so the plaintext token never has to be compared
     * row by row — and a revoked or soft-deleted scanner resolves to nothing,
     * which is how `scanner_invalid` gets raised on the next poll.
     */
    public static function authenticate(string $token): ?self
    {
        $token = trim($token);
        if ($token === '') {
            return null;
        }

        $scanner = new self();
        $ok = $scanner->getFromDBByCrit([
            'token_hash' => self::hashToken($token),
            'is_active'  => 1,
            'is_deleted' => 0,
        ]);

        return $ok ? $scanner : null;
    }

    /** Record that we heard from this scanner. */
    public function touch(string $address, string $agentVersion = '', string $arch = ''): void
    {
        /** @var DBmysql $DB */
        global $DB;

        $fields = ['last_seen' => time(), 'last_address' => $address];
        if ($agentVersion !== '') {
            $fields['agent_version'] = $agentVersion;
        }
        // Recorded on every poll rather than only at enrolment: a host rebuilt
        // onto different hardware keeps its token, and self-update matching it
        // against a stale architecture would offer a package that cannot run.
        if ($arch !== '') {
            $fields['arch'] = $arch;
        }

        // Written straight through rather than via update(): a heartbeat every
        // poll must not generate a history entry per scanner per minute.
        $DB->update(self::getTable(), $fields, ['id' => $this->getID()]);

        // Keep GLPI's agent row current too, so last_contact there means the
        // same thing as last_seen here rather than drifting apart.
        $this->getFromDB($this->getID());
        AgentLink::sync($this, $agentVersion);
    }

    /** Route what the new scanner imports into its entity. */
    public function post_addItem()
    {
        EntityRule::sync($this->fields);
        parent::post_addItem();
    }

    /** Keep the entity rule in step when the scanner moves entity. */
    public function post_updateItem($history = true)
    {
        if (array_intersect(['entities_id', 'is_recursive', 'name'], $this->updates) !== []) {
            EntityRule::sync($this->fields);
        }
        parent::post_updateItem($history);
    }

    /** Remove the GLPI agent row and the entity rule alongside the scanner. */
    public function post_purgeItem()
    {
        AgentLink::forget($this);
        EntityRule::drop($this->getID());
        parent::post_purgeItem();
    }

    public function isStale(): bool
    {
        $last = (int) $this->fields['last_seen'];
        return $last === 0 || (time() - $last) > Settings::get('stale_after');
    }

    private static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    public function rawSearchOptions()
    {
        $opts = [];

        $opts[] = ['id' => 'common', 'name' => self::getTypeName(2)];

        $opts[] = [
            'id'            => '1',
            'table'         => self::getTable(),
            'field'         => 'name',
            'name'          => __('Name'),
            'datatype'      => 'itemlink',
            'massiveaction' => false,
        ];
        $opts[] = [
            'id'       => '2',
            'table'    => self::getTable(),
            'field'    => 'id',
            'name'     => __('ID'),
            'datatype' => 'number',
        ];
        $opts[] = [
            'id'       => '3',
            'table'    => self::getTable(),
            'field'    => 'hostname',
            'name'     => __('Hostname', 'glpinetscan'),
            'datatype' => 'string',
        ];
        $opts[] = [
            'id'       => '4',
            'table'    => self::getTable(),
            'field'    => 'platform',
            'name'     => __('Platform', 'glpinetscan'),
            'datatype' => 'string',
        ];
        $opts[] = [
            'id'       => '5',
            'table'    => self::getTable(),
            'field'    => 'agent_version',
            'name'     => __('Version'),
            'datatype' => 'string',
        ];
        $opts[] = [
            'id'       => '6',
            'table'    => self::getTable(),
            'field'    => 'last_address',
            'name'     => __('Last address', 'glpinetscan'),
            'datatype' => 'string',
        ];
        $opts[] = [
            'id'       => '7',
            'table'    => self::getTable(),
            'field'    => 'is_active',
            'name'     => __('Active'),
            'datatype' => 'bool',
        ];
        $opts[] = [
            'id'       => '8',
            'table'    => 'glpi_agents',
            'field'    => 'name',
            'name'     => __('Inventory agent', 'glpinetscan'),
            'datatype' => 'dropdown',
        ];
        $opts[] = [
            'id'       => '80',
            'table'    => 'glpi_entities',
            'field'    => 'completename',
            'name'     => __('Entity'),
            'datatype' => 'dropdown',
        ];

        return $opts;
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $this->showFormHeader($options);

        $stale = $ID > 0 && $this->isStale();

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Name') . "</td><td>";
        echo \Html::input('name', ['value' => $this->fields['name'] ?? '']);
        echo "</td>";
        echo "<td>" . __('Active') . "</td><td>";
        \Dropdown::showYesNo('is_active', $this->fields['is_active'] ?? 1);
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Hostname', 'glpinetscan') . "</td>";
        echo "<td>" . htmlspecialchars((string) ($this->fields['hostname'] ?? '')) . "</td>";
        echo "<td>" . __('Platform', 'glpinetscan') . "</td>";
        echo "<td>" . htmlspecialchars((string) ($this->fields['platform'] ?? '')) . "</td>";
        echo "</tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Version') . "</td>";
        echo "<td>" . htmlspecialchars((string) ($this->fields['agent_version'] ?? '')) . "</td>";
        echo "<td>" . __('Last seen', 'glpinetscan') . "</td>";
        echo "<td>";
        $last = (int) ($this->fields['last_seen'] ?? 0);
        if ($last > 0) {
            echo \Html::convDateTime(date('Y-m-d H:i:s', $last));
            if ($stale) {
                echo " <span class='badge bg-warning text-white'>" . __('stale', 'glpinetscan') . "</span>";
            }
        } else {
            echo '—';
        }
        echo "</td></tr>";

        echo "<tr class='tab_bg_1'>";
        echo "<td>" . __('Last address', 'glpinetscan') . "</td>";
        echo "<td colspan='3'>" . htmlspecialchars((string) ($this->fields['last_address'] ?? '')) . "</td>";
        echo "</tr>";

        echo "<tr class='tab_bg_1'><td colspan='4' class='text-muted'>";
        echo __(
            'The scanner token is shown only in the enrollment response and cannot be recovered. To replace it, deactivate this scanner and enroll again.',
            'glpinetscan'
        );
        echo "</td></tr>";

        $this->showFormButtons($options);

        return true;
    }
}
