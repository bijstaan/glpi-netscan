<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use CommonGLPI;
use Html;
use NetworkPort;
use Plugin;

/**
 * "Port map" tab: the switch, drawn.
 *
 * A faceplate answers in one glance what a forty-eight row table answers in a
 * minute of reading — which ports are live, which are shut, where a VLAN
 * actually reaches, and what is on the other end of each cable. Core has the
 * whole of that data already; what it has never had is a picture of it. Its
 * one faceplate feature, the model stencil, needs a photograph of that exact
 * model uploaded and every port zone placed on it by hand before it shows
 * anything at all, and once placed it shows link status and nothing else.
 *
 * This is drawn from the ports themselves, so it works on a device nobody has
 * ever prepared, and it is re-coloured by whichever of four questions is being
 * asked rather than committing to one.
 */
final class PortMapTab extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('Port map', 'glpinetscan');
    }

    public static function getIcon()
    {
        return 'ti ti-layout-grid';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || (int) $item->getID() <= 0) {
            return '';
        }

        $count = countElementsInTable(NetworkPort::getTable(), [
            'itemtype'   => $item->getType(),
            'items_id'   => $item->getID(),
            'is_deleted' => 0,
        ]);

        // No tab on a device with no ports, rather than an empty faceplate on
        // every appliance and firewall in the estate.
        return $count > 0 ? self::createTabEntry(self::getTypeName(), $count) : '';
    }

    public static function displayTabContentForItem(
        CommonGLPI $item,
        $tabnum = 1,
        $withtemplate = 0
    ) {
        if (!$item instanceof CommonDBTM || (int) $item->getID() <= 0) {
            return false;
        }

        self::show($item->getType(), (int) $item->getID());
        return true;
    }

    /**
     * The whole tab: a toolbar that outlives a refresh, and the map that does not.
     *
     * The split is deliberate. Refreshing replaces the map's markup wholesale
     * so that there is exactly one renderer and the browser never has to
     * reimplement any of it — which means anything the operator has set must
     * live outside the part being replaced, or it is thrown away every minute
     * on a device they are watching precisely because it is changing.
     */
    public static function show(string $itemtype, int $items_id): void
    {
        $rand = mt_rand();
        $id   = 'glpinetscan-portmap-' . $rand;
        $e    = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        $endpoint = Url::to('ajax/portmap.php');

        echo "<div class='glpinetscan-surface glpinetscan-portmap' id='" . $e($id) . "'"
            . " data-mode='status'"
            . " data-endpoint='" . $e($endpoint) . "'"
            . " data-itemtype='" . $e($itemtype) . "'"
            . " data-items-id='" . (int) $items_id . "'>";

        echo "<div class='card mb-3'>";
        self::toolbar();
        echo "<div class='card-body' data-portmap-content>";
        self::content($itemtype, $items_id);
        echo '</div></div></div>';

        self::script($id);
    }

    /** Colour-by switch, and the refresh controls. */
    private static function toolbar(): void
    {
        $modes = [
            'status' => __s('Status', 'glpinetscan'),
            'vlan'   => __s('VLAN', 'glpinetscan'),
            'speed'  => __s('Speed', 'glpinetscan'),
            'link'   => __s('Neighbour', 'glpinetscan'),
        ];

        echo "<div class='card-header d-flex flex-wrap gap-2 align-items-center'>";
        echo "<h3 class='card-title mb-0 me-auto'>" . __s('Port map', 'glpinetscan') . '</h3>';

        echo "<div class='btn-group btn-group-sm' role='group'"
            . " aria-label='" . __s('Colour ports by', 'glpinetscan') . "'>";
        foreach ($modes as $mode => $label) {
            $active = $mode === 'status' ? ' active' : '';
            echo "<button type='button' class='btn btn-outline-secondary$active'"
                . " data-portmap-mode='" . $mode . "'"
                . " aria-pressed='" . ($mode === 'status' ? 'true' : 'false') . "'>"
                . $label . '</button>';
        }
        echo '</div>';

        echo "<button type='button' class='btn btn-sm btn-outline-secondary' data-portmap-refresh>"
            . "<i class='ti ti-refresh' aria-hidden='true'></i> " . __s('Refresh', 'glpinetscan')
            . '</button>';

        // Auto-refresh is off until asked for: this is a page people leave
        // open on a second screen while they patch something, and a page that
        // polls whether or not anyone is watching it is a page that polls all
        // night.
        echo "<label class='form-check form-switch mb-0'>"
            . "<input class='form-check-input' type='checkbox' data-portmap-auto>"
            . "<span class='form-check-label'>" . __s('Auto', 'glpinetscan') . '</span></label>';

        echo '</div>';
    }

    /** Everything a refresh replaces. */
    public static function content(string $itemtype, int $items_id): void
    {
        $map = PortMap::forItem($itemtype, $items_id);

        self::header($map);

        if ($map['ports'] === []) {
            echo "<p class='text-muted mb-0'>"
                . __s('No ports are recorded on this asset.', 'glpinetscan') . '</p>';
            return;
        }

        self::legends($map);

        foreach ($map['groups'] as $group) {
            self::faceplate($group);
        }

        self::logical($map['logical']);
        self::detail($map);
        self::table($map);
    }

    /** Counts, freshness, and when this picture was drawn. */
    private static function header(array $map): void
    {
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
        $counts = $map['counts'];

        echo "<div class='d-flex flex-wrap gap-3 align-items-center mb-3 small text-muted'"
            . " data-portmap-summary>";

        printf(
            __s('%1$d ports · %2$d up · %3$d down · %4$d shut · %5$d with a known neighbour', 'glpinetscan'),
            $counts['total'],
            $counts['up'],
            $counts['down'],
            $counts['disabled'],
            $counts['connected']
        );

        $scanned = $map['scanned'];
        if ($scanned !== null && $scanned['last_inventory'] > 0) {
            echo '<span>';
            printf(
                __s('Last walked %s', 'glpinetscan'),
                $e(Html::convDateTime(date('Y-m-d H:i:s', $scanned['last_inventory'])))
            );
            if ($scanned['stale']) {
                // The faceplate is only ever as true as the last walk, and a
                // stale one being indistinguishable from a live one is how a
                // picture starts being trusted after it has stopped being right.
                echo " <span class='badge bg-warning text-white'>"
                    . __s('stale', 'glpinetscan') . '</span>';
            }
            echo '</span>';
        }

        echo "<span class='ms-auto' data-portmap-drawn>"
            . sprintf(__s('as of %s', 'glpinetscan'), $e(date('H:i:s')))
            . '</span>';

        echo '</div>';
    }

    /** One legend per mode; the stylesheet shows whichever is in force. */
    private static function legends(array $map): void
    {
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='glpinetscan-legends mb-3'>";

        $swatch = static function (string $attr, string $value, string $label) use ($e): void {
            echo "<span class='glpinetscan-legend-item'>"
                . "<span class='glpinetscan-swatch' $attr='" . $e($value) . "'></span>"
                . $e($label) . '</span>';
        };

        echo "<div class='glpinetscan-legend' data-legend='status'>";
        foreach (['up', 'down', 'disabled', 'dormant', 'unknown'] as $state) {
            $swatch('data-state', $state, PortMap::stateLabel($state));
        }
        echo '</div>';

        echo "<div class='glpinetscan-legend' data-legend='vlan'>";
        if ($map['vlans'] === []) {
            echo "<span class='text-muted'>"
                . __s('No VLAN membership has been collected from this device.', 'glpinetscan')
                . '</span>';
        } else {
            foreach ($map['vlans'] as $vlan) {
                $label = $vlan['name'] !== ''
                    ? sprintf('%d — %s', $vlan['tag'], $vlan['name'])
                    : (string) $vlan['tag'];
                $swatch('data-vlan', (string) $vlan['color'], $label);
            }
            $swatch('data-vlan', 'none', __('No untagged VLAN', 'glpinetscan'));
            echo "<span class='glpinetscan-legend-item'>"
                . "<span class='glpinetscan-swatch' data-vlan='none' data-trunk='1'></span>"
                . __s('Trunk (carries tagged VLANs)', 'glpinetscan') . '</span>';
        }
        echo '</div>';

        echo "<div class='glpinetscan-legend' data-legend='speed'>";
        foreach ([
            '10g'  => __('10 Gb/s and above', 'glpinetscan'),
            '1g'   => __('1 Gb/s', 'glpinetscan'),
            '100m' => __('100 Mb/s', 'glpinetscan'),
            '10m'  => __('Below 100 Mb/s', 'glpinetscan'),
            'none' => __('Not reported', 'glpinetscan'),
        ] as $band => $label) {
            $swatch('data-band', $band, $label);
        }
        echo '</div>';

        echo "<div class='glpinetscan-legend' data-legend='link'>";
        $swatch('data-link', '1', __('Neighbour identified', 'glpinetscan'));
        $swatch('data-link', '0', __('Nothing known on the other end', 'glpinetscan'));
        echo '</div>';

        echo '</div>';
    }

    /**
     * One module's ports, drawn as they are arranged on the box.
     *
     * The grid flows down then across, which is what puts port 1 above port 2
     * and port 47 above port 48 — the arrangement of the sockets themselves,
     * and the reason this can be read against the hardware rather than
     * translated.
     */
    private static function faceplate(array $group): void
    {
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='glpinetscan-module mb-3'>";
        echo "<div class='glpinetscan-module-label'>" . $e($group['label']) . '</div>';
        echo "<div class='glpinetscan-faceplate' style='--ns-rows:" . (int) $group['rows'] . "'>";

        foreach ($group['ports'] as $port) {
            self::tile($port);
        }

        echo '</div></div>';
    }

    /** Ports with no place on the front: aggregates, management, loopbacks. */
    private static function logical(array $ports): void
    {
        if ($ports === []) {
            return;
        }

        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='glpinetscan-module mb-3'>";
        echo "<div class='glpinetscan-module-label'>"
            . __s('Logical interfaces', 'glpinetscan') . '</div>';
        echo "<div class='glpinetscan-faceplate glpinetscan-faceplate-wide' style='--ns-rows:1'>";

        foreach ($ports as $port) {
            self::tile($port, true);
        }

        echo '</div></div>';
    }

    /**
     * One port.
     *
     * Every mode's answer is on the element at once, as data attributes, and
     * the stylesheet picks. Switching mode is then a single attribute change
     * on the container with no re-render and no request — which is what makes
     * flipping between "what is up" and "where does VLAN 20 go" a comparison
     * rather than two separate lookups.
     */
    private static function tile(array $port, bool $wide = false): void
    {
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        $native = null;
        foreach ($port['vlans'] as $vlan) {
            if (!$vlan['tagged']) {
                $native = $vlan;
                break;
            }
        }

        $summary = [$port['name'], PortMap::stateLabel($port['state'])];
        if ($port['speed_label'] !== '') {
            $summary[] = $port['speed_label'];
        }
        if ($native !== null) {
            $summary[] = sprintf(__('VLAN %s', 'glpinetscan'), $native['tag']);
        }
        if ($port['trunk']) {
            $summary[] = __('trunk', 'glpinetscan');
        }
        if ($port['peer'] !== null) {
            $summary[] = $port['peer']['name'];
        }
        if ($port['ifalias'] !== '') {
            $summary[] = $port['ifalias'];
        }
        $summary = implode(' · ', $summary);

        $label = $wide
            ? $port['name']
            : (string) ($port['position'] ?? $port['index']);

        echo "<button type='button' class='glpinetscan-port"
            . ($wide ? ' glpinetscan-port-wide' : '') . "'"
            . " data-port='" . (int) $port['id'] . "'"
            . " data-state='" . $e($port['state']) . "'"
            . " data-band='" . $e($port['speed_band']) . "'"
            . " data-vlan='" . ($port['vlan_color'] === null ? 'none' : (int) $port['vlan_color']) . "'"
            . " data-link='" . ($port['peer'] !== null ? '1' : '0') . "'"
            . " data-trunk='" . ($port['trunk'] ? '1' : '0') . "'"
            . " title='" . $e($summary) . "'"
            . " aria-label='" . $e($summary) . "'>";

        echo "<span class='glpinetscan-port-id'>" . $e($label) . '</span>';
        echo "<span class='glpinetscan-port-sub' data-for='vlan'>"
            . ($native !== null ? $e($native['tag']) : '·') . '</span>';
        echo "<span class='glpinetscan-port-sub' data-for='speed'>"
            . $e(self::shortSpeed($port['speed'])) . '</span>';

        echo '</button>';
    }

    /** A speed that has to fit inside a port tile. */
    private static function shortSpeed(int $bps): string
    {
        return match (true) {
            $bps >= 1000000000 => sprintf('%dG', (int) ($bps / 1000000000)),
            $bps >= 1000000    => sprintf('%dM', (int) ($bps / 1000000)),
            $bps > 0           => sprintf('%dk', (int) ($bps / 1000)),
            default            => '·',
        };
    }

    /**
     * The panel a clicked port fills.
     *
     * Every port's panel is rendered up front and hidden, rather than fetched
     * on click. The whole map is one query set already, so the detail is
     * paid for either way, and clicking through forty ports should not be
     * forty round trips.
     */
    private static function detail(array $map): void
    {
        echo "<div class='glpinetscan-detail' data-portmap-detail>";
        echo "<p class='text-muted mb-0' data-portmap-placeholder>"
            . __s('Select a port to see its VLANs, its neighbour and its counters.', 'glpinetscan')
            . '</p>';

        foreach ($map['ports'] as $port) {
            self::detailFor($port);
        }

        echo '</div>';
    }

    private static function detailFor(array $port): void
    {
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<div class='glpinetscan-detail-port' data-detail-for='" . (int) $port['id'] . "' hidden>";

        echo "<div class='d-flex flex-wrap align-items-center gap-2 mb-2'>";
        echo "<strong>" . $e($port['name']) . '</strong>';
        echo "<span class='badge " . self::stateBadge($port['state']) . "'>"
            . $e(PortMap::stateLabel($port['state'])) . '</span>';
        if ($port['trunk']) {
            echo "<span class='badge bg-secondary'>" . __s('Trunk', 'glpinetscan') . '</span>';
        }
        echo "<a class='ms-auto small' href='"
            . $e(NetworkPort::getFormURLWithID((int) $port['id'])) . "'>"
            . __s('Open port', 'glpinetscan') . '</a>';
        echo '</div>';

        echo "<div class='row g-2'>";

        self::field(__s('ifIndex', 'glpinetscan'), (string) $port['index']);
        self::field(__s('Description', 'glpinetscan'), $port['ifdescr']);
        self::field(__s('Alias', 'glpinetscan'), $port['ifalias']);
        self::field(__s('Speed', 'glpinetscan'), $port['speed_label']);
        self::field(__s('Duplex', 'glpinetscan'), $port['duplex']);
        self::field(__s('MAC', 'glpinetscan'), $port['mac']);
        self::field(__s('IP', 'glpinetscan'), implode(', ', $port['ips']));

        // Administrative state only when it disagrees with the operational
        // one — when they agree it is a second word for the same fact.
        if ($port['admin'] === 2) {
            self::field(
                __s('Administrative state', 'glpinetscan'),
                __('down — the port is shut at the device', 'glpinetscan')
            );
        }

        if ($port['aggregate'] !== null) {
            self::field(__s('Aggregated into', 'glpinetscan'), $port['aggregate']['name']);
        }
        if ($port['members'] !== []) {
            self::field(
                __s('Bundles', 'glpinetscan'),
                implode(', ', array_column($port['members'], 'name'))
            );
        }
        if ($port['iflastchange'] !== '') {
            self::field(__s('Last state change', 'glpinetscan'), $port['iflastchange']);
        }
        // Only on a port that is not up, where it is the answer to "since
        // when" — on a live port it is the last time it bounced, which is a
        // different and much less interesting fact.
        if ($port['state'] !== 'up' && $port['lastup'] !== '') {
            self::field(
                __s('Last up', 'glpinetscan'),
                Html::convDateTime($port['lastup'])
            );
        }

        echo '</div>';

        // --- VLANs ---
        echo "<div class='mt-2'><div class='text-muted small'>"
            . __s('VLANs', 'glpinetscan') . '</div>';
        if ($port['vlans'] === []) {
            echo "<span class='text-muted'>" . __s('None recorded', 'glpinetscan') . '</span>';
        } else {
            foreach ($port['vlans'] as $vlan) {
                $name = $vlan['name'] !== '' ? ' ' . $vlan['name'] : '';
                // Tagged and untagged are drawn differently because the
                // difference decides what an unconfigured device plugged in
                // here would actually reach.
                echo "<span class='badge me-1 " . ($vlan['tagged'] ? 'bg-secondary' : 'bg-blue') . "'>"
                    . $e($vlan['tag'] . $name)
                    . ' · ' . ($vlan['tagged'] ? __s('tagged', 'glpinetscan') : __s('untagged', 'glpinetscan'))
                    . '</span>';
            }
        }
        echo '</div>';

        // --- neighbour ---
        echo "<div class='mt-2'><div class='text-muted small'>"
            . __s('Neighbour', 'glpinetscan') . '</div>';
        if ($port['peer'] === null) {
            echo "<span class='text-muted'>"
                . __s('Nothing is recorded on the other end of this port.', 'glpinetscan') . '</span>';
        } else {
            $peer = $port['peer'];
            $name = $e($peer['name']);
            if ($peer['url'] !== '') {
                $name = "<a href='" . $e($peer['url']) . "'>" . $name . '</a>';
            }
            echo $name . " <span class='text-muted'>" . $e($peer['type_name']) . '</span>';
            if ($peer['port_name'] !== '') {
                echo ' · ' . $e($peer['port_name']);
            }
            if ($peer['port_mac'] !== '') {
                echo " <code>" . $e($peer['port_mac']) . '</code>';
            }
        }
        echo '</div>';

        // --- counters ---
        if ($port['metrics'] !== null) {
            $m = $port['metrics'];
            echo "<div class='mt-2'><div class='text-muted small'>"
                . sprintf(__s('Counters (%s)', 'glpinetscan'), $e($m['date'])) . '</div>';
            printf(
                '%s ↓ · %s ↑',
                $e(self::bytes($m['inbytes'])),
                $e(self::bytes($m['outbytes']))
            );
            if ($m['inerrors'] > 0 || $m['outerrors'] > 0) {
                // Errors are called out rather than listed alongside the byte
                // counts: a port passing traffic and taking errors is the one
                // shape this view can show that a status light cannot.
                echo " <span class='badge bg-danger'>"
                    . sprintf(
                        __s('%1$d in / %2$d out errors', 'glpinetscan'),
                        $m['inerrors'],
                        $m['outerrors']
                    )
                    . '</span>';
            }
            echo '</div>';
        }

        echo '</div>';
    }

    private static function field(string $label, string $value): void
    {
        if (trim($value) === '') {
            return;
        }
        echo "<div class='col-6 col-md-3'>";
        echo "<div class='text-muted small'>" . $label . '</div>';
        echo '<div>' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '</div>';
        echo '</div>';
    }

    private static function stateBadge(string $state): string
    {
        return match ($state) {
            'up'       => 'bg-success',
            'disabled' => 'bg-danger',
            'down'     => 'bg-secondary',
            default    => 'bg-warning',
        };
    }

    private static function bytes(int $bytes): string
    {
        $units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];
        $i = 0;
        $value = (float) $bytes;
        while ($value >= 1000 && $i < count($units) - 1) {
            $value /= 1000;
            $i++;
        }
        return sprintf($i === 0 ? '%d %s' : '%.1f %s', $value, $units[$i]);
    }

    /** The table the faceplate is a picture of. */
    private static function table(array $map): void
    {
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');

        echo "<details class='mt-3'><summary class='text-muted'>"
            . sprintf(__s('All %d ports as a table', 'glpinetscan'), count($map['ports']))
            . '</summary>';

        echo "<div class='table-responsive mt-2'><table class='table table-sm align-middle'><thead><tr>"
            . '<th>' . __s('Port', 'glpinetscan') . '</th>'
            . '<th>' . __s('Alias', 'glpinetscan') . '</th>'
            . '<th>' . __s('State', 'glpinetscan') . '</th>'
            . '<th>' . __s('Speed', 'glpinetscan') . '</th>'
            . '<th>' . __s('VLANs', 'glpinetscan') . '</th>'
            . '<th>' . __s('Neighbour', 'glpinetscan') . '</th>'
            . '<th>' . __s('MAC', 'glpinetscan') . '</th>'
            . '<th class="text-end">' . __s('Errors', 'glpinetscan') . '</th>'
            . '</tr></thead><tbody>';

        foreach ($map['ports'] as $port) {
            $vlans = [];
            foreach ($port['vlans'] as $vlan) {
                $vlans[] = $vlan['tag'] . ($vlan['tagged'] ? 'T' : '');
            }

            $peer = '';
            if ($port['peer'] !== null) {
                $peer = $port['peer']['url'] !== ''
                    ? "<a href='" . $e($port['peer']['url']) . "'>" . $e($port['peer']['name']) . '</a>'
                    : $e($port['peer']['name']);
                if ($port['peer']['port_name'] !== '') {
                    $peer .= " <span class='text-muted'>" . $e($port['peer']['port_name']) . '</span>';
                }
            }

            $errors = $port['metrics'] === null
                ? '—'
                : (int) $port['metrics']['inerrors'] + (int) $port['metrics']['outerrors'];

            echo '<tr>';
            echo '<td>' . $e($port['name']) . '</td>';
            echo "<td class='small'>" . $e($port['ifalias']) . '</td>';
            echo "<td><span class='badge " . self::stateBadge($port['state']) . "'>"
                . $e(PortMap::stateLabel($port['state'])) . '</span>'
                . ($port['trunk'] ? " <span class='badge bg-secondary'>"
                    . __s('trunk', 'glpinetscan') . '</span>' : '')
                . '</td>';
            echo '<td>' . $e($port['speed_label'] !== '' ? $port['speed_label'] : '—') . '</td>';
            echo "<td class='small'>" . $e(implode(', ', $vlans)) . '</td>';
            echo '<td>' . $peer . '</td>';
            echo "<td class='small'><code>" . $e($port['mac']) . '</code></td>';
            echo "<td class='text-end'>" . $e($errors) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table></div></details>';
    }

    /**
     * Mode switching, selection and refresh.
     *
     * Inline rather than a file shipped by `add_javascript`, for the reason
     * the settings page's check button is: one behaviour on one tab, against
     * markup only this tab produces, and `add_javascript` would ship it with
     * every page in GLPI for every user. Every listener is delegated from the
     * container, which is what lets a refresh replace the markup underneath
     * them without rebinding anything.
     */
    private static function script(string $id): void
    {
        // json_encode, not htmlspecialchars: both of these land inside JS
        // string literals, where HTML entities are not decoded — an escaped
        // apostrophe in a translation would print as `&#039;` — and where the
        // escaping that actually matters is the one that cannot end the
        // <script> element early. HEX_TAG does that; HEX_AMP keeps the
        // entities in the already-HTML-escaped message intact through the JS
        // string, so insertAdjacentHTML decodes them once, at the end.
        $flags  = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
        $id     = json_encode($id, $flags);
        $failed = json_encode(
            '<div class="alert alert-warning">'
            . htmlspecialchars(
                __('The port map could not be refreshed.', 'glpinetscan'),
                ENT_QUOTES,
                'UTF-8'
            )
            . '</div>',
            $flags
        );

        echo <<<HTML
<script>
(function () {
    const root = document.getElementById($id);
    if (!root || root.dataset.wired === '1') { return; }
    root.dataset.wired = '1';

    let selected = null;
    let timer = null;

    const show = function (portId) {
        const detail = root.querySelector('[data-portmap-detail]');
        if (!detail) { return; }

        detail.querySelectorAll('[data-detail-for]').forEach(function (block) {
            block.hidden = String(block.dataset.detailFor) !== String(portId);
        });
        root.querySelectorAll('.glpinetscan-port').forEach(function (tile) {
            tile.classList.toggle('selected', String(tile.dataset.port) === String(portId));
        });

        const placeholder = detail.querySelector('[data-portmap-placeholder]');
        const found = detail.querySelector('[data-detail-for="' + portId + '"]');
        if (placeholder) { placeholder.hidden = !!found; }
    };

    root.addEventListener('click', function (event) {
        const mode = event.target.closest('[data-portmap-mode]');
        if (mode) {
            root.dataset.mode = mode.dataset.portmapMode;
            root.querySelectorAll('[data-portmap-mode]').forEach(function (button) {
                const on = button === mode;
                button.classList.toggle('active', on);
                button.setAttribute('aria-pressed', on ? 'true' : 'false');
            });
            return;
        }

        const tile = event.target.closest('.glpinetscan-port');
        if (tile) {
            // Clicking the selected port again clears it, so the map can be
            // read without a panel under it.
            selected = String(tile.dataset.port) === String(selected) ? null : tile.dataset.port;
            show(selected);
            return;
        }

        if (event.target.closest('[data-portmap-refresh]')) {
            refresh();
        }
    });

    root.addEventListener('change', function (event) {
        const auto = event.target.closest('[data-portmap-auto]');
        if (!auto) { return; }

        if (timer) { window.clearInterval(timer); timer = null; }
        if (auto.checked) { timer = window.setInterval(refresh, 60000); }
    });

    function refresh() {
        const body = root.querySelector('[data-portmap-content]');
        const url = root.dataset.endpoint
            + '?itemtype=' + encodeURIComponent(root.dataset.itemtype)
            + '&items_id=' + encodeURIComponent(root.dataset.itemsId);

        body.classList.add('glpinetscan-refreshing');

        fetch(url, {
            credentials: 'same-origin',
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        }).then(function (response) {
            if (!response.ok) { throw new Error(response.status); }
            return response.text();
        }).then(function (html) {
            body.innerHTML = html;
            // The selection survives the replacement, because the port being
            // watched is the reason the page is being refreshed at all.
            if (selected) { show(selected); }
        }).catch(function () {
            body.insertAdjacentHTML('afterbegin', $failed);
        }).finally(function () {
            body.classList.remove('glpinetscan-refreshing');
        });
    }
})();
</script>
HTML;
    }
}
