<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpinetscan\Health;
use GlpiPlugin\Glpinetscan\Menu;
use GlpiPlugin\Glpinetscan\OidProfile;
use GlpiPlugin\Glpinetscan\Secret;
use GlpiPlugin\Glpinetscan\Settings;
use GlpiPlugin\Glpinetscan\Update;

Session::checkRight('config', READ);

// GLPI 11's CheckCsrfListener validated and consumed the token before this
// page ran, so there is no second check here.
/**
 * Which settings belong to which card, and therefore to which Save button.
 *
 * This page has four independent settings cards, each its own form with its own
 * Save. They all used to post into one handler that rebuilt *every* setting
 * from `$_POST` — and a checkbox that is not in the submitted form is
 * indistinguishable from one that was unticked, so saving any card switched off
 * every checkbox in the other three and reset their numbers to defaults.
 *
 * The damage was not cosmetic: pressing Save under "Device control" turned off
 * `require_tls`, which is what stops SNMP write credentials being handed out
 * over plaintext. Nothing errored and the card you were looking at saved
 * correctly, so the only way to notice was to go back and read the others.
 *
 * Each form now names its section and only that section's keys are written.
 */
const SETTING_SECTIONS = [
    'api'     => ['require_tls', 'allow_off_target', 'record_outlet_count', 'pdu_in_asset_types', 'poll_interval', 'stale_after'],
    'control' => ['allow_control'],
    'traps'   => ['allow_traps', 'trap_port'],
    'updates' => ['update_enabled', 'rollout_percent'],
];

/** Settings that are checkboxes: absent means unticked, but only within their own form. */
const SETTING_FLAGS = [
    'require_tls', 'allow_off_target', 'record_outlet_count', 'pdu_in_asset_types',
    'update_enabled', 'allow_control', 'allow_traps',
];

if (!empty($_POST['update'])) {
    Session::checkRight('config', UPDATE);

    $section = (string) ($_POST['section'] ?? '');
    $keys    = SETTING_SECTIONS[$section] ?? null;

    if ($keys === null) {
        // A submission that does not say which card it came from cannot be
        // applied safely, because the checkboxes it omits are unreadable. Far
        // better to refuse than to guess and silently disable something.
        Session::addMessageAfterRedirect(
            __s('That form did not say which settings it was saving; nothing was changed.', 'glpinetscan'),
            false,
            ERROR
        );
        Html::back();
    }

    $values = [];
    foreach ($keys as $key) {
        $values[$key] = in_array($key, SETTING_FLAGS, true)
            ? (!empty($_POST[$key]) ? 1 : 0)
            : (int) ($_POST[$key] ?? Settings::DEFAULTS[$key]);
    }

    Settings::save($values);
    Session::addMessageAfterRedirect(__s('Settings saved.', 'glpinetscan'));
    Html::back();
}

if (!empty($_POST['add_secret'])) {
    Session::checkRight('config', UPDATE);
    $name = trim((string) ($_POST['secret_name'] ?? ''));
    if ($name !== '') {
        Secret::create($name, (int) ($_POST['secret_entity'] ?? 0));
        Session::addMessageAfterRedirect(__s('Enrollment secret created.', 'glpinetscan'));
    }
    // Post/redirect/get rather than Html::back(): the page has several forms
    // and a back() lands on whichever one was submitted last.
    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['publish_package'])) {
    Session::checkRight('config', UPDATE);
    $error = Update::publish([
        'version'  => $_POST['pkg_version'] ?? '',
        'platform' => $_POST['pkg_platform'] ?? '',
        'arch'     => $_POST['pkg_arch'] ?? '',
        'url'      => $_POST['pkg_url'] ?? '',
        'sha256'   => $_POST['pkg_sha256'] ?? '',
        'size'     => $_POST['pkg_size'] ?? 0,
    ]);
    if ($error !== null) {
        Session::addMessageAfterRedirect($error, false, ERROR);
    } else {
        Session::addMessageAfterRedirect(__('Package published.', 'glpinetscan'));
    }
    Html::back();
}

if (!empty($_POST['withdraw_package'])) {
    Session::checkRight('config', UPDATE);
    Update::withdraw((int) $_POST['withdraw_package']);
    Html::back();
}

if (!empty($_POST['revoke_secret'])) {
    Session::checkRight('config', UPDATE);
    Secret::revoke((int) $_POST['revoke_secret']);
    Session::addMessageAfterRedirect(
        __s('Secret revoked. Already-enrolled scanners keep working.', 'glpinetscan')
    );
    Html::redirect($_SERVER['REQUEST_URI']);
}

Html::header(
    __('Network scanning', 'glpinetscan'),
    $_SERVER['PHP_SELF'],
    'config',
    // Breadcrumbed under Plugins: this page is reached from the Plugins list
    // rather than from a Setup-menu entry of its own.
    'plugins'
);

$cfg  = Settings::all();
$e    = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
$csrf = Session::getNewCSRFToken();

// Read-only visitors keep the page but lose every control.
//
// READ opens this page and UPDATE changes it, and the two are separately
// grantable — so a profile can legitimately arrive here able to look and not
// touch. Offering the buttons anyway and answering with an access-denied page
// tells them nothing they could have known beforehand.
$can_edit = Session::haveRight('config', UPDATE);

// Dark-palette helper-text rules used to be an inline <style> here, as a
// property override on `.text-muted` — which core's own `!important`
// declaration silently beats, so it never worked. The working fix (redefine
// the --tblr-muted / --tblr-secondary-color VARIABLES inside the plugin
// scope) now ships in public/css/netscan.css, keyed to the
// `glpinetscan-surface` marker this wrapper carries.
echo "<div class='container-fluid glpinetscan-config glpinetscan-surface' style='max-width:960px'>";

if (!$can_edit) {
    echo "<div class='alert alert-info py-2'>"
       . __('Read only: you can see this configuration but not change it.', 'glpinetscan')
       . '</div>';
}

// Warranty lookups live on a page of their own: seven vendors with up to eight
// credentials each is more configuration than everything on this page put
// together, and it is a separate decision — nothing leaves the building until
// somebody makes it.
echo "<div class='card mb-3'><div class='card-body d-flex justify-content-between align-items-center'>";
echo "<div>";
echo "<strong>" . __s('Warranty lookups', 'glpinetscan') . "</strong><br>";
echo "<span class='text-muted'>"
   . __s('Ask Cisco, HPE, Fortinet, Dell, HP, Lenovo and Apple about the serial numbers the '
      . 'scanner found, and write what they say onto each asset\'s Financial information tab.', 'glpinetscan')
   . "</span>";
echo "</div>";
echo "<a class='btn btn-outline-primary' href='"
   . Plugin::getWebDir('glpinetscan') . "/front/warranty.php'>"
   . __s('Configure', 'glpinetscan') . "</a>";
echo "</div></div>";

// --- Readiness ---
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
    . __s('Readiness', 'glpinetscan') . '</h3></div><div class="card-body">';
echo '<p class="text-muted">'
    . __s(
        'Each of these is a way a scan can appear to succeed while importing nothing. Both of the first two are GLPI settings rather than plugin settings.',
        'glpinetscan'
    )
    . '</p>';
echo "<ul class='list-unstyled mb-0'>";
foreach (Health::checks() as $check) {
    [$icon, $class] = match ($check['state']) {
        Health::OK    => ['ti ti-circle-check', 'text-success'],
        Health::WARN  => ['ti ti-alert-triangle', 'text-warning'],
        default       => ['ti ti-circle-x', 'text-danger'],
    };
    echo "<li class='mb-2'>";
    echo "<i class='" . $icon . ' ' . $class . " me-1'></i>";
    echo '<strong>' . $e($check['title']) . '</strong>';
    if ($check['detail'] !== '') {
        echo "<div class='text-muted ms-4'>" . $e($check['detail']) . '</div>';
    }
    echo '</li>';
}
echo '</ul></div></div>';

// --- Settings ---
echo "<form method='post'>";
echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
echo Html::hidden('section', ['value' => 'api']);
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
    . __s('Scanner API', 'glpinetscan') . '</h3></div><div class="card-body">';

$tls = $cfg['require_tls'] ? "checked='checked'" : '';
echo "<label class='form-check'><input type='checkbox' class='form-check-input' name='require_tls' value='1' $tls>";
echo "<span class='form-check-label'>" . __s('Require TLS for scanner requests', 'glpinetscan') . '</span></label>';
echo "<p class='text-muted'>"
    . __s(
        'The job response carries decrypted SNMP community strings and v3 passphrases. Serving this API over plain HTTP hands them to anyone on the path.',
        'glpinetscan'
    )
    . '</p>';

$off = $cfg['allow_off_target'] ? "checked='checked'" : '';
echo "<label class='form-check'><input type='checkbox' class='form-check-input' name='allow_off_target' value='1' $off>";
echo "<span class='form-check-label'>"
    . __s('Accept inventory for addresses outside the target ranges', 'glpinetscan') . '</span></label>';
echo "<p class='text-muted'>"
    . __s(
        'Leave off unless you have a reason. With it off, a scanner can only report on addresses it was actually asked to scan, so a compromised scanner cannot rewrite arbitrary assets.',
        'glpinetscan'
    )
    . '</p>';

$outlets = $cfg['record_outlet_count'] ? "checked='checked'" : '';
echo "<label class='form-check'><input type='checkbox' class='form-check-input' name='record_outlet_count' value='1' $outlets>";
echo "<span class='form-check-label'>"
    . __s('Record the discovered outlet count on PDU assets', 'glpinetscan') . '</span></label>';
echo "<p class='text-muted'>"
    . __s(
        'Adds a GLPI plug entry named "Outlet (discovered)" with the number of sockets found. SNMP does not report the physical connector standard, so the plug is named neutrally rather than guessed at.',
        'glpinetscan'
    )
    . '</p>';

$pduAsset = $cfg['pdu_in_asset_types'] ? "checked='checked'" : '';
echo "<label class='form-check'><input type='checkbox' class='form-check-input' name='pdu_in_asset_types' value='1' $pduAsset>";
echo "<span class='form-check-label'>"
    . __s('Let switch topology resolve to UPS and PDU assets', 'glpinetscan') . '</span></label>';
echo "<p class='text-muted'>"
    . __s(
        'GLPI matches the MAC addresses in a switch\'s forwarding table only against its asset_types list, which does not include PDU — so a switch port facing a UPS links to an "Unmanaged" placeholder instead of the real asset. Enabling this adds PDU to that list. It is off by default because asset_types is consulted widely across core, so turn it on deliberately and check your asset lists afterwards.',
        'glpinetscan'
    )
    . '</p>';

echo "<div class='row'>";
echo "<div class='col-md-6 mb-3'><label class='form-label'>"
    . __s('Poll interval (seconds)', 'glpinetscan') . '</label>'
    . "<input type='number' min='10' max='3600' class='form-control' name='poll_interval' value='"
    . $e($cfg['poll_interval']) . "'></div>";
echo "<div class='col-md-6 mb-3'><label class='form-label'>"
    . __s('Consider a scanner stale after (seconds)', 'glpinetscan') . '</label>'
    . "<input type='number' min='60' class='form-control' name='stale_after' value='"
    . $e($cfg['stale_after']) . "'></div>";
echo '</div>';

if ($can_edit) {
    echo "<div class='text-end'><button type='submit' name='update' value='1' class='btn btn-primary'>"
        . __s('Save') . '</button></div>';
}
echo '</div></div></form>';

// --- Enrollment secrets ---
//
// The point of this card is that everything needed to bring a scanner online
// is on it: pick an entity, name the key, and copy the command. An operator
// should never have to find the server URL, hand-write a config file, or read
// the docs to install an agent.
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
    . __s('Enrollment secrets', 'glpinetscan') . '</h3></div><div class="card-body">';
echo '<p class="text-muted">'
    . __s(
        'A scanner presents one of these once and receives its own token in exchange. Revoking a secret prevents new enrollments but leaves existing scanners running — deactivate the scanner itself to cut one off.',
        'glpinetscan'
    )
    . '</p>';

// The command has to be one that will actually work, which means following the
// TLS *policy* rather than however the admin happens to be browsing. With
// require_tls on, both ends reject plain HTTP — so emitting the http:// URL of
// the current session would hand someone a line guaranteed to fail.
$browsing_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
$requires_tls = (bool) $cfg['require_tls'];
$scheme = ($requires_tls || $browsing_https) ? 'https' : 'http';
$base_url = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'glpi.example.com');

if ($requires_tls && !$browsing_https) {
    echo "<div class='alert alert-warning'>"
        . __s(
            'You are viewing GLPI over plain HTTP, but scanners are required to use TLS — so the command below names an https:// URL. Check that this host answers on TLS, or adjust the address before running it.',
            'glpinetscan'
        )
        . '</div>';
}

echo "<table class='table table-hover align-middle'><thead><tr>";
echo '<th>' . __s('Name') . '</th>';
echo '<th>' . __s('Entity') . '</th>';
echo '<th>' . __s('Enrolments', 'glpinetscan') . '</th>';
echo '<th>' . __s('Status') . '</th>';
echo '<th>' . __s('Install command', 'glpinetscan') . '</th>';
echo '<th></th>';
echo '</tr></thead><tbody>';

$secrets = Secret::all();
foreach ($secrets as $row) {
    $plain  = Secret::reveal($row);
    $active = (int) $row['is_active'] === 1;

    echo '<tr>';
    echo '<td>' . $e($row['name']) . '</td>';
    echo '<td>' . $e(Dropdown::getDropdownName('glpi_entities', (int) $row['entities_id'])) . '</td>';
    echo '<td>' . (int) $row['enroll_count'] . '</td>';
    echo '<td>' . ($active
        ? "<span class='badge bg-success text-white'>" . __s('Active') . '</span>'
        : "<span class='badge bg-secondary text-white'>" . __s('Revoked', 'glpinetscan') . '</span>')
        . '</td>';

    echo '<td>';
    if ($active && $plain !== null) {
        $cmd = sprintf(
            'glpi-netscan install --server %s --secret %s',
            $base_url,
            $plain
        );
        echo "<code class='user-select-all small'>" . $e($cmd) . '</code>';
    } elseif ($active) {
        echo "<span class='text-muted'>"
            . __s('Unreadable — the GLPI encryption key changed. Issue a new secret.', 'glpinetscan')
            . '</span>';
    } else {
        echo "<span class='text-muted'>&mdash;</span>";
    }
    echo '</td>';

    echo "<td class='text-end'>";
    if ($active) {
        echo "<form method='post' class='d-inline'>";
        echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
if ($can_edit) {
            echo "<button class='btn btn-sm btn-outline-danger' name='revoke_secret' value='"
                . (int) $row['id'] . "'>" . __s('Revoke', 'glpinetscan') . '</button>';
}
        echo '</form>';
    }
    echo '</td></tr>';
}

if ($secrets === []) {
    echo "<tr><td colspan='6' class='text-muted'>"
        . __s('No secrets yet. Create one to enroll your first scanner.', 'glpinetscan')
        . '</td></tr>';
}

echo '</tbody></table>';

echo "<form method='post' class='row g-2 align-items-end mt-2'>";
echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
echo "<div class='col-md-4'><label class='form-label' for='secret_name'>" . __s('New secret name') . '</label>'
    . "<input type='text' class='form-control' id='secret_name' name='secret_name' placeholder='"
    . __s('e.g. Branch office scanners', 'glpinetscan') . "'></div>";
echo "<div class='col-md-4'><label class='form-label'>" . __s('Entity') . '</label>';
// Defaults to the entity being worked in, not the root: a key is almost always
// wanted for the site the operator is currently looking at.
Entity::dropdown([
    'name'  => 'secret_entity',
    'value' => $_SESSION['glpiactive_entity'] ?? 0,
]);
echo '</div>';
echo "<div class='col-md-4 text-end'><button class='btn btn-success' name='add_secret' value='1'>"
    . __s('Create secret', 'glpinetscan') . '</button></div>';
echo '</form>';

echo "<p class='text-muted mt-3 mb-0'>"
    . __s(
        'Run the command on the machine that will do the scanning. It writes the configuration and enrolls immediately, so a wrong URL or a revoked secret fails there and then rather than at the next service start. Add --ca-cert for a private certificate authority.',
        'glpinetscan'
    )
    . '</p>';

echo '</div></div>';

// --- Shipped profile packs ---
// Collapsed by default: this is reference material, and at 50-odd rows it
// otherwise buries the things on this page an operator actually acts on.
// --- Device control ---
//
// The only setting here that lets the plugin write to hardware. Off by default,
// and stated plainly rather than buried: an operator turning this on should be
// left in no doubt what it permits.
echo "<form method='post'>";
echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
echo Html::hidden('section', ['value' => 'control']);
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
    . __s('Device control', 'glpinetscan') . '</h3></div><div class="card-body">';

$control = $cfg['allow_control'] ? "checked='checked'" : '';
echo "<label class='form-check'><input type='checkbox' class='form-check-input' name='allow_control' value='1' $control>";
echo "<span class='form-check-label'>" . __s('Allow scanners to write to devices', 'glpinetscan') . '</span></label>';
echo "<p class='text-muted'>"
    . __s(
        'Everything else this plugin does is read-only. With this on, an administrator can switch a port from an asset page and a scanner will perform it. Turning it on is not by itself enough: each scan target must also be given a write credential of its own, separate from the ones it reads with, so a community string that happens to be read-write cannot make an estate controllable by accident.',
        'glpinetscan'
    )
    . '</p>';
echo "<p class='text-muted'>"
    . __s(
        'Every action is recorded with who asked for it and what came of it, and is abandoned if no scanner collects it within ten minutes — so a click that is forgotten cannot switch something off hours later.',
        'glpinetscan'
    )
    . '</p>';

if ($can_edit) {
    echo "<div class='text-end'><button type='submit' name='update' value='1' class='btn btn-primary'>"
        . __s('Save') . '</button></div>';
}
echo '</div></div></form>';

// --- Notifications ---
echo "<form method='post'>";
echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
echo Html::hidden('section', ['value' => 'traps']);
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
    . __s('SNMP notifications (traps)', 'glpinetscan') . '</h3></div><div class="card-body">';

$traps = $cfg['allow_traps'] ? "checked='checked'" : '';
echo "<label class='form-check'><input type='checkbox' class='form-check-input' name='allow_traps' value='1' $traps>";
echo "<span class='form-check-label'>" . __s('Let scanners listen for notifications', 'glpinetscan') . '</span></label>';
echo "<p class='text-muted'>"
    . __s(
        'A device that sends a notification is telling the scanner it has changed, which is better evidence than the counters a discovery pass reads — so a notification causes that device to be fully inventoried on the next pass rather than waiting for the interval.',
        'glpinetscan'
    )
    . '</p>';
echo "<p class='text-muted'>"
    . __s(
        'An SNMPv1 or v2c notification is an unauthenticated datagram and is trivially forged. Scanners therefore accept them only from addresses inside their own scan ranges, and nothing a notification says is ever written into an asset: the worst a forged one achieves is an SNMP walk of a device the scanner was already allowed to walk.',
        'glpinetscan'
    )
    . '</p>';

echo "<div class='row'><div class='col-md-4 mb-3'><label class='form-label'>"
    . __s('Listening port', 'glpinetscan') . '</label>'
    . "<input type='number' min='1' max='65535' class='form-control' name='trap_port' value='"
    . $e($cfg['trap_port']) . "'>"
    . "<div class='form-text'>"
    . __s('162 is the standard. Binding it needs a capability the packaged systemd unit does not grant by default — apply packaging/glpi-netscan-traps.conf, or use a high port.', 'glpinetscan')
    . '</div></div></div>';

if ($can_edit) {
    echo "<div class='text-end'><button type='submit' name='update' value='1' class='btn btn-primary'>"
        . __s('Save') . '</button></div>';
}
echo '</div></div></form>';

// --- Scanner updates ---
//
// Two switches rather than one. Enabling updates does not by itself move any
// scanner, because the rollout starts at 0% — so the sequence is "turn it on,
// then open the tap", and the tap can be closed again. One combined control
// would make the first click irreversible across the whole fleet.
echo "<form method='post'>";
echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
echo Html::hidden('section', ['value' => 'updates']);
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
    . __s('Scanner updates', 'glpinetscan') . '</h3></div><div class="card-body">';

$updEnabled = $cfg['update_enabled'] ? "checked='checked'" : '';
echo "<label class='form-check'><input type='checkbox' class='form-check-input' name='update_enabled' value='1' $updEnabled>";
echo "<span class='form-check-label'>" . __s('Offer published packages to scanners', 'glpinetscan') . '</span></label>';
echo "<p class='text-muted'>"
    . __s(
        'Scanners ask on the poll they already make, verify the download against its SHA-256, restart onto it, and roll themselves back if the new version cannot start or cannot reach GLPI. Off by default: this lets GLPI replace the binary running on every scanner host.',
        'glpinetscan'
    )
    . '</p>';

echo "<div class='row'>";
echo "<div class='col-md-6 mb-3'><label class='form-label'>"
    . __s('Rollout percentage', 'glpinetscan') . '</label>'
    . "<input type='number' min='0' max='100' class='form-control' name='rollout_percent' value='"
    . $e($cfg['rollout_percent']) . "'>"
    . "<div class='form-text'>"
    . __s(
        'Each scanner sits in a fixed ring from 0 to 99, so raising this always reaches the same machines first and in the same order. A scanner never loses an update it has already taken when the number goes back down.',
        'glpinetscan'
    )
    . '</div></div>';
echo '</div>';

if ($can_edit) {
    echo "<div class='text-end'><button type='submit' name='update' value='1' class='btn btn-primary'>"
        . __s('Save') . '</button></div>';
}

// Version spread. The one number that says whether a rollout is working.
$spread = Update::versionSpread();
if ($spread !== []) {
    echo "<h4 class='h5 mt-4'>" . __s('Versions in the fleet', 'glpinetscan') . '</h4>';
    echo "<table class='table table-sm'><thead><tr><th>" . __s('Version', 'glpinetscan')
        . '</th><th>' . __s('Scanners', 'glpinetscan') . '</th></tr></thead><tbody>';
    foreach ($spread as $entry) {
        $label = $entry['version'] !== '' ? $entry['version'] : __('not yet reported', 'glpinetscan');
        echo '<tr><td><code>' . $e($label) . '</code></td><td>' . $e($entry['cpt']) . '</td></tr>';
    }
    echo '</tbody></table>';
}

echo '</div></div></form>';

// --- Published packages ---
echo "<div class='card mb-3'><div class='card-header'><h3 class='card-title'>"
    . __s('Published packages', 'glpinetscan') . '</h3></div><div class="card-body">';

echo "<p class='text-muted'>"
    . __s(
        'GLPI records where a release lives and what it should hash to; it does not host the file. Scanners authenticate the download by its checksum, so it can be served from wherever you already publish artifacts. The newest active package for a platform and architecture is the one offered.',
        'glpinetscan'
    )
    . '</p>';

$packages = Update::all();
if ($packages !== []) {
    echo "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr>"
        . '<th>' . __s('Version', 'glpinetscan') . '</th>'
        . '<th>' . __s('Platform', 'glpinetscan') . '</th>'
        . '<th>' . __s('Architecture', 'glpinetscan') . '</th>'
        . '<th>' . __s('SHA-256', 'glpinetscan') . '</th>'
        . '<th>' . __s('Size', 'glpinetscan') . '</th>'
        . '<th></th></tr></thead><tbody>';
    foreach ($packages as $pkg) {
        echo '<tr><td>' . $e($pkg['version']) . '</td>';
        echo '<td>' . $e($pkg['platform']) . '</td>';
        echo '<td>' . $e($pkg['arch']) . '</td>';
        echo "<td><code class='small' title='" . $e($pkg['sha256']) . "'>"
            . $e(substr((string) $pkg['sha256'], 0, 16)) . '…</code></td>';
        echo '<td>' . $e(Toolbox::getSize((int) $pkg['size'])) . '</td>';
        echo "<td class='text-end'><form method='post' class='d-inline'>";
        echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
if ($can_edit) {
            echo "<button class='btn btn-sm btn-outline-danger' name='withdraw_package' value='"
                . (int) $pkg['id'] . "'>" . __s('Withdraw', 'glpinetscan') . '</button></form></td></tr>';
}
    }
    echo '</tbody></table></div>';
} else {
    echo "<p class='text-muted'>"
        . __s('No packages published. Scanners will be told there is nothing to install.', 'glpinetscan')
        . '</p>';
}

// The checksum and size are asked for rather than fetched by GLPI on the
// operator's behalf. Publishing is meant to be a copy of what the build
// produced — `sha256sum` next to the artifact — not a second, independent
// measurement of whatever happens to be at that URL right now, which would
// certify a swapped file just as readily as the real one.
echo "<h4 class='h5 mt-3'>" . __s('Publish a release', 'glpinetscan') . '</h4>';
echo "<form method='post'><div class='row g-2 align-items-end'>";
echo Html::hidden('_glpi_csrf_token', ['value' => $csrf]);
echo "<div class='col-md-2'><label class='form-label'>" . __s('Version', 'glpinetscan')
    . "</label><input class='form-control' name='pkg_version' placeholder='0.2.0' required></div>";
echo "<div class='col-md-2'><label class='form-label'>" . __s('Platform', 'glpinetscan')
    . "</label><select class='form-select' name='pkg_platform'>";
foreach (Update::PLATFORMS as $platform) {
    echo "<option value='" . $e($platform) . "'>" . $e($platform) . '</option>';
}
echo '</select></div>';
echo "<div class='col-md-2'><label class='form-label'>" . __s('Architecture', 'glpinetscan')
    . "</label><select class='form-select' name='pkg_arch'>";
foreach (Update::ARCHES as $arch) {
    echo "<option value='" . $e($arch) . "'>" . $e($arch) . '</option>';
}
echo '</select></div>';
echo "<div class='col-md-6'><label class='form-label'>" . __s('URL (https)', 'glpinetscan')
    . "</label><input class='form-control' name='pkg_url' type='url' placeholder='https://…/glpi-netscan' required></div>";
echo "<div class='col-md-8'><label class='form-label'>" . __s('SHA-256', 'glpinetscan')
    . "</label><input class='form-control font-monospace' name='pkg_sha256' pattern='[0-9a-fA-F]{64}' required></div>";
echo "<div class='col-md-2'><label class='form-label'>" . __s('Size (bytes)', 'glpinetscan')
    . "</label><input class='form-control' type='number' min='1' name='pkg_size' required></div>";
if ($can_edit) {
    echo "<div class='col-md-2 text-end'><button class='btn btn-primary' name='publish_package' value='1'>"
        . __s('Publish', 'glpinetscan') . '</button></div>';
}
echo '</div></form>';

echo '</div></div>';

echo "<div class='card mb-4'><div class='card-header'><h3 class='card-title'>"
    . __s('Shipped OID profiles', 'glpinetscan') . '</h3></div><div class="card-body">';
echo '<p class="text-muted">'
    . __s(
        'Read from the plugin on disk and always sent to scanners. Profiles you create in the UI layer on top of these by priority, so a site can override a shipped OID without forking the plugin.',
        'glpinetscan'
    )
    . '</p>';

$packs = OidProfile::shipped();
if ($packs === []) {
    echo '<em>' . __s('No shipped packs found.', 'glpinetscan') . '</em>';
} else {
    echo '<details><summary class="mb-2" style="cursor:pointer">'
        . sprintf(__s('Show all %d profiles', 'glpinetscan'), count($packs))
        . '</summary>';
    echo "<table class='table table-sm'><thead><tr><th>" . __s('Name') . '</th><th>'
        . __s('Priority', 'glpinetscan') . '</th><th>' . __s('Matches', 'glpinetscan') . '</th><th>'
        . __s('OIDs', 'glpinetscan') . '</th></tr></thead><tbody>';
    foreach ($packs as $pack) {
        $match = $pack['match']['sysobjectid_prefix'] ?? [];
        $count = count($pack['device'] ?? []) + count($pack['ports'] ?? [])
            + count($pack['components'] ?? []) + count($pack['pagecounters'] ?? []);
        echo '<tr>';
        echo '<td>' . $e($pack['name'] ?? '') . '</td>';
        echo '<td>' . (int) ($pack['priority'] ?? 0) . '</td>';
        echo '<td>' . ($match === []
            ? '<em>' . __s('all devices', 'glpinetscan') . '</em>'
            : $e(implode(', ', (array) $match))) . '</td>';
        echo '<td>' . $count . '</td>';
        echo '</tr>';
    }
    echo '</tbody></table></details>';
}

echo '</div></div>';

echo '</div>';

Html::footer();
