<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Setup → GLPI Netscan → Warranty lookups.
 *
 * A page of its own rather than another card on the settings page: seven
 * vendors with up to eight credentials each is more configuration than the
 * rest of the plugin put together, and burying the master switch under it
 * would hide the one control that decides whether anything leaves the
 * building at all.
 *
 * House conventions, all of which have bitten this codebase before:
 *
 * - **No `action` attribute on the forms.** Under GLPI 11's front controller
 *   `$_SERVER['PHP_SELF']` resolves to /index.php, so a form pointing at it
 *   posts to the router, which answers 400 — and the page comes back looking
 *   exactly as though it had saved.
 * - **Each form posts a hidden `section` and only that section's keys are
 *   written.** A checkbox absent from a submission is indistinguishable from
 *   an unticked one, so a handler that rebuilds every setting from `$_POST`
 *   switches off every checkbox on the cards that were not submitted.
 * - **READ opens the page, UPDATE saves it, and they are separately
 *   grantable.** A read-only visitor gets the page with no controls rather
 *   than a form that answers Save with an access-denied.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpinetscan\Warranty\Record;
use GlpiPlugin\Glpinetscan\Warranty\Registry;
use GlpiPlugin\Glpinetscan\Warranty\Settings;
use GlpiPlugin\Glpinetscan\Warranty\Sync;

Session::checkRight('config', READ);

// ------------------------------------------------------------------- handlers

$section = (string) ($_POST['section'] ?? '');

if ($section !== '') {
    Session::checkRight('config', UPDATE);
    // No Session::checkCSRF() here on purpose — GLPI 11's CheckCsrfListener has
    // already validated and consumed the token for this POST.

    if ($section === 'general') {
        Settings::save([
            'warranty_enabled'               => !empty($_POST['warranty_enabled']) ? 1 : 0,
            'warranty_interval_days'         => (int) ($_POST['warranty_interval_days'] ?? 7),
            'warranty_expired_interval_days' => (int) ($_POST['warranty_expired_interval_days'] ?? 30),
            'warranty_unknown_interval_days' => (int) ($_POST['warranty_unknown_interval_days'] ?? 30),
            'warranty_run_limit'             => (int) ($_POST['warranty_run_limit'] ?? 200),
            'warranty_http_timeout'          => (int) ($_POST['warranty_http_timeout'] ?? 30),
            'warranty_default_country'       => (string) ($_POST['warranty_default_country'] ?? ''),
            'warranty_write_infocom'         => !empty($_POST['warranty_write_infocom']) ? 1 : 0,
            'warranty_set_buy_date'          => !empty($_POST['warranty_set_buy_date']) ? 1 : 0,
            'warranty_set_supplier'          => !empty($_POST['warranty_set_supplier']) ? 1 : 0,
            'warranty_overwrite_manual'      => !empty($_POST['warranty_overwrite_manual']) ? 1 : 0,
        ]);

        Session::addMessageAfterRedirect(__('Warranty settings saved.', 'glpinetscan'));
        Html::redirect($_SERVER['REQUEST_URI']);
    }

    $vendor_class = Registry::classFor($section);

    if ($vendor_class !== null) {
        $values = [
            'warranty_' . $section . '_enabled' => !empty($_POST['vendor_enabled']) ? 1 : 0,
        ];

        foreach (array_keys($vendor_class::credentials()) as $name) {
            $key = Settings::credentialKey($section, $name);
            if (array_key_exists($key, $_POST)) {
                $values[$key] = (string) $_POST[$key];
            }
        }

        Settings::save($values);

        // Assets skipped because this vendor was off are put back in the queue,
        // so switching it on produces results on the next cron run rather than
        // a day later.
        Sync::requeueSkipped();

        Session::addMessageAfterRedirect(
            sprintf(__('%s settings saved.', 'glpinetscan'), $vendor_class::label())
        );
        Html::redirect($_SERVER['REQUEST_URI']);
    }
}

// A vendor's one-off setup step — currently only Microsoft's tenant enrolment.
// Handled separately from a settings save because it reaches out and changes
// state at the vendor, which is not something saving a form should do.
if (!empty($_POST['setup_vendor']) && !empty($_POST['setup_action'])) {
    Session::checkRight('config', UPDATE);

    $key    = (string) $_POST['setup_vendor'];
    $client = Registry::isConfigured($key) ? Registry::make($key) : null;

    if ($client === null) {
        Session::addMessageAfterRedirect(
            __('That vendor is not configured yet.', 'glpinetscan'),
            false,
            WARNING
        );
    } else {
        try {
            Session::addMessageAfterRedirect($client->runSetupAction((string) $_POST['setup_action']));
        } catch (\Throwable $e) {
            Session::addMessageAfterRedirect($e->getMessage(), false, ERROR);
        }
    }

    Html::redirect($_SERVER['REQUEST_URI']);
}

if (!empty($_POST['run_now'])) {
    Session::checkRight('config', UPDATE);

    $stats = Sync::run();

    Session::addMessageAfterRedirect(sprintf(
        __('%1$d assets considered, %2$d looked up, %3$d with cover, %4$d unknown to the vendor, %5$d failed.', 'glpinetscan'),
        $stats['considered'],
        $stats['looked_up'],
        $stats['covered'],
        $stats['not_found'],
        $stats['errors']
    ));
    Html::redirect($_SERVER['REQUEST_URI']);
}

// ---------------------------------------------------------------------- page

Html::header(
    __('Warranty lookups', 'glpinetscan'),
    $_SERVER['PHP_SELF'],
    'config',
    'plugins'
);

$settings = Settings::all();
$can_edit = Session::haveRight('config', UPDATE);
$summary  = Record::summary();

echo "<div class='container-fluid glpinetscan-config' style='max-width:960px'>";

if (!$can_edit) {
    echo "<div class='alert alert-info'>"
       . __('Read only: your profile can view this configuration but not change it.', 'glpinetscan')
       . "</div>";
}

// ------------------------------------------------------------------- status

echo "<div class='card mb-3'><div class='card-body'>";
echo "<h3 class='card-title'>" . __('Status', 'glpinetscan') . "</h3>";

$usable = Registry::usableKeys($settings);

if ((int) $settings['warranty_enabled'] !== 1) {
    echo "<div class='alert alert-secondary mb-3'>"
       . __('Warranty lookups are switched off. Nothing is sent to any vendor.', 'glpinetscan')
       . "</div>";
} elseif ($usable === []) {
    echo "<div class='alert alert-warning mb-3'>"
       . __('Switched on, but no vendor is both enabled and fully configured, so nothing will be looked up.', 'glpinetscan')
       . "</div>";
} else {
    echo "<div class='alert alert-success mb-3'>"
       . sprintf(
           __('Active. %s will be asked about matching assets.', 'glpinetscan'),
           htmlspecialchars(implode(', ', array_map(
               static fn(string $key): string => Registry::classFor($key)::label(),
               $usable
           )))
       )
       . "</div>";
}

echo "<div class='row'>";
foreach ([
    __('Covered', 'glpinetscan')            => $summary[Record::OK],
    __('Unknown to vendor', 'glpinetscan')  => $summary[Record::NOT_FOUND],
    __('Not applicable', 'glpinetscan')     => $summary[Record::SKIPPED],
    __('Failed', 'glpinetscan')             => $summary[Record::ERROR],
] as $label => $count) {
    echo "<div class='col-md-3 mb-2'>";
    echo "<div class='text-muted small'>" . htmlspecialchars($label) . "</div>";
    echo "<div class='h3 mb-0'>" . (int) $count . "</div>";
    echo "</div>";
}
echo "</div>";

$failures = Record::recentFailures(5);
if ($failures !== []) {
    echo "<h4 class='mt-3'>" . __('Recent failures', 'glpinetscan') . "</h4>";
    echo "<div class='table-responsive'><table class='table table-sm'><tbody>";
    foreach ($failures as $failure) {
        echo "<tr>";
        echo "<td class='text-muted small' style='white-space:nowrap'>"
           . htmlspecialchars((string) Html::convDateTime($failure['checked_at'])) . "</td>";
        echo "<td class='small'>" . htmlspecialchars((string) $failure['message']) . "</td>";
        echo "</tr>";
    }
    echo "</tbody></table></div>";
}

if ($can_edit) {
    echo "<form method='post'>";
    echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
    echo "<button type='submit' name='run_now' value='1' class='btn btn-outline-primary btn-sm mt-2'>"
       . __('Run a lookup pass now', 'glpinetscan') . "</button>";
    echo "</form>";
}

echo "</div></div>";

// ------------------------------------------------------------------ general

echo "<form method='post'>";
echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
echo Html::hidden('section', ['value' => 'general']);

echo "<div class='card mb-3'><div class='card-body'>";
echo "<h3 class='card-title'>" . __('General', 'glpinetscan') . "</h3>";

echo "<p class='text-muted'>"
   . __('Only serial numbers leave this server, and only to the vendors switched on below. '
      . 'Results are written to each asset\'s Financial information tab, in GLPI\'s own warranty '
      . 'fields, so every existing report and the warranty-expiry alert keep working unchanged.', 'glpinetscan')
   . "</p>";

echo "<label class='form-check form-switch'>";
echo "<input type='checkbox' class='form-check-input' name='warranty_enabled' value='1'"
   . ((int) $settings['warranty_enabled'] === 1 ? ' checked' : '')
   . ($can_edit ? '' : ' disabled') . ">";
echo "<span class='form-check-label'>" . __('Look warranties up with hardware vendors', 'glpinetscan') . "</span>";
echo "</label>";

echo "<div class='row mt-3'>";

foreach ([
    'warranty_interval_days' => [
        __('Re-check a covered asset every (days)', 'glpinetscan'),
        __('A warranty only changes when somebody buys an extension.', 'glpinetscan'),
    ],
    'warranty_expired_interval_days' => [
        __('Re-check an expired asset every (days)', 'glpinetscan'),
        __('Most of an ageing estate. This is where the vendor quota goes.', 'glpinetscan'),
    ],
    'warranty_unknown_interval_days' => [
        __('Re-try a serial the vendor does not know every (days)', 'glpinetscan'),
        __('Usually permanent: kit registered to a reseller rather than to you.', 'glpinetscan'),
    ],
    'warranty_run_limit' => [
        __('Assets per scheduled run', 'glpinetscan'),
        __('Keeps a first pass over a large estate from spending a day\'s quota at once.', 'glpinetscan'),
    ],
    'warranty_http_timeout' => [
        __('Request timeout (seconds)', 'glpinetscan'),
        '',
    ],
] as $key => [$label, $hint]) {
    echo "<div class='col-md-4 mb-3'>";
    echo "<label class='form-label'>" . htmlspecialchars($label) . "</label>";
    echo "<input type='number' min='1' class='form-control' name='" . $key . "' value='"
       . (int) $settings[$key] . "'" . ($can_edit ? '' : ' disabled') . ">";
    if ($hint !== '') {
        echo "<div class='form-text'>" . htmlspecialchars($hint) . "</div>";
    }
    echo "</div>";
}

echo "<div class='col-md-4 mb-3'>";
echo "<label class='form-label'>" . __('Default country code', 'glpinetscan') . "</label>";
echo "<input type='text' maxlength='2' class='form-control' name='warranty_default_country' value='"
   . htmlspecialchars((string) $settings['warranty_default_country']) . "'" . ($can_edit ? '' : ' disabled') . ">";
echo "<div class='form-text'>"
   . __('Sent to the vendors that price entitlements per region.', 'glpinetscan') . "</div>";
echo "</div>";

echo "</div>";

echo "<h4>" . __('What is written to the asset', 'glpinetscan') . "</h4>";

foreach ([
    'warranty_write_infocom' => [
        __('Write the warranty onto the asset', 'glpinetscan'),
        __('Fills warranty start, duration and information on the Financial information tab. '
         . 'Switch off to keep the lookups as a report only.', 'glpinetscan'),
    ],
    'warranty_set_buy_date' => [
        __('Fill in a missing purchase date', 'glpinetscan'),
        __('From the vendor\'s ship date, and only when GLPI has none.', 'glpinetscan'),
    ],
    'warranty_set_supplier' => [
        __('Set the supplier to the manufacturer', 'glpinetscan'),
        __('Off by default: in an estate bought through resellers the supplier is the reseller, '
         . 'and that is who you actually call.', 'glpinetscan'),
    ],
    'warranty_overwrite_manual' => [
        __('Overwrite manually edited warranties', 'glpinetscan'),
        __('Off by default: somebody typed those in, and a lookup that disagrees is not '
         . 'automatically the one that is right.', 'glpinetscan'),
    ],
] as $key => [$label, $hint]) {
    echo "<label class='form-check form-switch mt-2'>";
    echo "<input type='checkbox' class='form-check-input' name='" . $key . "' value='1'"
       . ((int) $settings[$key] === 1 ? ' checked' : '')
       . ($can_edit ? '' : ' disabled') . ">";
    echo "<span class='form-check-label'>" . htmlspecialchars($label) . "</span>";
    echo "</label>";
    echo "<div class='form-text mb-2'>" . htmlspecialchars($hint) . "</div>";
}

if ($can_edit) {
    echo "<button type='submit' class='btn btn-primary mt-3'>" . __('Save') . "</button>";
}

echo "</div></div>";
echo "</form>";

// ------------------------------------------------------------------ vendors

echo "<h3 class='mt-4'>" . __('Vendors', 'glpinetscan') . "</h3>";
echo "<p class='text-muted'>"
   . __('Every one of these needs an account with the vendor. None of them has an anonymous tier, '
      . 'and none is contacted until it is switched on here.', 'glpinetscan')
   . "</p>";

foreach (Registry::vendorClasses() as $vendor_class) {
    $key        = $vendor_class::key();
    $enabled    = Registry::isEnabled($key, $settings);
    $configured = Registry::isConfigured($key, $settings);

    echo "<form method='post'>";
    echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
    echo Html::hidden('section', ['value' => $key]);

    // Only the vendors actually in use stay expanded. A closed <details> still
    // posts its inputs, so nothing is dropped by collapsing one.
    echo "<details class='card mb-3'" . ($enabled ? ' open' : '') . "><summary class='card-header'>";
    echo "<strong>" . htmlspecialchars($vendor_class::label()) . "</strong>";
    if ($enabled && $configured) {
        echo " <span class='badge bg-success ms-2'>" . __('Active', 'glpinetscan') . "</span>";
    } elseif ($enabled) {
        echo " <span class='badge bg-warning ms-2'>" . __('Missing credentials', 'glpinetscan') . "</span>";
    } else {
        echo " <span class='badge bg-secondary ms-2'>" . __('Off', 'glpinetscan') . "</span>";
    }
    echo "</summary>";

    echo "<div class='card-body'>";

    echo "<label class='form-check form-switch mb-3'>";
    echo "<input type='checkbox' class='form-check-input' name='vendor_enabled' value='1'"
       . ($enabled ? ' checked' : '') . ($can_edit ? '' : ' disabled') . ">";
    echo "<span class='form-check-label'>"
       . sprintf(__('Ask %s about matching assets', 'glpinetscan'), htmlspecialchars($vendor_class::label()))
       . "</span>";
    echo "</label>";

    foreach ($vendor_class::credentials() as $name => $spec) {
        $field = Settings::credentialKey($key, $name);
        $value = (string) ($settings[$field] ?? '');

        echo "<div class='mb-3'>";
        echo "<label class='form-label'>" . htmlspecialchars($spec['label']);
        if (!$spec['required']) {
            echo " <span class='text-muted small'>(" . __('optional', 'glpinetscan') . ")</span>";
        }
        echo "</label>";

        if ($spec['type'] === 'secret') {
            // The stored secret is never sent to the browser. The placeholder
            // posts back unchanged and is understood by Settings::save() to
            // mean "leave it alone".
            echo "<input type='password' autocomplete='new-password' class='form-control' name='"
               . $field . "' value='" . ($value !== '' ? Settings::SECRET_PLACEHOLDER : '') . "'"
               . ($can_edit ? '' : ' disabled') . ">";
        } else {
            echo "<input type='text' class='form-control' name='" . $field . "' value='"
               . htmlspecialchars($value) . "'" . ($can_edit ? '' : ' disabled') . ">";
        }

        if ($spec['hint'] !== '') {
            echo "<div class='form-text'>" . htmlspecialchars($spec['hint']) . "</div>";
        }
        echo "</div>";
    }

    if ($can_edit) {
        echo "<button type='submit' class='btn btn-primary'>" . __('Save') . "</button>";
    }

    echo "</div></details>";
    echo "</form>";

    // Outside the settings form on purpose: a nested form is invalid HTML, and
    // these buttons must not carry the credential fields with them.
    $actions = $vendor_class::setupActions();

    if ($actions !== [] && $can_edit && $enabled) {
        echo "<div class='card mb-3'><div class='card-body'>";
        foreach ($actions as $action => $spec) {
            echo "<form method='post' class='mb-2'>";
            echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
            echo Html::hidden('setup_vendor', ['value' => $key]);
            echo Html::hidden('setup_action', ['value' => $action]);
            echo "<button type='submit' class='btn btn-outline-primary'"
               . ($configured ? '' : ' disabled') . ">"
               . htmlspecialchars($spec['label']) . "</button>";
            echo "<div class='form-text'>" . htmlspecialchars($spec['hint']) . "</div>";
            echo "</form>";
        }
        echo "</div></div>";
    }
}

echo "<div class='card mb-3'><div class='card-body'>";
echo "<h3 class='card-title'>" . __('Vendors without an API', 'glpinetscan') . "</h3>";
echo "<p class='text-muted'>"
   . __('These were looked at and have no serial-number warranty API a plugin can call, so assets '
      . 'from them are marked "not applicable" rather than failing:', 'glpinetscan')
   . "</p>";
echo "<ul class='text-muted'>";
foreach ([
    __('Arista Networks — the only public API on arista.com is the software download service, '
     . 'and CloudVision describes devices under management rather than support entitlement.', 'glpinetscan'),
    __('Ubiquiti — api.ui.com returns device inventory with no coverage data; warranty goes '
     . 'through the RMA form, which wants proof of purchase rather than a serial.', 'glpinetscan'),
    __('Supermicro — the serial-number warranty check is a web form and RMA is email.', 'glpinetscan'),
    __('Zebra, APC/Schneider, Acer, ASUS, MSI, Dynabook/Toshiba and Fujitsu — a web form in '
     . 'every case. Scraping one would break silently and is not shipped here.', 'glpinetscan'),
    __('Cisco Meraki — excluded on purpose: Meraki serials are not in the Cisco support API and '
     . 'would fail on every device, every night.', 'glpinetscan'),
] as $reason) {
    echo "<li>" . htmlspecialchars($reason) . "</li>";
}
echo "</ul>";
echo "</div></div>";

echo "</div>";

Html::footer();
