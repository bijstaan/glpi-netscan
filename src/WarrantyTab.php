<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use CommonDBTM;
use CommonGLPI;
use GlpiPlugin\Glpinetscan\Warranty\Detector;
use GlpiPlugin\Glpinetscan\Warranty\Entitlement;
use GlpiPlugin\Glpinetscan\Warranty\Record;
use GlpiPlugin\Glpinetscan\Warranty\Registry;
use GlpiPlugin\Glpinetscan\Warranty\Scope;
use GlpiPlugin\Glpinetscan\Warranty\Settings;
use Html;
use Plugin;
use Session;

/**
 * "Warranty" tab on an inventoried asset.
 *
 * The dates themselves are on the Financial information tab, in GLPI's own
 * fields, which is the whole point of the feature — so this tab does not
 * repeat them as a second source of truth. It answers the questions Infocom
 * cannot:
 *
 * - **which entitlements exist.** Infocom holds one span; a machine with a
 *   base warranty and an extension has several, and the technician on the
 *   phone to the vendor needs the service level, not the end date.
 * - **where the number came from**, and when it was last confirmed.
 * - **why there is no number**, which is the case that actually generates
 *   support questions. "Dell has no record of this serial" and "the Dell
 *   credentials expired a fortnight ago" produce an identical blank Financial
 *   tab and have completely different answers.
 */
class WarrantyTab extends CommonGLPI
{
    /**
     * GLPI's own financial-information right, not a plugin right.
     *
     * This tab is a window onto the asset's Infocom — the same warranty, with
     * the entitlements behind it — so whoever may open the Financial
     * information tab may open this one. Inventing a plugin right here would
     * mean a finance-facing profile could see the date and not why it is that
     * date, and an administrator would have to grant a second right to undo
     * something nobody asked for.
     */
    public static $rightname = 'infocom';

    public static function getTypeName($nb = 0)
    {
        return __('Warranty', 'glpinetscan');
    }

    public static function getIcon()
    {
        return 'ti ti-certificate';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || $item->isNewItem()) {
            return '';
        }

        if (!Session::haveRight(self::$rightname, READ) || !Settings::isEnabled()) {
            return '';
        }

        // Only where there is something to say: an asset this plugin inventoried,
        // or one that has already been looked up. An empty panel on every
        // computer in the estate is noise.
        if (!Scope::covers($item->getType(), (int) $item->getID())
            && Record::for($item->getType(), (int) $item->getID()) === null) {
            return '';
        }

        return self::getTypeName();
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || $item->isNewItem()) {
            return false;
        }

        $itemtype = $item->getType();
        $items_id = (int) $item->getID();

        $row = Record::for($itemtype, $items_id);

        echo "<div class='card glpinetscan-surface'><div class='card-body'>";

        self::renderStatus($row, $itemtype, $items_id);

        if ($row !== null && ($row['status'] ?? '') === Record::OK) {
            self::renderFacts($row);
            self::renderEntitlements($row);
        }

        self::renderActions($item, $row);

        echo "</div></div>";

        return true;
    }

    /** The headline: covered, expired, unknown, or broken. */
    private static function renderStatus(?array $row, string $itemtype, int $items_id): void
    {
        if ($row === null) {
            $subject = Scope::subjectFor($itemtype, $items_id);
            $vendor  = $subject !== null ? Detector::detect($subject) : null;

            $message = match (true) {
                $subject === null => __('This asset has no usable serial number, so no vendor can be asked.', 'glpinetscan'),
                $vendor === null  => __('No vendor warranty API matches this asset\'s manufacturer.', 'glpinetscan'),
                default           => __('Not looked up yet.', 'glpinetscan'),
            };

            echo "<div class='alert alert-secondary'>" . htmlspecialchars($message) . "</div>";
            return;
        }

        $status = (string) ($row['status'] ?? '');
        $vendor = self::vendorLabel((string) ($row['vendor'] ?? ''));

        if ($status === Record::OK) {
            $end      = (string) ($row['end_date'] ?? '');
            $lifetime = (int) ($row['is_lifetime'] ?? 0) === 1;
            $covered  = (int) ($row['is_covered'] ?? 0) === 1;

            $headline = match (true) {
                $lifetime => __('Covered — this warranty does not expire.', 'glpinetscan'),
                $covered && $end !== '' => sprintf(
                    __('Covered until %s.', 'glpinetscan'),
                    Html::convDate($end)
                ),
                $end !== '' => sprintf(__('Cover ended on %s.', 'glpinetscan'), Html::convDate($end)),
                default     => __('Cover reported, with no end date.', 'glpinetscan'),
            };

            echo "<div class='alert " . ($covered || $lifetime ? 'alert-success' : 'alert-warning') . "'>"
               . "<strong>" . htmlspecialchars($headline) . "</strong>"
               . " <span class='text-muted'>" . sprintf(__('According to %s.', 'glpinetscan'), htmlspecialchars($vendor)) . "</span>"
               . "</div>";

            if (trim((string) ($row['message'] ?? '')) !== '') {
                echo "<div class='alert alert-info'>" . htmlspecialchars((string) $row['message']) . "</div>";
            }

            if ((int) ($row['applied'] ?? 0) !== 1) {
                echo "<div class='alert alert-warning'>"
                   . __('These dates have not been written to the Financial information tab.', 'glpinetscan')
                   . "</div>";
            }

            return;
        }

        $class = $status === Record::ERROR ? 'alert-danger' : 'alert-secondary';

        echo "<div class='alert $class'>"
           . ($vendor !== '' ? "<strong>" . htmlspecialchars($vendor) . "</strong> — " : '')
           . htmlspecialchars((string) ($row['message'] ?? __('No warranty information.', 'glpinetscan')))
           . "</div>";
    }

    private static function renderFacts(array $row): void
    {
        $fields = [
            __('Vendor', 'glpinetscan')        => self::vendorLabel((string) ($row['vendor'] ?? '')),
            __('Product', 'glpinetscan')       => (string) ($row['product'] ?? ''),
            __('Service level', 'glpinetscan') => (string) ($row['service_level'] ?? ''),
            __('Serial number')                => (string) ($row['serial'] ?? ''),
            __('Shipped', 'glpinetscan')       => self::date($row['ship_date'] ?? null),
            __('Purchased', 'glpinetscan')     => self::date($row['purchase_date'] ?? null),
            __('Country', 'glpinetscan')       => (string) ($row['country'] ?? ''),
        ];

        echo "<div class='row'>";
        foreach ($fields as $label => $value) {
            if (trim((string) $value) === '') {
                continue;
            }
            echo "<div class='col-md-3 mb-3'>";
            echo "<div class='text-muted small'>" . htmlspecialchars($label) . "</div>";
            echo "<div>" . htmlspecialchars((string) $value) . "</div>";
            echo "</div>";
        }
        echo "</div>";
    }

    private static function renderEntitlements(array $row): void
    {
        $entitlements = Record::entitlements($row);

        if ($entitlements === []) {
            return;
        }

        // Newest expiry first: the line that decides whether the machine is
        // covered is the one to read, and it is the one GLPI's fields reflect.
        usort(
            $entitlements,
            static fn(Entitlement $a, Entitlement $b): int => ($b->end ?? '9999') <=> ($a->end ?? '9999')
        );

        $today = date('Y-m-d');

        echo "<h4 class='mt-3'>" . __('Entitlements', 'glpinetscan') . "</h4>";
        echo "<div class='table-responsive'><table class='table table-sm'>";
        echo "<thead><tr>"
           . "<th>" . __('Service level', 'glpinetscan') . "</th>"
           . "<th>" . __('Kind', 'glpinetscan') . "</th>"
           . "<th>" . __('Start') . "</th>"
           . "<th>" . __('End') . "</th>"
           . "<th>" . __('Reference', 'glpinetscan') . "</th>"
           . "</tr></thead><tbody>";

        foreach ($entitlements as $entitlement) {
            $active = $entitlement->isActive($today);

            echo "<tr class='" . ($active ? '' : 'text-muted') . "'>";
            echo "<td>" . htmlspecialchars($entitlement->level !== '' ? $entitlement->level : '—') . "</td>";
            echo "<td>" . htmlspecialchars(self::kind($entitlement->type)) . "</td>";
            echo "<td>" . htmlspecialchars(self::date($entitlement->start)) . "</td>";
            echo "<td>" . ($entitlement->lifetime
                ? htmlspecialchars(__('Never', 'glpinetscan'))
                : htmlspecialchars(self::date($entitlement->end))) . "</td>";
            echo "<td class='small'>" . htmlspecialchars($entitlement->reference) . "</td>";
            echo "</tr>";
        }

        echo "</tbody></table></div>";

        echo "<p class='text-muted small'>"
           . __('GLPI stores one warranty span per asset, so the Financial information tab carries '
              . 'the entitlement that ends last. The rest are listed here.', 'glpinetscan')
           . "</p>";
    }

    private static function renderActions(CommonDBTM $item, ?array $row): void
    {
        if ($row !== null) {
            echo "<p class='text-muted small mb-2'>";
            echo sprintf(
                __('Last checked %s.', 'glpinetscan'),
                self::dateTime($row['checked_at'] ?? null) ?: __('never', 'glpinetscan')
            );
            if (trim((string) ($row['next_check_at'] ?? '')) !== '') {
                echo ' ' . sprintf(__('Next check %s.', 'glpinetscan'), self::dateTime($row['next_check_at']));
            }
            echo "</p>";
        }

        // Spending a call against a vendor's quota is a write-shaped act
        // against this machine, so it needs UPDATE on the asset — and on *this*
        // asset, which is where the entity restriction lives.
        if (!$item->canUpdateItem() || !Session::haveRight(self::$rightname, READ)) {
            return;
        }

        echo "<form method='post' action='" . Plugin::getWebDir('glpinetscan') . "/front/warranty.form.php'>";
        echo Html::hidden('itemtype', ['value' => $item->getType()]);
        echo Html::hidden('items_id', ['value' => (int) $item->getID()]);
        echo "<button type='submit' name='check_now' value='1' class='btn btn-primary'>"
           . "<i class='ti ti-refresh me-1'></i>"
           . __('Check with the vendor now', 'glpinetscan')
           . "</button>";
        Html::closeForm();
    }

    private static function vendorLabel(string $key): string
    {
        $class = $key !== '' ? Registry::classFor($key) : null;

        return $class !== null ? $class::label() : '';
    }

    private static function kind(string $type): string
    {
        return match ($type) {
            Entitlement::BASE     => __('Base warranty', 'glpinetscan'),
            Entitlement::EXTENDED => __('Extension', 'glpinetscan'),
            Entitlement::CONTRACT => __('Support contract', 'glpinetscan'),
            default               => __('Other', 'glpinetscan'),
        };
    }

    private static function date(mixed $value): string
    {
        $value = trim((string) ($value ?? ''));

        return $value === '' ? '' : (string) Html::convDate($value);
    }

    private static function dateTime(mixed $value): string
    {
        $value = trim((string) ($value ?? ''));

        return $value === '' ? '' : (string) Html::convDateTime($value);
    }
}
