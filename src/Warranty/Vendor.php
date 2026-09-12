<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * A hardware vendor's warranty API.
 *
 * Implementations own exactly one thing: turning serial numbers into
 * {@see Coverage}. They do not read the database, do not write assets, do not
 * decide what is due for a check and do not know what Infocom is. Everything
 * on the GLPI side of that line lives in {@see Sync} and {@see Writer}, which
 * is what keeps a vendor client small enough to verify against a captured
 * payload.
 */
interface Vendor
{
    /** Stable identifier, used in settings keys and stored on every lookup row. */
    public static function key(): string;

    /** Shown in the UI. Not translated: these are trademarks. */
    public static function label(): string;

    /**
     * The credentials this vendor needs.
     *
     * @return array<string,array{label:string,type:string,required:bool,hint:string,default?:string}>
     *         type is one of text, secret, path.
     */
    public static function credentials(): array;

    /**
     * Manufacturer names, lower-cased, that mean this vendor.
     *
     * Matched as substrings against the asset's manufacturer, because GLPI
     * stores whatever the firmware said — "Dell Inc.", "Dell Computer
     * Corporation" and "Dell" all appear in the same estate.
     *
     * @return string[]
     */
    public static function aliases(): array;

    /** How many serials may travel in one request. */
    public static function batchSize(): int;

    /** Seconds the transport must leave between requests to this vendor. */
    public static function minInterval(): float;

    /**
     * One-off setup steps this vendor needs a human to trigger.
     *
     * Exists for Microsoft, whose warranty data only appears after the tenant
     * has been *enrolled for scanning* — a state change inside the customer's
     * own Microsoft tenant, which a plugin should not make on its own the first
     * time a cron happens to run. Rendered as a button on the settings page.
     *
     * @return array<string,array{label:string,hint:string}>
     */
    public static function setupActions(): array;

    /**
     * Run one of {@see setupActions()}.
     *
     * @return string a message for the operator
     * @throws WarrantyException
     */
    public function runSetupAction(string $action): string;

    /**
     * Look up a batch.
     *
     * @param Subject[] $subjects at most {@see batchSize()} of them
     * @return array<string,Coverage> keyed by {@see Subject::key()}. A serial
     *         the vendor does not recognise is simply absent — that is not an
     *         error, it is the common case for kit bought through a reseller
     *         that never registered it.
     *
     * @throws WarrantyException when the batch as a whole failed
     */
    public function lookup(array $subjects): array;
}
