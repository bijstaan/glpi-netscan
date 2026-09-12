<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * Somewhere a vendor client can keep a credential it was issued at runtime.
 *
 * Only Apple needs this, and it needs it badly: GSX hands out an *activation*
 * token that can be exchanged exactly once for a session token, and the
 * session token is then the only way in until it lapses. Holding that in
 * memory for the length of a cron run would burn the activation token on the
 * first run and lock the instance out on the second.
 *
 * An interface rather than a direct write to `glpi_configs` so the Apple
 * client stays free of GLPI, and so the token round trip can be tested.
 */
interface TokenStore
{
    public function get(string $name): string;

    public function put(string $name, string $value): void;
}
