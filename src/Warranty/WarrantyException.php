<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

use RuntimeException;

/**
 * A warranty lookup that did not produce an answer.
 *
 * The kind matters more than the message, because it decides what happens
 * next. A transport failure is retried on the following cron cycle; a
 * throttle backs the whole vendor off; an auth failure is a credential the
 * administrator has to fix, so retrying it every hour only burns the vendor's
 * rate limit and fills the log. Distinguishing them here is what lets the sync
 * loop react without parsing prose.
 */
final class WarrantyException extends RuntimeException
{
    /** Could not reach the vendor: DNS, TLS, connect or read timeout. */
    public const TRANSPORT = 'transport';

    /** Credentials rejected, expired or absent. Not retryable without a human. */
    public const AUTH = 'auth';

    /** The vendor asked us to slow down (HTTP 429, or its own quota message). */
    public const THROTTLED = 'throttled';

    /** Reached it, got something we cannot use. */
    public const RESPONSE = 'response';

    /** The plugin is missing a setting this vendor needs. */
    public const CONFIG = 'config';

    public function __construct(
        public readonly string $kind,
        string $message,
        public readonly int $status = 0
    ) {
        parent::__construct($message);
    }

    /** Is another attempt on the next cycle worth making? */
    public function isRetryable(): bool
    {
        return $this->kind === self::TRANSPORT || $this->kind === self::THROTTLED;
    }
}
