<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * What came back, before anyone has decided whether it is good news.
 */
final class Reply
{
    /**
     * @param array<string,string> $headers lower-cased names
     */
    public function __construct(
        public readonly int $status,
        public readonly string $body,
        public readonly array $headers = []
    ) {
    }

    public function ok(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    /**
     * The body as an array.
     *
     * @throws WarrantyException when it is not JSON, or is a bare scalar —
     *         which is what a captive portal, a proxy error page or an HTML
     *         maintenance notice looks like, and is worth saying plainly
     *         rather than letting it surface later as "undefined index".
     */
    public function json(string $who): array
    {
        $decoded = json_decode($this->body, true);

        if (!is_array($decoded)) {
            throw new WarrantyException(
                WarrantyException::RESPONSE,
                sprintf('%s returned a body that is not JSON: %s', $who, self::clip($this->body)),
                $this->status
            );
        }

        return $decoded;
    }

    /** A short, single-line excerpt safe to put in a log or a status column. */
    public static function clip(string $body, int $limit = 200): string
    {
        $body = trim(preg_replace('/\s+/', ' ', $body) ?? $body);

        return mb_strlen($body) <= $limit ? $body : mb_substr($body, 0, $limit - 1) . '…';
    }
}
