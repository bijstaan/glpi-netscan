<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan\Warranty;

/**
 * One HTTP round trip, as the vendor clients need it.
 *
 * An interface rather than a Guzzle client passed around directly, for one
 * reason that turned out to matter: every vendor here is behind a contract, a
 * paid support agreement or an NDA, so none of them can be exercised from a
 * test environment. A fixture transport replaying captured payloads is the
 * only way the seven clients get tested at all, and the seam has to be the
 * request rather than the client so that headers, bodies and query strings are
 * asserted too — those are exactly what goes wrong.
 */
interface Transport
{
    /**
     * @param array{
     *     query?: array<string,string|int>,
     *     json?: mixed,
     *     form?: array<string,string>,
     *     body?: string,
     *     headers?: array<string,string>
     * } $options
     *
     * @throws WarrantyException on transport failure only. A non-2xx response
     *         is returned, not thrown: several of these APIs answer "no such
     *         serial" with a 404 and a useful body, and one answers an
     *         exhausted quota with 403.
     */
    public function send(string $method, string $url, array $options = []): Reply;
}
