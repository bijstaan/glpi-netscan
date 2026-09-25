<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

/**
 * URLs for the plugin's own resources.
 *
 * GLPI 11 deprecated Plugin::getWebDir in favour of the plain `/plugins/` path,
 * but that path still has to be prefixed with root_doc so an installation in a
 * subdirectory works. Files under the plugin's `public/` directory are served
 * *without* the `public/` segment.
 */
final class Url
{
    public const KEY = 'glpinetscan';

    /**
     * Root-relative path, WITHOUT the root_doc prefix — what Html::css() and
     * Html::script() want, since they prepend root_doc themselves.
     */
    public static function path(string $path): string
    {
        return '/plugins/' . self::KEY . '/' . ltrim($path, '/');
    }

    /** Absolute URL including root_doc, for anything fetched from JavaScript. */
    public static function to(string $path): string
    {
        global $CFG_GLPI;

        return rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . self::path($path);
    }
}
