// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
/**
 * Put the "Port map" tab next to the ports it draws.
 *
 * The faceplate and core's "Network ports" table are two views of one thing,
 * and a tab bar that puts twenty entries between them makes them read as
 * unrelated features. The map belongs immediately before the table.
 *
 * This is done in the browser because GLPI has no server-side seam for it.
 * Core builds its tab list in CommonGLPI::defineTabs() and appends every
 * plugin tab afterwards, in defineAllTabs() — which is `final`, takes no
 * hook, and adds plugin tabs strictly last. registerStandardTab()'s `$order`
 * weight only sorts plugin tabs against each other, never against a core tab
 * added inside defineTabs(). Moving one list item is the whole of the
 * alternative, and it is done from a global script rather than from the tab's
 * own markup because the tab bar exists before any tab content is fetched,
 * and a device whose remembered tab is something else would otherwise never
 * be reordered at all.
 *
 * Guarded at every step: it does nothing unless both tabs are present and the
 * map is still after the ports table, so a GLPI release that ever orders this
 * itself, or an asset with no port tab, is left alone.
 */
(function () {
    'use strict';

    // Targets, not labels: `data-bs-target` is built from the tab's key
    // (CommonGLPI's own `tab-<key>-<rand>` id), which is stable, while the
    // label is translated and the trailing number is a count.
    var MAP = 'a[data-bs-target^="#tab-GlpiPlugin_Glpinetscan_PortMapTab_"]';
    var PORTS = 'a[data-bs-target^="#tab-NetworkPort_"]';

    document.addEventListener('DOMContentLoaded', function () {
        var nav = document.getElementById('tabspanel');
        if (!nav) {
            return;
        }

        var mapLink = nav.querySelector(MAP);
        var portsLink = nav.querySelector(PORTS);
        if (!mapLink || !portsLink) {
            return;
        }

        var mapItem = mapLink.closest('li');
        var portsItem = portsLink.closest('li');
        if (!mapItem || !portsItem || mapItem === portsItem) {
            return;
        }

        var items = Array.prototype.slice.call(nav.children);
        var from = items.indexOf(mapItem);
        var to = items.indexOf(portsItem);
        if (from < 0 || to < 0 || from < to) {
            return;
        }

        nav.insertBefore(mapItem, portsItem);
        reindexSelect(from, to);
    });

    /**
     * Keep the narrow-screen picker in step.
     *
     * Below the md breakpoint the tab bar is hidden and a <select> drives it
     * instead — and core switches tabs from it by POSITION
     * (`$('#tabspanel li a').eq($(this).val())`), so an option list left in
     * the old order does not merely look wrong on a phone, it opens the wrong
     * tab. The options are moved the same way and then renumbered.
     */
    function reindexSelect(from, to) {
        var select = document.getElementById('tabspanel-select');
        if (!select || select.options.length <= from) {
            return;
        }

        var options = Array.prototype.slice.call(select.options);
        var chosen = select.options[select.selectedIndex] || null;

        options.splice(to, 0, options.splice(from, 1)[0]);

        options.forEach(function (option, index) {
            option.value = String(index);
            select.appendChild(option);
        });

        if (chosen) {
            select.value = chosen.value;
        }
    }
})();
