// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Verify the glpinetscan plugin's UI pages render and the API behaves.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const { fullPage } = require('./shot');
const { openDark, audit } = require('./dark');
const BASE = 'http://localhost:8081';
const SHOTS = process.env.SHOT_DIR || '.';
const DARK_SHOTS = path.join(SHOTS, 'dark');
const fail = [];
const check = (n, c, d) => { console.log(`${c?'PASS':'FAIL'}  ${n}${d?' :: '+String(d).slice(0,140):''}`); if(!c) fail.push(n); };

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1500,height:1100}});
  const errs=[]; p.on('pageerror',e=>errs.push(e.message));
  await p.goto(`${BASE}/`, {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');

  // Resolve real row ids: the plugin's tables are dropped on reinstall, so
  // hard-coded ids silently become 404s that look like broken pages.
  const firstId = async (listPath, formPath) => {
    await p.goto(BASE + listPath, { waitUntil: 'networkidle' });
    return await p.evaluate((fp) => {
      const a = Array.from(document.querySelectorAll('a'))
        .find(x => x.href.includes(fp) && /id=\d+/.test(x.href));
      return a ? (a.href.match(/id=(\d+)/) || [])[1] : null;
    }, formPath);
  };
  const targetId  = await firstId('/plugins/glpinetscan/front/target.php', 'target.form.php');
  const profileId = await firstId('/plugins/glpinetscan/front/oidprofile.php', 'oidprofile.form.php');

  const pages = {
    'config':      '/plugins/glpinetscan/front/config.php',
    'scanners':    '/plugins/glpinetscan/front/scanner.php',
    'targets':     '/plugins/glpinetscan/front/target.php',
    'oidprofiles': '/plugins/glpinetscan/front/oidprofile.php',
    'target form (new)': '/plugins/glpinetscan/front/target.form.php?id=0',
    'target form': `/plugins/glpinetscan/front/target.form.php?id=${targetId}`,
    'profile form':`/plugins/glpinetscan/front/oidprofile.form.php?id=${profileId}`,
    'scanner form':'/plugins/glpinetscan/front/scanner.form.php?id=1',
  };
  for (const [name, path] of Object.entries(pages)) {
    const r = await p.goto(BASE+path, {waitUntil:'networkidle'});
    const body = await p.evaluate(()=>document.body.innerText);
    const bad = /unexpected error|not been found|Fatal error/i.test(body);
    check(`${name} renders`, r.status()===200 && !bad, `HTTP ${r.status()}`);
  }

  // readiness panel content
  await p.goto(`${BASE}/plugins/glpinetscan/front/config.php`, {waitUntil:'networkidle'});
  // The shipped-profile list is a collapsed <details>, whose text innerText
  // omits until it is opened.
  await p.evaluate(()=>document.querySelectorAll('details').forEach(d=>d.open=true));
  await p.waitForTimeout(200);
  const txt = await p.evaluate(()=>document.body.innerText);
  check('readiness shows inventory state', /native inventory is enabled/i.test(txt), '');
  check('readiness shows import-rule state', /imported by MAC address|serial number will be imported/i.test(txt), '');
  check('shipped profiles listed', /Base \(standard MIBs\)/.test(txt) && /Printers/.test(txt), '');
  check('vendor packs loaded', /Cisco/.test(txt) && /Fortinet/.test(txt), '');
  check('UPS pack loaded', /UPS-MIB/.test(txt), '');
  check('power packs loaded', /rPDU2/.test(txt) && /Sentry3/.test(txt), '');
  check('VoIP packs loaded', /Yealink phone/.test(txt) && /Polycom phone/.test(txt), '');
  check('readiness reports power devices', /UPS and .* PDU tracked|No power devices/.test(txt), '');
  // The enrollment card has to be usable on its own: a key scoped to an
  // entity, and a command you can paste without hunting for the server URL.
  check('enrollment secret shown', /[0-9a-f]{40}/.test(txt), '');
  check('install command generated', /glpi-netscan install --server \S+ --secret [0-9a-f]{40}/.test(txt),
    (txt.match(/glpi-netscan install[^\n]{0,60}/)||[''])[0]);
  check('secret table shows entity + enrolments', /ENTITY|Entity/.test(txt) && /Enrolments/i.test(txt), '');
  const entityDefault = await p.evaluate(() => {
    const sel = document.querySelector('select[name="secret_entity"]');
    const o = sel && sel.options[sel.selectedIndex];
    return o ? o.textContent.trim() : null;
  });
  check('new-key entity defaults to the active entity', entityDefault !== null, entityDefault);
  check('profiles reference is collapsed', /Show all \d+ profiles/.test(txt), '');
  await p.screenshot({path:`${SHOTS}/netscan-01-config.png`, fullPage:true});

  // profile form exposes the new sections
  await p.goto(`${BASE}/plugins/glpinetscan/front/oidprofile.form.php?id=${profileId}`, {waitUntil:'networkidle'});
  const form = await p.evaluate(()=>document.body.innerText);
  check('profile form offers collectors', /fdb/.test(form) && /lldp/.test(form) && /vlans/.test(form), '');
  check('profile form offers topology overrides', /dot1d_fdb_port/.test(form), '');
  await p.screenshot({path:`${SHOTS}/netscan-03-profile.png`, fullPage:true});

  // the imported asset
  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const list = await p.evaluate(()=>document.body.innerText);
  check('imported switch listed', /core-sw-01/.test(list), '');
  await p.screenshot({path:`${SHOTS}/netscan-02-asset.png`});

  // power devices become native GLPI PDU assets with a state tab
  await p.goto(`${BASE}/front/pdu.php`, {waitUntil:'networkidle'});
  const pdus = await p.evaluate(()=>document.body.innerText);
  check('UPS imported as a PDU asset', /ups-mdf-01/.test(pdus), '');
  check('rack PDU imported', /pdu-mdf-a/.test(pdus), '');

  const pduId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x=>/pdu-mdf-a/.test(x.textContent));
    return a ? (a.href.match(/id=(\d+)/)||[])[1] : null;
  });
  if (pduId) {
    await p.goto(`${BASE}/front/pdu.form.php?id=${pduId}`, {waitUntil:'networkidle'});
    const tabs = await p.evaluate(()=>Array.from(document.querySelectorAll('a')).map(a=>a.textContent.trim()));
    check('Power state tab present', tabs.some(t=>/Power state/i.test(t)), '');
    await p.click('a:has-text("Power state")');
    await p.waitForTimeout(1200);
    const tab = await p.evaluate(()=>document.body.innerText);
    check('outlets listed on tab', /Outlets \(8\)/.test(tab) && /esxi-01 PSU A/.test(tab), '');
    check('sensors listed on tab', /Inlet temperature/.test(tab) && /22\.3/.test(tab), '');

    // A real UPS/PDU reaches the network through a management card. Without
    // its port the asset records no way to reach the device, and the switch
    // that learns its MAC has nothing to wire to.
    const pduOptInSetting = await p.evaluate(async (base) => {
      const r = await fetch(base + '/plugins/glpinetscan/front/config.php', {credentials:'same-origin'});
      const html = await r.text();
      return /name=['"]pdu_in_asset_types['"][^>]*checked/.test(html);
    }, BASE);

    await p.goto(`${BASE}/front/pdu.form.php?id=${pduId}`, {waitUntil:'networkidle'});
    await p.click('a:has-text("Network ports")');
    await p.waitForTimeout(1200);
    const ports = await p.evaluate(()=>document.body.innerText);
    check('management port on PDU', /eth0/.test(ports), '');
    // Whether the switch links to the PDU *asset* depends on the opt-in
    // setting: GLPI only matches forwarding-table MACs against asset_types,
    // which excludes PDU. Assert whichever behaviour the setting selects, so
    // this passes on a default install and still catches a real break.
    if (pduOptInSetting) {
      check('PDU port wired to the switch', /core-sw-01/.test(ports), 'opt-in on');
    } else {
      check('PDU port present (wiring is opt-in)', /eth0/.test(ports), 'opt-in off');
    }

    // MAC and IP are form field values, not rendered text — the list's default
    // columns show the *peer* MAC, which is a different thing entirely.
    const portHref = await p.evaluate(() => {
      const a = Array.from(document.querySelectorAll('a'))
        .find(x => /networkport\.form\.php\?id=\d+/.test(x.href));
      return a ? a.href : null;
    });
    if (portHref) {
      await p.goto(portHref, {waitUntil:'networkidle'});
      await p.waitForTimeout(600);
      const f = await p.evaluate(() => {
        const v = {};
        document.querySelectorAll('input').forEach(i => { if (i.name && i.value) v[i.name] = i.value; });
        return v;
      });
      check('management MAC recorded', /^00:c0:b7:/.test(f.mac || ''), f.mac);
      check('management IP recorded',
        Object.entries(f).some(([k, v]) => /ipaddresses/.test(k) && /^10\.10\.10\./.test(v)),
        Object.entries(f).filter(([k]) => /ipaddresses/.test(k)).map(([, v]) => v).join(','));
      check('port typed as Ethernet on the PDU',
        f.itemtype === 'PDU' && f.instantiation_type === 'NetworkPortEthernet',
        `${f.itemtype}/${f.instantiation_type}`);
    } else {
      check('management MAC recorded', false, 'no port form link');
    }
    await p.screenshot({path:`${SHOTS}/netscan-04-power.png`, fullPage:true});
  } else {
    check('Power state tab present', false, 'no PDU link found');
  }

  // VoIP handsets become native Phone assets
  await p.goto(`${BASE}/front/phone.php`, {waitUntil:'networkidle'});
  const phones = await p.evaluate(()=>document.body.innerText);
  check('phone imported as a Phone asset', /phone-1042/.test(phones), '');
  const phoneId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x=>/phone-1042/.test(x.textContent));
    return a ? (a.href.match(/id=(\d+)/)||[])[1] : null;
  });
  if (phoneId) {
    // forcetab for the same reason as the access point below: GLPI remembers
    // the active tab per itemtype, so reading main-form fields must say so.
    await p.goto(`${BASE}/front/phone.form.php?id=${phoneId}&forcetab=Phone$main`,
                 {waitUntil:'networkidle'});
    const f = await p.evaluate(() => {
      const v = {}; document.querySelectorAll('input').forEach(i=>{ if(i.name&&i.value) v[i.name]=i.value; });
      const sel = {}; document.querySelectorAll('select').forEach(s=>{
        const o = s.options[s.selectedIndex]; if (o) sel[s.name] = o.textContent.trim();
      });
      return {v, sel, text: document.body.innerText};
    });
    check('phone serial recorded', f.v.serial === '8801234567890', f.v.serial);
    check('phone brand recorded', /Yealink/.test(f.v.brand || ''), f.v.brand);
    // A desk phone reports two interfaces: the switch uplink and the PC
    // passthrough port the user's computer plugs into.
    await p.click('a:has-text("Network ports")');
    await p.waitForTimeout(1200);
    const pp = await p.evaluate(()=>document.body.innerText);
    check('phone uplink + PC port recorded', /eth0/.test(pp) && /eth1/.test(pp), '');
    check('phone wired to the switch', /core-sw-01/.test(pp), '');
    await p.screenshot({path:`${SHOTS}/netscan-06-phone.png`, fullPage:true});
  } else {
    check('phone serial recorded', false, 'no phone link');
  }

  // --- LLDP-MED inventory ------------------------------------------------
  // Devices the scanner never spoke to. phone-1055 and the lobby camera have no
  // simulator at all: everything recorded about them was read out of the switch
  // they are plugged into, over LLDP-MED.
  check('phone reachable only over LLDP-MED imported', /phone-1055/.test(phones), '');
  // ...and exactly once, though the switch reports phone-1042 over MED as well
  // as the handset answering SNMP directly.
  check('handset seen twice is one asset',
        (phones.match(/phone-1042/g) || []).length === 1,
        `${(phones.match(/phone-1042/g) || []).length} rows`);

  // Back to the list: the block above navigated away to the handset's form.
  await p.goto(`${BASE}/front/phone.php`, {waitUntil:'networkidle'});
  const medId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x=>/phone-1055/.test(x.textContent));
    return a ? (a.href.match(/id=(\d+)/)||[])[1] : null;
  });
  if (medId) {
    await p.goto(`${BASE}/front/phone.form.php?id=${medId}&forcetab=Phone$main`,
                 {waitUntil:'networkidle'});
    const m = await p.evaluate(() => {
      const v = {}; document.querySelectorAll('input').forEach(i=>{ if(i.name&&i.value) v[i.name]=i.value; });
      const sel = {}; document.querySelectorAll('select').forEach(x=>{
        const o = x.options[x.selectedIndex]; if (o) sel[x.name] = o.textContent.trim();
      });
      return {v, sel};
    });
    // The payoff: an inventory record for a handset the scanner never spoke to,
    // identified well enough to raise an RMA against.
    check('MED phone serial from the switch', m.v.serial === '8C4470112233', m.v.serial);
    check('MED phone brand from the switch', /Polycom/.test(m.v.brand || ''), m.v.brand);
    check('MED phone asset tag from the switch', m.v.otherserial === 'AST-4488', m.v.otherserial);
    check('MED phone model from the switch', /VVX 411/.test(m.sel.phonemodels_id || ''), m.sel.phonemodels_id);
    await p.screenshot({path:`${SHOTS}/netscan-09-lldp-med.png`, fullPage:true});
  } else {
    check('MED phone serial from the switch', false, 'no phone-1055 link');
  }

  // The lobby camera is inventoried over MED too, and advertises no voice
  // policy. Nothing here is entitled to call it a phone.
  check('non-voice MED endpoint is not filed as a phone', !/P3245/.test(phones), '');

  // --- SNMP notifications ----------------------------------------------
  // A trap is the fastest change signal there is: the device says it changed
  // rather than the scanner inferring it from counters at sweep time. What a
  // trap must never do is assert anything about the asset, because a v1/v2c
  // notification is an unauthenticated datagram.
  await p.goto(`${BASE}/plugins/glpinetscan/front/config.php`, {waitUntil:'networkidle'});
  const cfgTraps = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
  check('notification settings present', /SNMP notifications \(traps\)/.test(cfgTraps), '');
  check('settings state the forgery risk plainly',
        /unauthenticated datagram and is trivially forged/i.test(cfgTraps), '');
  check('settings explain the capability needed for port 162',
        /capability the packaged systemd unit does not grant/i.test(cfgTraps), '');

  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const trapSwId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'core-sw-01');
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });
  if (trapSwId) {
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${trapSwId}`, {waitUntil:'networkidle'});
    const trapTabs = await p.evaluate(() =>
      Array.from(document.querySelectorAll('a[href*=forcetab]')).map(a => a.textContent.trim()));
    const hasTrapTab = trapTabs.some(t => /Notification/i.test(t));
    check('notifications tab on a device that has sent one', hasTrapTab,
          trapTabs.filter(t => /Notif/i.test(t)).join());

    if (hasTrapTab) {
      // Clicked by its forcetab href, not by text: GLPI's own global menu has a
      // "Notifications" entry too, and matching on text lands on Setup instead.
      await p.locator('a[href*="forcetab"]', {hasText: /Notification/i}).first().click();
      await p.waitForTimeout(1800);
      const tt = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
      // Named rather than shown as bare arcs: 1.3.6.1.6.3.1.1.5.3 tells an
      // operator nothing, linkDown tells them what happened.
      check('notification shown by name', /linkDown/.test(tt), '');
      check('tab says notifications are not written into the asset',
            /nothing here is written into the asset/i.test(tt), '');
    }
  } else {
    check('notifications tab on a device that has sent one', false, 'core-sw-01 not found');
  }

  // --- device control --------------------------------------------------
  // The only part of the plugin that writes to hardware, so the checks are
  // about the gates as much as the function: off by default, hidden when off,
  // and refusing an unconfirmed action when on.
  const setControl = async (on) => {
    await p.goto(`${BASE}/plugins/glpinetscan/front/config.php`, {waitUntil:'networkidle'});
    const box = p.locator('input[name="allow_control"]');
    if (await box.isChecked() !== on) { await box.setChecked(on); }
    await p.locator('form', {has: box}).locator('button[name="update"]').click();
    await p.waitForLoadState('networkidle');
  };

  const swCtlId = await (async () => {
    await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
    return p.evaluate(() => {
      const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'core-sw-01');
      return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
    });
  })();

  await setControl(false);
  await p.goto(`${BASE}/front/networkequipment.form.php?id=${swCtlId}`, {waitUntil:'networkidle'});
  const tabsOff = await p.evaluate(() =>
    Array.from(document.querySelectorAll('a[href*=forcetab]')).map(a => a.textContent.trim()));
  check('no control tab while device control is off',
        !tabsOff.some(t => /^Control/.test(t)), tabsOff.filter(t => /Control/.test(t)).join());

  await setControl(true);
  await p.goto(`${BASE}/front/networkequipment.form.php?id=${swCtlId}`, {waitUntil:'networkidle'});
  const tabsOn = await p.evaluate(() =>
    Array.from(document.querySelectorAll('a[href*=forcetab]')).map(a => a.textContent.trim()));
  check('control tab appears once enabled', tabsOn.some(t => /^Control/.test(t)), '');

  if (tabsOn.some(t => /^Control/.test(t))) {
    await p.click('a:has-text("Control")');
    await p.waitForTimeout(2000);
    const ctl = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
    check('control tab states what shutting a port risks', /cut a site off/i.test(ctl), '');
    check('every port offers a typed confirmation',
          (await p.locator('input[name=control_confirm]').count()) > 0, '');

    // A confirmation that does not match the row must change nothing. This is
    // the guard against acting on the wrong line of a table, which a
    // click-through "are you sure?" does not prevent.
    const row = p.locator('form', {has: p.locator('input[name=control_confirm]')}).first();
    await row.locator('input[name=control_confirm]').fill('definitely-not-the-port');
    await row.locator('button[value=down]').click();
    await p.waitForLoadState('networkidle');
    const refused = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
    check('a mistyped confirmation changes nothing', /Nothing was changed/i.test(refused),
          (refused.match(/Nothing was changed[^.]{0,40}/) || [''])[0]);
  }

  // --- discovery / inventory split -------------------------------------
  // The scanner probes every address cheaply on every pass and only walks a
  // device in full when GLPI says it is worth it. The saving is real: a full
  // walk costs 86-157x a probe even against these simulators.
  await p.goto(`${BASE}/plugins/glpinetscan/front/target.form.php?id=${targetId}`, {waitUntil:'networkidle'});
  const targetForm = await p.evaluate(() => {
    const v = {}; document.querySelectorAll('input').forEach(i => { if (i.name) v[i.name] = i.value; });
    return {v, text: document.body.innerText.replace(/\s+/g, ' ')};
  });
  check('target has a full-inventory interval',
        'inventory_interval' in targetForm.v, Object.keys(targetForm.v).join(','));
  check('the two intervals are distinguishable in the UI',
        /Discovery interval/.test(targetForm.text) && /Full inventory at least every/.test(targetForm.text), '');

  // The run history is where an operator sees the split working: a sweep that
  // probes everything and walks nothing is the point, and one that walks
  // everything every time means the signals are not reaching that hardware.
  await p.goto(`${BASE}/plugins/glpinetscan/front/target.form.php?id=1`, {waitUntil:'networkidle'});
  const runs = await p.evaluate(() => {
    const t = Array.from(document.querySelectorAll('table')).find(x => /Walked in full/i.test(x.innerText));
    return t ? t.innerText.replace(/\s+/g, ' ') : '(no run history table)';
  });
  check('run history separates probing from walking',
        /addresses probed in \d+/.test(runs), runs.slice(0, 110));
  // A sweep whose message stops at "answered" walked nothing at all — the
  // split working, and the number an operator tunes the interval against.
  check('the walked column is recorded per sweep',
        /WALKED IN FULL/i.test(runs), runs.slice(0, 60));

  // --- link aggregation ------------------------------------------------
  // GLPI ships ieee8023adLag(161) as not importable, so a port-channel is
  // silently discarded before its member list is ever read. The plugin switches
  // the type on at install; without that this whole section is empty.
  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const swAggId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'core-sw-01');
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });

  if (swAggId) {
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${swAggId}`, {waitUntil:'networkidle'});
    await p.click('a:has-text("Network ports")');
    await p.waitForTimeout(2000);
    const portText = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));

    check('port-channel imported at all', /Port-channel1/.test(portText),
          'ieee8023adLag is not importable in a stock GLPI');
    // The members must still be ordinary ethernet ports in their own right.
    check('aggregate members still present as ports',
          /GigabitEthernet0\/1/.test(portText) && /GigabitEthernet0\/4/.test(portText), '');
  } else {
    check('port-channel imported at all', false, 'core-sw-01 not found');
  }

  // --- port map --------------------------------------------------------
  // The faceplate. Everything it draws is core's own port data, so the checks
  // are about the drawing: that the layout is the arrangement of the sockets
  // rather than a list, that switching what the colours mean re-colours
  // without a round trip, and that a port's VLANs and neighbour are one click
  // away rather than one tab away.
  if (swAggId) {
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${swAggId}`, {waitUntil: 'networkidle'});

    // Core has no hook for tab order — plugin tabs are appended last, always —
    // so the map sitting next to the table it is a picture of is done by
    // moving one list item at load. Checked because it is the kind of DOM edit
    // a GLPI release can quietly break.
    const navOrder = await p.evaluate(() => Array.from(
      document.querySelectorAll('#tabspanel > li a')
    ).map(a => a.textContent.trim()));
    const mapAt = navOrder.findIndex(t => /^Port map/.test(t));
    const portsAt = navOrder.findIndex(t => /^Network ports/.test(t));
    check('port map tab present', mapAt >= 0, navOrder.slice(0, 3).join());
    check('port map sits immediately before the ports table',
          mapAt >= 0 && portsAt === mapAt + 1, `map ${mapAt}, ports ${portsAt}`);

    // The narrow-screen picker switches tabs by POSITION, so a reordered bar
    // with an unrenumbered <select> opens the wrong tab on a phone.
    const selAligned = await p.evaluate(() => {
      const opts = document.querySelectorAll('#tabspanel-select option');
      return Array.from(document.querySelectorAll('#tabspanel > li')).every((li, i) =>
        opts[i] && String(opts[i].value) === String(i)
        && opts[i].textContent.trim().startsWith(
          (li.querySelector('a').textContent.trim().split(' ')[0])));
    });
    check('the narrow-screen tab picker was renumbered with it', selAligned, '');

    if (mapAt >= 0) {
      await p.locator('a[href*="forcetab"]', {hasText: /^Port map/}).first().click();
      await p.waitForTimeout(2000);

      const face = await p.evaluate(() => {
        const root = document.querySelector('.glpinetscan-portmap');
        if (!root) { return null; }
        const tiles = Array.from(root.querySelectorAll('.glpinetscan-port'));
        const byName = (n) => tiles.find(t => t.title.startsWith(n + ' '));
        const box = (t) => t ? t.getBoundingClientRect() : null;
        return {
          mode: root.dataset.mode,
          tiles: tiles.length,
          modules: Array.from(root.querySelectorAll('.glpinetscan-module-label'))
            .map(x => x.textContent.trim()),
          summary: root.querySelector('[data-portmap-summary]').innerText.replace(/\s+/g, ' '),
          one: box(byName('GigabitEthernet0/1')),
          two: box(byName('GigabitEthernet0/2')),
          three: box(byName('GigabitEthernet0/3')),
          trunk: byName('GigabitEthernet0/4')?.dataset.trunk,
          upFill: getComputedStyle(byName('GigabitEthernet0/1')).backgroundColor,
          rows: root.querySelectorAll('details tbody tr').length,
        };
      });

      check('faceplate rendered', face !== null, '');
      if (face) {
        // Port 2 below port 1, port 3 to the right of port 1: the physical
        // arrangement, which is the whole reason this is a picture. A list
        // would put 2 to the right of 1 and nothing below anything.
        check('ports are laid out two to a column, as on the box',
              face.two.top > face.one.top && face.three.left > face.one.left
              && Math.abs(face.three.top - face.one.top) < 2,
              `1@${face.one.top}/${face.one.left} 2@${face.two.top} 3@${face.three.left}`);
        // The aggregate and the management port have no socket on the front
        // and must not be drawn as if they did.
        check('logical interfaces are kept off the faceplate',
              face.modules.some(m => /Logical/i.test(m)) && face.modules.length >= 2,
              face.modules.join());
        check('the summary counts the ports', /\d+ ports/.test(face.summary), face.summary.slice(0, 60));
        check('a trunk is marked as one', face.trunk === '1', face.trunk);
        check('every port is also in the table', face.rows === face.tiles, `${face.rows}/${face.tiles}`);
      }

      // Switching what the colours mean is an attribute change, not a reload:
      // every mode's answer is already on every tile.
      const vlanMode = await p.evaluate(() => {
        document.querySelector('[data-portmap-mode="vlan"]').click();
        const root = document.querySelector('.glpinetscan-portmap');
        const legend = root.querySelector('.glpinetscan-legend[data-legend="vlan"]');
        const tile = Array.from(root.querySelectorAll('.glpinetscan-port'))
          .find(t => t.title.startsWith('GigabitEthernet0/3 '));
        return {
          mode: root.dataset.mode,
          legendShown: getComputedStyle(legend).display !== 'none',
          legend: legend.innerText.replace(/\s+/g, ' '),
          vlanOnTile: tile.querySelector('[data-for="vlan"]').textContent.trim(),
          fill: getComputedStyle(tile).backgroundColor,
        };
      });
      check('VLAN mode names the VLANs it colours by',
            vlanMode.legendShown && /voice/.test(vlanMode.legend), vlanMode.legend.slice(0, 70));
      check('a port shows the VLAN an untagged device would land in',
            vlanMode.vlanOnTile === '20', vlanMode.vlanOnTile);
      await p.mouse.move(0, 0);
      await p.screenshot({path: `${SHOTS}/netscan-10-portmap-vlan.png`, fullPage: true});

      // Clicking a port is what turns "port 3 is up" into "port 3 is the
      // handset on desk 14", which is the question the view exists for.
      const detail = await p.evaluate(() => {
        const root = document.querySelector('.glpinetscan-portmap');
        Array.from(root.querySelectorAll('.glpinetscan-port'))
          .find(t => t.title.startsWith('GigabitEthernet0/3 ')).click();
        const open = Array.from(root.querySelectorAll('[data-detail-for]')).filter(d => !d.hidden);
        return open.map(d => d.innerText.replace(/\s+/g, ' '));
      });
      check('exactly one port detail is open at a time', detail.length === 1, `${detail.length} open`);
      await p.mouse.move(0, 0);
      await p.screenshot({path: `${SHOTS}/netscan-10-portmap.png`, fullPage: true});
      check('the detail names the port\'s VLAN and its state',
            detail.length === 1 && /voice/.test(detail[0]) && /Up/.test(detail[0]),
            (detail[0] || '').slice(0, 90));

      // Refreshing rebuilds the map from the same renderer the tab used, so a
      // reload must not lose the selection or leave an error banner behind.
      await p.click('[data-portmap-refresh]');
      await p.waitForTimeout(1500);
      const after = await p.evaluate(() => {
        const root = document.querySelector('.glpinetscan-portmap');
        return {
          tiles: root.querySelectorAll('.glpinetscan-port').length,
          failed: !!root.querySelector('.alert'),
          stillSelected: root.querySelectorAll('.glpinetscan-port.selected').length,
          mode: root.dataset.mode,
        };
      });
      check('refresh redraws the map', after.tiles === (face ? face.tiles : 0) && !after.failed,
            JSON.stringify(after));
      check('refresh keeps the port being watched selected', after.stillSelected === 1,
            String(after.stillSelected));
      check('refresh keeps the chosen colouring', after.mode === 'vlan', after.mode);
    }
  }

  // --- wireless --------------------------------------------------------
  // One scanned address has to produce many assets. The access points behind a
  // controller do not answer SNMP at all — the controller is the only place
  // they exist — but each is a serial-numbered box somebody tracks and replaces.
  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const gear = await p.evaluate(() => document.body.innerText);
  check('controller imported', /wlc-hq-01/.test(gear), '');
  for (const ap of ['ap-floor1-north', 'ap-floor1-south', 'ap-floor2-lab', 'ap-warehouse']) {
    check(`access point imported: ${ap}`, new RegExp(ap).test(gear), '');
  }

  const apId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'ap-floor1-north');
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });

  if (apId) {
    // forcetab is not optional here. GLPI remembers the active tab *per
    // itemtype in the session*, so once any earlier check has clicked "Network
    // ports" on a network device, every network device form opens on that tab —
    // and the fields below are not on it. Without this the check passes or
    // fails depending on what ran before it.
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${apId}&forcetab=NetworkEquipment$main`,
                 {waitUntil:'networkidle'});
    // Read form inputs, not innerText: GLPI renders asset fields as editable
    // values, so the serial is in an input and never appears in the page text.
    const apForm = await p.evaluate(() => {
      const v = {}; document.querySelectorAll('input').forEach(i => { if (i.name && i.value) v[i.name] = i.value; });
      return {v, text: document.body.innerText.replace(/\s+/g, ' ')};
    });
    // Serial, model and location are what make an AP an asset rather than a
    // statistic: they are what gets RMA'd, ordered and walked to.
    check('AP carries its serial', apForm.v.serial === 'FGL2145X1AA', apForm.v.serial);
    check('AP carries its model', /AIR-AP2802I-E-K9/.test(apForm.text), '');
    check('AP carries its location', /Floor 1, north corridor/.test(apForm.text), '');

    // The AP's own management port, built from the MAC and address the
    // controller reported for it.
    await p.click('a:has-text("Network ports")');
    await p.waitForTimeout(1500);
    const apPorts = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
    check('AP management port recorded',
          /00:c0:b7:e1:00:11/.test(apPorts) && /10\.10\.20\.11/.test(apPorts),
          apPorts.slice(0, 100));
  } else {
    check('AP carries its serial', false, 'ap-floor1-north not found');
  }

  // The payoff, checked from the switch side where GLPI renders the link: an AP
  // that never answered SNMP is wired to the port it is physically plugged
  // into, because the controller reported the same Ethernet MAC the switch had
  // learned. Without that, GLPI would invent an Unmanaged asset for a device it
  // already has.
  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const swId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'core-sw-01');
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });
  if (swId) {
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${swId}`, {waitUntil:'networkidle'});
    await p.click('a:has-text("Network ports")');
    await p.waitForTimeout(2000);
    const swPorts = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
    check('switch port wired to the access point',
          /ap-floor1-north/.test(swPorts), swPorts.slice(0, 120));
  } else {
    check('AP carries its serial', false, 'ap-floor1-north not found');
  }

  // An AP reporting no serial must still be one asset, not a new one per scan.
  const warehouse = (gear.match(/ap-warehouse/g) || []).length;
  check('serial-less AP is not duplicated', warehouse <= 1, `${warehouse} occurrences`);

  // Per-AP client counts are summed from a radio table indexed one arc finer
  // than the AP table, so these numbers exist nowhere on the wire: 9+14=23 and
  // 4+7=11. A wrong correlation would put one radio's clients on another AP.
  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const wlcId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'wlc-hq-01');
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });
  if (wlcId) {
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${wlcId}`, {waitUntil:'networkidle'});
    const hasTab = await p.evaluate(() =>
      Array.from(document.querySelectorAll('a[href*=forcetab]')).some(a => /Wireless/i.test(a.textContent)));
    check('wireless tab on the controller', hasTab, '');

    if (hasTab) {
      await p.click('a:has-text("Wireless")');
      await p.waitForTimeout(2000);
      const tab = await p.evaluate(() => Array.from(document.querySelectorAll('table'))
        .map(t => t.innerText.replace(/\s+/g, ' ')).join(' | '));

      check('SSIDs listed with client counts', /corp-secure 143/.test(tab) && /corp-iot 61/.test(tab), '');
      check('per-AP client total summed from its radios',
            /ap-floor1-north .*? 23 /.test(tab), (tab.match(/ap-floor1-north[^|]{0,80}/) || [''])[0]);
      check('second AP summed independently', /ap-floor1-south .*? 11 /.test(tab), '');
      check('per-radio band and channel shown',
            /2\.4GHz\), ch 6, 9 clients, up/.test(tab), '');
      check('a down AP shows down radios and no clients',
            /ap-floor2-lab .*? disassociated 0/.test(tab) && /ch 36, 0 clients, down/.test(tab), '');
    }
  } else {
    check('wireless tab on the controller', false, 'wlc-hq-01 not found');
  }

  // Radios become wifi ports on the AP's own asset — GLPI models a radio as a
  // NetworkPort whose instantiation is NetworkPortWifi, with the 802.11
  // flavour as its version.
  const northId = await p.evaluate(() => null);
  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const apId2 = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'ap-floor1-north');
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });
  if (apId2) {
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${apId2}`, {waitUntil:'networkidle'});
    await p.click('a:has-text("Network ports")');
    await p.waitForTimeout(1800);
    const rp = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
    check('AP radios recorded as wifi ports', /radio0/.test(rp) && /radio1/.test(rp), '');
  } else {
    check('AP radios recorded as wifi ports', false, 'ap-floor1-north not found');
  }

  // The standalone shape: a UniFi AP has no AP table at all, so it is the asset
  // and the networks it broadcasts belong to it. The same SSID appears once per
  // radio in its VAP table and must be folded, not double-counted: 8 + 12 = 20.
  await p.goto(`${BASE}/front/networkequipment.php`, {waitUntil:'networkidle'});
  const uapId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.trim() === 'uap-branch-01');
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });
  check('standalone AP imported', !!uapId, '');
  if (uapId) {
    await p.goto(`${BASE}/front/networkequipment.form.php?id=${uapId}`, {waitUntil:'networkidle'});
    await p.click('a:has-text("Wireless")');
    await p.waitForTimeout(1800);
    // Read the SSID table specifically. Joining every table on the page makes a
    // failure message point at whichever table happened to mention the name.
    const utab = await p.evaluate(() => {
      const t = Array.from(document.querySelectorAll('table')).find(x => /SSID/i.test(x.innerText));
      return t ? t.innerText.replace(/\s+/g, ' ') : '(no SSID table)';
    });
    check('standalone AP folds one SSID across its radios', /corp-secure 20/.test(utab), utab.slice(0, 80));
    check('standalone AP lists no access points of its own', !/ap-floor/.test(utab), '');
  }

  // --- printers --------------------------------------------------------
  // Supply levels come from the standard Printer MIB, so no vendor OIDs and no
  // per-model profile are involved: if this works on the fixture it works on
  // any printer that implements RFC 3805 properly.
  const printerRow = await p.goto(`${BASE}/front/printer.php`, {waitUntil:'networkidle'});
  const printerList = await p.evaluate(() => document.body.innerText);
  check('MFP imported as a Printer', /printer-acct-01/.test(printerList), '');
  check('inkjet imported as a Printer despite no page counter',
        /printer-reception-02/.test(printerList),
        'classification falls back to the marker supplies table');

  const printerId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.includes('printer-acct-01'));
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });

  if (printerId) {
    await p.goto(`${BASE}/front/printer.form.php?id=${printerId}&forcetab=Cartridge$1`, {waitUntil:'networkidle'});
    await p.waitForTimeout(2000);
    const supplies = await p.evaluate(() => {
      const t = Array.from(document.querySelectorAll('table'))
        .find(t => /toner/i.test(t.innerText));
      return t ? t.innerText.replace(/\s+/g, ' ') : '';
    });

    // Values derived from level/capacity in tenths of grams (7400/10000) and
    // read directly where the unit is already percent.
    check('toner levels recorded', /Toner Black 74%/.test(supplies), supplies.slice(0, 90));
    check('a nearly-empty toner is visible', /Toner Yellow 3%/.test(supplies), '');
    check('drum levels recorded', /Drum Black 88%/.test(supplies), '');
    check('a supply typed other\u0028\u0029 is identified by description',
          /Maintenance kit 60%/.test(supplies), '');
    check('non-percentage units still resolve', /Staples 30%/.test(supplies), '');

    // The point of the whole exercise. The fixture's waste bottle reports
    // unknown(-2) and its fuser reports someRemaining(-3); both must be absent
    // rather than reported as 0%, which would read as empty — and would bury
    // the genuinely empty yellow toner in a list where everything looks empty.
    check('a supply with an unknown level is omitted, not shown as 0%',
          !/Waste/i.test(supplies), supplies.slice(0, 120));
    check('a someRemaining supply is omitted, not shown as 0%',
          !/Fuser/i.test(supplies), '');
  } else {
    check('toner levels recorded', false, 'printer-acct-01 not found');
  }

  const inkjetId = await p.evaluate(() => null);
  await p.goto(`${BASE}/front/printer.php`, {waitUntil:'networkidle'});
  const inkId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x => x.textContent.includes('printer-reception-02'));
    return a ? (a.getAttribute('href').match(/id=(\d+)/) || [])[1] : null;
  });
  if (inkId) {
    await p.goto(`${BASE}/front/printer.form.php?id=${inkId}&forcetab=Cartridge$1`, {waitUntil:'networkidle'});
    await p.waitForTimeout(2000);
    const inks = await p.evaluate(() => {
      const t = Array.from(document.querySelectorAll('table'))
        .find(t => /cartridge|ink/i.test(t.innerText) && /%/.test(t.innerText));
      return t ? t.innerText.replace(/\s+/g, ' ') : '';
    });
    // This device has no colorant table at all: the colour has to be parsed
    // out of "Cyan Ink LC427XLC".
    check('ink colours parsed from the description alone',
          /Cyan 20%/.test(inks) && /Yellow 5%/.test(inks), inks.slice(0, 100));
  } else {
    check('ink colours parsed from the description alone', false, 'inkjet not found');
  }

  // --- self-update -----------------------------------------------------
  // The settings page is the whole operator interface for updates, so the
  // controls have to be there and the publish form has to actually validate.
  await p.goto(`${BASE}/plugins/glpinetscan/front/config.php`, {waitUntil:'networkidle'});
  const cfgText = await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
  for (const label of ['Scanner updates', 'Rollout percentage', 'Published packages', 'Publish a release']) {
    check(`settings page has "${label}"`, cfgText.includes(label), '');
  }

  const publish = async (fields) => {
    await p.goto(`${BASE}/plugins/glpinetscan/front/config.php`, {waitUntil:'networkidle'});
    for (const [name, value] of Object.entries(fields)) {
      await p.fill(`[name="${name}"]`, value).catch(() => p.selectOption(`[name="${name}"]`, value));
    }
    await p.click('button[name="publish_package"]');
    await p.waitForLoadState('networkidle');
    return (await p.evaluate(() => document.body.innerText.replace(/\s+/g, ' ')));
  };

  const sha = 'a'.repeat(64);
  // A plain-HTTP package URL must be refused. The checksum means an attacker
  // could not plant a payload over http, but it would let anyone on the path
  // see which version every machine is fetching.
  let out = await publish({pkg_version: '9.9.98', pkg_url: 'http://example.com/glpi-netscan',
                           pkg_sha256: sha, pkg_size: '1234'});
  check('publish rejects a non-https URL', /must be https/i.test(out),
        (out.match(/must be[^.]{0,40}/) || [''])[0]);

  out = await publish({pkg_version: '9.9.98', pkg_url: 'https://example.com/glpi-netscan',
                       pkg_sha256: 'nothex', pkg_size: '1234'});
  check('publish rejects a malformed checksum',
        /64 hexadecimal|hexadecimal characters/i.test(out) || !/Package published/i.test(out), '');

  out = await publish({pkg_version: '9.9.98', pkg_url: 'https://example.com/glpi-netscan',
                       pkg_sha256: sha, pkg_size: '10485760'});
  check('publish accepts a well-formed release', /Package published/i.test(out), '');
  check('published release listed', /9\.9\.98/.test(out), '');

  // Withdraw it again so the check leaves nothing behind that a scanner in the
  // dev stack would then be offered.
  // Clicked through a locator rather than in-page JS: the click navigates, and
  // an evaluate() that submits a form loses its execution context mid-call.
  const row = p.locator('tr', {hasText: '9.9.98'}).first();
  if (await row.count()) {
    await row.locator('button[name="withdraw_package"]').click();
    await p.waitForLoadState('networkidle');
    const after = await p.evaluate(() => document.body.innerText);
    check('withdraw removes the release', !/9\.9\.98/.test(after), '');
  } else {
    check('withdraw removes the release', false, 'no row to withdraw');
  }

  // --- navigation ------------------------------------------------------
  // Every managed object needs its own reachable menu entry: burying targets
  // behind the scanner list is how "there is no way to set IP ranges" happens.
  //
  // The *sector* is asserted, not just the presence of a link. GLPI splits
  // Administration (operational data) from Setup (how the instance is
  // configured), and filing configuration under Administration is not a
  // cosmetic difference — it is the wrong drawer, so nobody finds it.
  //
  // Sector titles are read with textContent rather than innerText: the
  // dropdowns are collapsed at rest, and innerText is empty for hidden nodes.
  await p.goto(`${BASE}/front/central.php`, {waitUntil:'networkidle'});
  const menu = await p.evaluate(() => {
    const out = [];
    document.querySelectorAll('#navbar-menu > ul > li').forEach(li => {
      const head = li.firstElementChild;
      if (!head) return;
      const sector = head.textContent.replace(/\s+/g, ' ').trim();
      li.querySelectorAll('a[href*="glpinetscan"]').forEach(a => {
        if (head.contains(a)) return;
        out.push({sector, href: a.getAttribute('href') || ''});
      });
    });
    return out;
  });
  for (const [label, page, sector] of [['targets','target.php','Administration'],
                                       ['scanners','scanner.php','Administration'],
                                       ['OID profiles','oidprofile.php','Administration']]) {
    const hit = menu.find(m => m.href.endsWith(page));
    check(`${sector} menu links to ${label}`,
          !!hit && hit.sector.startsWith(sector),
          hit ? `found under ${hit.sector}` : 'no link at all');
  }

  // The settings page is deliberately *not* in the sidebar: Setup > Plugins
  // already links it, and a second entry pointing at the same page is what
  // turned the Setup menu into a list nobody read.
  check('the settings page is not duplicated into the sidebar',
        !menu.some(m => m.href.endsWith('glpinetscan/front/config.php')),
        (menu.find(m => m.href.endsWith('glpinetscan/front/config.php'))||{}).sector);
  await p.goto(`${BASE}/front/plugin.php`, {waitUntil:'networkidle'});
  check('and is reachable from the Plugins page',
        (await p.locator('a[href*="glpinetscan/front/config.php"]').count()) > 0);

  // The Add button used to point at nothing and land on the dashboard.
  for (const [label, path, wantAdd] of [['targets','target.php',true],
                                        ['OID profiles','oidprofile.php',true],
                                        ['scanners','scanner.php',false]]) {
    await p.goto(`${BASE}/plugins/glpinetscan/front/${path}`, {waitUntil:'networkidle'});
    const add = p.locator('a:has-text("Add")').first();
    const present = (await add.count()) > 0;
    if (wantAdd) {
      let reachesForm = false;
      if (present) {
        await add.click(); await p.waitForLoadState('networkidle'); await p.waitForTimeout(400);
        reachesForm = await p.evaluate(()=>!!document.querySelector('form[action$=".form.php"] button[name="add"]'));
      }
      check(`${label}: Add reaches a form`, present && reachesForm, p.url().replace(BASE,''));
    } else {
      // Scanners enroll themselves; an Add button here has nothing to create.
      check(`${label}: no Add button`, !present, '');
    }
  }

  // --- creating a scan target through the UI ---------------------------
  await p.goto(`${BASE}/plugins/glpinetscan/front/target.form.php`, {waitUntil:'networkidle'});
  const tform = p.locator('form[action$="target.form.php"]');
  const tname = 'UI created ' + Date.now();
  await tform.locator('input[name="name"]').fill(tname);
  await tform.locator('textarea[name="ranges"]').fill('203.0.113.0/24');
  // Numeric fields left untouched on purpose: GLPI seeds them as empty
  // strings, which MySQL rejects for an integer column.
  await tform.locator('button[name="add"]').click();
  await p.waitForLoadState('networkidle'); await p.waitForTimeout(600);
  const saved = /id=\d+/.test(p.url());
  check('target saves with untouched numeric fields', saved, p.url().replace(BASE,''));
  if (saved) {
    const vals = await p.evaluate(() => {
      const f = document.querySelector('form[action$="target.form.php"]');
      const g = n => { const e = f.querySelector(`[name="${n}"]`); return e ? e.value : null; };
      return {port:g('snmp_port'), timeout:g('timeout_ms'), retries:g('retries'), ranges:g('ranges')};
    });
    check('numeric defaults applied', vals.port === '161' && vals.timeout === '2000', JSON.stringify(vals));
    check('ranges persisted', /203\.0\.113\.0\/24/.test(vals.ranges || ''), vals.ranges);
  }

  // --- scanner registered with GLPI's inventory ------------------------
  await p.goto(`${BASE}/front/agent.php`, {waitUntil:'networkidle'});
  const agentsTxt = await p.evaluate(()=>document.body.innerText);
  check('scanner listed on GLPI Agents page', /netscan-/.test(agentsTxt), '');
  const agentId = await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(x=>/netscan-/.test(x.textContent));
    return a ? (a.href.match(/id=(\d+)/)||[])[1] : null;
  });
  if (agentId) {
    await p.goto(`${BASE}/front/agent.form.php?id=${agentId}`, {waitUntil:'networkidle'});
    await p.waitForTimeout(500);
    const at = await p.evaluate(()=>document.body.innerText.replace(/\s+/g,' '));
    check('agent reports its supported tasks', /NETDISCOVERY/.test(at) && /NETINVENTORY/.test(at), '');
    check('agent reports a version', /NETSCAN: \S+/.test(at), (at.match(/NETSCAN: \S+/)||[''])[0]);
    check('agent typed as GLPI Netscan', /GLPI Netscan/.test(at), '');
  } else {
    check('agent reports its supported tasks', false, 'no agent link');
  }

  check('no page errors', errs.length===0, errs.join(' | '));

  // --- The dark palette --------------------------------------------------
  //
  // The scan target and scanner lists and the port map are all drawn by this
  // plugin, the port map in colours it picks per VLAN — the surface most likely
  // to stop being legible on a black body.
  fs.mkdirSync(DARK_SHOTS, { recursive: true });
  console.log('\nswitching to the dark palette...');

  const dark = await openDark(b, { plugin: 'glpinetscan' });

  for (const [url, name, shot] of [
    [`${BASE}/plugins/glpinetscan/front/target.php`, 'the scan targets', 'netscan-dark-01-targets.png'],
    [`${BASE}/plugins/glpinetscan/front/scanner.php`, 'the scanners', 'netscan-dark-02-scanners.png'],
    [`${BASE}/plugins/glpinetscan/front/config.php`, 'the settings page', 'netscan-dark-03-settings.png'],
  ]) {
    await dark.goto(url, { waitUntil: 'networkidle' });
    await dark.waitForTimeout(500);
    const bad = await audit(dark, 'glpinetscan-');
    check(`[dark] ${name}: no near-white panel carrying dark-body text`,
      bad.whiteBg.length === 0, JSON.stringify(bad.whiteBg));
    check(`[dark] ${name}: muted text meets 4.5:1`,
      bad.lowContrast.length === 0, JSON.stringify(bad.lowContrast));
    await fullPage(dark, `${DARK_SHOTS}/${shot}`);
  }

  check('[dark] no page errors', dark.__darkErrors.length === 0, dark.__darkErrors.join(' | '));

  await b.close();
  console.log(fail.length ? `\n${fail.length} FAILED: ${fail.join(', ')}` : '\nall checks passed');
  process.exit(fail.length?1:0);
})().catch(e=>{console.error('ERROR:',e.message);process.exit(1);});
