# GLPI Netscan

A lightweight SNMP network scanner for GLPI 11: a single static Go binary that
holds no scan policy and no OID knowledge of its own, plus a GLPI plugin where
all of it is configured.

Companion to `glpiosquery`, which covers endpoints. This covers everything that
answers SNMP but cannot run an agent — switches, routers, firewalls, printers,
PDUs, UPSes.

```
GLPI plugin                              scanner (Go, static)
├ scan targets (ranges, schedule)  ──job──►  expand ranges
├ SNMP credentials (core's own)    ──job──►  probe v1 / v2c / v3
├ OID profiles (shipped + UI)      ──job──►  walk standard MIBs + profile OIDs
└ ingest  ◄──────────────report────────────  emit GLPI inventory JSON
     │
     └──► Glpi\Inventory\Inventory  ──►  NetworkEquipment / Printer / Unmanaged
                                          + ports, IPs, components
```

## Division of labour

| Concern | Owned by |
|---|---|
| SNMP credentials (v1/v2c/v3, encrypted) | **GLPI core** — `glpi_snmpcredentials` |
| Turning inventory data into assets | **GLPI core** — native inventory pipeline |
| Ports, IPs, components, locations | **GLPI core** |
| Payload format | **GLPI core** — `inventory.schema.json` |
| *What to scan, when, with which OIDs* | **this plugin** |
| *Talking SNMP and emitting the payload* | **this scanner** |

Core has no IP-range or scan-task tables, so telling a scanner what to scan is
the actual gap, and it belongs in the web UI. The scanner is ~1,800 lines of Go
with one dependency (`gosnmp`) and ships no OIDs: profiles arrive with the job.

## What it collects

Standard MIBs out of the box, nothing vendor-specific, so it works across
switches, routers, firewalls, UPSes, printers and VoIP phones alike:

| MIB | Gives |
|---|---|
| SNMPv2-MIB | name, description, contact, location, uptime, sysObjectID |
| IF-MIB `ifTable` | per-port descr, type, MTU, speed, admin/oper status, last change, in/out bytes and errors, MAC |
| IF-MIB `ifXTable` | 64-bit octet counters, `ifHighSpeed`, port name, alias |
| EtherLike-MIB | duplex status |
| IP-MIB | device and per-port addresses |
| BRIDGE-MIB | forwarding table — which MACs are behind which port |
| Q-BRIDGE-MIB | VLAN names, per-port membership, tagged/untagged, PVID, VLAN-aware FDB |
| IF-MIB `ifStackTable` / IEEE8023-LAG-MIB | link aggregation: which ports are bundled into which port-channel |
| LLDP-MIB | neighbour chassis, port, system name/description, management address |
| CISCO-CDP-MIB | neighbours where LLDP is absent |
| ENTITY-MIB | serial, model, manufacturer, firmware, asset tag; stack members and modules |
| HOST-RESOURCES-MIB | memory |
| PRINTER-MIB (RFC 3805) | toner, ink, drum, waste and kit levels; page counters, serial and model |
| UPS-MIB (RFC 1628) | battery state, runtime, input/output lines, alarms |
| ENTITY-SENSOR-MIB | temperature, humidity, current and power sensors |
| PowerNet / XUPS / Sentry3 / PDU2 | vendor UPS identity and PDU outlet tables |
| AIRESPACE-WIRELESS-MIB | Cisco WLC: access points, radios, SSIDs, client counts |
| WLSX-WLAN-MIB / RUCKUS-ZD-WLAN-MIB | Aruba and Ruckus controllers, the same per vendor |
| UBNT-UniFi-MIB / MIKROTIK-MIB | standalone access points: networks broadcast and their clients |

### Topology

The forwarding table and LLDP/CDP together give GLPI real port-level topology:
switch ports wired to the devices behind them, with `Unmanaged` assets for
neighbours never seen before. Verified against a simulated Cisco switch: 8
port-to-port links, neighbours resolved by LLDP, MAC-only neighbours resolved by
OUI.

Three details handled explicitly:

- **Bridge ports are not ifIndex.** `dot1dBasePortIfIndex` maps between them; the
  dev simulator offsets bridge ports by 100 so a collector conflating the two
  fails loudly.
- **VLAN membership is a bit-packed `PortList`**, MSB-first, indexed by bridge
  port, so a 24-port switch numbering from 101 needs a 14-byte bitmap.
- **`self(4)` and `mgmt(5)` FDB entries are dropped.** They are the switch's own
  addresses; importing them wires every switch to itself.

A port is reported either as an LLDP/CDP link *or* as learned MACs, never both:
GLPI's `NetworkPort` asset switches on the port's `lldp` flag and reads the whole
`connections` array one way or the other.

### Link aggregation

From two sources, in order of how much they can be trusted:

- **IEEE8023-LAG-MIB** — `dot3adAggPortAttachedAggID` says which aggregator each
  port is currently attached to, and the MIB defines that identifier as the
  aggregator's own ifIndex. Nothing is inferred. Not every device implements it.
- **ifStackTable** — which interfaces are layered above which. Everything
  implements it, but a LAG is not the only thing that stacks: a VLAN interface
  sits above its ports, and a tunnel above its transport.

The stack table is filtered by the *aggregator's* interface type, the one signal
separating a port-channel from an SVI. Default set is `ieee8023adLag(161)` and
`propMultiplexor(54)`; hardware reporting a bundle as plain ethernet needs
`aggregate_iftypes` in a profile.

**GLPI drops these ports unless told not to.** `glpi_networkporttypes` ships
`ieee8023adLag(161)` with `is_importable = 0` and no instantiation type, so an
aggregated interface is discarded before its member list is read — verified by
submitting one and watching only the members appear. GLPI models aggregation
properly through `NetworkPortAggregate`; the row is simply not switched on. The
plugin switches it on at install and reverts at uninstall, and only reverts it if
it still looks like ours.

Members are reported on the aggregator as ifIndexes, the shape GLPI resolves to
port ids itself. A member not among the collected ports is dropped rather than
reported, since GLPI matches by ifIndex and a name resolving to nothing leaves a
silent hole in the aggregate.

### Interface metrics

`ifXTable` is preferred wherever present. The 32-bit `ifSpeed` gauge **saturates
at 4294967295** on anything above 4 Gbps, and 32-bit octet counters wrap in under
a minute on a loaded 10G link. `ifHighSpeed` is only trusted when `ifSpeed` could
not have been accurate, since below saturation `ifSpeed` is the more precise of
the two.

GLPI's inventory schema has no field for discards, and none for live UPS state —
that is monitoring data, so it is not collected rather than forced somewhere it
does not belong.

### Power devices — UPS, PDU and ATS

Power gear becomes a native GLPI `PDU` asset, typed *UPS*, *Rack PDU* or *ATS*,
with a **Power state** tab.

| Collected | From |
|---|---|
| Battery status, charge %, runtime, voltage, temperature, replace-battery | UPS-MIB, PowerNet, XUPS |
| Output source — the "is it on battery?" answer | UPS-MIB |
| Input and output lines: volts, amps, watts, Hz, load % | UPS-MIB, rPDU2 phase table |
| Active alarms, named | UPS-MIB alarm table |
| Per-outlet name, on/off state and current | rPDU2, Sentry3, Raritan PX |
| Inlet temperature, humidity, per-bank sensors | ENTITY-SENSOR-MIB |
| Outlet count on the asset | GLPI `Item_Plug` |
| Management port: name, MAC, IP, speed, MTU | IF-MIB + IP-MIB → GLPI `NetworkPort` |

Power devices bypass core's inventory pipeline, for two verified reasons: there
is no `Glpi\Inventory\MainAsset\PDU`, so the best core could manage is filing a
UPS as `Unmanaged`; and the inventory schema has no vocabulary for batteries,
outlets or load, so the interesting half of the data would be dropped.

That state is a single current snapshot, not a time series. "Is this UPS on
battery, and how long has it got?" is an inventory-shaped question; trending is
monitoring's job.

Detection is behavioural rather than a guess from `sysObjectID`: a device is a
power device if it answers the standard UPS battery group, a profile-declared
outlet table, or a profile says so. `sysServices` cannot help — power gear
reports itself as an ordinary IP-managed appliance. A battery then separates a
UPS from a rack strip.

There is **no IETF PDU MIB**, so rack strips are reached entirely through vendor
profiles. Shipped: APC rPDU2, ServerTech Sentry3 and Raritan PX for outlets; APC
PowerNet and Eaton XUPS for UPS identity. Every OID came from the published MIBs
— APC's *switched* outlet table is under `26.9.2` while `26.9.4` is the separate
*metered* table.

Power OIDs accept a `*factor` scale suffix, because these MIBs report tenths of a
volt, amp or hertz and the factor differs per vendor for the same field:

```
battery_voltage = 1.3.6.1.2.1.33.1.2.5.0*0.1
outlet_current  = 1.3.6.1.4.1.318.1.1.26.9.4.3.1.6*0.1
```

### One GLPI limitation, and the opt-in around it

A switch's forwarding table names the MAC of the UPS plugged into it. GLPI
resolves those MACs through `RuleImportAsset`, which searches
`$CFG_GLPI['asset_types']` — and **PDU is not in that list** (it *is* in
`networkport_types`, which is why the port itself works). So by default a switch
port facing a UPS links to an `Unmanaged` placeholder rather than the UPS asset
that already exists.

**Let switch topology resolve to UPS and PDU assets** adds PDU to that list.
It is off by default because `asset_types` is consulted widely across core.

With it off nothing churns: the placeholders are created once and left alone,
measured stable across repeated scans. With it on, placeholders left by earlier
scans are retired as each device is identified.

Ingest is ordered so referenced devices land before the devices referencing them
— switches are imported last, so the ports they point at already exist.

### A GLPI bug that shapes how LLDP is submitted

GLPI reads a port's connections one of two ways, chosen by its `lldp` flag, and
only one of them works:

- `handleMacConnection()` resolves each MAC through the rule engine and calls
  `addPortsWiring()` — this links the switch port to the real asset.
- `handleLLDPConnection()` runs the same rules but guards the wiring behind
  `count($this->connection_ports) != 1`, on a property it resets to `[]`
  immediately above and never populates. GLPI's own source marks this as dead
  code, with a TODO calling it "most likely" a real bug.

So an LLDP neighbour always becomes an `Unmanaged` placeholder even when the
device is already inventoried, meaning preferring LLDP — otherwise the richer
signal — actively loses the link.

The plugin rewrites LLDP connections it can already identify into the MAC form
the working path understands: if a port already exists carrying the neighbour's
chassis MAC, GLPI gets the MAC and links to the real asset; otherwise the LLDP
form is kept, since nothing can be linked anyway and LLDP at least yields a
placeholder named `core-rtr-01` rather than one named after an OUI.

The scanner also sends the far end's port **name** (`lldpRemPortId`, when the
port-ID subtype says it is an interface name) rather than its human description,
since GLPI matches on the name.

### VoIP phones

A handset answering SNMP becomes a native GLPI `Phone` — name, serial, model,
manufacturer, `brand`, firmware, location, contact, type *VoIP* — plus its
network ports. Desk phones report two interfaces: the switch uplink and the PC
passthrough port. Both are recorded; the uplink MAC is the one the switch learns.

Recognising a phone is the interesting part, because the obvious signals fail:

- **`sysServices` cannot do it.** A desk phone contains a two-port switch, so it
  sets the datalink bit and looks like network equipment.
- **`sysObjectID` only works for vendors already in a profile.**

The primary signal is **LLDP**: `lldpLocSysCapEnabled` is a `BITS` value in which
`telephone(5)` is the bit a phone sets about itself, which works for any vendor.
Profiles for Yealink, Polycom, Grandstream, Snom, Mitel, Fanvil, Gigaset, Avaya
and Cisco add the manufacturer on top; every enterprise number was checked
against the IANA registry. Cisco phones share Cisco's arc with every switch they
make, so those are matched by `sysDescr` regex.

Phones bypass core's inventory pipeline for a verified reason: `MainAsset\Phone`
extends the base MainAsset, whose `prepare()` reads `hardware`/`bios` — the
*computer* inventory shape. Only `NetworkEquipment` reads `network_device`.
Feeding core a netinventory payload with `itemtype: Phone` produces an asset with
no name, MAC or serial, which its own "Phone constraint (name)" rule then
refuses. Unlike PDU, `Phone` *is* in `asset_types`, so topology resolves to it
with no opt-in.

#### Handsets that answer nothing

Most desk phones do not answer SNMP, or answer only on a voice VLAN the scanner
cannot route to. Those are inventoried by **LLDP-MED**: a phone announces its
manufacturer, model, serial and firmware to the switch port it is plugged into,
and the switch hands it over. A scan of one switch therefore produces a `Phone`
for every handset on it, for devices the scanner never spoke to.

What makes an endpoint a phone is
`lldpXMedRemMediaPolicyAppType = voice(1)` — a statement the MIB makes, not an
inference from the model string. The media policy table is indexed one arc wider
than the inventory table, so the application type is available per endpoint. The
alternative is guessing from model names, which turns an estate's cameras and
door controllers into telephones.

A handset visible both ways is submitted once. The MED record knows nothing about
the device's interfaces, so letting it through would strip the ports the direct
walk found; a device walked directly in the same pass suppresses its MED record.
The match is on serial and MAC rather than address, because the two sources
disagree about addresses by nature.

The OIDs are from LLDP-EXT-MED-MIB (ANSI/TIA-1057), under the TIA OUI subtree
`1.0.8802.1.1.2.1.5.4795`, read out of the published MIB.

### Wireless controllers and access points

An access point behind a controller is a real asset — a serial-numbered box that
gets RMA'd, moved and replaced — and most cannot be scanned at all: a
CAPWAP-tunnelled AP has no reachable management address. So one scanned address
produces many assets: the controller, plus a NetworkEquipment for every AP it
reports, each with its own name, model, serial, location, firmware and address.

The identity is the AP's own — serial first, then MAC — never the controller's
address. An AP moved to a different controller is the same physical box, and a
controller replaced under warranty must not orphan sixty access points.

**The switch port comes for free.** The controller reports each AP's Ethernet
MAC, which is what the switch it is plugged into has learned, so the existing
topology correlation wires the AP to its real port. An AP that never answered a
single SNMP request ends up on the right port of the right switch.

Provenance is the controller's address, not the AP's. The off-target guard checks
submissions against the ranges the scanner was told to sweep, and an AP
legitimately sits outside them.

| Pack | |
|---|---|
| Cisco | AIRESPACE-WIRELESS-MIB — APs, radios, SSIDs |
| Aruba / HPE | WLSX-WLAN-MIB — APs, radios, SSIDs |
| Ruckus | RUCKUS-ZD-WLAN-MIB — APs, with a per-AP client count the others lack |
| UniFi | UBNT-UniFi-MIB — standalone, virtual APs |
| MikroTik | MIKROTIK-MIB — standalone, AP-mode interfaces |

Matched on enterprise roots rather than per-model: a Catalyst 9800 reports a
Cisco chassis sysObjectID, so a model list stops working at the next hardware
refresh. Detection is behavioural and the gate is cheap — one probe decides, so
an ordinary Cisco switch does not pay for six empty walks per scan.

Adding a vendor is a profile, not a release: the collector owns the mechanism,
the profile owns the OIDs, under a `wireless` section (`ap_name`, `ap_model`,
`ap_serial`, `ap_mac`, `ap_ip`, `ap_location`, `ap_status`, `ap_firmware`,
`ap_radios`, `ap_clients`, `radio_band`, `radio_channel`, `radio_clients`,
`radio_status`, `ssid`, `ssid_clients`, and `*_map` decoders).

**Client counts.** Cisco and Aruba report clients per *radio*, in a table indexed
one arc finer than the AP table. The scanner sums them back onto each access
point by longest index prefix, so a per-AP total exists nowhere on the wire and
is derived. Reading that column as if it were an AP column would attribute one
radio's clients to the whole AP. Ruckus publishes a real per-AP count, and where
a vendor does its own figure is used. A virtual-AP table lists the same SSID once
per radio, so those are folded by name and their clients summed.

**Radios become wifi ports.** GLPI models a radio as a `NetworkPort` whose
instantiation is `NetworkPortWifi`, with the 802.11 flavour as its version — a
shape the inventory format cannot express, so the plugin writes it directly. A
standalone AP additionally gets a port per SSID linked to a `WifiNetwork` entry.
A controller's SSID list does not: it is estate-wide, and no MIB here says which
network is on which radio of which AP.

**The Wireless tab** on a controller lists its SSIDs with client counts and every
access point — model, serial, status, clients, per-radio band, channel and
occupancy — each linked to its own asset. It appears only on devices the scanner
recorded wireless state for.

### Printer supplies

Toner, ink, drum, waste, fuser, transfer, cleaning and staple levels from
`prtMarkerSuppliesTable`. No vendor OIDs and no per-model profile: every printer
worth managing implements RFC 3805. Levels land on the printer's **Cartridges**
tab as GLPI's own properties, because GLPI matches against a closed vocabulary
and anything outside it is stored unlabelled.

Two conventions are handled: a level in physical units (tenths of grams,
impressions, items) becomes a percentage of max capacity, and a level already in
percent is taken as-is.

**A supply that will not report a level is omitted, never sent as 0%.** The MIB
says "I do not know" with a negative level — `unknown(-2)`, `other(-1)` — and
`someRemaining(-3)` means there is some left. Turning any of those into 0%
produces an estate where every printer looks empty: toner gets ordered for
printers that do not need it, and the one cartridge that really is empty is
invisible.

Waste bottles are reported as the percentage the device gives, which for a
receptacle is how *full* it is. That is not inverted here — GLPI stores one
number per property with no room for the distinction.

Paper tray levels are collected by no one: GLPI's inventory format has nowhere to
put them.

### Device classification

Decided from a live marker counter *or* a marker supplies table (printer), a
battery or outlet table (power), and the `sysServices` datalink/internet bits
(networking); a vendor profile can force it. Anything else is reported
`Unmanaged` rather than guessed, and an operator can promote it.

Both printer signals are checked because small inkjets report ink levels and no
page counter at all.

## Discovery and inventory

Every pass probes the whole range cheaply. A device is only walked in full when
that is worth doing.

Against the SNMP simulators, with tiny tables over loopback, **a full walk costs
86–157× a probe** — roughly 2 ms against 200–360 ms. A 48-port switch across a
WAN is far worse.

```
first pass    probed 8 in 4ms, answered 8, walked 8 in 2.5s
second pass   probed 8 in 4ms, answered 8, walked 0
after a reboot on one switch      walked 1 in 555ms
after deleting one printer asset  walked 1 in 316ms
```

**The decision is GLPI's, not the scanner's.** Only the server knows what it
already holds, when it last held it, and whether someone has since deleted the
asset. A scanner keeping its own notes would skip a device whose asset had been
removed, and GLPI would stay empty with nothing to explain why.

A device is walked when:

- it has never been walked, **or the asset it produced no longer exists** — which
  makes deleting an asset a supported way to force a clean re-import;
- it rebooted, seen as `sysUpTime` going backwards. That matters twice over,
  since every other counter here is measured against `sysUpTime`;
- a standard change counter moved: `ifTableLastChange`, `ifStackLastChange` or
  `entLastChangeTime`;
- the last full walk is older than the target's **inventory interval**.

That last rule exists because the counters cannot see everything: none moves when
a port goes down or a MAC moves between ports. It defaults to a day. Zero
switches the rule off and leaves only the change signals.

A device implementing none of the counters reports zero every pass. That is an
absence of evidence, not evidence of change: treating it as a change would walk
such hardware on every sweep and give back the whole saving.

Each target's form shows its recent scans — probed, answered, walked, and the
timings — because those are the numbers the two intervals are tuned against.

The split is negotiated, not assumed. A scanner talking to a plugin that predates
it gets no `inventory_wanted` field and walks everything it finds.

## Port map

A **Port map** tab on every `NetworkEquipment` with ports: the switch drawn as
its own front panel, sat immediately before core's "Network ports" table it is a
picture of.

```
GIGABITETHERNET0
┌──┐┌──┐┌──┐┌──┐┌──┐        1 above 2, 3 above 4 — the arrangement of
│ 1││ 3││ 5││ 7││ 9│        the sockets, so the picture can be read
└──┘└──┘└──┘└──┘└──┘        against the hardware instead of translated
┌──┐┌──┐┌──┐┌──┐┌──┐
│ 2││ 4││ 6││ 8││10│        ▔▔▔▔ a stripe marks a trunk
└──┘└──┘└──┘└──┘└──┘
LOGICAL INTERFACES
┌───────────┐┌──────────────┐   ports with no place on the front are
│Management ││Port-channel1 │   drawn apart rather than given one
└───────────┘└──────────────┘
```

Four ways to colour the same switch, switched without a reload:

| Mode | Answers |
|---|---|
| **Status** | what is up, what is down, and what somebody *shut* — admin-down wins over oper-down, because "the port is down" sends a technician to check a patch lead that is fine |
| **VLAN** | where each VLAN actually reaches. Coloured by the *untagged* VLAN, which is what an ordinary device plugged in would land in; trunks carry the stripe instead |
| **Speed** | what negotiated at what — the 100 Mb/s port in a gigabit row, without reading 48 rows |
| **Neighbour** | which ports have something identified on the other end, and which are dark |

Clicking a port opens its detail without a round trip: VLANs tagged and
untagged, the neighbouring asset and its port (linked), aggregate membership,
MAC and addresses, last state change, and the latest counters with errors called
out. Every port is also listed as a table under the faceplate.

Nothing here is a second copy of the port inventory. The scan hands ports,
VLANs and topology to GLPI's native pipeline and **core owns them from there** —
this is a projection of `glpi_networkports` and its relations, so it draws a
switch some other agent inventoried just as well. The only line it cannot show
for one of those is when it was last walked, which is the one fact that is this
plugin's.

### Why not core's stencil

GLPI 11 can already show a faceplate — `NetworkEquipmentModelStencil` — and it
is a different tool. It needs a photograph of that exact model uploaded and
every port zone placed on the image by hand, per model, before it shows
anything; and once placed it shows `ifOperStatus` as a coloured dot and nothing
else. This needs no preparation at all, and the layout is derived from the port
names: the trailing run of digits is the position and everything before it is the
module, which is how every vendor names ports whatever else they disagree about
(`GigabitEthernet0/1`, `Ethernet1/48`, `ge-0/0/7`, `Te1/1/4`, `port12`, `swp3`).
Splitting at the *last* run is what keeps a stack's members apart — otherwise two
members' port 1s are drawn on top of each other.

### Two things worth knowing

- **Tab order is done in the browser.** `CommonGLPI::defineAllTabs()` is `final`,
  appends plugin tabs strictly last, and takes no hook;
  `registerStandardTab()`'s `$order` only sorts plugin tabs against each other.
  Moving one list item at load is the whole of the alternative — and the
  narrow-screen `<select>` has to be renumbered with it, because core switches
  tabs from it *by position*.
- **Tile colours are fixed hex, not theme tokens.** Green-is-up has to mean the
  same thing on every palette, or two people describing the same switch disagree
  about its colour. Contrast was measured rather than assumed, in both the light
  and the `auror_dark` palettes: the tile border is theme-derived so the edge
  stays visible (a "down" tile is 1.8:1 against the dark body), and core's solid
  `.badge` inherits the ambient text colour in the **light** palette too — the
  same trap the dark rules already document, measuring 1.43:1 on `bg-secondary`.

`php plugin/tests/portmap-layout.php` covers the position, status and speed
rules without GLPI; the faceplate's layout, mode switching, detail panel, refresh
and tab position are checked in `plugin/tests/browser/netscan-check.js`.

## Device control (SNMP write)

Everything else here reads. This does not, and the same mechanism that reboots a
stuck access point can black out a rack or cut the link the scanner reaches the
device by.

**Four gates, all of which must be open** before one SNMP SET leaves a scanner:

1. **A global setting**, off by default and off after upgrades.
2. **A separate write credential per target**, not the community the scanner
   reads with. Reusing the read credentials would mean a community that happened
   to be read-write silently made every device it reached controllable.
3. **A right**, checked when the action is queued — `config` UPDATE rather than
   UPDATE on the asset: being allowed to correct a switch's serial number is not
   the same as being allowed to shut its ports.
4. **An expiry.** A queued action not collected within ten minutes is abandoned
   and marked so, so a forgotten click does not power-cycle a rack when a scanner
   reconnects hours later.

Actions are queued rather than performed inline, because GLPI usually cannot
reach the device network at all; the scanner is the thing with a route. The queue
also produces an audit trail.

The confirmation is **typed, not clicked**: to shut `GigabitEthernet0/3` you type
its name. The mistake this prevents is acting on the wrong row of a table, which
an "are you sure?" dismissed by reflex prevents none of.

**One control is built in**: `port_admin`, which is `ifAdminStatus` — standard,
indexed by ifIndex, and meaning the same on every device implementing IF-MIB.
Everything vendor-specific (outlet switching, PoE) comes from a profile's
`control` section, because those are the ones where a wrong OID or index does not
fail — it switches off something else:

```json
"control": { "outlet_power": "1.3.6.1.4.1.318.1.1.26.9.2.4.1.5 on=1,off=2,cycle=3" }
```

The queue holds intent (`this port, down`) rather than an OID: the profile
declaring a control is matched on the device's sysObjectID and only the scanner
knows it, and an audit row saying `Gi0/3 → down` is still readable a year later
where `1.3.6.1.2.1.2.2.1.7.3 = 2` is not.

## SNMP notifications (traps)

A device sending a trap is telling the scanner it has changed — better evidence
than the counters a discovery pass reads, and it arrives immediately. **A
notification clears that device's last-inventory stamp and the next pass walks
it.** Measured on the dev estate: a `linkDown` from one switch turned the next
sweep into `probed 8, answered 8, walked 1`.

The trust model is weak by design of the protocol, not of this code. An SNMPv1 or
v2c trap is an unauthenticated UDP datagram with a community string in it,
trivially forged by anything that can route a packet to the listener. So:

- notifications are **off** unless switched on;
- a scanner accepts them **only from addresses inside its own scan ranges**, the
  same rule inventory submissions follow. An empty range list closes the listener
  rather than opening it;
- **nothing a trap says is written into an asset.** It is stored and shown as the
  device's claim, and can cause a re-inventory where the facts are then read from
  the device itself.

That last rule is what makes the weak authentication tolerable: the worst a
forged trap achieves is an SNMP walk of a device the scanner could already walk.

Notifications appear on a **Notifications** tab, named where the OID is
well-known (`coldStart`, `warmStart`, `linkDown`, `linkUp`,
`authenticationFailure`). They are pruned per device, since a flapping port would
otherwise fill a disk with copies of one sentence.

Binding port 162 needs `CAP_NET_BIND_SERVICE`, which the hardened systemd unit
does not grant. Apply `packaging/glpi-netscan-traps.conf` as a drop-in, or use a
port above 1024 — a drop-in rather than a change to the unit, because most
installations do not receive traps and should not carry the capability.

## Two GLPI settings that will bite you

Both make a scan look completely successful while importing nothing, and neither
raises an error. The Readiness panel checks both, and a rejected device reports
which one it hit.

1. **`enabled_inventory` must be on** (*Setup → General → Inventory*). With it
   off, `doInventory()` accepts payloads and discards them.
2. **`NetworkEquipment import (by mac)` ships disabled.** GLPI's stock rules only
   import network equipment that has a serial number, and many switches expose
   none. Everything else falls through to *import denied* and lands in
   *Administration → Refused equipment*. Enable the by-mac rule under
   *Administration → Rules → Rules for asset import*.

The scanner mitigates (2) by deriving a device MAC from the lowest-numbered port
when the device offers no chassis MAC.

## Extending it with device-specific OIDs

Profiles are layered by priority; the base profile is 0 and vendor profiles sit
above it. Two sources, merged at job time:

- **Shipped packs** — `plugin/data/profiles/*.json`, matched by
  `sysobjectid_prefix`. Diffable in git, upgraded with the plugin. A pack file
  may hold one profile or a list.

  Shipped today: the standard-MIB base, printers, UPS identity, and ~36 vendor
  entries covering switching/routing (Cisco, HPE/Aruba, Juniper, Arista, Extreme,
  Dell, Huawei, MikroTik, Ubiquiti, Brocade, ALE, NETGEAR, TP-Link, D-Link,
  Zyxel, Allied Telesis, 3Com), firewalls (Fortinet, Palo Alto, SonicWall, Check
  Point, F5), power (APC, Eaton, CyberPower, Raritan), printers (Xerox, Lexmark,
  Ricoh, Kyocera, Brother, Epson) and VoIP (Avaya, Yealink).

  The vendor list is identification only — it sets the manufacturer and, for
  power and VoIP, the asset type. No data collection depends on it being
  complete, because collection comes from the standard MIBs.
- **UI profiles** — rows under *Administration → Network scanning → OID
  profiles*, layered on top. This is how a site adds one OID for one switch model
  without forking the plugin or losing it on upgrade.

UI profiles are authored as `field = OID` lines rather than raw JSON, because the
field names are a closed vocabulary mapping onto the inventory schema, so the
form rejects a typo instead of accepting a profile that silently collects
nothing. OIDs are validated as dotted decimal.

```
# a plain OID
serial = 1.3.6.1.4.1.9.3.6.3.0

# alternatives, tried in order until one answers
serial = 1.3.6.1.2.1.43.5.1.1.17.1|1.3.6.1.2.1.47.1.1.1.1.11.1

# a literal, for a device that exposes no OID for the field at all
manufacturer = =Cisco

# empty deletes a field inherited from a lower-priority profile
model =
```

**Alternatives exist because layering is otherwise destructive.** The printer pack
applied to every device and overrode `serial`, so every switch it touched came
back with a blank serial — the base ENTITY-MIB OID was never read. A broad
profile can now say "prefer mine, fall back to the standard one".

Prefix matching is arc-wise, not string-wise: `1.3.6.1.4.1.9` does not match
enterprise `91`.

Individual collectors can be switched off per profile (`fdb`, `lldp`, `cdp`,
`vlans`, `hc_counters`) for hardware that answers a table with *wrong* data
rather than no data. All are on unless turned off.

## Warranty lookups

Asks hardware vendors when the support contract or warranty on each scanned
device ends, and writes the answer into **GLPI's own warranty fields** on the
asset's *Financial information* tab. Nothing is stored in a private format, so
GLPI's warranty-expiry search option, expiry-alert cron, dashboards and CSV
export keep working unchanged.

**Setup → GLPI Netscan → Warranty lookups.** Covers NetworkEquipment, Printer,
Phone, PDU and Computer — everything the scanner produces that GLPI can hold an
Infocom on. (`Unmanaged` is not in `$CFG_GLPI['infocom_types']`.)

| Vendor | API | Credentials |
|---|---|---|
| Cisco | Support API SN2INFO v2 | OAuth2 client ID + secret, from apiconsole.cisco.com |
| Juniper | Service Asset API v1.0 (`css-asset`) | API key + application id + customer source id |
| HPE | Support Entitlement (warrantyCheck) | OAuth2 client ID + secret, issued against a support agreement |
| Fortinet | FortiCare Registration API v3 | A FortiCloud **IAM API user**, not a portal login |
| Pure Storage | Pure1 REST API, support contracts | Pure1 application id + an RSA private key |
| Dell | TechDirect Asset Entitlements v5 | OAuth2 client ID + secret, from techdirect.dell.com |
| HP Inc. | Product Warranty API v2 | OAuth2 client ID + secret, from developers.hp.com |
| Lenovo | Warranty & Contract v2.5 | A `ClientID` token from a Lenovo account representative |
| Apple | GSX REST v2 | AASP/self-servicing agreement, client certificate, Sold-To/Ship-To, activation token |
| Microsoft Surface | Surface API Management Service | Entra app in the Intune tenant + an API subscription key |

Every one needs an account with the vendor; none has an anonymous tier. Each is a
separate switch on top of a master switch, and nothing is contacted until both
are on. **Only the serial number leaves the server** — no hostname, address,
entity or instance URL. Requests go through GLPI's configured proxy.

Cisco and Juniper batch (75 and 50 serials per call), so an estate of switches is
a handful of requests. Lookups run hourly from cron, bounded per run, with a
per-vendor interval floor; a vendor answering "wrong credentials" or "slow down"
is dropped for the rest of the run.

**Two of the ten answer about a fleet rather than a serial.** Microsoft and Pure
Storage publish no per-device endpoint, so the whole tenant or organisation is
fetched once per run.

- **Pure Storage matches on array name, not serial.** Pure1 publishes no serial
  number anywhere in its public API, so an asset matches the Pure1 array whose
  name or FQDN equals its GLPI name (the SNMP sysName, in practice) and the
  Warranty tab says so. Rename in one place and not the other and it surfaces as
  "not found" rather than a wrong date.
- **Microsoft needs its tenant enrolled for scanning first** — a state change
  inside your Microsoft tenant, so it is a button on the settings page rather than
  something the cron does. The first scan takes up to five business days.

**HP and HPE are told apart by asset type**, not by name: the 2015 split left two
companies with two APIs, and an estate's ProCurve switches and its EliteBooks both
report a manufacturer of "HP". Anything on a NetworkEquipment, PDU, Enclosure or
Rack goes to HPE.

**Kit with no manufacturer is matched on its model**, which matters more here than
anywhere else: a Cisco access point routinely lands in GLPI with no manufacturer
at all, because the enterprise OID never mapped to one, and a model of
`AIR-AP2802I-E-K9` or `C9120AXI-E`. Both were sitting unmatched in a real
inventory, which is how the product-ID patterns in `Warranty/Detector.php` came
to exist.

**Vendors deliberately absent**, each checked rather than assumed:

- **Arista Networks** — the only public API on `arista.com` is the software
  download service (`custom_data/api`, as used by eos-downloader); CloudVision
  describes devices under management, not support entitlement.
- **Ubiquiti** — `api.ui.com` and the UniFi APIs return device inventory with no
  coverage data; warranty runs through rma.ui.com, which wants proof of purchase.
- **Supermicro** — the serial warranty check is a web form; RMA is email.
- **Zebra, APC/Schneider, Acer, ASUS, MSI, Dynabook/Toshiba, Fujitsu**, and the
  phone and printer makers (Polycom, Yealink, Kyocera, Brother) — a web form in
  every case.
- **Cisco Meraki** — excluded on purpose: Meraki serials are not in SN2INFO, so
  every access point in an estate would fail every night.

Assets from any of those are recorded as *not applicable* rather than failing.

### What lands where

A device routinely has several overlapping entitlements — a hardware warranty, a
SmartNet or FortiCare contract, sometimes both with different clocks. Infocom
holds one span, so the **entitlement that ends last** is written; the full list is
on the asset's *Warranty* tab with the service level, when it was last checked,
and why there is no warranty when there is none.

Warranty fields typed in by hand are never overwritten unless an administrator
allows it, and the purchase date and supplier are only filled in when empty.

Two quirks that look like bugs here and are not:

- **Cisco reports an end date and no start date.** GLPI stores a start plus a
  duration in months, so a coverage with no start is written as a zero-length span
  ending on the right day. Every expiry view and alert is then correct; the
  "start" column holds the end date, and `warranty_info` says so explicitly.
- **GLPI computes the expiry two different ways.** The search option and the
  warranty-alert cron both use
  `DATE_ADD(warranty_date, INTERVAL warranty_duration MONTH)` and land exactly on
  the vendor's end date; the Financial tab subtracts a day to show the last
  covered day.

The engine is shared with `glpiosquery`, which does the same job for the machines
its agent inventories. Both ship a complete copy so neither requires the other; in
the monorepo `tools/sync-warranty.sh` projects one into the other, and everything
per-plugin lives in `Warranty/Scope.php`.

No glpi-ai tool is added for this: the data is in GLPI's native fields, which the
assistant already reads.

## Security

Modelled on the osquery agent's credentials, because the threat is the same
shape.

- **Two-tier credentials.** A shared, scopable, revocable *enrollment secret* is
  exchanged once for a *per-scanner token*. The token is stored as a SHA-256 hash
  and shown exactly once — the database never holds a value that can be replayed.
- **TLS required by default**, at both ends. The job response carries decrypted
  community strings and v3 passphrases.
- **Revocation** is `scanner_invalid`; deactivating a scanner cuts it off at the
  next poll and the agent re-enrolls rather than retrying.
- **Scanners can only report on what they were told to scan.** Reported addresses
  are checked against the target's ranges, and the target is resolved from the run
  row rather than the request.
- **Entity comes from the scanner**, never from the payload — a submission is
  data, not authority.
- **Range expansion is capped** at 65,536 addresses, so `/8` instead of `/24` is a
  visible error rather than a scanner that appears hung for a week.
- **The enrollment key passed to the MSI can reach a verbose install log.**
  `ENROLLSECRET` is marked hidden, but the resolved command line of the enrolment
  action can still appear under `/l*v`. An enrollment key buys exactly one thing —
  the right to obtain a per-scanner token — and revoking it in GLPI kills it while
  already-enrolled scanners keep working on their own tokens.
- **Self-update payloads are verified before they execute** — SHA-256, size, and
  the binary's own reported version, checked while the old version is still
  active. A self-updater that installs whatever it downloads is a remote code
  execution channel, and TLS to the right host proves only where the bytes came
  from.
- The systemd unit keeps an empty capability bounding set, `ProtectSystem=strict`
  and a `@system-service` seccomp filter. It runs as a dedicated unprivileged user
  rather than `DynamicUser`, which self-update made impossible: a transient UID
  has no persistent writable install tree to update into.

## Install

### Plugin

```bash
# from the GLPI root — the directory must be named for the plugin key,
# which is not the repository name
git clone https://github.com/bijstaan/glpi-netscan.git plugins/glpinetscan
php bin/console plugin:install -u glpi glpinetscan
php bin/console plugin:activate glpinetscan
```

| Menu | Entry | For |
|---|---|---|
| Administration | **Scan targets** | IP ranges, credentials, schedule, timeouts — the main page |
| Administration | **Scanners** | Enrolled scanners, status, version. No "add": they enroll themselves |
| Administration | **OID profiles** | Operator-authored OID overrides layered on the shipped packs |
| Setup | **Network scanning** | Enrollment keys, TLS policy, readiness checks |

With `glpinav` installed and on, the three Administration entries move together
into its **Operations** section; the pages resolve their own sector, so
breadcrumbs and Add buttons follow.

Everything the plugin needs is configured on those pages; GLPI's own inventory
setup screens are not involved. Check the **Readiness** panel first — it catches
the two GLPI settings above.

### Scanner

Linux and Windows, amd64 and arm64. One static binary either way — no runtime, no
interpreter, no agent framework. There is no macOS build.

Go to *Setup → Network scanning*, pick the entity the scanner belongs to, name a
key, and the page generates the command with the server and key filled in.

```bash
# Linux
sudo ./install-linux.sh
glpi-netscan install --server https://glpi.example.com --secret <key>
systemctl enable --now glpi-netscan
```

```
# Windows — an MSI, for GPO, Intune, SCCM or any other deployment channel
msiexec /i glpi-netscan_0.2.0_amd64.msi /qn ^
    SERVER=https://glpi.example.com ENROLLSECRET=<key>
```

| Property | |
|---|---|
| `SERVER` | GLPI base URL. Required to enrol |
| `ENROLLSECRET` | Enrollment key. Required to enrol |
| `CACERT` | Path on the target machine to a PEM bundle for a private CA |
| `SCANNERNAME` | Name shown in GLPI; defaults to the hostname |
| `NOUPDATES` | `1` to pin this host to the installed version |
| `INSTALLFOLDER` | Install root; defaults to `%ProgramFiles%\GLPI Netscan` |

Omit `SERVER` and `ENROLLSECRET` and the service is registered but left stopped
rather than restart-looping against a server it has never been told about.
Enrolment failing does not fail the install: the configuration is written before
GLPI is contacted, so a scanner deployed during an outage enrols on a later poll.

`install-windows.ps1` does the same without an MSI. It lays out
`%ProgramFiles%\GLPI Netscan` in the same versioned shape the updater maintains,
keeps state under `%ProgramData%\GLPINetscan`, and registers the service as
**LocalService** — the Windows counterpart of the empty capability bounding set
on the systemd unit.

`install` writes the configuration **and enrolls immediately**, so the failures
people actually hit — wrong URL, revoked key, untrusted certificate — surface at
the terminal rather than silently at the next service start.

Keys are **scoped to an entity**, and the entity a scanner enrolled into is where
its discovered assets land, so an MSP issues one key per client site and
everything files itself with no per-asset rules. Revoking a key stops new
enrollments and leaves running scanners alone; revoked keys stay listed, because
their enrolment counts are the record of what was installed with them.

### Building the MSI

Built on Linux with `packaging/build-msi.sh`, which needs `wixl` and `msitools`.
It asserts the package's own contents — secure properties, the versioned
directory name, the service account and start type, the custom-action type — and
fails rather than shipping a subtly wrong installer. Both architectures are built
the same way (`build-msi.sh <version> arm64`); wixl has no arm64 target, so the
package is built as x64 and its summary-information template corrected
afterwards, that template being the only architecture-dependent thing in an MSI
database.

wixl rather than the WiX Toolset: WiX only emits an MSI on Windows, so a release
could not be produced in one place, and from v6 it requires accepting the Open
Source Maintenance Fee EULA. wixl is LGPL and native. The cost is that it
implements a subset of WiX, which is why everything past "lay down the files and
register the service" lives in `glpi-netscan msi-install`.

## Self-update

Publish a release under *Setup → Network scanning → Published packages*: version,
platform, architecture, an **https** URL, its SHA-256 and its size. GLPI records
where a release lives and what it should hash to; it does not host the file. The
scanner authenticates the download by checksum, so the host serving it does not
have to be trusted.

Then open the tap. Two switches, not one:

| Setting | Default | |
|---|---|---|
| **Offer published packages to scanners** | off | Lets GLPI replace the binary on every scanner host |
| **Rollout percentage** | 0 | Share of the fleet the release has reached |

Enabling updates moves nothing by itself. Each scanner sits in a fixed ring from 0
to 99 derived from a hash of its row id, so raising the percentage always reaches
the same machines first, in the same order — a bad build is found on 5% of the
estate rather than all of it. The ring is keyed on the row id rather than hostname
or token because it has to be stable for the life of the machine.

The offer rides the poll a scanner already makes. Unlike the osquery agent —
which needs a channel of its own, because osqueryd's protocol is fixed — this
protocol is ours end to end and the poll already reports the running version.

**What a scanner does with an offer**

1. Downloads it and checks size and SHA-256. A mismatch is refused and nothing is
   touched.
2. Runs the new binary once and compares the version it reports against the
   manifest, catching a package built for the wrong architecture or the right
   bytes labelled as the wrong release, while the old version is still active.
3. Installs it as `versions/<version>/`, writes a rollback marker, flips the
   `current` symlink, and exits so systemd restarts it onto the new version.
4. On the next successful poll — reaching GLPI, not merely starting — clears the
   marker and prunes versions older than the previous one.

**When it goes wrong.** `preflight.sh` runs as `ExecStartPre` before every start,
including systemd's restarts after a crash, which is what lets it catch a version
that cannot start at all. It counts attempts in the marker and after three points
`current` back at the previous version.

It also quarantines the failed version. Without that the machine ping-pongs: the
restored version polls, is offered the same broken build, stages it again — and
because staging records whatever `current` points at as its rollback target, the
second attempt records the *broken* version as the fallback, after which there is
no way back. Quarantine is per-version, so publishing a fix reaches the machine
immediately.

A scanner installed by hand has no `versions/` tree, and the updater refuses to
stage rather than replacing the running binary in place. `updates_enabled = false`
in `agent.conf` pins an individual host.

| | Guard | Covers a binary that cannot start at all |
|---|---|---|
| Linux | `preflight.sh`, run by systemd as `ExecStartPre` | yes |
| Windows | `updater.Preflight()`, in-process at startup | no |

Windows has no `ExecStartPre`: the service control manager starts one binary, so
a guard running before it must be a second program or live inside it. Rather than
ship a launcher whose only job is to start another program, the check runs as the
first thing the scanner does.

That leaves one narrow case uncovered on Windows — a staged binary that cannot
start as a process at all — narrow because a version is only activated after the
updater has run it once and compared the version it printed. What remains is a
binary that runs standalone but dies as a service, and that does reach the
in-process guard.

Both implementations are held to the same behaviour by a test running them side
by side that fails if they roll back after a different number of failed starts.

## glpi-ai tools

| Tool | What it answers |
|---|---|
| `network_coverage` | What the scanner is watching: targets and ranges, when each last ran and whether it failed, and the devices that answered SNMP but never became an asset |
| `network_alarms` | What devices reported, with timestamps — a link that dropped overnight, a reboot, a power event |
| `power_status` | Whether a UPS is on mains or battery, charge, runtime, alarms |
| `wireless_status` | Access points, firmware, radios and client counts |

Deliberately not the port inventory. Ports, connections and link status end up in
GLPI's own tables, and glpi-ai reads them there natively — a site with no scanner
still has that data from the native agent, and offering a second copy would give
the model two sources that can disagree.

`network_coverage` is the exception to that rule, and earns it by being about the
*scanner* rather than the network: an inventory by definition only contains what
made it in, so "there is nothing on that subnet" usually means nobody has scanned
it. An unmapped device that answered SNMP is either shadow kit or a broken
mapping.

Gated on GLPI's `networking` right rather than `config`, which this plugin uses
for its scanners and targets. Those are configuration and belong to an
administrator; this is diagnostic data about network devices, and gating a UPS
battery level behind the configuration right would mean a technician could not
ask why the site lost power.

## Development

Two dev targets, because one is not enough:

- a real `net-snmp` agent with v1, v2c and v3 (SHA-512 / AES) all enabled, so the
  protocol paths are exercised against real software;
- three simulated devices (snmpsim): a Cisco switch serving BRIDGE-MIB,
  Q-BRIDGE-MIB and LLDP-MIB, an APC Smart-UPS serving UPS-MIB and PowerNet, and
  an APC rack PDU serving rPDU2 outlets and ENTITY-SENSOR. net-snmp on Linux
  implements none of these. One persona per container, because the scanner meets
  one device per address — sharing an endpoint would let the first matching
  community win and hide the others.

The fixtures are generated rather than hand-written: FDB tables are indexed by
MAC, VLAN membership is a bit-packed PortList, and sensor values carry an implied
decimal precision. All are easy enough to get wrong by hand that a bad fixture
would "prove" a broken collector — which happened once, when a mistyped alarm OID
made correct code look broken.

```bash
# local diagnostic; talks to no server
glpi-netscan -once -target 172.20.0.7 -community public \
             -profiles plugin/data/profiles/00-base.json

go test ./...
cd plugin/tests/browser && node netscan-check.js

# 370 dependency-free tests for the warranty lookup: all ten vendor clients
# against captured response shapes (asserting the requests too, since none of
# these APIs can be called from a test environment), vendor detection, failure
# classification and the projection onto GLPI's fields.
docker exec glpi-glpi-1 php /var/www/glpi/plugins/glpinetscan/tests/warranty.php
```

## Status

Working end to end: enroll → job → sweep → SNMP walk → payload → GLPI. A single
scan of the dev lab produces a `NetworkEquipment` with ports, VLANs and topology,
a `PDU` typed *UPS* with battery state and alarms, a `PDU` typed *Rack PDU* with
eight named outlets and inlet sensors, a `Phone` typed *VoIP* with both its
interfaces, and a second `Phone` for a handset that answers nothing at all,
inventoried out of the switch over LLDP-MED — and the switch's ports wire to
them.

Not yet built:

- **Vendor power control out of the box.** The mechanism ships and is tested;
  what does not ship is an APC/Eaton/Raritan outlet OID, because none could be
  read out of a published MIB here — the Observium listing for PowerNet is
  incomplete in exactly that subtree. Outlet switching therefore needs a profile
  entry, and this is the one place where an unverified OID would switch off the
  wrong thing rather than merely read the wrong value.
- **Rack placement.** GLPI can position a PDU in a rack; SNMP does not report
  where it is mounted.
- **Outlet-to-asset links.** Outlet names are captured verbatim ("esxi-01 PSU A")
  but they are free text a human typed into the PDU, and a wrong power dependency
  is worse than none.
- **Wireless client *sessions*.** Per-AP, per-radio and per-SSID client counts are
  collected; the tables listing individual associated stations are not. They are a
  point-in-time view of people rather than an inventory of things.
- **Phone line/extension.** `glpi_phones.number_line` is left empty: the extension
  is not in any standard MIB, and the vendor objects carrying it differ per
  handset. It is a profile field away for a site that knows its own fleet.
- **Non-voice LLDP-MED endpoints.** The switch reports model and serial for every
  MED endpoint, cameras and door controllers included, and the scanner reads all
  of it — but only phones can be delivered. Anything else could only be an
  `Unmanaged`, and GLPI has already created one: every MED endpoint is an LLDP
  neighbour of the switch, and GLPI's own inventory makes an `Unmanaged` for each
  unmatched neighbour while processing the switch. That asset wins — a later
  submission for the same MAC is matched to its network port instead of applied to
  it, and the model and serial are dropped.
- **Phone firmware.** Collected over LLDP-MED, but `glpi_phones` has no firmware
  column and GLPI only builds a firmware *component* for wireless controllers.

## Licence

Two components, two licences.

- `plugin/` — GPL-3.0-or-later. A GLPI plugin loaded into GLPI's process and
  extending its classes, so a derivative work.
- `scanner/` — MIT. A standalone program that reaches the plugin over HTTP and
  contains no GLPI code.
