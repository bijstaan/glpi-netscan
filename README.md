# GLPI Netscan

A lightweight SNMP network scanner for GLPI: a single static Go binary that
holds **no scan policy and no OID knowledge of its own**, plus a GLPI plugin
where all of it is configured.

Companion to [glpi-osquery](../glpi-osquery), which covers endpoints. This
covers everything that answers SNMP but cannot run an agent — switches,
routers, firewalls, printers, PDUs, UPSes.

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

## Why it is small

Because GLPI already does the hard half, and this deliberately does not
duplicate it:

| Concern | Owned by |
|---|---|
| SNMP credentials (v1/v2c/v3, encrypted) | **GLPI core** — `glpi_snmpcredentials` |
| Turning inventory data into assets | **GLPI core** — native inventory pipeline |
| Ports, IPs, components, locations | **GLPI core** |
| Payload format | **GLPI core** — `inventory.schema.json` |
| *What to scan, when, with which OIDs* | **this plugin** |
| *Talking SNMP and emitting the payload* | **this scanner** |

Core has no IP-range or scan-task tables — telling a scanner what to scan is
the actual gap, and it is the part that belongs in the web UI.

The scanner is ~1,800 lines of Go with one dependency (`gosnmp`). It ships no
OIDs: profiles arrive with the job.

## What it collects

Standard MIBs, out of the box. Nothing here is vendor-specific, so it works
across switches, routers, firewalls, UPSes, printers and VoIP phones alike:

| MIB | Gives |
|---|---|
| SNMPv2-MIB | name, description, contact, location, uptime, sysObjectID |
| IF-MIB `ifTable` | per-port descr, type, MTU, speed, admin/oper status, last change, in/out bytes and errors, MAC |
| IF-MIB `ifXTable` | **64-bit** octet counters, `ifHighSpeed`, port name, alias |
| EtherLike-MIB | duplex status |
| IP-MIB | device and per-port addresses |
| **BRIDGE-MIB** | **forwarding table — which MACs are behind which port** |
| **Q-BRIDGE-MIB** | **VLAN names, per-port membership, tagged/untagged, PVID, VLAN-aware FDB** |
| **IF-MIB ifStackTable / IEEE8023-LAG-MIB** | **link aggregation: which ports are bundled into which port-channel** |
| **LLDP-MIB** | **neighbour chassis, port, system name/description, management address** |
| **CISCO-CDP-MIB** | neighbours where LLDP is absent |
| ENTITY-MIB | serial, model, manufacturer, firmware, asset tag; stack members and modules |
| HOST-RESOURCES-MIB | memory |
| **PRINTER-MIB (RFC 3805)** | **toner, ink, drum, waste and kit levels; page counters, serial and model** |
| **UPS-MIB (RFC 1628)** | **battery state, runtime, input/output lines, alarms** |
| **ENTITY-SENSOR-MIB** | **temperature, humidity, current and power sensors** |
| **PowerNet / XUPS / Sentry3 / PDU2** | **vendor UPS identity and PDU outlet tables** |
| **AIRESPACE-WIRELESS-MIB** | **Cisco WLC: access points, radios, SSIDs and client counts** |
| **WLSX-WLAN-MIB / RUCKUS-ZD-WLAN-MIB** | **Aruba and Ruckus controllers: the same, per vendor** |
| **UBNT-UniFi-MIB / MIKROTIK-MIB** | **standalone access points: the networks they broadcast and their clients** |

### Topology

The forwarding table and LLDP/CDP together give GLPI real port-level topology:
it wires switch ports to the devices behind them and creates `Unmanaged` assets
for neighbours it has never seen. Verified end to end against a simulated
Cisco switch: 8 port-to-port links, neighbours resolved by LLDP, and MAC-only
neighbours resolved by OUI (GLPI turns `00:50:56:…` into "VMware, Inc.").

Three details that are easy to get wrong and are handled explicitly:

- **Bridge ports are not ifIndex.** `dot1dBasePortIfIndex` maps between them;
  the dev simulator deliberately offsets bridge ports by 100 so a collector
  that conflates the two fails loudly.
- **VLAN membership is a bit-packed `PortList`**, MSB-first, indexed by bridge
  port — so a 24-port switch numbering from 101 needs a 14-byte bitmap.
- **`self(4)` and `mgmt(5)` FDB entries are dropped.** They are the switch's
  own addresses; importing them wires every switch to itself.

A port is reported either as an LLDP/CDP link *or* as learned MACs, never both:
GLPI's `NetworkPort` asset switches on the port's `lldp` flag and reads the
whole `connections` array one way or the other.

### Link aggregation

Port-channels, bonds and ether-channels, from two sources in order of how much
they can be trusted:

- **IEEE8023-LAG-MIB** — `dot3adAggPortAttachedAggID` says outright which
  aggregator each port is *currently attached to*, and the MIB defines that
  identifier as the aggregator's own ifIndex. Nothing is inferred. Not every
  device implements it.
- **ifStackTable** (IF-MIB) — which interfaces are layered above which.
  Everything implements it, but a LAG is not the only thing that stacks: a VLAN
  interface sits above its ports too, and a tunnel above its transport.

So the stack table is filtered by the *aggregator's* interface type — the one
signal that separates a port-channel from an SVI. Taking every stack entry as an
aggregation would file each of a switch's SVIs as a port-channel containing half
the estate. The default set is `ieee8023adLag(161)` and `propMultiplexor(54)`;
hardware that reports a bundle as plain ethernet needs `aggregate_iftypes` in a
profile, because it cannot be distinguished from an SVI otherwise.

**GLPI drops these ports unless you tell it not to.** `glpi_networkporttypes`
ships `ieee8023adLag(161)` with `is_importable = 0` and no instantiation type,
so an aggregated interface is discarded by the inventory pipeline before its
member list is ever read — verified by submitting one and watching only the
members appear. GLPI models aggregation properly through `NetworkPortAggregate`;
the row simply is not switched on. The plugin switches it on at install and
reverts it at uninstall, and only reverts it if it still looks like ours, so a
site that enabled it deliberately does not lose it.

This is narrower than the `pdu_in_asset_types` opt-in and so is not a setting:
it changes one reference row, and the only behaviour it changes is whether an
aggregated interface is imported at all. Without it the collected data has
nowhere to go.

The member list is reported on the aggregator as ifIndexes, which is the shape
GLPI resolves to port ids itself. Members carry nothing — they are ordinary
ports that happen to be named by one — and a member that is not among the
collected ports is dropped rather than reported, since GLPI matches by ifIndex
and a name that resolves to nothing leaves a silent hole in the aggregate.

### Interface metrics

`ifXTable` is preferred wherever present. This is not cosmetic: the 32-bit
`ifSpeed` gauge **saturates at 4294967295** on anything above 4 Gbps (the dev
target shows exactly that), and 32-bit octet counters wrap in under a minute on
a loaded 10G link. `ifHighSpeed` is only trusted when `ifSpeed` could not have
been accurate, since below saturation `ifSpeed` is the more precise of the two.

GLPI's inventory schema has no field for discards, and none for live UPS state
(charge, runtime, load) — that is monitoring data, not inventory, so it is
deliberately not collected rather than forced somewhere it does not belong.

### Power devices — UPS, PDU and ATS

Power gear becomes a **native GLPI `PDU` asset**, typed *UPS*, *Rack PDU* or
*ATS*, with a **Power state** tab on the asset itself.

| Collected | From |
|---|---|
| Battery status, charge %, runtime, voltage, temperature, "replace battery" | UPS-MIB, PowerNet, XUPS |
| Output source — the "is it on battery?" answer | UPS-MIB |
| Input and output lines: volts, amps, watts, Hz, load % | UPS-MIB, rPDU2 phase table |
| Active alarms, named | UPS-MIB alarm table |
| Per-outlet name, on/off state and current | rPDU2, Sentry3, Raritan PX |
| Inlet temperature, humidity, per-bank sensors | ENTITY-SENSOR-MIB |
| Outlet **count** on the asset | GLPI `Item_Plug` |
| **Management port: name, MAC, IP, speed, MTU** | **IF-MIB + IP-MIB → GLPI `NetworkPort`** |

Every real UPS and rack PDU reaches the network through a management card, and
GLPI's PDU asset supports `NetworkPort` natively — so the port is created with
its MAC and address, as a proper Ethernet port. That records how to reach the
device, makes it findable by MAC or IP, and gives the switch's forwarding table
something to resolve against.

Power devices deliberately **bypass core's inventory pipeline**. Two
independent reasons, both verified rather than assumed: there is no
`Glpi\Inventory\MainAsset\PDU`, so core cannot build a PDU even if handed
one — the best it could manage is filing a UPS as `Unmanaged`; and the
inventory schema has no vocabulary for batteries, outlets or load, so the
interesting half of the data would be dropped. The plugin therefore creates the
PDU itself and keeps live state in its own tables.

That state is a **single current snapshot, not a time series**. "Is this UPS on
battery, and how long has it got?" is an inventory-shaped question; trending is
monitoring's job and does not belong in an asset database.

### One GLPI limitation, and the opt-in around it

A switch's forwarding table names the MAC of the UPS plugged into it. GLPI
resolves those MACs through its `RuleImportAsset` engine, which searches
`$CFG_GLPI['asset_types']` — and **PDU is not in that list** (it *is* in
`networkport_types`, which is why the port itself works). So by default a
switch port facing a UPS links to an `Unmanaged` placeholder rather than to the
UPS asset that already exists.

The setting **"Let switch topology resolve to UPS and PDU assets"** adds PDU to
that list, and with it the switch wires straight to the real asset — verified.
It is **off by default** because `asset_types` is consulted widely across core,
so it is an operator's decision rather than something a plugin should do to a
GLPI instance silently.

With it off, nothing churns: the placeholders are created once and left alone
(measured stable across repeated scans). With it on, placeholders left behind
by earlier scans are retired as each device is identified.

Ingest is also ordered so that referenced devices land before the devices that
reference them — switches are imported last, so the ports they point at
already exist.

### A GLPI bug that shapes how LLDP is submitted

GLPI reads a port's connections one of two ways, chosen by its `lldp` flag, and
**only one of them works**:

- `handleMacConnection()` resolves each MAC through the rule engine and calls
  `addPortsWiring()` — this links the switch port to the real asset.
- `handleLLDPConnection()` runs the same rules but guards the wiring behind
  `count($this->connection_ports) != 1`, on a property it resets to `[]`
  immediately above and never populates. GLPI's own source marks this as dead
  code, with a TODO calling it *"most likely"* a real bug.

So an LLDP neighbour always becomes an `Unmanaged` placeholder, even when the
device is already inventoried — meaning preferring LLDP, which is otherwise the
richer signal, actively loses the link.

The plugin therefore rewrites LLDP connections it can already identify into the
MAC form the working path understands: if a port already exists carrying the
neighbour's chassis MAC, GLPI gets the MAC and links to the real asset;
otherwise the LLDP form is kept, since nothing can be linked anyway and LLDP at
least yields a placeholder named `core-rtr-01` rather than one named after an
OUI.

The scanner also sends the far end's port **name** (`lldpRemPortId`, when the
port-ID subtype says it is an interface name) rather than its human description
— GLPI matches on the name, so sending `uplink` instead of `eth0` guarantees a
miss.

Detection is behavioural, not a guess from `sysObjectID`: a device is a power
device if it answers the standard UPS battery group, or a profile-declared
outlet table, or a profile says so. `sysServices` cannot help — power gear
reports itself as an ordinary IP-managed appliance, indistinguishable from
anything else with a web interface. A battery then separates a UPS from a rack
strip.

Because there is **no IETF PDU MIB**, rack strips are reached entirely through
vendor profiles. Shipped: APC rPDU2, ServerTech Sentry3 and Raritan PX for
outlets; APC PowerNet and Eaton XUPS for UPS identity. Every OID was taken from
the published MIBs — APC's *switched* outlet table is under `26.9.2` while
`26.9.4` is the separate *metered* table, which is not something to guess at.

Power OIDs accept a `*factor` scale suffix, because these MIBs report tenths of
a volt, amp or hertz and the factor differs per vendor for the same field:

```
battery_voltage = 1.3.6.1.2.1.33.1.2.5.0*0.1
outlet_current  = 1.3.6.1.4.1.318.1.1.26.9.4.3.1.6*0.1
```

Live UPS metrics that GLPI genuinely cannot hold — per-second load history,
energy totals over time — are still not collected, for the same reason as
before: they are monitoring data.

### VoIP phones

A handset that answers SNMP becomes a native GLPI **`Phone`** asset — name,
serial, model, manufacturer, `brand`, firmware, location, contact, type *VoIP*
— plus its network ports. Desk phones report **two** interfaces: the switch
uplink and the PC passthrough port the user's computer plugs into. Both are
recorded; the uplink MAC is the one the switch learns.

Recognising a phone is the interesting part, because the obvious signals fail:

- **`sysServices` cannot do it.** A desk phone contains a two-port switch, so
  it sets the datalink bit and looks like network equipment.
- **`sysObjectID` only works for vendors already in a profile**, which is no
  help for an unfamiliar handset.

So the primary signal is **LLDP**: `lldpLocSysCapEnabled` is a `BITS` value in
which `telephone(5)` is the bit a phone sets about itself, and that works for
any vendor. Profiles for Yealink, Polycom, Grandstream, Snom, Mitel, Fanvil,
Gigaset, Avaya and Cisco add the manufacturer on top. Every enterprise number
was checked against the IANA registry — two I had previously omitted as
unverified turned out to be right (Polycom 13885, Grandstream 42397), and one I
might have guessed wrong is not a phone vendor at all. Cisco phones share
Cisco's arc with every switch they make, so those are matched by `sysDescr`
regex instead.

Like PDU, phones bypass core's inventory pipeline, and for a verified reason:
`MainAsset\Phone` extends the base MainAsset, whose `prepare()` reads
`hardware`/`bios` — the *computer* inventory shape. Only `NetworkEquipment`
reads `network_device`. Feeding core a netinventory payload with
`itemtype: Phone` produces an asset with no name, MAC or serial, which its own
"Phone constraint (name)" rule then refuses. Unlike PDU, `Phone` **is** in
`asset_types`, so topology resolves to it with no opt-in.

#### Handsets that answer nothing

Most desk phones do not answer SNMP at all, or answer it only on a voice VLAN
the scanner cannot route to. Those are inventoried anyway, by **LLDP-MED**:
a phone announces its own manufacturer, model, serial number and firmware to
the switch port it is plugged into, and the switch hands all of it over. So a
scan of one switch produces a `Phone` asset for every handset on it — name,
serial, model, brand and asset tag — for devices the scanner never spoke to.
Same shape as access points behind a controller: one scanned address, several
assets, each keyed on its own identity.

What makes an endpoint a phone is **`lldpXMedRemMediaPolicyAppType = voice(1)`**
— a statement the MIB makes, not an inference from the model string. The media
policy table is indexed one arc wider than the inventory table, so the
application type is available per endpoint. The alternative is guessing from
model names, which turns an estate's cameras and door controllers into
telephones.

A handset visible both ways — answering SNMP *and* reported by its switch — is
submitted once. Both submissions describe the same asset, so GLPI merges them,
and the MED record knows nothing about the device's interfaces: letting it
through strips the ports the direct walk found. Second-hand information
overwriting first-hand information is a straight downgrade, so a device walked
directly in the same pass suppresses its MED record. The match is on serial and
MAC rather than address, because the two sources disagree about addresses by
nature — LLDP reports the endpoint's management address, often on a VLAN that
is never swept.

The OIDs are from **LLDP-EXT-MED-MIB** (ANSI/TIA-1057), under the TIA OUI
subtree `1.0.8802.1.1.2.1.5.4795`, and were read out of the published MIB
rather than recalled. The inventory table's seven columns come out contiguous,
which is itself a check on the reading.

### Wireless controllers and access points

An access point behind a controller is a real asset — a serial-numbered box that
gets RMA'd, moved between sites and replaced — and most of them cannot be
scanned at all. A CAPWAP-tunnelled AP has no reachable management address; the
controller is the only thing that knows it exists. So **one scanned address
produces many assets**: the controller, plus a NetworkEquipment for every AP it
reports, each with its own name, model, serial, location, firmware and address.

They are assets rather than components of the controller because that is what
they are. Filing them as components would make an RMA, a move and a replacement
all invisible.

The identity is the AP's own — serial first, then MAC — never the controller's
address. An AP moved to a different controller is the same physical box, and a
controller replaced under warranty must not orphan sixty access points.

**The switch port comes for free.** The controller reports each AP's Ethernet
MAC, which is exactly what the switch it is plugged into has learned, so the
existing topology correlation wires the AP to its real port. An AP that never
answered a single SNMP request ends up on the right port of the right switch —
and GLPI stops inventing an Unmanaged asset for a device it already has.

Provenance is the controller's address, not the AP's. The off-target guard
checks submissions against the ranges the scanner was told to sweep, and an AP
legitimately sits outside them — often on a management VLAN the scanner cannot
reach. Reporting its own address would have every AP rejected by a guard doing
its job correctly.

**Two shapes, one mechanism.** A *controller* enumerates access points that
cannot be scanned themselves. A *standalone* AP — UniFi, MikroTik — is the
asset, and only reports the networks it is broadcasting. Neither is
special-cased: the AP table is walked if the profile declares one, the SSID
table if it declares one, and whatever answers is what gets reported.

| Pack | |
|---|---|
| Cisco | AIRESPACE-WIRELESS-MIB — APs, radios, SSIDs |
| Aruba / HPE | WLSX-WLAN-MIB — APs, radios, SSIDs |
| Ruckus | RUCKUS-ZD-WLAN-MIB — APs, with a per-AP client count the others lack |
| UniFi | UBNT-UniFi-MIB — standalone, virtual APs |
| MikroTik | MIKROTIK-MIB — standalone, AP-mode interfaces |

Matched on enterprise roots rather than per-model: a Catalyst 9800 reports a
Cisco chassis sysObjectID, so a model list is whack-a-mole that stops working at
the next hardware refresh. Detection is behavioural and the gate is deliberately
cheap — one probe decides, so an ordinary Cisco switch does not pay for six
empty walks on every scan.

Adding a vendor is a **profile, not a release**: the collector owns the
mechanism, the profile owns the OIDs, under a `wireless` section
(`ap_name`, `ap_model`, `ap_serial`, `ap_mac`, `ap_ip`, `ap_location`,
`ap_status`, `ap_firmware`, `ap_radios`, `ap_clients`, `radio_band`,
`radio_channel`, `radio_clients`, `radio_status`, `ssid`, `ssid_clients`, and
`*_map` decoders).

The OIDs are read out of the published MIBs with
an internal MIB-parsing tool rather than recalled,
because a wrong OID here produces confidently wrong data rather than an error.
That tool refuses to print a parse that fails its anchors, and flags the one
systematic trap in the source: when a MIB does not publish its `Entry` object,
the table's index column absorbs the Entry's OID and comes out one arc short.

**Client counts, and where they really live.** Cisco and Aruba report clients
per *radio*, in a table indexed one arc finer than the AP table. The scanner
sums them back onto each access point by longest index prefix — so a per-AP
total exists nowhere on the wire and is derived. Reading that column as if it
were an AP column would attribute one radio's clients to the whole AP. Ruckus
publishes a real per-AP count, and where a vendor does, its own figure is used
rather than recomputed. A virtual-AP table lists the same SSID once per radio,
so those are folded by name and their clients summed.

**Radios become wifi ports.** GLPI models a radio as a `NetworkPort` whose
instantiation is `NetworkPortWifi`, with the 802.11 flavour as its version —
the right shape, and one the inventory format cannot express, so the plugin
writes it directly. A standalone AP additionally gets a port per SSID linked to
a `WifiNetwork` entry, because the networks genuinely belong to it. A
controller's SSID list does not: it is estate-wide, and no MIB here says which
network is on which radio of which AP, so inventing that link would be
fabrication.

**The Wireless tab** on a controller lists its SSIDs with client counts and
every access point — model, serial, status, clients, per-radio band, channel and
occupancy — each linked to its own asset. It appears only on devices the scanner
recorded wireless state for, rather than as an empty tab on every switch.

### Printer supplies

Toner, ink, drum, waste, fuser, transfer, cleaning and staple levels, from
`prtMarkerSuppliesTable`. No vendor OIDs and no per-model profile: every printer
worth managing implements RFC 3805, so a Kyocera, an HP and a Brother all answer
the same two tables. Levels land on the printer's **Cartridges** tab as GLPI's
own properties — *Toner Black*, *Drum Cyan*, *Maintenance kit* — because GLPI
matches against a closed vocabulary and anything outside it is stored unlabelled.

Two conventions are handled: a level in physical units (tenths of grams,
impressions, items) becomes a percentage of max capacity, and a level already
reported in percent is taken as-is.

**A supply that will not report a level is omitted, never sent as 0%.** The MIB
says "I do not know" with a negative level — `unknown(-2)`, `other(-1)` — and
`someRemaining(-3)` means there *is* some left. Turning any of those into 0%
produces an estate where every printer looks empty, which fails twice over:
toner gets ordered for printers that do not need it, and the one cartridge that
really is empty is invisible in the noise.

Waste bottles are reported as the percentage the device gives, which for a
receptacle is how *full* it is rather than how much is left. That is not
inverted here — GLPI stores one number per property with no room for the
distinction, and inverting would be a guess dressed as data.

Paper tray levels are collected by no one: GLPI's inventory format has nowhere
to put them.

### Device classification

Decided from a live marker counter *or* a marker supplies table (printer), a
battery or outlet table (power), and the `sysServices` datalink/internet bits
(networking); a vendor profile can force it. Anything else is reported
`Unmanaged` rather than guessed — GLPI has a first-class Unmanaged asset for
exactly that, and an operator can promote it.

Both printer signals are checked because small inkjets report ink levels and no
page counter at all, and would otherwise be filed as Unmanaged despite having
said plainly what they are.

## Device control (SNMP write)

Everything else here reads. This does not — and that difference is worth more
care than a feature flag, because the same mechanism that reboots a stuck access
point can black out a rack or cut the link the scanner reaches the device by.

**Four gates, all of which must be open** before one SNMP SET leaves a scanner:

1. **A global setting**, off by default and off after upgrades. Installing this
   plugin does not make an estate writable.
2. **A separate write credential per target** — not the community the scanner
   reads with. Reusing the read credentials would mean a community that happened
   to be read-write silently made every device it reached controllable.
3. **A right**, checked when the action is queued. Deliberately `config` UPDATE
   rather than UPDATE on the asset: being allowed to correct a switch's serial
   number is not the same as being allowed to shut its ports.
4. **An expiry.** A queued action not collected within ten minutes is abandoned
   and marked so. Otherwise a click that gets forgotten power-cycles a rack when
   a scanner reconnects hours later — the thing people rightly fear from this.

Actions are **queued, not performed inline**, because GLPI usually cannot reach
the device network at all; the scanner is the thing with a route. That the queue
also produces an audit trail — who asked, what for, what came of it — is a
consequence worth having.

The confirmation is **typed, not clicked**: to shut `GigabitEthernet0/3` you type
its name. The mistake this prevents is acting on the wrong row of a table, and an
"are you sure?" dismissed by reflex prevents none of it.

**One control is built in**: `port_admin`, which is `ifAdminStatus` — standard,
indexed by ifIndex like everything else about a port, and meaning the same on
every device implementing IF-MIB. Everything vendor-specific (outlet switching,
PoE) comes from a profile's `control` section instead, because those are the ones
where a wrong OID or a wrong index does not fail — it switches off something
else:

```json
"control": { "outlet_power": "1.3.6.1.4.1.318.1.1.26.9.2.4.1.5 on=1,off=2,cycle=3" }
```

The queue holds **intent** (`this port, down`) rather than an OID: the profile
that declares a control is matched on the device's sysObjectID and only the
scanner knows it — and an audit row saying `Gi0/3 → down` is still readable a
year later where `1.3.6.1.2.1.2.2.1.7.3 = 2` is not.

## SNMP notifications (traps)

A device that sends a trap is telling the scanner it has changed. That is better
evidence than the counters a discovery pass reads, and it arrives immediately
rather than at the next sweep — so **a notification clears that device's
last-inventory stamp and the next pass walks it**, without waiting for the
interval. Measured on the dev estate: a `linkDown` from one switch turned the
next sweep into `probed 8, answered 8, walked 1`.

The trust model is stated plainly because it is weak by design of the protocol,
not of this code. An SNMPv1 or v2c trap is an unauthenticated UDP datagram with a
community string in it, trivially forged by anything that can route a packet to
the listener. So:

- notifications are **off** unless switched on;
- a scanner accepts them **only from addresses inside its own scan ranges** —
  the same rule inventory submissions follow. An empty range list closes the
  listener rather than opening it;
- **nothing a trap says is written into an asset.** It is stored and shown as the
  device's claim. It can cause a re-inventory, where the facts are then read from
  the device itself.

That last rule is what makes the weak authentication tolerable: the worst a
forged trap achieves is an SNMP walk of a device the scanner was already allowed
to walk.

Notifications appear on a **Notifications** tab, named where the OID is
well-known (`coldStart`, `warmStart`, `linkDown`, `linkUp`,
`authenticationFailure`) rather than shown as bare arcs. They are pruned per
device, because a trap log is a stream and a flapping port would otherwise fill a
disk with copies of one sentence.

Binding the standard port 162 needs `CAP_NET_BIND_SERVICE`, which the hardened
systemd unit does not grant. Apply `packaging/glpi-netscan-traps.conf` as a
drop-in, or set a port above 1024 — a drop-in rather than a change to the unit,
because most installations do not receive traps and should not carry the
capability.

## Discovery and inventory

Every pass probes the whole range cheaply. A device is only walked in full when
that is worth doing.

The reason is a measurement, not a hunch: against the SNMP simulators,
with tiny tables over loopback, **a full walk costs 86–157× a probe** — roughly
2 ms against 200–360 ms. A 48-port switch across a WAN is far worse. So a
sweep's cost is dominated by walking the devices that *answer*, not by probing
the addresses that do not, and the saving comes from not re-walking a device
that has not changed.

```
first pass    probed 8 in 4ms, answered 8, walked 8 in 2.5s
second pass   probed 8 in 4ms, answered 8, walked 0
after a reboot on one switch      walked 1 in 555ms
after deleting one printer asset  walked 1 in 316ms
```

**The decision is GLPI's, not the scanner's.** Only the server knows what it
already holds, when it last held it, and whether someone has since deleted the
asset. A scanner keeping its own notes would happily skip a device whose asset
had been removed, and GLPI would stay empty with nothing to explain why. So a
discovery batch is answered with the list of devices to walk, and the scanner
stays as stateless as it is everywhere else.

A device is walked when:

- it has never been walked, **or the asset it produced no longer exists** —
  which is what makes deleting an asset a supported way to force a clean
  re-import;
- it rebooted, seen as `sysUpTime` going backwards. That matters twice over,
  because every other counter here is measured against `sysUpTime` and none of
  them is comparable across a restart;
- a standard change counter moved: `ifTableLastChange` (an interface created or
  deleted), `ifStackLastChange` (the layering between them changed), or
  `entLastChangeTime` (a module, stack member or transceiver);
- the last full walk is older than the target's **inventory interval**.

That last rule exists because the counters cannot see everything. None of them
moves when a port goes down or a MAC moves between ports, and both matter to
GLPI — so "nothing looks changed" is never allowed to mean "never walk again".
It defaults to a day. Zero switches the rule off and leaves only the change
signals, which suits a range of appliances that never change and does not suit a
switch estate.

A device that implements none of the counters reports zero every pass. That is
an absence of evidence, not evidence of change: treating it as a change would
walk such hardware on every single sweep and give back the whole saving.

Each target's form shows its **recent scans** — probed, answered, walked, and
the timings — because those are the numbers the two intervals are tuned
against, and a sweep that walks everything every time means the change signals
are not reaching that hardware.

The split is negotiated, not assumed. A scanner talking to a plugin that
predates it gets no `inventory_wanted` field and walks everything it finds,
which is exactly the behaviour before any of this existed.

## Extending it with device-specific OIDs

Profiles are layered by priority; the base profile is 0 and vendor profiles sit
above it. Two sources, merged at job time:

- **Shipped packs** — `plugin/data/profiles/*.json`, matched by
  `sysobjectid_prefix` (the enterprise arc under `1.3.6.1.4.1` is assigned per
  vendor, so a prefix is a reliable discriminator). Diffable in git, upgraded
  with the plugin. A pack file may hold one profile or a list of them.

  Shipped today: the standard-MIB base, printers, UPS identity, and ~36 vendor
  entries covering switching/routing (Cisco, HPE/Aruba, Juniper, Arista,
  Extreme, Dell, Huawei, MikroTik, Ubiquiti, Brocade, ALE, NETGEAR, TP-Link,
  D-Link, Zyxel, Allied Telesis, 3Com), firewalls (Fortinet, Palo Alto,
  SonicWall, Check Point, F5), power (APC, Eaton, CyberPower, Raritan),
  printers (Xerox, Lexmark, Ricoh, Kyocera, Brother, Epson) and VoIP (Avaya,
  Yealink).

  The vendor list is **identification only** — it sets the manufacturer and,
  for power and VoIP, the asset type. No data collection depends on it being
  complete, because collection comes from the standard MIBs.
- **UI profiles** — rows created under *Administration → Network scanning →
  OID profiles*, layered on top. This is how a site adds one OID for one switch
  model without forking the plugin or losing it on upgrade.

UI profiles are authored as `field = OID` lines, not raw JSON, because the
field names are a closed vocabulary that maps onto the inventory schema — so
the form rejects a typo instead of accepting a profile that silently collects
nothing. OIDs are validated as dotted decimal; the value is forwarded to the
scanner and used to build requests, so it is not a place to smuggle text.

Three value forms, all usable from the UI:

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

**Alternatives exist because layering is otherwise destructive**, and this bit
me while building: the printer pack applied to every device and overrode
`serial`, so every switch it touched came back with a blank serial — the base
ENTITY-MIB OID was never even read. A broad profile can now say "prefer mine,
fall back to the standard one".

Prefix matching is **arc-wise**, not string-wise: `1.3.6.1.4.1.9` does not
match enterprise `91`.

Individual collectors can also be switched off per profile (`fdb`, `lldp`,
`cdp`, `vlans`, `hc_counters`) for hardware that answers a table with *wrong*
data rather than no data. All are on unless turned off, so a new device needs
no configuration.

## Security

Modelled on the osquery agent's credentials, because the threat is the same
shape. Full detail in [docs/protocol.md](https://gitlab.rfni.dev/norsewind/glpi-erpnext-mods/-/wikis/glpi-netscan/protocol).

- **Two-tier credentials.** A shared, scopable, revocable *enrollment secret*
  is exchanged once for a *per-scanner token*. The token is stored as a
  SHA-256 hash and shown exactly once — the database never holds a value that
  can be replayed.
- **TLS required by default**, at both ends. The job response carries
  decrypted community strings and v3 passphrases.
- **Revocation** is `scanner_invalid`; deactivating a scanner cuts it off at
  the next poll and the agent re-enrolls rather than retrying.
- **Scanners can only report on what they were told to scan.** Reported
  addresses are checked against the target's ranges, and the target is resolved
  from the run row rather than the request. Off by default to change.
- **Entity comes from the scanner**, never from the payload — a submission is
  data, not authority.
- **Range expansion is capped** at 65,536 addresses, so `/8` instead of `/24`
  is a visible error rather than a scanner that appears hung for a week.
- **The enrollment key passed to the MSI can reach a verbose install log.**
  `ENROLLSECRET` is marked hidden, which masks the property itself, but the
  resolved command line of the enrolment action can still appear under `/l*v`.
  This is tolerable by design rather than by accident: an enrollment key is a
  shared, scopable, revocable credential that buys exactly one thing — the right
  to obtain a per-scanner token. Revoke it in GLPI and it is dead, while
  scanners that already enrolled keep working on their own tokens.
- **Self-update payloads are verified before they execute** — SHA-256, size,
  and the binary's own reported version, checked while the old version is still
  active. A self-updater that installs whatever it downloads is a remote code
  execution channel into every machine running it, and TLS to the right host
  proves only where the bytes came from.
- The systemd unit keeps an empty capability bounding set, `ProtectSystem=strict`
  and a `@system-service` seccomp filter. It runs as a dedicated unprivileged
  user rather than `DynamicUser`, which self-update made impossible: a transient
  UID has no persistent writable install tree to update into.

## Install

**Plugin**

```bash
# from the GLPI root — the directory has to be named for the plugin
# key, which is not the repository name
git clone https://github.com/bijstaan/glpi-netscan.git plugins/glpinetscan
php bin/console plugin:install -u glpi glpinetscan
php bin/console plugin:activate glpinetscan
```

Four entries appear, split the way GLPI itself splits things — the day-to-day
objects under **Administration**, and how the plugin is configured under
**Setup**:

| Menu | Entry | For |
|---|---|---|
| Administration | **Scan targets** | IP ranges, credentials, schedule, timeouts — the main page |
| Administration | **Scanners** | Enrolled scanners, status, version. No "add": they enroll themselves |
| Administration | **OID profiles** | Operator-authored OID overrides layered on the shipped packs |
| Setup | **Network scanning** | Enrollment keys, TLS policy, readiness checks |

With **GLPI Nav** installed and switched on, the three Administration entries
move together into its **Operations** section; the pages resolve their own
sector, so their breadcrumbs and Add buttons follow. Without it — or with it
switched off — they are exactly where the table says.

Everything the plugin needs is configured on those pages. GLPI's own inventory
setup screens are not involved and do not need to be touched. Check the **Readiness**
panel first — it catches the two GLPI settings that make scans silently import
nothing (see below).

**Scanner**

Linux and Windows, amd64 and arm64. One static binary either way — no runtime,
no interpreter, no agent framework.

Go to *Setup → Network scanning*, pick the entity the scanner belongs to, name a
key, and the page generates the command with the server and key filled in.

*Linux* — `install-linux.sh` lays out `/opt/glpi-netscan` and the systemd unit,
then enroll:

```bash
sudo ./install-linux.sh
glpi-netscan install --server https://glpi.example.com --secret <key>
systemctl enable --now glpi-netscan
```

Both amd64 and arm64 MSIs are built the same way — `build-msi.sh <version> arm64`.
wixl has no arm64 target, so the package is built as x64 and its
summary-information template corrected afterwards; that template is the only
architecture-dependent thing in an MSI database.

The MSI is built on Linux with `packaging/build-msi.sh`, which needs
`wixl` and `msitools` (`wixl` is a separate Debian package). It asserts the
package's own contents — secure properties, the versioned directory name, the
service account and start type, the custom-action type — and fails rather than
shipping a subtly wrong installer. The `windows-msi` workflow builds it the same
way and then installs and uninstalls it on a Windows runner.

wixl rather than the WiX Toolset: WiX only emits an MSI on Windows, so a release
could not be produced in one place, and from v6 it requires accepting the Open
Source Maintenance Fee EULA with a fee due above a revenue threshold. wixl is
LGPL and native. The cost is that it implements a subset of WiX, which is why
everything past "lay down the files and register the service" lives in
`glpi-netscan msi-install` rather than in installer custom actions.

*Windows* — an MSI, for GPO, Intune, SCCM or any other deployment channel:

```
msiexec /i glpi-netscan_0.2.0_amd64.msi /qn ^
    SERVER=https://glpi.example.com ENROLLSECRET=<key>
```

| Property | |
|---|---|
| `SERVER` | GLPI base URL. Required to enrol. |
| `ENROLLSECRET` | Enrollment key. Required to enrol. |
| `CACERT` | Path on the target machine to a PEM bundle for a private CA |
| `SCANNERNAME` | Name shown in GLPI; defaults to the hostname |
| `NOUPDATES` | `1` to pin this host to the installed version |
| `INSTALLFOLDER` | Install root; defaults to `%ProgramFiles%\GLPI Netscan` |

Omit `SERVER` and `ENROLLSECRET` and the service is registered but left stopped,
rather than restart-looping against a server it has never been told about. Enrol
later with `glpi-netscan install` and start it.

Enrolment failing does **not** fail the install: the configuration is written
before GLPI is contacted, so a scanner deployed while GLPI happens to be down
enrols itself on a later poll. A five-minute outage should not turn into hundreds
of failed deployments.

`install-windows.ps1` does the same thing without an MSI, for one-off installs.

It lays out `%ProgramFiles%\GLPI Netscan` in the same versioned shape the
updater maintains, keeps state and configuration under
`%ProgramData%\GLPINetscan`, and registers the service as **LocalService** —
the Windows counterpart of the empty capability bounding set on the systemd
unit. The scanner needs no privilege; it sends SNMP and HTTPS and writes its own
token.

There is no macOS build. A scanner is placed on a server or a small always-on
box at a site, and Apple sells neither.

`install` writes the configuration **and enrolls immediately**, so the failures
people actually hit — wrong URL, revoked key, untrusted certificate — surface
at the terminal rather than silently at the next service start. Add
`--ca-cert` for a private certificate authority, `--name` to override the
hostname shown in GLPI.

Keys are **scoped to an entity**, and the entity a scanner enrolled into is the
entity its discovered assets land in — so an MSP issues one key per client site
and everything files itself correctly with no per-asset rules. The new-key form
defaults to whichever entity you are currently working in.

The settings page lists every key with its entity, how many scanners have
enrolled with it, and its status. Revoking a key stops new enrollments and
leaves running scanners alone; revoked keys stay listed, because their
enrolment counts are the record of what was installed with them.

## Self-update

Scanners can update themselves, on the same model as the osquery agent — a site
running both should not need two mental models of how its fleet upgrades.

Publish a release under *Setup → Network scanning → Published packages*: version,
platform, architecture, an **https** URL, its SHA-256 and its size. GLPI records
where a release lives and what it should hash to; it does not host the file.
Since the scanner authenticates the download by checksum, the host serving it
does not have to be trusted, and GLPI does not become a binary distribution
point with the storage and access-control questions that would bring.

Then open the tap. Two switches, not one:

| Setting | Default | |
|---|---|---|
| **Offer published packages to scanners** | off | Lets GLPI replace the binary on every scanner host |
| **Rollout percentage** | 0 | Share of the fleet the release has reached |

Enabling updates moves nothing by itself, because the rollout starts at zero.
Each scanner sits in a fixed ring from 0 to 99 derived from a hash of its row
id, so raising the percentage always reaches the same machines first, in the
same order — a bad build is found on 5% of the estate rather than all of it, and
a scanner never oscillates as the number moves. The ring is keyed on the row id
rather than hostname or token because it has to be stable for the life of the
machine: a rename or a re-enrolment would otherwise silently re-roll it.

The offer rides the poll a scanner already makes. Unlike the osquery agent —
which needs a channel of its own, because osqueryd's protocol is fixed and knows
nothing about updating itself — this protocol is ours end to end, and the poll
already reports the running version.

**What a scanner does with an offer**

1. Downloads it and checks the size and SHA-256. A mismatch is refused and
   nothing is touched.
2. Runs the new binary once and compares the version it reports against the
   manifest — this catches a package built for the wrong architecture, or the
   right bytes labelled as the wrong release, while the old version is still
   active and recoverable.
3. Installs it as `versions/<version>/`, writes a rollback marker, flips the
   `current` symlink, and exits so systemd restarts it onto the new version.
4. On the next successful poll — **reaching GLPI, not merely starting** — clears
   the marker and prunes versions older than the previous one.

**When it goes wrong**

`preflight.sh` runs as `ExecStartPre` before every start, including systemd's
restarts after a crash, which is what lets it catch a version that cannot start
at all: the scanner itself could not, because it would never run. It counts
attempts in the marker, and after three points `current` back at the previous
version.

It also quarantines the failed version. Without that the machine ping-pongs:
the restored version polls, is offered the same broken build, stages it again —
and because staging records whatever `current` points at as its rollback target,
the second attempt records the *broken* version as the thing to fall back to,
after which there is no way back at all. Quarantine is per-version, so
publishing a fix reaches the machine immediately while the bad build stays
refused.

A scanner installed by hand rather than by an installer has no `versions/` tree,
and the updater refuses to stage rather than replacing the running binary in
place. `updates_enabled = false` in `agent.conf` pins an individual host whatever
GLPI offers.

**Rollback differs by platform, deliberately**

| | Guard | Covers a binary that cannot start at all |
|---|---|---|
| Linux | `preflight.sh`, run by systemd as `ExecStartPre` | yes |
| Windows | `updater.Preflight()`, in-process at startup | no |

Windows has no `ExecStartPre`: the service control manager starts one binary, so
a guard that runs before it must either be a second program or live inside it.
Rather than ship a launcher whose only job is to start another program, the check
runs as the first thing the scanner does.

That leaves one narrow case uncovered on Windows — a staged binary that cannot
start as a process at all. It is narrow because a version is only activated after
the updater has already run it once and compared the version it printed, so a
package for the wrong architecture, a truncated download or a missing runtime is
rejected while the old version is still active. What remains is a binary that
runs standalone but dies as a service, and that one does reach the in-process
guard.

Both implementations are held to the same behaviour by a test that runs them
side by side and fails if they roll back after a different number of failed
starts.

## Two GLPI settings that will bite you

Both make a scan look completely successful while importing nothing, and
neither raises an error. The Readiness panel checks both, and a rejected
device reports which one it hit.

1. **`enabled_inventory` must be on** (*Setup → General → Inventory*). With it
   off, `doInventory()` accepts payloads and discards them.
2. **`NetworkEquipment import (by mac)` ships disabled.** GLPI's stock rules
   only import network equipment that has a *serial number*, and many switches
   expose none. Everything else falls through to *import denied* and lands in
   *Administration → Refused equipment*. Enable the by-mac rule under
   *Administration → Rules → Rules for asset import*.

The scanner mitigates (2) by deriving a device MAC from the lowest-numbered
port when the device offers no chassis MAC, so the by-mac rule has something
to key on.

## Development

Two dev targets, because one is not enough:

- a real `net-snmp` agent with v1, v2c and v3 (SHA-512 /
  AES) all enabled, so the protocol paths are exercised against real software.
- three simulated devices (snmpsim): a Cisco switch
  serving BRIDGE-MIB, Q-BRIDGE-MIB and LLDP-MIB, an APC Smart-UPS serving
  UPS-MIB and PowerNet, and an APC rack PDU serving rPDU2 outlets and
  ENTITY-SENSOR. net-snmp on Linux implements none of these. One persona per
  container, because the scanner meets one device per address — sharing an
  endpoint would let the first matching community win and hide the others.

  The fixtures are *generated* rather than hand-written: FDB tables are indexed
  by MAC, VLAN membership is a bit-packed PortList, and sensor values carry an
  implied decimal precision. All are easy enough to get wrong by hand that a
  bad fixture would "prove" a broken collector — which is exactly what happened
  once, when a mistyped alarm OID made correct code look broken.

```bash
# local diagnostic; talks to no server
glpi-netscan -once -target 172.20.0.7 -community public \
             -profiles plugin/data/profiles/00-base.json

go test ./...
cd glpi-netscan/plugin/tests/browser && node netscan-check.js
```

## Status

Working end to end: enroll → job → sweep → SNMP walk → payload → GLPI. A single
scan of the dev lab produces a `NetworkEquipment` with ports, VLANs and
topology, a `PDU` typed *UPS* with battery state and alarms, a `PDU` typed
*Rack PDU* with eight named outlets and inlet sensors, and a `Phone` typed
*VoIP* with both its interfaces, and a second `Phone` for a handset that
answers nothing at all, inventoried out of the switch over LLDP-MED — and the
switch's ports wire to them.

Not yet built:

- **Vendor power control out of the box.** The mechanism ships and is tested;
  what does not ship is an APC/Eaton/Raritan outlet OID, because none could be
  read out of a published MIB here — the Observium listing for PowerNet is
  incomplete in exactly that subtree. Outlet switching therefore needs a
  profile entry, and this is the one place in the plugin where an unverified
  OID would switch off the wrong thing rather than merely read the wrong value.
- **Rack placement.** GLPI can position a PDU in a rack; SNMP does not report
  where it is mounted, so this stays manual.
- **Outlet-to-asset links.** Outlet names are captured verbatim ("esxi-01 PSU
  A"), but they are free text a human typed into the PDU — matching them to
  GLPI assets would be guesswork, and a wrong power dependency is worse than
  none.
- **Wireless client *sessions*.** Per-AP, per-radio and per-SSID client
  *counts* are collected; the tables listing individual associated stations —
  which device, which signal strength, how long — are not. They are a
  point-in-time view of people rather than an inventory of things, and GLPI has
  nowhere to put them that would not go stale between scans.
- **Phone line/extension.** `glpi_phones.number_line` is left empty: the
  extension is not in any standard MIB, and the vendor objects that carry it
  differ per handset. It is a profile field away for a site that knows its own
  fleet.
- **Non-voice LLDP-MED endpoints.** The switch reports model and serial for
  every MED endpoint, cameras and door controllers included, and the scanner
  reads all of it — but only phones can be delivered. Anything else could only
  be an `Unmanaged`, and GLPI has already created one for it: every MED
  endpoint is an LLDP neighbour of the switch, and GLPI's own inventory makes
  an `Unmanaged` (named from the MAC's vendor prefix) for each unmatched
  neighbour while processing the switch. That asset wins — a later submission
  for the same MAC is matched to its network port instead of applied to it, and
  the model and serial are dropped. Submitting one before the switch's own
  inventory gives the same result, so this is not an ordering problem. Sending
  them anyway would be code that runs, reports success and changes nothing.
- **Phone firmware.** Collected over LLDP-MED, but `glpi_phones` has no
  firmware column and GLPI only builds a firmware *component* for wireless
  controllers, so there is nowhere to put it. This is true of the directly
  scanned handsets too.

## Licence

Two components, two licences.

- `plugin/` — GNU General Public License, version 3 or later. It is a GLPI
  plugin, loaded into GLPI's process and extending its classes, so it is a
  derivative work of GLPI and carries GLPI's licence.
- `scanner/` — MIT. It is a standalone program that reaches the plugin over
  HTTP and contains no GLPI code.

---

## Asking the scanner from glpi-ai's assistant

If **glpi-ai** is installed, this plugin registers three tools with its
troubleshooting assistant:

| Tool | What it answers |
|---|---|
| `network_alarms` | what devices reported, with timestamps — a link that dropped overnight, a reboot, a power event |
| `power_status` | whether a UPS is on mains or battery, charge, runtime, alarms |
| `wireless_status` | access points, firmware, radios and client counts |

Deliberately **not** the port inventory. Ports, connections and link status end
up in GLPI's own tables, and glpi-ai reads them there natively — a site with no
scanner still has that data from the native agent, and offering a second copy
would give the model two sources that can disagree.

What is here is the part with nowhere else to live. The trap tool is the one
worth having: "the link dropped at some point last night" is answerable from an
inventory only by inference, and a linkDown trap with a timestamp answers it
outright.

The tools are gated on GLPI's `networking` right rather than on `config`, which
is what this plugin uses for its scanners and targets. Those are configuration
and belong to an administrator; this is diagnostic data about network devices,
and gating a UPS battery level behind the configuration right would mean a
technician could not ask why the site lost power.
