# glpi-netscan protocol — verified notes

Everything here was verified against a running GLPI 11 and a real `net-snmp`
agent (all three SNMP versions), not taken from documentation. The dev SNMP
target is a stock `net-snmp` agent.

## The central design decision

**GLPI already owns the hard half.** Core ships:

- `glpi_snmpcredentials` — SNMP v1/v2c/v3 credentials, already managed in the
  web UI, with `auth_passphrase` / `priv_passphrase` GLPIKey-encrypted.
- `Glpi\Inventory\MainAsset\NetworkEquipment`, `GenericPrinterAsset`,
  `Unmanaged` — the asset builders.
- `Glpi\Inventory\Request`, which accepts `NETDISCOVERY` / `NETINVENTORY` and,
  **when no plugin hooks `Hooks::NETWORK_INVENTORY`, falls back to core's own
  native handling**.
- The authoritative payload contract at
  `vendor/glpi-project/inventory_format/inventory.schema.json`.

So this plugin does *not* assemble assets. The scanner emits the documented
format and the plugin hands it to `Glpi\Inventory\Inventory` in-process. What
core does **not** provide is any way to tell a scanner *what to scan* — there
are no IP-range or task tables — and that gap is what the plugin fills.

## Why not post to `/Inventory` directly?

Core's inventory endpoint authenticates with `auth_required`, which is only
`none` or a single shared `basic_auth`. That is well below the bar set by the
osquery agent's per-node credentials. Instead the scanner reports to the
plugin with its own per-scanner token and the plugin drives the inventory
pipeline directly — same objects created, one strong credential, and no
publicly reachable inventory endpoint required.

## Auth model

Mirrors the osquery agent, because the threat has the same shape.

| | Enrollment secret | Scanner token |
|---|---|---|
| Scope | Shared bootstrap, per entity | One scanner |
| Storage | SHA-256 **and** GLPIKey-encrypted (see below) | SHA-256 **hash** only |
| Rotation | Create/revoke freely; existing scanners unaffected | Deactivate the scanner |
| Compromise | Register a visible, revocable scanner | Expose one scanner |

A secret is stored **twice**, which is not redundancy. GLPIKey encryption is
non-deterministic, so an encrypted column cannot be matched against — without a
hash, verifying a presented secret means decrypting every row on every
enrollment attempt. The encrypted copy exists so the settings page can rebuild
the install command later without the plaintext sitting at rest in the clear.
`enroll_count` records how many scanners each key has brought online.

The entity on the secret is the entity the scanner enrolls into, and
`Ingest`/`PowerIngest`/`PhoneIngest` all take the asset entity from the scanner
rather than from anything in the payload — so one key per client site is all
the entity routing an MSP needs.

Revocation is `scanner_invalid: true`, which tells the agent to discard its
token and re-enroll. Deactivating a scanner in the UI is sufficient to cut it
off at the next poll.

`require_tls` defaults **on**. The job response carries decrypted community
strings and v3 passphrases; plaintext hands the estate's SNMP credentials to
anyone on the path. The agent refuses a non-`https` server URL for the same
reason, so a misconfiguration fails at both ends.

The three endpoints are registered `STRATEGY_NO_CHECK` and stateless via
`Firewall::addPluginStrategyForLegacyScripts()` and
`SessionManager::registerPluginStatelessPath()`. That removes *GLPI's* session
and CSRF checks, not the plugin's — each endpoint authenticates first.

## Endpoints

All POST, JSON in and out, under `/plugins/glpinetscan/front/`.

### `enroll.php`

```json
{"enroll_secret":"…","hostname":"…","platform":"linux/amd64","agent_version":"0.1.0"}
→ 201 {"scanner_token":"…","scanner_id":1,"entities_id":0}
```

The token is returned **once**; only its hash is stored. Wrong, expired and
revoked secrets all return an identical `403 enrollment_refused` — an
unauthenticated caller must not be able to enumerate which secrets exist.

### `job.php`

```json
{"scanner_token":"…"}
→ {"scanner_invalid":false,"poll_interval":60,
   "jobs":[{"job_id":10,"target_id":1,"ranges":["172.20.0.0/24"],
            "credentials":[{"id":4,"version":"3","username":"netscan",
                            "auth_protocol":"SHA512","auth_passphrase":"…",
                            "priv_protocol":"AES","priv_passphrase":"…"}],
            "options":{"port":161,"timeout_ms":1500,"retries":1,"concurrency":64}}],
   "profiles":[…]}
```

Targets are claimed on dispatch (`last_run` is stamped immediately) so two
scanners polling at once are not handed the same sweep. Profiles are omitted
when there is no work — they are the bulkiest part and the idle poll should
stay cheap.

### `report.php`

```json
{"scanner_token":"…","job_id":10,"discovered":1,"failed":0,
 "payloads":[{"deviceid":"…","action":"netinventory","itemtype":"NetworkEquipment","content":{…}}]}
→ {"accepted":1,"rejected":0,"results":[{"ok":true,"itemtype":"NetworkEquipment","items_id":1}]}
```

The target used for range validation is resolved from the **run row**, never
from the request, so a scanner cannot nominate the ranges it will be checked
against.

## Payload contract — three things that bite

These were all found by running the pipeline, not by reading the schema.

**1. `itemtype` is top-level and defaults to `Computer`.**
`Inventory::extractMetadata()` reads `$raw_data->itemtype ?? Computer::class`.
Omit it and every switch and printer is silently filed as a computer — it does
not error. The scanner sets it; the plugin derives it again as a safety net.

**2. The agent row pins the itemtype.**
`doInventory()` calls `$this->agent->handleAgent($metadata)` and then takes the
itemtype **from the agent row**, keyed by `deviceid`. A deviceid first seen
with the wrong itemtype keeps it. If a device is stuck as the wrong type,
delete its `glpi_agents` row.

**3. Port status fields are integers, not strings.**
`ifstatus` (ifOperStatus), `ifinternalstatus` (ifAdminStatus, constrained to
1..3), `iftype` and `ifportduplex` are all `"type": "integer"`. `connections`
and `aggregate` are **arrays**. `uptime` and `iflastchange` are strings in
`"X days, HH:MM:SS"` form. `network_device.type` is pinned to
`^(Unmanaged|Computer|Networking|Printer|Storage|Power|Phone|Video|KVM)$`.

## The refusal trap

GLPI's stock asset-import rules only import a `NetworkEquipment` that has a
**serial number**:

| Rule | Ships |
|---|---|
| NetworkEquipment update (by serial) | enabled |
| NetworkEquipment update (by mac) | **disabled** |
| NetworkEquipment import (by serial) | enabled |
| NetworkEquipment import (by mac) | **disabled** |
| NetworkEquipment import denied | enabled |

Plenty of switches expose no ENTITY-MIB serial. On a default install those
fall through to *import denied* and land in
`glpi_refusedequipments` — `doInventory()` raises **no error**, so the
submission looks successful and no asset appears.

Two mitigations, both implemented:

- The scanner derives a device MAC from the lowest-numbered port when the
  device offers no chassis MAC, so the by-mac rule has something to key on.
- The plugin treats "no asset created" as a **failure**, inspects
  `getMainAsset()->getRefused()`, and reports the refusal with the rule to
  enable. The config page's Readiness panel checks the same thing up front.

`enabled_inventory` being off produces exactly the same silent success, and is
checked in the same two places.

## Topology encodings — the three that bite

Verified against a simulated Cisco switch (snmpsim), whose fixture
is generated precisely because these are easy to get wrong by hand.

**Bridge ports are a separate number space from ifIndex.** `dot1dBasePortIfIndex`
(`1.3.6.1.2.1.17.1.4.1.2`) maps between them. Everything else in BRIDGE-MIB and
Q-BRIDGE-MIB is keyed by bridge port, so conflating the two silently attributes
MACs and VLANs to the wrong interfaces. The simulator offsets bridge ports by
100 so this fails loudly rather than coincidentally working.

**FDB tables are indexed by the MAC itself.** `dot1dTpFdbPort` appends six
decimal arcs; the Q-BRIDGE equivalent `dot1qTpFdbPort` prefixes those with the
VLAN id. The MAC is recovered from the index, not from a value column.

**VLAN membership is a bit-packed `PortList`** — an OCTET STRING in which the
*most significant* bit of the first byte is bridge port 1. A switch numbering
bridge ports from 101 therefore needs a 14-byte bitmap to reach them.
`dot1qVlanStaticEgressPorts` gives membership and `dot1qVlanStaticUntaggedPorts`
gives which of those are untagged; tagged = egress minus untagged. Where the
untagged bitmap is absent, `dot1qPvid` is the fallback, since the PVID is by
definition the untagged VLAN.

### FDB hygiene

`dot1dTpFdbStatus` must be filtered to `learned(3)`. The table also carries
`self(4)` — the switch's own port addresses — and `mgmt(5)`. Importing those
wires every switch to itself.

### LLDP indexing

`lldpRemTable` is indexed `timeMark.localPortNum.remIndex`. `localPortNum` is
usually ifIndex but not on every platform, so it is refined by matching
`lldpLocPortId` against collected port names. The neighbour's management
address is carried in the **index** of `lldpRemManAddrTable`, not its value:
the key ends with addrSubtype, address length, then the address bytes.

### One mode per port

GLPI's `NetworkPort` asset calls `isLLDP($port)` and then reads the entire
`connections` array one of two ways:

- `lldp: true` → each entry is a neighbour record (`sysmac`, `sysname`,
  `ifdescr`, `ifnumber`), mapped onto mac/name/logical_number.
- otherwise → each entry must carry `mac`, and they are flattened to a list of
  MAC strings.

So a port is reported as *either* an LLDP link or a set of learned MACs, never
both. A neighbour is the better signal and wins.

## Scanners are registered as GLPI Agents

`AgentLink::sync()` creates and maintains a row in `glpi_agents` for every
enrolled scanner, on enrollment and on each heartbeat. Without it a scanner
exists only in the plugin's tables and is invisible on the page an
administrator actually checks.

Three fields need care, because they are what that page renders:

- **`version` is not a string.** GLPI reads it with `importArrayFromDB()` and
  renders one line per module, so it is written with `exportArrayToDB()` as
  `{"NETSCAN": …, "NETDISCOVERY": …, "NETINVENTORY": …}`. A bare `0.1.0`
  displays as an unexplained blob.
- **`use_module_*` are the supported tasks**, declared exhaustively —
  network discovery and network inventory on, everything else explicitly off.
- **`threads_*` / `timeout_*`** come from the scanner's own targets, so the
  numbers shown are the ones it will really use.

`deviceid` is keyed on the scanner's id rather than its name, so renaming a
scanner does not orphan its agent row. `itemtype` is left as `Computer` with
`items_id = 0`: a scanner collects *for* GLPI rather than being collected, and
inventing a Computer asset for it would be worse than leaving the link empty.

## Power devices bypass core

`Ingest::submit()` routes any submission carrying a `power` block — or an
`itemtype` of `PDU` — to `PowerIngest` instead of `Glpi\Inventory\Inventory`.

Two independent reasons, both checked against core rather than assumed:

1. `Inventory::getMainClass()` resolves `\Glpi\Inventory\MainAsset\<Itemtype>`
   and there is no `MainAsset\PDU`. Core cannot build a PDU; the best it could
   do is file a UPS as `Unmanaged`.
2. `inventory.schema.json` has no vocabulary for batteries, outlets or load, so
   the half of the payload that matters would be dropped even if it validated.

GLPI *does* have a first-class `PDU` asset — `glpi_pdus`, with serial, model,
manufacturer, type, location and rack placement — so the plugin creates that
directly. The power block therefore travels **outside `content`**, like
`scan_address`, and is never shown to core.

### Matching

In order: the plugin's own `deviceid` → `pdus_id` mapping, then serial. Name is
deliberately **not** a match key — "pdu-mdf-a" is exactly the sort of name that
repeats in every rack of every site.

### Management ports

The device's management interface is created as a real `NetworkPort` on the
PDU (`PDU` is in `$CFG_GLPI['networkport_types']`), with its MAC, addresses,
speed and MTU, instantiated as `NetworkPortEthernet` and chained
NetworkPort → NetworkName → IPAddress, which is how GLPI models an address.

Ports and addresses we created are marked `is_dynamic`, and ones the device
stops reporting are removed — scoped to dynamic rows so an operator's
hand-added port survives.

### Why a switch still links to "Unmanaged"

`NetworkPort::handleMacConnection()` resolves each forwarding-table MAC via
`RuleImportAssetCollection::processAllRules(['mac' => $mac])`. That engine
searches `$CFG_GLPI['asset_types']`, plus `Unmanaged` and `Peripheral`.

**PDU is absent from `asset_types`** — while being present in
`networkport_types`. So the port exists and holds the right MAC, but the rule
engine never looks at it, falls through to "Import only mac address (mac on
switch port)", and creates an `Unmanaged` placeholder.

Adding PDU to `asset_types` is the only lever that changes this, and it does
work — verified: the switch then wires ports 5 and 6 straight to `ups-mdf-01`
and `pdu-mdf-a`. It is exposed as an off-by-default setting because
`asset_types` is consulted widely across core.

Two supporting behaviours:

- **Ingest order.** `report.php` sorts NetworkEquipment last, so the ports a
  switch refers to already exist when it is imported. Nothing re-evaluates an
  existing wiring, so getting this right on first import matters.
- **Placeholder retirement**, gated on the same setting. Without it the switch
  simply recreates the placeholder each scan, and deleting it every time would
  churn asset ids for no gain.

### Phones bypass core too

`MainAsset\Phone` extends `MainAsset`, whose `prepare()` reads `hardware` and
`bios` — the *computer* inventory shape. Only `MainAsset\NetworkEquipment`
(and its subclass `GenericNetworkAsset`) reads `network_device`.

Verified rather than assumed: feeding core a netinventory payload with
`itemtype: Phone` produced `RefusedEquipment` with **empty name, mac and
serial**, refused by rule 41 "Phone constraint (name)" — while the
NetworkEquipment refusal beside it carried both ip and mac. Core never
populated the asset at all.

Unlike PDU, `Phone` *is* in `$CFG_GLPI['asset_types']`, so once the asset and
its ports exist, a switch resolves to it with no extra configuration.

### The LLDP wiring bug

GLPI picks one of two code paths per port, on the port's `lldp` flag:

| Path | Resolves | Wires |
|---|---|---|
| `handleMacConnection()` | rule engine on each MAC | **yes** — calls `addPortsWiring()` |
| `handleLLDPConnection()` | same rule engine | **no** — unreachable |

The LLDP path guards its wiring with `count($this->connection_ports) != 1` on a
property reset to `[]` five lines above and never written to. GLPI's source
carries the analysis in a comment: *"phpstan report dead code here … this
condition is always true and the code after is never executed. TODO:
Investigate … most likely the case [a real bug]"*.

Consequence: an LLDP neighbour can never link to an existing asset. So
`Ingest::preferResolvableConnections()` rewrites LLDP connections whose chassis
MAC already matches a known port into plain MAC connections, and clears the
port's `lldp` flag, so the working path runs. Ports whose neighbours are not
yet known keep the LLDP form — nothing can be linked for them anyway, and LLDP
produces a better-named placeholder.

The flag is per port and the whole connections array is read one way or the
other, so the rewrite only applies when *every* neighbour on that port is
resolvable.

### LLDP port identity

`lldpRemPortId` means different things depending on `lldpRemPortIdSubtype`:
interfaceAlias(1), portComponent(2), macAddress(3), networkAddress(4),
interfaceName(5), agentCircuitId(6), local(7). GLPI matches a neighbour by the
far end's `logical_number`, `mac`, then port **name** — so:

- macAddress(3) → send it as `mac`, the strongest match available;
- interfaceName(5)/interfaceAlias(1) → send it as `ifdescr`;
- anything else → fall back to `lldpRemPortDesc`.

Sending the human description (`uplink`) where GLPI expects the port name
(`eth0`) guarantees the lookup misses and the neighbour becomes a placeholder.

### What GLPI can and cannot hold

`glpi_items_plugs` models outlet **types and counts** ("24 × C13"), not
individually addressable sockets. So the outlet *count* is recorded natively
via `Item_Plug`, under a neutrally-named plug — SNMP does not report the
physical connector standard, and claiming "C13" because a strip has 24 sockets
would be fabrication. Per-outlet name, state and current live in the plugin and
are surfaced on a **Power state** tab on the PDU asset.

State is stored as one row per device, overwritten each scan. It answers "what
does it say now", which is the inventory-shaped question; trending is
monitoring's job.

## SNMP notes

- **v1 has no GETBULK**, so column walks fall back to GETNEXT. That is why a
  v1 scan of a 48-port switch is slow rather than impossible.
- **Protocol names** come from core's `SNMPCredential::getAuthProtocol()` /
  `getEncryption()`. The AES variants split two ways and the distinction is
  real on the wire: `AES192C`/`AES256C` are the Reeder/Cisco key extension,
  `CFB192-AES`/`CFB256-AES` the Blumenthal draft. `3DES` has no gosnmp
  equivalent and is rejected rather than approximated — silently substituting
  a cipher is worse than a clear error.
- **OctetStrings carry both text and binary.** Binary is hex-encoded rather
  than dumped as mojibake, and NUL padding is stripped: GLPI writes these
  straight to MySQL, where an embedded NUL truncates the column.
- **Empty and all-zero `ifPhysAddress`** is common on virtual interfaces and
  must not become an asset's MAC.
- **`ifSpeed` saturates.** It is a 32-bit gauge, so anything above 4 Gbps reads
  4294967295; `ifHighSpeed` (Mbps) carries the real figure. 32-bit octet
  counters likewise wrap in under a minute on a loaded 10G link, so `ifXTable`
  is preferred wherever it exists.
- **Power MIBs report tenths.** RFC 1628 gives battery voltage in decivolts,
  currents in deciamps and frequency in decihertz, while the input and output
  line tables use plain RMS volts. Vendors differ again for the same logical
  field, which is why the scale factor lives in the profile as a `*factor`
  suffix rather than in code.
- **`entPhySensorValue` needs two corrections**, not one: `entPhySensorScale`
  is an SI magnitude (units(9) = 10^0) and `entPhySensorPrecision` is the count
  of implied decimal places. Ignoring precision reports 22.3 °C as 223.
- **`entPhySensorOperStatus` must be checked.** A sensor reporting
  `nonoperational` is telling you its own reading is unusable; recording the
  value anyway turns a broken probe into a fact.
- **`entPhysicalIsFRU` is a TruthValue** — true(1)/false(2) — and the inventory
  schema types `fru` as an *integer*. Emitting a JSON boolean fails validation.
