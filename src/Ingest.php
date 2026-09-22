<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpinetscan;

use Glpi\Agent\Communication\AbstractRequest;
use Glpi\Inventory\Inventory;

/**
 * Hands scanner submissions to GLPI's native inventory pipeline.
 *
 * Everything downstream of here — creating the NetworkEquipment or Printer,
 * reconciling ports, IPs and components, applying entity rules — is core's job.
 * The plugin's only responsibilities are proving the submission came from a
 * scanner we trust and that it is about an address we asked that scanner to
 * look at.
 */
final class Ingest
{
    /**
     * Ingest one device payload.
     *
     * @param array $payload Decoded submission (`deviceid`, `action`, `content`).
     * @return array{ok:bool,errors:string[],itemtype:?string,items_id:?int}
     */
    public static function submit(Scanner $scanner, array $payload, ?Target $target): array
    {
        $errors = [];

        $deviceId = trim((string) ($payload['deviceid'] ?? ''));
        if ($deviceId === '') {
            return ['ok' => false, 'errors' => ['missing deviceid'], 'itemtype' => null, 'items_id' => null];
        }

        $action = (string) ($payload['action'] ?? AbstractRequest::NETINV_ACTION);
        if (!in_array($action, [AbstractRequest::NETDISCOVERY_ACTION, AbstractRequest::NETINV_ACTION], true)) {
            return ['ok' => false, 'errors' => ['unsupported action'], 'itemtype' => null, 'items_id' => null];
        }

        $content = $payload['content'] ?? null;
        if (!is_array($content)) {
            return ['ok' => false, 'errors' => ['missing content'], 'itemtype' => null, 'items_id' => null];
        }

        // Power devices are handled entirely by the plugin: core has no
        // MainAsset for PDU and its schema has no vocabulary for batteries or
        // outlets, so routing them through the inventory pipeline would file a
        // UPS as an Unmanaged asset and discard the interesting half.
        $isPower = is_array($payload['power'] ?? null)
            || ($payload['itemtype'] ?? '') === 'PDU';

        // A scanner is trusted to report on what it was told to scan and
        // nothing else. Without this, a compromised scanner could rewrite any
        // asset in the instance by claiming to have inventoried its address.
        //
        // The check is against the address the scanner actually contacted, not
        // the addresses the device claims: a switch routinely answers on a
        // management address that is absent from its own IP-MIB (an SVI, a
        // second interface, a NAT), so validating on reported IPs rejects
        // legitimate scans. Reported addresses are only a fallback for an
        // older scanner that does not send scan_address.
        if ($target !== null && !Settings::get('allow_off_target')) {
            $scanned = trim((string) ($payload['scan_address'] ?? ''));

            if ($scanned !== '') {
                if (!$target->coversAddress($scanned)) {
                    return [
                        'ok'       => false,
                        'errors'   => [sprintf(
                            'scanned address %s falls outside the target ranges',
                            $scanned
                        )],
                        'itemtype' => null,
                        'items_id' => null,
                    ];
                }
            } else {
                $addresses = self::addressesIn($content);
                if ($addresses !== [] && !self::anyCovered($target, $addresses)) {
                    return [
                        'ok'       => false,
                        'errors'   => ['reported addresses fall outside the target ranges'],
                        'itemtype' => null,
                        'items_id' => null,
                    ];
                }
            }
        }

        if ($isPower) {
            return PowerIngest::submit($scanner, $payload, $target);
        }

        // Phones bypass core for the same reason: MainAsset\Phone inherits the
        // base prepare(), which reads `hardware`/`bios` and never looks at
        // `network_device` — so core builds a nameless asset that its own
        // "Phone constraint (name)" rule then refuses.
        if (($payload['itemtype'] ?? '') === 'Phone') {
            return PhoneIngest::submit($scanner, $payload, $target);
        }

        // Entities are decided by the scanner's own entity, never by anything
        // in the payload — the submission is data, not authority. Core decides
        // an imported asset's entity from the entity rules alone, so the
        // scanner's entity reaches that decision through its tag: see
        // EntityRule. The active entity set below only covers what core
        // creates outside the main asset.
        $entities_id = (int) $scanner->fields['entities_id'];

        // Rewrite LLDP connections that GLPI could resolve into the MAC form
        // its working code path understands. See resolvableConnections().
        $content = self::preferResolvableConnections($content);

        // GLPI reads the top-level `itemtype` in extractMetadata() and falls
        // back to Computer when it is absent — so an unset itemtype does not
        // fail loudly, it files switches and printers as computers. Derive it
        // here as well as in the scanner: this is the last point where the
        // mistake is still cheap to correct.
        $itemtype = self::itemtypeFor($payload, $content);

        $document = [
            'deviceid' => $deviceId,
            'action'   => $action,
            'itemtype' => $itemtype,
            'content'  => $content,
        ];
        $tag = EntityRule::tagFor($scanner->getID());
        if ($tag !== null) {
            $document['tag'] = $tag;
        }

        $object = json_decode(json_encode($document, JSON_THROW_ON_ERROR));

        $inventory = new Inventory();
        $inventory->setDiscovery($action === AbstractRequest::NETDISCOVERY_ACTION);
        $inventory->setRequestQuery($action);

        if (!$inventory->setData($object, AbstractRequest::JSON_MODE)) {
            return [
                'ok'       => false,
                'errors'   => $inventory->getErrors() ?: ['schema validation failed'],
                'itemtype' => null,
                'items_id' => null,
            ];
        }

        $previous = $_SESSION['glpiactive_entity'] ?? null;
        $_SESSION['glpiactive_entity'] = $entities_id;

        try {
            $inventory->doInventory();
        } finally {
            if ($previous === null) {
                unset($_SESSION['glpiactive_entity']);
            } else {
                $_SESSION['glpiactive_entity'] = $previous;
            }
        }

        if ($inventory->inError()) {
            return [
                'ok'       => false,
                'errors'   => $inventory->getErrors(),
                'itemtype' => null,
                'items_id' => null,
            ];
        }

        $createdType = null;
        $items_id    = null;
        try {
            $item = $inventory->getItem();
            if ($item !== null && (int) $item->getID() > 0) {
                $createdType = $item->getType();
                $items_id    = (int) $item->getID();
            }
        } catch (\Throwable) {
            // Core does not guarantee an item object on every path.
        }

        // A full inventory that produced no asset is a failure, even though
        // core reported no error. Reporting it as success is worse than an
        // error, because the run log then claims devices were imported that do
        // not exist.
        if ($items_id === null && $action === AbstractRequest::NETINV_ACTION) {
            return [
                'ok'       => false,
                'errors'   => [self::whyNothingCreated($inventory)],
                'itemtype' => null,
                'items_id' => null,
            ];
        }

        // Wireless state, once the asset exists to hang it on. Kept out of the
        // native pipeline because the inventory format has nowhere for it, and
        // done after rather than before because it needs the asset's id.
        if ($items_id !== null && $createdType !== null && is_array($payload['wireless'] ?? null)) {
            $wireless = $payload['wireless'];
            WirelessIngest::store($items_id, $createdType, $wireless, $scanner->getID());

            // A device that reports networks but no access points is itself the
            // access point — a UniFi or MikroTik rather than a controller — so
            // the networks genuinely belong to it and can be attached as wifi
            // ports. A controller's SSID list is estate-wide and belongs to no
            // single radio, and the MIBs do not say which network is on which
            // AP, so inventing that link would be fabrication.
            if (empty($wireless['access_points']) && !empty($wireless['ssids'])) {
                WirelessIngest::attachStandaloneNetworks(
                    $items_id,
                    (int) $scanner->fields['entities_id'],
                    (array) $wireless['ssids']
                );
            }
        }

        return ['ok' => true, 'errors' => $errors, 'itemtype' => $createdType, 'items_id' => $items_id];
    }

    /**
     * Convert LLDP neighbours GLPI can already identify into plain MAC
     * connections.
     *
     * GLPI reads a port's connections one of two ways, chosen by its `lldp`
     * flag, and only one of them works:
     *
     *  - `handleMacConnection()` resolves each MAC through the rule engine and
     *    calls `addPortsWiring()` — this links a switch port to the real asset.
     *  - `handleLLDPConnection()` runs the same rules but then guards the
     *    wiring behind `count($this->connection_ports) != 1`, on a property it
     *    resets to `[]` immediately above and never populates. GLPI's own
     *    source marks this as dead code with a TODO calling it "most likely"
     *    a real bug, so `addPortsWiring()` is unreachable there.
     *
     * The upshot is that an LLDP neighbour always becomes an `Unmanaged`
     * placeholder, even when the device is already inventoried — so preferring
     * LLDP, which is otherwise the better signal, actively loses the link.
     *
     * The compromise: where a port already exists carrying the neighbour's
     * chassis MAC, hand GLPI the MAC form so the working path links to the
     * real asset. Where it does not, keep the LLDP form — nothing can be
     * linked anyway, and LLDP produces a placeholder named "core-rtr-01"
     * rather than one named after an OUI.
     */
    private static function preferResolvableConnections(array $content): array
    {
        if (empty($content['network_ports']) || !is_array($content['network_ports'])) {
            return $content;
        }

        foreach ($content['network_ports'] as $index => $port) {
            if (!is_array($port) || empty($port['lldp']) || empty($port['connections'])) {
                continue;
            }

            $macs = [];
            foreach ((array) $port['connections'] as $connection) {
                $mac = strtolower(trim((string) ($connection['sysmac'] ?? '')));
                if ($mac !== '' && self::portExistsForMac($mac)) {
                    $macs[] = ['mac' => $mac];
                }
            }

            // All of this port's neighbours must be resolvable: the flag is
            // per port and GLPI reads the whole array one way or the other.
            if ($macs === [] || count($macs) !== count((array) $port['connections'])) {
                continue;
            }

            $content['network_ports'][$index]['lldp'] = false;
            $content['network_ports'][$index]['connections'] = $macs;
        }

        return $content;
    }

    /** Is there already a network port carrying this MAC? */
    private static function portExistsForMac(string $mac): bool
    {
        return countElementsInTable(
            \NetworkPort::getTable(),
            ['mac' => $mac, 'is_deleted' => 0]
        ) > 0;
    }

    /**
     * Best explanation for an inventory that created nothing.
     *
     * The two causes look identical from the outside — core raises no error
     * for either — so they are distinguished here. Both are configuration
     * problems an operator can fix, and neither is discoverable from
     * "produced no asset".
     */
    private static function whyNothingCreated(Inventory $inventory): string
    {
        if (!self::nativeInventoryEnabled()) {
            return 'GLPI native inventory is disabled '
                . '(Setup > General > Inventory > Enable inventory); '
                . 'the payload was accepted and discarded';
        }

        // GLPI's import rules ship with "NetworkEquipment import (by mac)"
        // *disabled*, so a device with no serial number falls through to
        // "NetworkEquipment import denied" and is filed as refused equipment
        // rather than imported. That is by far the most common reason a
        // perfectly good switch never appears.
        try {
            $refused = $inventory->getMainAsset()->getRefused();
            if (!empty($refused)) {
                return 'refused by the asset import rules (see Administration > '
                    . 'Refused equipment). A device with no serial number needs '
                    . 'the "NetworkEquipment import (by mac)" rule enabled';
            }
        } catch (\Throwable) {
            // No main asset to ask; fall through to the generic message.
        }

        return 'inventory produced no asset';
    }

    /** Is core's native inventory switched on? */
    public static function nativeInventoryEnabled(): bool
    {
        global $CFG_GLPI;

        if (isset($CFG_GLPI['enabled_inventory'])) {
            return (int) $CFG_GLPI['enabled_inventory'] === 1;
        }

        $conf = new \Glpi\Inventory\Conf();
        return (int) ($conf->enabled_inventory ?? 0) === 1;
    }

    /**
     * Resolve the GLPI class for a submission.
     *
     * Trusts an explicit itemtype from the scanner when it is one we recognise,
     * and otherwise derives it from the device type in the payload.
     */
    private static function itemtypeFor(array $payload, array $content): string
    {
        $allowed = ['NetworkEquipment', 'Printer', 'Phone', 'Computer', 'Unmanaged'];

        $claimed = trim((string) ($payload['itemtype'] ?? ''));
        if (in_array($claimed, $allowed, true)) {
            return $claimed;
        }

        return match ((string) ($content['network_device']['type'] ?? '')) {
            'Networking' => 'NetworkEquipment',
            'Printer'    => 'Printer',
            'Phone'      => 'Phone',
            'Computer'   => 'Computer',
            default      => 'Unmanaged',
        };
    }

    /**
     * Every address the payload claims, from the device and its ports.
     *
     * @return string[]
     */
    private static function addressesIn(array $content): array
    {
        $out = [];

        foreach ((array) ($content['network_device']['ips'] ?? []) as $ip) {
            if (is_string($ip) && $ip !== '') {
                $out[] = $ip;
            }
        }

        foreach ((array) ($content['network_ports'] ?? []) as $port) {
            foreach ((array) ($port['ips'] ?? []) as $ip) {
                if (is_string($ip) && $ip !== '') {
                    $out[] = $ip;
                }
            }
        }

        return array_values(array_unique($out));
    }

    /**
     * @param string[] $addresses
     */
    private static function anyCovered(Target $target, array $addresses): bool
    {
        foreach ($addresses as $ip) {
            if ($target->coversAddress($ip)) {
                return true;
            }
        }
        return false;
    }
}
