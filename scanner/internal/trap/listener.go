// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package trap receives SNMP notifications and forwards them to GLPI.
package trap

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Traps are the only thing a device tells the scanner without being asked.
//
// They matter here for two reasons, and the second is the useful one. A trap is
// worth recording — linkDown at 03:00 explains a lot the next morning — but it
// is also the best possible input to the discovery/inventory split: a device
// saying "my link changed" or "I have restarted" is telling the scanner exactly
// what the change counters exist to guess at, and it says so immediately rather
// than at the next sweep.
//
// The trust model has to be stated plainly, because it is weak by design of the
// protocol rather than of this code. A v1 or v2c trap is a UDP datagram with a
// community string in it: unauthenticated, unencrypted, trivially forged by
// anyone who can route a packet to the listener. So:
//
//   - traps are off unless switched on;
//   - only traps from addresses inside the scanner's own target ranges are
//     accepted, which is the same rule inventory submissions already follow;
//   - a trap is never trusted to *assert* anything about a device. It can cause
//     a device to be re-inventoried — where the truth is then read from the
//     device — but nothing a trap says is recorded as fact about the asset.
//
// That last rule is what makes the weak authentication tolerable: the worst a
// forged trap achieves is an unnecessary SNMP walk of a device the scanner was
// already allowed to walk.

// Notification is one received trap, in the shape GLPI stores.
type Notification struct {
	Address    string            `json:"address"`
	Version    string            `json:"version"`
	Community  string            `json:"community,omitempty"`
	TrapOID    string            `json:"trap_oid"`
	TrapName   string            `json:"trap_name,omitempty"`
	Varbinds   map[string]string `json:"varbinds,omitempty"`
	ReceivedAt int64             `json:"received_at"`
}

// Well-known notification OIDs, so an operator reading the list sees words.
//
// coldStart, warmStart and authenticationFailure are defined by SNMPv2-MIB;
// linkDown and linkUp by IF-MIB. Both MIBs publish under the same snmpTraps
// subtree, and each one's listing fills the gaps in the other's.
var wellKnown = map[string]string{
	"1.3.6.1.6.3.1.1.5.1": "coldStart",
	"1.3.6.1.6.3.1.1.5.2": "warmStart",
	"1.3.6.1.6.3.1.1.5.3": "linkDown",
	"1.3.6.1.6.3.1.1.5.4": "linkUp",
	"1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
}

// snmpTrapOID is the varbind carrying a v2c/v3 notification's identity.
const snmpTrapOID = "1.3.6.1.6.3.1.1.4.1.0"

// Config is the listening policy, which comes from GLPI like every other
// policy the scanner follows.
type Config struct {
	Port      uint16
	Community string
	// Allowed limits which sources are accepted. Empty means accept nothing,
	// deliberately: a misconfiguration that produces an empty range list should
	// close the listener, not open it to the world.
	Allowed []netip.Prefix

	// FlushEvery is how often batches are handed to the sink. Zero uses the
	// default; it exists so tests do not have to wait ten seconds.
	FlushEvery time.Duration
}

// Listener receives traps and hands them to a sink in batches.
type Listener struct {
	cfg  Config
	sink func([]Notification)

	mu      sync.Mutex
	pending []Notification
	dropped int

	listener *gosnmp.TrapListener
}

// New builds a listener. The sink is called from a background goroutine.
func New(cfg Config, sink func([]Notification)) *Listener {
	return &Listener{cfg: cfg, sink: sink}
}

// maxPending bounds memory when GLPI is unreachable.
//
// A trap storm is a real thing — a flapping link can produce thousands a minute
// — and the scanner must survive one without growing without limit. Dropping
// the excess is right rather than sad: the value of a trap here is "something
// changed, go and look", and the thousandth copy of that message adds nothing
// the first did not already say.
const maxPending = 1000

// Run listens until the listener is closed.
func (l *Listener) Run() error {
	if l.cfg.Port == 0 {
		return fmt.Errorf("no trap port configured")
	}
	if len(l.cfg.Allowed) == 0 {
		return fmt.Errorf("no permitted source ranges; refusing to listen")
	}

	// A fresh GoSNMP rather than gosnmp.Default: that is a package-level
	// pointer, and assigning it here would mean configuring the listener also
	// reconfigured every other user of the defaults in this process.
	params := &gosnmp.GoSNMP{
		Port:      l.cfg.Port,
		Version:   gosnmp.Version2c,
		Community: l.cfg.Community,
		Timeout:   5 * time.Second,
		Retries:   0,
		Logger:    gosnmp.NewLogger(log.New(io.Discard, "", 0)),
	}

	tl := gosnmp.NewTrapListener()
	tl.OnNewTrap = l.handle
	tl.Params = params

	l.listener = tl

	go l.flushLoop()

	addr := fmt.Sprintf("0.0.0.0:%d", l.cfg.Port)
	log.Printf("listening for SNMP traps on %s", addr)

	return tl.Listen(addr)
}

// Close stops the listener.
func (l *Listener) Close() {
	if l.listener != nil {
		l.listener.Close()
	}
}

// handle is called by gosnmp for each received trap.
func (l *Listener) handle(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	if packet == nil || addr == nil {
		return
	}

	source, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return
	}
	source = source.Unmap()

	// The same rule inventory submissions follow: a scanner only speaks for the
	// addresses it was told to scan. Without this, anything that can route a
	// packet to this port can make the scanner act.
	if !l.permitted(source) {
		return
	}

	n := Notification{
		Address:    source.String(),
		Version:    packet.Version.String(),
		Community:  packet.Community,
		Varbinds:   map[string]string{},
		ReceivedAt: time.Now().Unix(),
	}

	for _, v := range packet.Variables {
		name := strings.TrimPrefix(v.Name, ".")

		if name == snmpTrapOID {
			n.TrapOID = strings.TrimPrefix(fmt.Sprintf("%v", v.Value), ".")
			continue
		}

		n.Varbinds[name] = varbindString(v)
	}

	// v1 traps carry their identity in the header rather than a varbind.
	if n.TrapOID == "" && packet.Enterprise != "" {
		n.TrapOID = fmt.Sprintf("%s.%d.%d",
			strings.TrimPrefix(packet.Enterprise, "."),
			packet.GenericTrap, packet.SpecificTrap)
	}

	n.TrapName = wellKnown[n.TrapOID]

	l.mu.Lock()
	if len(l.pending) >= maxPending {
		l.dropped++
	} else {
		l.pending = append(l.pending, n)
	}
	l.mu.Unlock()
}

func (l *Listener) permitted(addr netip.Addr) bool {
	for _, p := range l.cfg.Allowed {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// flushLoop hands batches to the sink.
//
// Batched rather than forwarded one at a time because traps arrive in bursts by
// nature — a switch reloading emits one per port — and a submission per trap
// would turn a link flap into a denial of service against GLPI.
func (l *Listener) flushLoop() {
	every := l.cfg.FlushEvery
	if every <= 0 {
		every = 10 * time.Second
	}

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		batch := l.pending
		dropped := l.dropped
		l.pending = nil
		l.dropped = 0
		l.mu.Unlock()

		if dropped > 0 {
			log.Printf("dropped %d traps: more arrived than could be forwarded", dropped)
		}
		if len(batch) == 0 {
			continue
		}

		l.sink(batch)
	}
}

// varbindString renders a varbind for storage.
//
// Everything becomes a string because that is all this is for: a trap's
// varbinds are shown to a person, never parsed into asset fields. Typing them
// would imply a trust in their contents that the protocol does not support.
func varbindString(v gosnmp.SnmpPDU) string {
	switch v.Type {
	case gosnmp.OctetString:
		if b, ok := v.Value.([]byte); ok {
			return strings.ToValidUTF8(string(b), "")
		}
	case gosnmp.ObjectIdentifier:
		return strings.TrimPrefix(fmt.Sprintf("%v", v.Value), ".")
	}

	return fmt.Sprintf("%v", v.Value)
}
