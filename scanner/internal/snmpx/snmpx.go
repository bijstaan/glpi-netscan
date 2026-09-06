// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package snmpx wraps gosnmp with the bits this scanner needs: building a
// session from a GLPI credential (v1, v2c or v3), walking columns into
// index-keyed maps, and coercing SNMP values into the types the inventory
// payload expects.
package snmpx

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gosnmp/gosnmp"
)

// Credential mirrors a row of GLPI's `glpi_snmpcredentials`, which is where
// operators already manage SNMP access — there is no reason for this plugin to
// invent a second place to store community strings and v3 users.
type Credential struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Version        string `json:"version"` // "1", "2c", "3"
	Community      string `json:"community,omitempty"`
	Username       string `json:"username,omitempty"`
	AuthProtocol   string `json:"auth_protocol,omitempty"`
	AuthPassphrase string `json:"auth_passphrase,omitempty"`
	PrivProtocol   string `json:"priv_protocol,omitempty"`
	PrivPassphrase string `json:"priv_passphrase,omitempty"`
}

// Session is a live SNMP conversation with one device.
type Session struct {
	client *gosnmp.GoSNMP
	cred   Credential
}

// Options tune the transport. They come from the job so an operator can slow
// the scanner down for congested links without rebuilding it.
type Options struct {
	Port    uint16
	Timeout time.Duration
	Retries int
}

func (o Options) withDefaults() Options {
	if o.Port == 0 {
		o.Port = 161
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	return o
}

// Dial opens a session. For v3 this performs engine discovery, so a failure
// here already tells us the credential is wrong rather than the host silent.
func Dial(host string, cred Credential, opts Options) (*Session, error) {
	opts = opts.withDefaults()

	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      opts.Port,
		Timeout:   opts.Timeout,
		Retries:   opts.Retries,
		Transport: "udp",
		MaxOids:   gosnmp.MaxOids,
	}

	switch normaliseVersion(cred.Version) {
	case "1":
		client.Version = gosnmp.Version1
		client.Community = cred.Community
	case "2c":
		client.Version = gosnmp.Version2c
		client.Community = cred.Community
	case "3":
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: cred.Username}

		auth, authOK := authProtocol(cred.AuthProtocol)
		if !authOK {
			return nil, fmt.Errorf("unsupported SNMPv3 auth protocol %q", cred.AuthProtocol)
		}
		priv, privOK := privProtocol(cred.PrivProtocol)
		if !privOK {
			// Silently dropping to noPriv here would turn a configuration
			// error into an authentication failure three layers away, and
			// would quietly send credentials in clear on the wire.
			return nil, fmt.Errorf("unsupported SNMPv3 privacy protocol %q", cred.PrivProtocol)
		}

		switch {
		case auth != gosnmp.NoAuth && priv != gosnmp.NoPriv:
			client.MsgFlags = gosnmp.AuthPriv
			usm.AuthenticationProtocol = auth
			usm.AuthenticationPassphrase = cred.AuthPassphrase
			usm.PrivacyProtocol = priv
			usm.PrivacyPassphrase = cred.PrivPassphrase
		case auth != gosnmp.NoAuth:
			client.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationProtocol = auth
			usm.AuthenticationPassphrase = cred.AuthPassphrase
		default:
			client.MsgFlags = gosnmp.NoAuthNoPriv
		}

		client.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("unsupported SNMP version %q", cred.Version)
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	return &Session{client: client, cred: cred}, nil
}

// Close releases the socket.
func (s *Session) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Conn.Close()
}

// Credential returns the credential this session authenticated with, so the
// caller can record which one worked against a device.
func (s *Session) Credential() Credential { return s.cred }

// Get reads scalar OIDs. Oversized batches are split, because MaxOids is a
// protocol limit and a device will answer tooBig rather than truncate.
func (s *Session) Get(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := make(map[string]gosnmp.SnmpPDU, len(oids))
	if len(oids) == 0 {
		return out, nil
	}

	const batch = 20
	for start := 0; start < len(oids); start += batch {
		end := min(start+batch, len(oids))

		res, err := s.client.Get(normaliseOIDs(oids[start:end]))
		if err != nil {
			return out, fmt.Errorf("get: %w", err)
		}
		for _, pdu := range res.Variables {
			if pdu.Type == gosnmp.NoSuchObject ||
				pdu.Type == gosnmp.NoSuchInstance ||
				pdu.Type == gosnmp.EndOfMibView {
				continue
			}
			out[strings.TrimPrefix(pdu.Name, ".")] = pdu
		}
	}

	return out, nil
}

// Walk reads a column and returns it keyed by the index suffix — the part of
// the OID after the column root, which for IF-MIB is the ifIndex and for
// ENTITY-MIB the entPhysicalIndex.
//
// v1 has no GETBULK, so it falls back to GETNEXT; that is the main reason v1
// scans of a large switch are slow rather than impossible.
// SetInt writes a single integer, which is what device control amounts to.
//
// Deliberately the only write this package offers. Every control action worth
// having — switching an outlet, shutting a port, rebooting an appliance — is an
// integer written to one OID, and a general "write anything" surface would
// invite exactly the mistakes that make people refuse to give a monitoring tool
// write access at all.
//
// The returned error distinguishes nothing about *why* a device refused: SNMP
// reports noSuchName, notWritable and authorizationError as bare error codes,
// and the practical difference between them is nil — the write did not happen
// and the operator needs to know that, not which of three ways it failed.
func (s *Session) SetInt(oid string, value int) error {
	oid = "." + strings.TrimPrefix(strings.TrimSpace(oid), ".")

	res, err := s.client.Set([]gosnmp.SnmpPDU{{
		Name:  oid,
		Type:  gosnmp.Integer,
		Value: value,
	}})
	if err != nil {
		return fmt.Errorf("set %s = %d: %w", oid, value, err)
	}

	if res != nil && res.Error != gosnmp.NoError {
		return fmt.Errorf("set %s = %d: device refused (%s)", oid, value, res.Error)
	}

	return nil
}

func (s *Session) Walk(root string) (map[string]gosnmp.SnmpPDU, error) {
	root = "." + strings.TrimPrefix(strings.TrimSpace(root), ".")
	out := map[string]gosnmp.SnmpPDU{}

	collect := func(pdu gosnmp.SnmpPDU) error {
		name := strings.TrimPrefix(pdu.Name, ".")
		bare := strings.TrimPrefix(root, ".")
		if !strings.HasPrefix(name, bare+".") {
			return nil
		}
		out[strings.TrimPrefix(name, bare+".")] = pdu
		return nil
	}

	var err error
	if s.client.Version == gosnmp.Version1 {
		err = s.client.Walk(root, collect)
	} else {
		err = s.client.BulkWalk(root, collect)
	}
	if err != nil {
		return out, fmt.Errorf("walk %s: %w", root, err)
	}

	return out, nil
}

func normaliseOIDs(oids []string) []string {
	out := make([]string, 0, len(oids))
	for _, oid := range oids {
		out = append(out, "."+strings.TrimPrefix(strings.TrimSpace(oid), "."))
	}
	return out
}

func normaliseVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "1", "v1":
		return "1"
	case "2", "2c", "v2", "v2c":
		return "2c"
	case "3", "v3":
		return "3"
	}
	return v
}

// authProtocol maps GLPI's stored protocol name onto gosnmp's constant.
//
// The names are the ones core's SNMPCredential::getAuthProtocol() emits, plus
// the punctuated spellings people actually type ("SHA-512"). The bool reports
// whether the name was understood: an empty name legitimately means "no auth",
// but an unrecognised one is a misconfiguration the caller must not paper over.
func authProtocol(name string) (gosnmp.SnmpV3AuthProtocol, bool) {
	switch canon(name) {
	case "":
		return gosnmp.NoAuth, true
	case "md5":
		return gosnmp.MD5, true
	case "sha", "sha1":
		return gosnmp.SHA, true
	case "sha224":
		return gosnmp.SHA224, true
	case "sha256":
		return gosnmp.SHA256, true
	case "sha384":
		return gosnmp.SHA384, true
	case "sha512":
		return gosnmp.SHA512, true
	}
	return gosnmp.NoAuth, false
}

// privProtocol maps core's SNMPCredential::getEncryption() names.
//
// The AES variants split two ways and the distinction matters on the wire:
// AES192C/AES256C are the Reeder/Cisco key-extension used by most vendor gear,
// while CFB192-AES/CFB256-AES are the Blumenthal draft variants. Getting these
// the wrong way round produces a device that authenticates and then returns
// undecryptable responses.
//
// 3DES is deliberately unsupported rather than approximated — gosnmp has no
// equivalent, and quietly substituting a different cipher would be worse than
// a clear error.
func privProtocol(name string) (gosnmp.SnmpV3PrivProtocol, bool) {
	switch canon(name) {
	case "":
		return gosnmp.NoPriv, true
	case "des":
		return gosnmp.DES, true
	case "aes", "aes128":
		return gosnmp.AES, true
	case "aes192c":
		return gosnmp.AES192C, true
	case "aes256c":
		return gosnmp.AES256C, true
	case "cfb192aes", "aes192":
		return gosnmp.AES192, true
	case "cfb256aes", "aes256":
		return gosnmp.AES256, true
	}
	return gosnmp.NoPriv, false
}

func canon(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("-", "", "_", "", " ", "").Replace(s)
	return s
}

// --- value coercion ---------------------------------------------------------

// String renders a PDU as text.
//
// OctetStrings are the awkward case: they carry both human text and raw binary
// (MAC addresses, engine IDs). Binary is hex-encoded rather than dumped as
// mojibake, and NUL padding is stripped — GLPI stores these straight into
// MySQL, where an embedded NUL truncates the column.
func String(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.OctetString:
		b, ok := pdu.Value.([]byte)
		if !ok {
			return ""
		}
		if printable(b) {
			return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", ""))
		}
		return strings.ToUpper(hex.EncodeToString(b))
	case gosnmp.ObjectIdentifier:
		s, _ := pdu.Value.(string)
		return strings.TrimPrefix(s, ".")
	case gosnmp.IPAddress:
		s, _ := pdu.Value.(string)
		return s
	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", gosnmp.ToBigInt(pdu.Value)))
	}
}

// Int coerces a PDU to an integer, returning 0 for anything non-numeric.
func Int(pdu gosnmp.SnmpPDU) int64 {
	switch pdu.Type {
	case gosnmp.OctetString:
		s := String(pdu)
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return 0
		}
		return n
	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return 0
	default:
		big := gosnmp.ToBigInt(pdu.Value)
		if big == nil {
			return 0
		}
		return big.Int64()
	}
}

// MAC formats a PDU as colon-separated hex, or "" when it is not a 6-byte
// address. Devices routinely return an empty or all-zero ifPhysAddress for
// virtual interfaces, and those must not become an asset's MAC.
func MAC(pdu gosnmp.SnmpPDU) string {
	b, ok := pdu.Value.([]byte)
	if !ok || len(b) != 6 {
		return ""
	}

	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}

	parts := make([]string, 0, 6)
	for _, c := range b {
		parts = append(parts, fmt.Sprintf("%02x", c))
	}
	return strings.Join(parts, ":")
}

func printable(b []byte) bool {
	for _, c := range b {
		if c == 0 || c == '\r' || c == '\n' || c == '\t' {
			continue
		}
		if c > unicode.MaxASCII {
			// Allow UTF-8 text through; only reject C0 control bytes, which
			// are what actually indicate a binary value.
			continue
		}
		if !unicode.IsPrint(rune(c)) {
			return false
		}
	}
	return true
}
