// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package client talks to the GLPI netscan plugin.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bijstaan/glpi-netscan/internal/payload"
	"github.com/bijstaan/glpi-netscan/internal/profile"
	"github.com/bijstaan/glpi-netscan/internal/snmpx"
)

// ErrScannerInvalid is returned when the server no longer recognises our token.
//
// It is the revocation signal: an operator deactivating a scanner in GLPI is
// what produces it, and the agent's correct response is to discard its stored
// credentials and enroll again rather than retry.
var ErrScannerInvalid = errors.New("scanner invalid; re-enrollment required")

// pluginPath is where GLPI serves this plugin's legacy scripts. Configuration
// names the GLPI root URL, not the plugin's, so an operator does not have to
// know the plugin's internal layout to point a scanner at their server.
const pluginPath = "/plugins/glpinetscan"

// Client is an HTTP client for the plugin's three endpoints.
type Client struct {
	BaseURL string
	Token   string
	http    *http.Client
}

// Config configures transport security.
type Config struct {
	BaseURL string
	// CAFile pins an internal CA, the normal case for an on-premise GLPI with
	// a private certificate.
	CAFile string
	// Insecure disables verification. Development only; the agent refuses to
	// stay quiet about it.
	Insecure bool
	Timeout  time.Duration
}

// New builds a client.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}

	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		return nil, errors.New("server URL is required")
	}
	if !strings.HasPrefix(base, "https://") && !cfg.Insecure {
		// The job response carries decrypted SNMP credentials. Refusing plain
		// HTTP here mirrors the server's own require_tls check, so a
		// misconfiguration fails at both ends rather than silently working.
		return nil, errors.New("server URL must be https (or -insecure for development)")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true
	}

	return &Client{
		BaseURL: base,
		http: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// EnrollRequest is the bootstrap call.
type EnrollRequest struct {
	EnrollSecret string `json:"enroll_secret"`
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse carries the token, which the server will never disclose again.
type EnrollResponse struct {
	ScannerToken string `json:"scanner_token"`
	ScannerID    int    `json:"scanner_id"`
	EntitiesID   int    `json:"entities_id"`
	Error        string `json:"error"`
}

// Enroll exchanges the shared secret for this scanner's own token.
func (c *Client) Enroll(req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if err := c.post("/front/enroll.php", req, &out); err != nil {
		return nil, err
	}
	if out.ScannerToken == "" {
		if out.Error != "" {
			return nil, fmt.Errorf("enrollment refused: %s", out.Error)
		}
		return nil, errors.New("enrollment refused")
	}
	return &out, nil
}

// Job is one assignment.
type Job struct {
	JobID       int                `json:"job_id"`
	TargetID    int                `json:"target_id"`
	TargetName  string             `json:"target_name"`
	Ranges      []string           `json:"ranges"`
	Credentials []snmpx.Credential `json:"credentials"`
	Options     JobOptions         `json:"options"`
}

// JobOptions are the per-target transport settings.
type JobOptions struct {
	Port        int `json:"port"`
	TimeoutMS   int `json:"timeout_ms"`
	Retries     int `json:"retries"`
	Concurrency int `json:"concurrency"`
}

// Package is the artifact the server wants installed: one static binary.
type Package struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// UpdateOffer is what the server says about this scanner's version.
//
// Ring and RolloutPercent are reported even when nothing is offered, because
// "you are in ring 71 and the rollout is at 20%" is the answer to the question
// an operator actually asks — why has this scanner not updated yet — and
// without it the only visible state is an unexplained old version.
type UpdateOffer struct {
	Available      bool     `json:"available"`
	Package        *Package `json:"package"`
	Ring           int      `json:"ring"`
	RolloutPercent int      `json:"rollout_percent"`
}

// UnmarshalJSON tolerates an empty JSON array in place of an object.
//
// PHP serialises an empty associative array as `[]`, not `{}`, and "nothing to
// offer" is by far the most common answer — so a strict decode would fail on
// almost every poll. That failure would not merely lose the update field: it
// aborts the whole JobResponse decode, so the scanner would stop receiving
// work entirely. Being liberal here also matters because a scanner can
// legitimately be talking to an older plugin, which is precisely the state
// self-update creates.
func (o *UpdateOffer) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" || trimmed == "[]" {
		*o = UpdateOffer{}
		return nil
	}

	type plain UpdateOffer
	var v plain
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*o = UpdateOffer(v)

	return nil
}

// ControlAction is one device write GLPI has queued for this scanner.
//
// It carries intent rather than an OID: the profile that declares a control is
// matched on the device's sysObjectID, which only the scanner knows. See
// collect.ResolveControl.
type ControlAction struct {
	ID      int    `json:"action_id"`
	Address string `json:"address"`
	Action  string `json:"action"`
	Index   string `json:"index"`
	Value   string `json:"value"`
	Label   string `json:"label"`

	Credential snmpx.Credential `json:"credential"`
	Options    struct {
		Port      int `json:"port"`
		TimeoutMS int `json:"timeout_ms"`
		Retries   int `json:"retries"`
	} `json:"options"`
}

// TrapPolicy is what GLPI says about listening for notifications.
type TrapPolicy struct {
	Enabled bool     `json:"enabled"`
	Port    int      `json:"port"`
	Ranges  []string `json:"ranges"`
}

// ControlResult reports what happened to one queued action.
type ControlResult struct {
	ID     int    `json:"action_id"`
	OK     bool   `json:"ok"`
	Result string `json:"result"`
}

// JobResponse is the poll result.
type JobResponse struct {
	ScannerInvalid bool              `json:"scanner_invalid"`
	PollInterval   int               `json:"poll_interval"`
	Jobs           []Job             `json:"jobs"`
	Profiles       []profile.Profile `json:"profiles"`
	Update         UpdateOffer       `json:"update"`

	// Traps is the notification-listening policy: whether to listen, on what
	// port, and which sources to accept. Sent on every poll so that switching
	// it off reaches a scanner as reliably as switching it on.
	Traps TrapPolicy `json:"traps"`

	// Actions are device writes to perform now. Empty unless an operator has
	// switched control on, given the target a write credential, and asked for
	// something — three separate deliberate acts.
	Actions []ControlAction `json:"actions,omitempty"`

	Error string `json:"error"`
}

// Jobs polls for work and, in the same round trip, asks what version this
// scanner should be running.
//
// Carried on the existing poll rather than a second endpoint: unlike the
// osquery agent — which needs its own channel because osqueryd's protocol is
// fixed and knows nothing about updating itself — this protocol is ours end to
// end, and the poll already reports the running version. A separate endpoint
// would be a second round trip and a second authentication for information the
// server is already computing.
func (c *Client) Jobs(agentVersion, platform, arch string) (*JobResponse, error) {
	var out JobResponse
	err := c.post("/front/job.php", map[string]any{
		"scanner_token": c.Token,
		"agent_version": agentVersion,
		// Reported on every poll rather than taken from the enrolment record:
		// a scanner rebuilt onto different hardware keeps its token, and being
		// offered a package for the architecture it used to be is an update
		// that cannot possibly run.
		"platform": platform,
		"arch":     arch,
	}, &out)

	// The invalid signal arrives with a 401, so it has to be read before the
	// status error is returned to the caller.
	if out.ScannerInvalid {
		return nil, ErrScannerInvalid
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ReportRequest submits results for one job.
type ReportRequest struct {
	// Phase is "discovery" or "inventory". The server answers a discovery batch
	// with the devices it wants walked; an inventory batch is the answer to
	// that question and gets no such reply.
	Phase string `json:"phase,omitempty"`

	ScannerToken string              `json:"scanner_token"`
	JobID        int                 `json:"job_id"`
	Discovered   int                 `json:"discovered"`
	Inventoried  int                 `json:"inventoried"`
	Failed       int                 `json:"failed"`
	Message      string              `json:"message"`
	Payloads     []payload.Inventory `json:"payloads"`
}

// ReportResponse is the per-device ingest outcome.
type ReportResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
	Results  []struct {
		Index    int      `json:"index"`
		DeviceID string   `json:"deviceid"`
		OK       bool     `json:"ok"`
		Errors   []string `json:"errors"`
		ItemType string   `json:"itemtype"`
		ItemsID  int      `json:"items_id"`
	} `json:"results"`

	// InventoryWanted names the devices GLPI wants a full walk of, in reply to
	// a discovery batch. The decision is the server's because the knowledge is:
	// it is the only party that knows what it already holds, when it last held
	// it, and whether someone has since deleted the asset.
	//
	// A nil field — an older plugin that does not know about the split — is
	// deliberately different from an empty one. Empty means "nothing needs
	// walking"; absent means "I was not asked", and the scanner falls back to
	// inventorying everything it found, which is exactly what it did before.
	InventoryWanted []string `json:"inventory_wanted"`

	ScannerInvalid bool   `json:"scanner_invalid"`
	Error          string `json:"error"`
}

// Download fetches a package body into w, returning the bytes written.
//
// Deliberately not routed through post(): the package URL is absolute and may
// point somewhere other than GLPI — an artifact store or a mirror — and it
// carries no token, because the bytes are authenticated by their checksum
// rather than by who served them.
func (c *Client) Download(url string, w io.Writer, limit int64) (int64, error) {
	resp, err := c.http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download %s returned %d", url, resp.StatusCode)
	}

	// Bounded so a wrong or hostile URL cannot fill the scanner's disk before
	// the checksum ever gets a chance to reject it.
	return io.Copy(w, io.LimitReader(resp.Body, limit))
}

// ReportControl returns what happened to each queued action.
//
// Sent separately from scan results, and promptly: an operator watching a port
// they just shut wants the outcome now, not after the sweep that happens to
// follow it.
func (c *Client) ReportControl(results []ControlResult) error {
	if len(results) == 0 {
		return nil
	}

	return c.post("/front/control.php", map[string]any{
		"scanner_token": c.Token,
		"results":       results,
	}, nil)
}

// ReportTraps forwards a batch of received notifications.
func (c *Client) ReportTraps(notifications any) error {
	return c.post("/front/trap.php", map[string]any{
		"scanner_token": c.Token,
		"notifications": notifications,
	}, nil)
}

// Report submits a job's findings.
func (c *Client) Report(req ReportRequest) (*ReportResponse, error) {
	req.ScannerToken = c.Token

	var out ReportResponse
	err := c.post("/front/report.php", req, &out)
	if out.ScannerInvalid {
		return nil, ErrScannerInvalid
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) post(path string, body any, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.BaseURL+pluginPath+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// Bound the read: the agent must not be talked into buffering an
	// unbounded body by whatever is answering on that URL.
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}

	// Decode before checking status: the error responses carry the fields the
	// caller needs, notably scanner_invalid.
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}

	if res.StatusCode >= 400 {
		return fmt.Errorf("%s: HTTP %d: %s", path, res.StatusCode, snippet(raw))
	}

	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
