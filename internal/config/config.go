// Package config loads and validates the agent configuration file (docs/configuration.md).
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Roles.
const (
	RoleNode        = "node"
	RoleCoordinator = "coordinator"
	RoleHost        = "host"
)

// Capabilities.
const (
	CapInventory = "inventory"
	CapMetrics   = "metrics"
	CapLogs      = "logs"
)

// Lookback source types (PRD I6a, I6b).
const (
	SourcePrometheus      = "prometheus"
	SourceMimir           = "mimir"
	SourceVictoriaMetrics = "victoriametrics"
	SourceLoki            = "loki"
	SourceVictoriaLogs    = "victorialogs"
)

// Bytes is a byte size accepting suffixes Ki, Mi, Gi, Ti, K, M, G, T.
type Bytes int64

func (b *Bytes) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseBytes(n.Value)
	if err != nil {
		return err
	}
	*b = Bytes(v)
	return nil
}

// ParseBytes parses a size such as 16Mi or 1G.
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}} {
		if strings.HasSuffix(s, u.suf) {
			mult, s = u.m, strings.TrimSuffix(s, u.suf)
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * mult, nil
}

// Duration accepts Go duration strings.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q", n.Value)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the full agent configuration.
type Config struct {
	Role                string        `yaml:"role"`
	Endpoint            string        `yaml:"endpoint"`
	EndpointCAFile      string        `yaml:"endpointCAFile"`
	EnrollmentTokenFile string        `yaml:"enrollmentTokenFile"`
	StateDir            string        `yaml:"stateDir"`
	Capabilities        []string      `yaml:"capabilities"`
	Kubernetes          Kubernetes    `yaml:"kubernetes"`
	Coordinator         Coordinator   `yaml:"coordinator"`
	Spool               Spool         `yaml:"spool"`
	Node                Node          `yaml:"node"`
	Host                Host          `yaml:"host"`
	Lookback            []Lookback    `yaml:"lookback"`
	AirGap              AirGap        `yaml:"airgap"`
	Trust               Trust         `yaml:"trust"`
	Policy              Policy        `yaml:"policy"`
	Investigation       Investigation `yaml:"investigation"`
	Logging             Logging       `yaml:"logging"`
}

// Kubernetes configures collection scope (PRD A3, 7.2).
type Kubernetes struct {
	Scope               string   `yaml:"scope"`
	Namespaces          []string `yaml:"namespaces"`
	ExcludeNamespaces   []string `yaml:"excludeNamespaces"`
	LabelAllowlist      []string `yaml:"labelAllowlist"`
	AnnotationAllowlist []string `yaml:"annotationAllowlist"`
	Resources           []string `yaml:"resources"`
	ClusterName         string   `yaml:"clusterName"`
}

// Coordinator configures the coordinator listener and the node side of the node API.
type Coordinator struct {
	Listen      string `yaml:"listen"`
	TLSCertFile string `yaml:"tlsCertFile"`
	TLSKeyFile  string `yaml:"tlsKeyFile"`
	ServiceURL  string `yaml:"serviceURL"`
	CAFile      string `yaml:"caFile"`
	Audience    string `yaml:"audience"`
	TokenFile   string `yaml:"tokenFile"`
	Namespace   string `yaml:"namespace"`
	PodName     string `yaml:"podName"`
}

// Spool sizes the coordinator spool (PRD 8.2).
type Spool struct {
	Capacity   Bytes   `yaml:"capacity"`
	Window     Bytes   `yaml:"window"`
	CoalesceAt float64 `yaml:"coalesceAt"`
}

// Node configures a node agent (PRD 6.3, 7.6).
type Node struct {
	Name           string   `yaml:"name"`
	DiskCap        Bytes    `yaml:"diskCap"`
	EvidenceRing   Bytes    `yaml:"evidenceRing"`
	LogsPath       string   `yaml:"logsPath"`
	ScrapeInterval Duration `yaml:"scrapeInterval"`
	MaxTargets     int      `yaml:"maxTargets"`
	MaxSeries      int      `yaml:"maxSeries"`
	MaxSamplesRate int      `yaml:"maxSamplesPerSecond"`
	KubeletTLS     string   `yaml:"kubeletTLS"`
	KubeletPort    int      `yaml:"kubeletPort"`
}

// Host configures host mode (PRD 7.10).
type Host struct {
	DiskCap          Bytes    `yaml:"diskCap"`
	SpoolReserve     Bytes    `yaml:"spoolReserve"`
	TSDBMax          Bytes    `yaml:"tsdbMax"`
	EvidenceRing     Bytes    `yaml:"evidenceRing"`
	ScrapeInterval   Duration `yaml:"scrapeInterval"`
	LogFiles         []string `yaml:"logFiles"`
	Journal          bool     `yaml:"journal"`
	JournalDir       string   `yaml:"journalDir"`
	MetricsEndpoints []string `yaml:"metricsEndpoints"`
	AllowNonLoopback bool     `yaml:"allowNonLoopback"`
}

// Lookback is one optional read-only external store (PRD I6).
type Lookback struct {
	Name              string   `yaml:"name"`
	Type              string   `yaml:"type"`
	URL               string   `yaml:"url"`
	Tenant            string   `yaml:"tenant"`
	AccountID         string   `yaml:"accountID"`
	ProjectID         string   `yaml:"projectID"`
	BearerTokenFile   string   `yaml:"bearerTokenFile"`
	BasicUsernameFile string   `yaml:"basicUsernameFile"`
	BasicPasswordFile string   `yaml:"basicPasswordFile"`
	CAFile            string   `yaml:"caFile"`
	Timeout           Duration `yaml:"timeout"`
	Retention         Duration `yaml:"retention"`
}

// AirGap configures the air-gap profile (PRD A9).
type AirGap struct {
	Enabled   bool   `yaml:"enabled"`
	BundleDir string `yaml:"bundleDir"`
	ExportDir string `yaml:"exportDir"`
}

// Trust is the rule bundle trust root of the ExitMesh deployment (PRD R2a). Each self-hosted
// deployment has its own root key set, shown on its onboarding page next to the enrollment token.
type Trust struct {
	// Roots are "<id>:<base64 ed25519 public key>" entries.
	Roots     []string `yaml:"roots"`
	RootsFile string   `yaml:"rootsFile"`
	Threshold int      `yaml:"threshold"`
}

// Policy is the local administrator upper bound on rules (PRD 7.5).
type Policy struct {
	MaxRuleEvalTime   Duration `yaml:"maxRuleEvalTime"`
	MaxRuleSamples    int      `yaml:"maxRuleSamples"`
	MaxRuleSeries     int      `yaml:"maxRuleSeries"`
	MaxCounterBytes   Bytes    `yaml:"maxCounterBytes"`
	MaxEvidenceBytes  Bytes    `yaml:"maxEvidenceBytes"`
	DisabledRules     []string `yaml:"disabledRules"`
	LateThreshold     Duration `yaml:"lateThreshold"`
	RedactionPatterns []string `yaml:"redactionPatterns"`
}

// Investigation bounds live queries (PRD I3).
type Investigation struct {
	MaxConcurrency int      `yaml:"maxConcurrency"`
	Timeout        Duration `yaml:"timeout"`
	MaxBytes       Bytes    `yaml:"maxBytes"`
	MaxLines       int      `yaml:"maxLines"`
	MaxSeries      int      `yaml:"maxSeries"`
	MaxSamples     int      `yaml:"maxSamples"`
	MaxWindow      Duration `yaml:"maxWindow"`
}

// Logging configures diagnostics.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads, defaults, and validates a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes YAML strictly, applies defaults, and validates.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyDefaults fills unset fields with the proposed defaults of PRD 8.2 and H15.
func (c *Config) ApplyDefaults() {
	setS := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	setB := func(p *Bytes, v int64) {
		if *p == 0 {
			*p = Bytes(v)
		}
	}
	setD := func(p *Duration, v time.Duration) {
		if *p == 0 {
			*p = Duration(v)
		}
	}
	setI := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	if len(c.Capabilities) == 0 {
		c.Capabilities = []string{CapInventory, CapMetrics, CapLogs}
	}
	switch c.Role {
	case RoleCoordinator:
		setS(&c.StateDir, "/data")
	default:
		setS(&c.StateDir, "/var/lib/exitmesh")
	}
	setS(&c.Kubernetes.Scope, "cluster")
	setS(&c.Coordinator.Listen, ":8443")
	setS(&c.Coordinator.Audience, "exitmesh-coordinator")
	setS(&c.Coordinator.TokenFile, "/var/run/secrets/exitmesh/token")
	setB(&c.Spool.Capacity, 10<<30)
	setB(&c.Spool.Window, 8<<20)
	if c.Spool.CoalesceAt == 0 {
		c.Spool.CoalesceAt = 0.90
	}
	setB(&c.Node.DiskCap, 1<<30)
	setB(&c.Node.EvidenceRing, 16<<20)
	setS(&c.Node.LogsPath, "/var/log/pods")
	setD(&c.Node.ScrapeInterval, 30*time.Second)
	setI(&c.Node.MaxTargets, 200)
	setI(&c.Node.MaxSeries, 100_000)
	setI(&c.Node.MaxSamplesRate, 20_000)
	setS(&c.Node.KubeletTLS, "verify")
	setI(&c.Node.KubeletPort, 10250)
	setB(&c.Host.DiskCap, 2<<30)
	setB(&c.Host.SpoolReserve, 1<<30)
	setB(&c.Host.TSDBMax, 768<<20)
	setB(&c.Host.EvidenceRing, 16<<20)
	setD(&c.Host.ScrapeInterval, 30*time.Second)
	if len(c.Host.LogFiles) == 0 {
		c.Host.LogFiles = []string{"/var/log"}
	}
	for i := range c.Lookback {
		setD(&c.Lookback[i].Timeout, 30*time.Second)
	}
	setD(&c.Policy.MaxRuleEvalTime, 2*time.Second)
	setI(&c.Policy.MaxRuleSamples, 5_000_000)
	setI(&c.Policy.MaxRuleSeries, 10_000)
	setB(&c.Policy.MaxCounterBytes, 4<<20)
	setB(&c.Policy.MaxEvidenceBytes, 1<<20)
	setD(&c.Policy.LateThreshold, 15*time.Minute)
	setI(&c.Investigation.MaxConcurrency, 4)
	setD(&c.Investigation.Timeout, 30*time.Second)
	setB(&c.Investigation.MaxBytes, 4<<20)
	setI(&c.Investigation.MaxLines, 5_000)
	setI(&c.Investigation.MaxSeries, 1_000)
	setI(&c.Investigation.MaxSamples, 500_000)
	setD(&c.Investigation.MaxWindow, 6*time.Hour)
	setS(&c.Logging.Level, "info")
	setS(&c.Logging.Format, "json")
}

// HasCapability reports whether cap is enabled.
func (c *Config) HasCapability(cap string) bool {
	for _, x := range c.Capabilities {
		if x == cap {
			return true
		}
	}
	return false
}

// Validate rejects inconsistent configuration.
func (c *Config) Validate() error {
	var errs []string
	switch c.Role {
	case RoleNode, RoleCoordinator, RoleHost:
	default:
		errs = append(errs, fmt.Sprintf("role must be node, coordinator, or host (got %q)", c.Role))
	}
	for _, cp := range c.Capabilities {
		switch cp {
		case CapInventory, CapMetrics, CapLogs:
		default:
			errs = append(errs, "unknown capability "+cp)
		}
	}
	if (c.Role == RoleCoordinator || c.Role == RoleHost) && !c.AirGap.Enabled {
		u, err := url.Parse(c.Endpoint)
		if c.Endpoint == "" || err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, "endpoint must be an https URL unless airgap.enabled")
		}
		if c.EnrollmentTokenFile == "" {
			errs = append(errs, "enrollmentTokenFile is required")
		}
	}
	if c.Role == RoleNode && c.Coordinator.ServiceURL == "" {
		errs = append(errs, "coordinator.serviceURL is required for the node role")
	}
	if len(c.Trust.Roots) == 0 && c.Trust.RootsFile == "" {
		errs = append(errs, "trust.roots or trust.rootsFile is required: the root public keys of your ExitMesh deployment")
	}
	if c.Trust.Threshold < 0 || (len(c.Trust.Roots) > 0 && c.Trust.RootsFile == "" && c.Trust.Threshold > len(c.Trust.Roots)) {
		errs = append(errs, "trust.threshold exceeds the number of roots")
	}
	if c.Kubernetes.Scope != "cluster" && c.Kubernetes.Scope != "namespaces" {
		errs = append(errs, "kubernetes.scope must be cluster or namespaces")
	}
	if c.Kubernetes.Scope == "namespaces" && len(c.Kubernetes.Namespaces) == 0 {
		errs = append(errs, "kubernetes.namespaces is required when scope is namespaces")
	}
	if c.Spool.CoalesceAt <= 0 || c.Spool.CoalesceAt > 1 {
		errs = append(errs, "spool.coalesceAt must be in (0,1]")
	}
	if c.Host.SpoolReserve+c.Host.TSDBMax > c.Host.DiskCap {
		errs = append(errs, "host.spoolReserve + host.tsdbMax exceeds host.diskCap")
	}
	switch c.Node.KubeletTLS {
	case "verify", "skip":
	default:
		errs = append(errs, "node.kubeletTLS must be verify or skip")
	}
	names := map[string]bool{}
	for _, l := range c.Lookback {
		if l.Name == "" || names[l.Name] {
			errs = append(errs, "lookback sources need unique names")
		}
		names[l.Name] = true
		switch l.Type {
		case SourcePrometheus, SourceMimir, SourceVictoriaMetrics, SourceLoki, SourceVictoriaLogs:
		default:
			errs = append(errs, fmt.Sprintf("lookback %s: unknown type %q", l.Name, l.Type))
		}
		if u, err := url.Parse(l.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Sprintf("lookback %s: url must be http(s)", l.Name))
		}
	}
	if len(errs) > 0 {
		return errors.New("config: " + strings.Join(errs, "; "))
	}
	return nil
}
