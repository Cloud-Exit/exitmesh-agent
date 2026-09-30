package scrape

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Default in-pod credential paths used for kubelet scraping.
const (
	ServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // a file path, not a credential
	ServiceAccountCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Pod annotations for scrape discovery.
const (
	AnnotationScrape = "prometheus.io/scrape"
	AnnotationPort   = "prometheus.io/port"
	AnnotationPath   = "prometheus.io/path"
	AnnotationScheme = "prometheus.io/scheme"
)

// TLSConfig configures server verification.
type TLSConfig struct {
	CAFile             string
	InsecureSkipVerify bool
	ServerName         string
}

// Target is one scrape endpoint; job and instance labels default to "scrape" and the URL host.
type Target struct {
	URL             string
	Labels          map[string]string
	BearerTokenFile string
	TLS             TLSConfig
	Interval        time.Duration
	Timeout         time.Duration
}

// Key identifies a target by URL and labels.
func (t Target) Key() string {
	var b strings.Builder
	b.WriteString(t.URL)
	for _, k := range sortedKeys(t.Labels) {
		b.WriteByte('\xff')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(t.Labels[k])
	}
	return b.String()
}

func (t Target) config() string {
	return fmt.Sprintf("%s|%v|%v|%s|%+v", t.Key(), t.Interval, t.Timeout, t.BearerTokenFile, t.TLS)
}

// targetLabels returns the labels attached to samples, including job and instance.
func (t Target) targetLabels() (map[string]string, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("scrape: unsupported target URL %q", t.URL)
	}
	out := make(map[string]string, len(t.Labels)+2)
	for k, v := range t.Labels {
		out[k] = v
	}
	if out["job"] == "" {
		out["job"] = "scrape"
	}
	if out["instance"] == "" {
		out["instance"] = u.Host
	}
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// KubeletOptions configures KubeletTargets.
type KubeletOptions struct {
	Node string
	// TokenFile and CAFile default to the pod ServiceAccount mount.
	TokenFile          string
	CAFile             string
	InsecureSkipVerify bool
}

// KubeletTargets returns the kubelet /metrics and /metrics/cadvisor targets for a node.
func KubeletTargets(nodeIP string, port int, o KubeletOptions) []Target {
	if o.TokenFile == "" {
		o.TokenFile = ServiceAccountTokenFile
	}
	if o.CAFile == "" && !o.InsecureSkipVerify {
		o.CAFile = ServiceAccountCAFile
	}
	host := net.JoinHostPort(nodeIP, strconv.Itoa(port))
	var out []Target
	for _, p := range []string{"/metrics", "/metrics/cadvisor"} {
		l := map[string]string{"job": "kubelet", "metrics_path": p}
		if o.Node != "" {
			l["node"] = o.Node
		}
		out = append(out, Target{
			URL:             "https://" + host + p,
			Labels:          l,
			BearerTokenFile: o.TokenFile,
			TLS:             TLSConfig{CAFile: o.CAFile, InsecureSkipVerify: o.InsecureSkipVerify},
		})
	}
	return out
}

// Pod is the subset of a pod needed for annotation discovery.
type Pod struct {
	Namespace   string
	Name        string
	UID         string
	Node        string
	IP          string
	Phase       string
	Annotations map[string]string
	Ports       []PodPort
}

// PodPort is one declared container port.
type PodPort struct {
	Container string
	Port      int
	Protocol  string
}

// PodTargets returns targets for running annotated pods, one per declared TCP port without a port annotation.
func PodTargets(pods []Pod) []Target {
	var out []Target
	for _, p := range pods {
		if p.Annotations[AnnotationScrape] != "true" || p.IP == "" || p.Phase != "Running" {
			continue
		}
		scheme := p.Annotations[AnnotationScheme]
		if scheme == "" {
			scheme = "http"
		}
		if scheme != "http" && scheme != "https" {
			continue
		}
		path := p.Annotations[AnnotationPath]
		if path == "" {
			path = "/metrics"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		type pc struct {
			port      int
			container string
		}
		var ports []pc
		if s, ok := p.Annotations[AnnotationPort]; ok {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n <= 0 || n > 65535 {
				continue
			}
			c := ""
			for _, cp := range p.Ports {
				if cp.Port == n {
					c = cp.Container
				}
			}
			ports = append(ports, pc{n, c})
		} else {
			for _, cp := range p.Ports {
				if cp.Port > 0 && cp.Port <= 65535 && (cp.Protocol == "" || strings.EqualFold(cp.Protocol, "TCP")) {
					ports = append(ports, pc{cp.Port, cp.Container})
				}
			}
		}
		for _, x := range ports {
			l := map[string]string{"job": "kubernetes-pods", "namespace": p.Namespace, "pod": p.Name}
			if x.container != "" {
				l["container"] = x.container
			}
			if p.Node != "" {
				l["node"] = p.Node
			}
			out = append(out, Target{URL: scheme + "://" + net.JoinHostPort(p.IP, strconv.Itoa(x.port)) + path, Labels: l})
		}
	}
	return out
}
