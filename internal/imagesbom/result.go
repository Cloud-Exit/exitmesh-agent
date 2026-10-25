// Package imagesbom builds package inventories of running container images from the containerd content store (docs/architecture.md, Image inventory).
package imagesbom

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/version"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

// Result statuses.
const (
	StatusReady       = "ready"
	StatusPending     = "pending"
	StatusUnavailable = "unavailable"
)

// OCI annotation keys read from the image config labels.
const (
	LabelSource   = "org.opencontainers.image.source"
	LabelRevision = "org.opencontainers.image.revision"
)

// Scanner names the inventory engine and its version in every result.
const Scanner = "osv-scalibr " + version.ScannerVersion

// Result is the image.sbom.get result and the image_sbom task payload.
type Result struct {
	Status    string    `json:"status"`
	Digest    string    `json:"digest"`
	Reason    string    `json:"reason,omitempty"`
	Labels    Labels    `json:"labels"`
	Packages  []Package `json:"packages"`
	Truncated bool      `json:"truncated"`
	Scanner   string    `json:"scanner"`
}

// Labels are the OCI source and revision labels of the image config.
type Labels struct {
	Source   string `json:"source,omitempty"`
	Revision string `json:"revision,omitempty"`
}

// Package is one installed package; it carries metadata only, never file contents.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
	Location  string `json:"location,omitempty"`
}

// TaskRequest is the JSON payload of an image_sbom node task.
type TaskRequest struct {
	Digest string `json:"digest"`
}

// Pending reports that a build for digest is queued or running.
func Pending(digest string) Result {
	return Result{Status: StatusPending, Digest: digest, Packages: []Package{}, Scanner: Scanner}
}

// Unavailable reports why no inventory can be returned for digest, as a sentence.
func Unavailable(digest, reason string) Result {
	return Result{Status: StatusUnavailable, Digest: digest, Reason: reason, Packages: []Package{}, Scanner: Scanner}
}

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// ParseDigest validates a sha256 content digest.
func ParseDigest(s string) (string, error) {
	if !digestRE.MatchString(s) {
		return "", fmt.Errorf("digest %q is not of the form sha256:<64 lowercase hex characters>", s)
	}
	return s, nil
}

// DigestFromImageID extracts the content digest from a container status imageID.
func DigestFromImageID(id string) (string, bool) {
	for _, p := range []string{"docker-pullable://", "docker://"} {
		id = strings.TrimPrefix(id, p)
	}
	if i := strings.LastIndex(id, "@"); i >= 0 {
		id = id[i+1:]
	}
	if _, err := ParseDigest(id); err != nil {
		return "", false
	}
	return id, true
}

// Redact passes every free-form string of r through the redactor before it reaches a sink.
func Redact(r Result, red *redact.Redactor) Result {
	r.Reason = red.String(r.Reason)
	r.Labels.Source = red.String(r.Labels.Source)
	r.Labels.Revision = red.String(r.Labels.Revision)
	out := make([]Package, len(r.Packages))
	for i, p := range r.Packages {
		out[i] = Package{
			Ecosystem: red.String(p.Ecosystem),
			Name:      red.String(p.Name),
			Version:   red.String(p.Version),
			PURL:      red.String(p.PURL),
			Location:  red.String(p.Location),
		}
	}
	r.Packages = out
	return r
}

func (r Result) hex() string { return strings.TrimPrefix(r.Digest, "sha256:") }
