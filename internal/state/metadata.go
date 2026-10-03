package state

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

// NewMetadataClient forbids client-go's full-object content-negotiation fallback.
func NewMetadataClient(config *rest.Config) (metadata.Interface, error) {
	cfg := rest.CopyConfig(config)
	cfg.Wrap(func(next http.RoundTripper) http.RoundTripper { return metadataTransport{next: next} })
	return metadata.NewForConfig(cfg)
}

type metadataTransport struct{ next http.RoundTripper }

func (t metadataTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	var accept []string
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		_, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err == nil && params["g"] == "meta.k8s.io" && (params["as"] == "PartialObjectMetadata" || params["as"] == "PartialObjectMetadataList") {
			accept = append(accept, strings.TrimSpace(part))
		}
	}
	if len(accept) == 0 {
		return nil, errors.New("state: metadata request has no metadata-only Accept variant")
	}
	r.Header.Set("Accept", strings.Join(accept, ","))
	return t.next.RoundTrip(r)
}
