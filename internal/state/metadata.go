package state

import (
	"net/http"

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
	r.Header.Set("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1")
	return t.next.RoundTrip(r)
}
