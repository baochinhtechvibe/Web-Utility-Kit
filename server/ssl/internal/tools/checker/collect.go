package checker

import (
	"context"
	"net/http"
)

// Probe definitions
type probeDef struct {
	client *http.Client
	url    string
	method string
}

// Probe result structure
type Probe struct {
	URL      string
	Method   string
	Response *http.Response
	Error    error
}

func collectProbes(ctx context.Context, domain string) []*Probe {
	defs := []probeDef{
		{strictClient, "https://" + domain, http.MethodHead},
		{strictClient, "https://" + domain, http.MethodGet},

		{insecureClient, "https://" + domain, http.MethodHead},
		{insecureClient, "https://" + domain, http.MethodGet},

		{plainClient, "http://" + domain, http.MethodHead},
		{plainClient, "http://" + domain, http.MethodGet},
	}

	var probes []*Probe

	for _, d := range defs {
		resp, err := doRequest(ctx, d.client, d.url, d.method)

		probes = append(probes, &Probe{
			URL:      d.url,
			Method:   d.method,
			Response: resp,
			Error:    err,
		})
	}

	return probes
}
