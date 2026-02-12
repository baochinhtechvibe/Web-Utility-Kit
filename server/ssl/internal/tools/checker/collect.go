package checker

import (
	"context"
	"net/http"

	"tools.bctechvibe.io.vn/server/ssl/internal/tools/checker/detector"
)

type probeDef struct {
	client *http.Client
	url    string
	method string
}

func collectProbes(ctx context.Context, domain string) []*detector.Probe {
	defs := []probeDef{
		{strictClient, "https://" + domain, http.MethodHead},
		{strictClient, "https://" + domain, http.MethodGet},

		{insecureClient, "https://" + domain, http.MethodHead},
		{insecureClient, "https://" + domain, http.MethodGet},

		{plainClient, "http://" + domain, http.MethodHead},
		{plainClient, "http://" + domain, http.MethodGet},
	}

	var probes []*detector.Probe

	for _, d := range defs {
		resp, err := doRequest(ctx, d.client, d.url, d.method)

		probes = append(probes, &detector.Probe{
			URL:      d.url,
			Method:   d.method,
			Response: resp,
			Error:    err,
		})
	}

	return probes
}
