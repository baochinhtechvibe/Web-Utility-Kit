package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
	"tools.bctechvibe.io.vn/server/ssl/internal/tools/checker/detector"
)

/* ===========================
   HTTP Clients
=========================== */

var strictClient = &http.Client{
	Timeout: config.HTTPHeadTimeout,
}

var insecureClient = &http.Client{
	Timeout: config.HTTPHeadTimeout,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

var plainClient = &http.Client{
	Timeout: config.HTTPHeadTimeout,
}

/* ===========================
   Public API
=========================== */

func detectServerType(ctx context.Context, domain string) string {
	probes := collectProbes(ctx, domain)

	r := detector.RunPipeline(probes)
	if r == nil {
		return "unknown"
	}

	fmt.Println("DETECTOR RESULT:", r.Name, r.Vendor, r.Confidence)
	return r.Name
}
