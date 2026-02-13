package checker

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
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
   HELPER FUNCTIONS
=========================== */

func isGenericServer(v string) bool {
	s := strings.ToLower(v)

	switch s {
	case "server", "unknown":
		return true
	}
	return false
}

func normalizeServer(v string) string {
	s := strings.ToLower(v)

	switch {
	case strings.Contains(s, "cloudflare"):
		return "cloudflare"

	case strings.Contains(s, "cloudfront"):
		return "cloudfront"

	case strings.Contains(s, "fastly"),
		strings.Contains(s, "github"):
		return "fastly"

	case strings.Contains(s, "akamai"),
		strings.Contains(s, "akamai ghost"),
		strings.Contains(s, "akamaighost"):
		return "akamai"

	case strings.Contains(s, "gws"),
		strings.Contains(s, "esf"):
		return "gws"

	case strings.Contains(s, "proxygen"):
		return "proxygen-bolt"
	}

	return v
}

/* ===========================
   Public API
=========================== */

func detectServerType(ctx context.Context, domain string) string {
	probes := collectProbes(ctx, domain)

	scores := map[string]int{}
	var fallback string

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if isGenericServer(v) {
			return
		}
		scores[v]++
	}

	for _, p := range probes {
		if p.Response == nil {
			continue
		}

		h := p.Response.Header

		server := h.Get("Server")
		serverLower := strings.ToLower(server)
		viaLower := strings.ToLower(h.Get("Via"))

		// =====================
		// Strong: Server header
		// =====================
		add(server)

		// =====================
		// Big Tech fingerprints
		// =====================

		if h.Get("X-Fb-Debug") != "" ||
			h.Get("X-Fb-Connection-Quality") != "" {
			add("proxygen-bolt")
		}

		if strings.Contains(strings.ToLower(h.Get("Report-To")), "gws") {
			add("gws")
		}

		// =====================
		// Cloudflare
		// =====================
		if h.Get("CF-Ray") != "" ||
			strings.Contains(serverLower, "cloudflare") {
			add("cloudflare")
		}

		// =====================
		// CloudFront
		// =====================
		if h.Get("X-Amz-Cf-Id") != "" ||
			h.Get("X-Amz-Cf-Pop") != "" ||
			strings.Contains(viaLower, "cloudfront") {
			add("cloudfront")
		}

		// =====================
		// Fastly
		// =====================
		if strings.Contains(strings.ToLower(h.Get("X-Served-By")), "fastly") ||
			strings.Contains(viaLower, "fastly") {
			add("fastly")
		}

		if strings.Contains(serverLower, "akamaighost") {
			add("AkamaiGHost")

		} else if strings.Contains(serverLower, "akamai") ||
			strings.Contains(viaLower, "akamai") ||
			h.Get("X-Akamai-Transformed") != "" ||
			h.Get("X-Akamai-Staging") != "" ||
			h.Get("X-Akamai-Request-ID") != "" ||
			h.Get("Akamai-Origin-Hop") != "" {
			add("akamai")
		}

		// =====================
		// Weak fallback
		// =====================
		if fallback == "" {
			fallback = h.Get("X-Powered-By")
			if fallback == "" {
				fallback = h.Get("Via")
			}
		}
	}

	best := ""
	bestScore := 0

	for k, s := range scores {
		if s > bestScore {
			best = k
			bestScore = s
		}
	}

	if best != "" {
		return normalizeServer(best)
	}

	if fallback != "" {
		return normalizeServer(fallback)
	}

	return "Unknown"
}
