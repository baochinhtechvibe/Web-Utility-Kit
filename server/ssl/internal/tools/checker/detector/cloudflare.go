package detector

import "strings"

type CloudflareDetector struct{}

func (CloudflareDetector) Name() string { return "cloudflare" }

func (CloudflareDetector) Detect(probes []*Probe) *Result {
	for _, p := range probes {
		if p.Response == nil {
			continue
		}

		h := p.Response.Header
		raw := strings.TrimSpace(h.Get("Server"))
		s := strings.ToLower(raw)

		if h.Get("CF-Ray") != "" ||
			(raw != "" && strings.Contains(s, "cloudflare")) {

			name := raw
			if name == "" {
				name = "cloudflare"
			}

			return &Result{
				Name:       name,
				Vendor:     "Cloudflare",
				Category:   "cdn",
				Confidence: High,
				Evidence: []string{
					"CF-Ray",
					raw,
				},
			}
		}
	}
	return nil
}
