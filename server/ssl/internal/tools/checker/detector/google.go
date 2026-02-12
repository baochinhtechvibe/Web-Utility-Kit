package detector

import "strings"

type GoogleDetector struct{}

func (GoogleDetector) Name() string { return "google" }

func (GoogleDetector) Detect(probes []*Probe) *Result {
	for _, p := range probes {
		if p == nil || p.Response == nil {
			continue
		}

		h := p.Response.Header
		raw := strings.TrimSpace(h.Get("Server"))
		s := strings.ToLower(raw)

		if strings.Contains(s, "gws") ||
			strings.Contains(s, "gfe") {

			name := raw
			if name == "" {
				name = "Google Frontend"
			}

			return &Result{
				Name:       name,
				Vendor:     "Google",
				Category:   "edge",
				Confidence: High,
				Evidence:   []string{raw},
			}
		}
	}
	return nil
}
