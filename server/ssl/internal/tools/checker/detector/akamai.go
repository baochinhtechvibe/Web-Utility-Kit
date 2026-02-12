package detector

import "strings"

type AkamaiDetector struct{}

func (AkamaiDetector) Name() string { return "akamai" }

func (AkamaiDetector) Detect(probes []*Probe) *Result {
	for _, p := range probes {
		if p.Response == nil {
			continue
		}

		h := p.Response.Header
		raw := strings.TrimSpace(h.Get("Server"))
		s := strings.ToLower(raw)

		if raw != "" && strings.Contains(s, "akamaighost") {

			name := raw
			if name == "" {
				name = "akamaighost"
			}

			return &Result{
				Name:       name,
				Vendor:     "Akamai",
				Category:   "cdn",
				Confidence: High,
				Evidence:   []string{raw},
			}
		}
	}
	return nil
}
