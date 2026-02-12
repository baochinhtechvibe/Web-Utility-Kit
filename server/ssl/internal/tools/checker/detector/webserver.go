package detector

import "strings"

type WebServerDetector struct{}

func (WebServerDetector) Name() string { return "web-server" }

func (WebServerDetector) Detect(probes []*Probe) *Result {
	for _, p := range probes {
		if p.Response == nil {
			continue
		}

		raw := p.Response.Header.Get("Server")
		if raw == "" {
			continue
		}

		s := strings.ToLower(raw)

		switch {
		case strings.Contains(s, "nginx"),
			strings.Contains(s, "openresty"),
			strings.Contains(s, "tengine"):
			return webResult(raw, "Nginx", "web", High)

		case strings.Contains(s, "apache"):
			return webResult(raw, "Apache", "web", High)

		case strings.Contains(s, "litespeed"),
			strings.Contains(s, "openlitespeed"),
			strings.Contains(s, "lsws"):
			return webResult(raw, "LiteSpeed", "web", High)

		case strings.Contains(s, "caddy"):
			return webResult(raw, "Caddy", "web", High)

		case strings.Contains(s, "iis"),
			strings.Contains(s, "microsoft-iis"):
			return webResult(raw, "Microsoft", "web", High)
		}
	}

	return nil
}

func webResult(raw, vendor, category string, c Confidence) *Result {
	return &Result{
		Name:       raw,
		Vendor:     vendor,
		Category:   category,
		Confidence: c,
		Evidence:   []string{raw},
	}
}
