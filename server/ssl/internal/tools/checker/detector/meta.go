package detector

import "strings"

type MetaDetector struct{}

func (MetaDetector) Name() string { return "meta" }

func (MetaDetector) Detect(probes []*Probe) *Result {
	score := 0
	var ev []string
	var serverRaw string

	for _, p := range probes {
		if p.Response == nil {
			continue
		}

		h := p.Response.Header
		raw := strings.TrimSpace(h.Get("Server"))
		s := strings.ToLower(raw)

		if raw != "" && strings.HasPrefix(s, "proxygen") {
			score += 70
			ev = append(ev, raw)

			if serverRaw == "" {
				serverRaw = raw
			}
		}

		for _, k := range []string{
			"X-FB-Debug",
			"X-FB-Connection-Quality",
		} {
			if h.Get(k) != "" {
				score += 10
				ev = append(ev, k)
			}
		}
	}

	if score == 0 {
		return nil
	}

	if serverRaw == "" {
		serverRaw = "proxygen"
	}

	return &Result{
		Name:       serverRaw,
		Vendor:     "Meta",
		Category:   "edge",
		Confidence: mapScore(score),
		Evidence:   ev,
	}
}
