package detector

type FallbackDetector struct{}

func (FallbackDetector) Name() string {
	return "fallback"
}

func (FallbackDetector) Detect(probes []*Probe) *Result {
	for _, p := range probes {
		if p == nil || p.Response == nil {
			continue
		}

		if s := p.Response.Header.Get("Server"); s != "" {
			return &Result{
				Name:       s,
				Vendor:     "unknown",
				Category:   "unknown",
				Confidence: Low,
				Evidence:   []string{s},
			}
		}
	}
	return nil
}
