package detector

func RunPipeline(probes []*Probe) *Result {
	detectors := []Detector{
		MetaDetector{},
		CloudflareDetector{},
		AkamaiDetector{},
		AWSDetector{},
		GoogleDetector{},
		WebServerDetector{},
		FallbackDetector{},
	}

	var best *Result

	for _, d := range detectors {
		if r := d.Detect(probes); r != nil {
			if best == nil || rank(r.Confidence) > rank(best.Confidence) {
				best = r
			}
		}
	}

	return best
}

func rank(c Confidence) int {
	switch c {
	case High:
		return 3
	case Medium:
		return 2
	default:
		return 1
	}
}
