package detector

import "strings"

type AWSDetector struct{}

func (AWSDetector) Name() string { return "aws" }

func (AWSDetector) Detect(probes []*Probe) *Result {
	for _, p := range probes {
		if p == nil || p.Response == nil {
			continue
		}

		h := p.Response.Header
		raw := strings.TrimSpace(h.Get("Server"))
		s := strings.ToLower(raw)

		/* ---------- CloudFront ---------- */
		if h.Get("X-Amz-Cf-Id") != "" ||
			strings.Contains(s, "cloudfront") {

			name := raw
			if name == "" {
				name = "CloudFront"
			}

			return &Result{
				Name:       name,
				Vendor:     "AWS",
				Category:   "cdn",
				Confidence: High,
				Evidence:   []string{"X-Amz-Cf-Id", raw},
			}
		}

		/* ---------- ELB / ALB ---------- */
		if strings.Contains(s, "awselb") ||
			strings.Contains(s, "amazonelb") {

			name := raw
			if name == "" {
				name = "AmazonELB"
			}

			return &Result{
				Name:       name,
				Vendor:     "AWS",
				Category:   "cloud",
				Confidence: Medium,
				Evidence:   []string{raw},
			}
		}
	}
	return nil
}
