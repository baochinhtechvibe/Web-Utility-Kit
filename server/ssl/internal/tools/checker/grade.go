package checker

import "tools.bctechvibe.io.vn/server/ssl/internal/config"

func calcGrade(
	tls string,
	days int64,
	trusted bool,
	ocsp bool) string {

	score := 0

	// TLS version score
	if tls == config.TLSVersion13 {
		score += 30
	} else if tls == config.TLSVersion12 {
		score += 20
	}

	// Expiry score
	if days > config.CertExpiryWarningDays {
		score += 30
	} else if days > config.CertExpirySoonThreshold {
		score += 20
	}

	// Trust score
	if trusted {
		score += 20
	}

	// OCSP score
	if ocsp {
		score += 20
	}

	// Determine grade based on score
	switch {
	case score >= 90:
		return config.GradeAPlus
	case score >= 80:
		return config.GradeA
	case score >= 70:
		return config.GradeB
	case score >= 60:
		return config.GradeC
	default:
		return config.GradeF
	}
}
