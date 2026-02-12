package detector

func mapScore(score int) Confidence {
	switch {
	case score >= 70:
		return High
	case score >= 40:
		return Medium
	default:
		return Low
	}
}
