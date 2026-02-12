package checker

import "strings"

func normalizeServer(raw, name string) string {

	raw = strings.TrimSpace(raw)

	parts := strings.Fields(raw)

	for _, p := range parts {

		if strings.HasPrefix(
			strings.ToLower(p),
			name,
		) {
			return p
		}
	}

	return name
}
