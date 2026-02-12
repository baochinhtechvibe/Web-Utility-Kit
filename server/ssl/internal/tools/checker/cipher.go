package checker

import "strings"

func isSecureCipher(cipher string) bool {

	cipher = strings.ToUpper(cipher)

	insecure := []string{
		"RC4",
		"DES",
		"3DES",
		"MD5",
		"NULL",
		"EXPORT",
	}

	for _, bad := range insecure {
		if strings.Contains(cipher, bad) {
			return false
		}
	}

	return true
}
