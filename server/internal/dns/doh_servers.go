// internal/dns/doh_servers.go
package dns

import "time"

// DoHResolver handles DNS-over-HTTPS queries
type DoHResolver struct {
	Key      string
	Name     string
	Endpoint string
	Timeout  time.Duration
}

// DoHServers defines supported DNS-over-HTTPS providers
var DoHServers = map[string]*DoHResolver{
	"google": {
		Key:      "google",
		Name:     "Google DNS",
		Endpoint: "https://dns.google/resolve",
		Timeout:  5 * time.Second,
	},
	"cloudflare": {
		Key:      "cloudflare",
		Name:     "Cloudflare",
		Endpoint: "https://cloudflare-dns.com/dns-query",
		Timeout:  5 * time.Second,
	},
	"quad9": {
		Key:      "quad9",
		Name:     "Quad9",
		Endpoint: "https://dns.quad9.net/dns-query",
		Timeout:  5 * time.Second,
	},
	"opendns": {
		Key:      "opendns",
		Name:     "OpenDNS",
		Endpoint: "https://doh.opendns.com/dns-query",
		Timeout:  5 * time.Second,
	},
}
