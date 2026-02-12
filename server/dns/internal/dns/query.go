// ============================================
// FILE: internal/dns/query.go
// PURPOSE:
//   - Public DNS query facade used by handlers
//   - Internally delegates to ResolverManager
//   - Keeps legacy UDP logic intact
//
// ============================================
package dns

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"tools.bctechvibe.io.vn/server/internal/models"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

var GeoIPDB *geoip2.Reader
var GeoASNDB *geoip2.Reader

// ============================================
// PUBLIC FACADE (USED BY HANDLERS)
// ============================================

// QueryDNS is the public DNS entry point used by HTTP handlers.
//
// Default behavior:
//   - Prefer DNS-over-HTTPS (DoH)
//   - Resolver selection is hidden from handlers
//
// NOTE:
//   - This function preserves backward compatibility
//   - Internal architecture remains clean & extensible
func QueryDNS(server string, domain string, qtype uint16) []interface{} {
	// 1. Resolve DoH provider by key
	doh, ok := DoHServers[server]
	if !ok {
		log.Printf("Unknown DoH server key: %s", server)
		return []interface{}{}
	}

	// 2. Build resolver manager
	rm := NewResolverManager(
		doh,
		&UDPResolver{
			Server:  "8.8.8.8:53",
			Timeout: 5 * time.Second,
		},
	)

	// 3. Execute query (default = DoH)
	records, err := rm.Resolve(domain, qtype, "doh")
	if err != nil {
		log.Printf("Resolver error: %v", err)
		return []interface{}{}
	}

	// 4. Convert to generic interface slice
	result := make([]interface{}, 0, len(records))

	for i := range records {
		rec := records[i]

		switch rec.Type {
		case "A", "AAAA":
			ip := net.ParseIP(rec.Address)
			if ip != nil {
				enrichIPInfo(&rec, ip)
			}
		case "PTR":
			EnrichIPInfoByString(&rec, rec.Value)
		}

		result = append(result, rec)
	}

	return result
}

// ============================================
// LEGACY / LOW-LEVEL UDP IMPLEMENTATION
// ============================================

// QueryDNSUDP performs a raw DNS query over UDP.
//
// This function is kept for:
//   - Low-level access
//   - Debugging
//   - Future explicit UDP endpoints
func QueryDNSUDP(server, domain string, qtype uint16) []interface{} {
	var records []interface{}

	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		log.Printf("DNS query error for %s (type %d): %v", domain, qtype, err)
		return records
	}

	if resp.Rcode != dns.RcodeSuccess {
		log.Printf("DNS query failed for %s (type %d): Rcode=%d", domain, qtype, resp.Rcode)
		return records
	}

	log.Printf("DNS query success for %s (type %d): %d answers", domain, qtype, len(resp.Answer))

	// Parse answers
	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			record := models.DNSRecord{
				Type:    "A",
				Address: rr.A.String(),
				TTL:     rr.Hdr.Ttl,
			}
			enrichIPInfo(&record, rr.A)
			records = append(records, record)

		case *dns.AAAA:
			record := models.DNSRecord{
				Type:    "AAAA",
				Address: rr.AAAA.String(),
				TTL:     rr.Hdr.Ttl,
			}
			enrichIPInfo(&record, rr.AAAA)
			records = append(records, record)

		case *dns.NS:
			records = append(records, models.DNSRecord{
				Type:       "NS",
				Nameserver: rr.Ns,
				TTL:        rr.Hdr.Ttl,
			})

		case *dns.MX:
			records = append(records, models.DNSRecord{
				Type:     "MX",
				Exchange: rr.Mx,
				Priority: rr.Preference,
				TTL:      rr.Hdr.Ttl,
			})

		case *dns.CNAME:
			records = append(records, models.DNSRecord{
				Type:  "CNAME",
				Value: rr.Target,
				TTL:   rr.Hdr.Ttl,
			})

		case *dns.TXT:
			txtValue := strings.Join(rr.Txt, " ")
			records = append(records, models.DNSRecord{
				Type:  "TXT",
				Value: txtValue,
				TTL:   rr.Hdr.Ttl,
			})

		case *dns.PTR:
			record := models.DNSRecord{
				Type:  "PTR",
				Value: rr.Ptr,
				TTL:   rr.Hdr.Ttl,
			}
			records = append(records, record)

		default:
			log.Printf("Unknown record type: %T", rr)
		}
	}

	return records
}

// ============================================
// GEO-IP HELPERS (UNCHANGED)
// ============================================

func enrichIPInfo(record *models.DNSRecord, ip net.IP) {
	if GeoIPDB != nil {
		if city, err := GeoIPDB.City(ip); err == nil {
			record.Country = city.Country.Names["en"]
			record.CountryCode = strings.ToLower(city.Country.IsoCode)
		}
	}

	if GeoASNDB != nil {
		if asn, err := GeoASNDB.ASN(ip); err == nil {
			org := strings.TrimSpace(asn.AutonomousSystemOrganization)
			if org != "" {
				record.Org = org
				record.ISP = org
			}
		}
	}

	if record.Country != "" || record.ISP != "" {
		return
	}

	geoInfo := getGeoIPInfo(ip.String())
	if geoInfo != nil {
		record.Country = geoInfo.Country
		record.CountryCode = strings.ToLower(geoInfo.CountryCode)
		record.ISP = geoInfo.ISP
		record.Org = geoInfo.Org
	}
}

func EnrichIPInfoByString(record *models.DNSRecord, ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		enrichIPInfo(record, ip)
	}
}

type GeoIPInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
}

func getGeoIPInfo(ip string) *GeoIPInfo {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=country,countryCode,isp,org",
		ip,
	))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var info GeoIPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}
	return &info
}
