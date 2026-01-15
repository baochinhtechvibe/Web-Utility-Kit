package dns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tools.bctechvibe.io.vn/server/internal/models"
)

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  uint32 `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func (r *DoHResolver) Query(domain string, qtype uint16) ([]models.DNSRecord, error) {
	var records []models.DNSRecord

	req, err := http.NewRequest("GET", r.Endpoint, nil)
	if err != nil {
		return records, err
	}

	q := req.URL.Query()
	q.Set("name", domain)
	q.Set("type", fmt.Sprintf("%d", qtype))
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/dns-json")

	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return records, err
	}
	defer resp.Body.Close()

	var result dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return records, err
	}

	if result.Status != 0 {
		return records, nil
	}

	for _, ans := range result.Answer {
		rec := models.DNSRecord{
			Domain: domain,
			TTL:    ans.TTL,
		}

		switch ans.Type {
		case 1:
			rec.Type = "A"
			rec.Address = ans.Data
		case 28:
			rec.Type = "AAAA"
			rec.Address = ans.Data
		case 5:
			rec.Type = "CNAME"
			rec.Value = strings.TrimSuffix(ans.Data, ".")
		case 2:
			rec.Type = "NS"
			rec.Nameserver = strings.TrimSuffix(ans.Data, ".")
		case 12:
			rec.Type = "PTR"
			rec.Value = strings.TrimSuffix(ans.Data, ".")
		case 16:
			rec.Type = "TXT"
			rec.Value = strings.Trim(ans.Data, "\"")
		case 15:
			rec.Type = "MX"
			parts := strings.SplitN(ans.Data, " ", 2)
			if len(parts) == 2 {
				p, _ := strconv.Atoi(parts[0])
				rec.Priority = uint16(p)
				rec.Exchange = strings.TrimSuffix(parts[1], ".")
			}
		default:
			continue
		}

		records = append(records, rec)
	}

	return records, nil
}
