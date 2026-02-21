package checker

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Probe definitions
type probeDef struct {
	client *http.Client
	url    string
	method string
}

// Probe result structure
type Probe struct {
	URL      string
	Method   string
	Response *http.Response
	Error    error
}

func collectProbes(ctx context.Context, domain string, ip string) []*Probe {
	// Create custom dialer enforcing the resolved IP
	dialer := &net.Dialer{Timeout: 5 * time.Second} // Use HTTPHeadTimeout roughly

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && host == domain {
			addr = net.JoinHostPort(ip, port)
		}
		return dialer.DialContext(ctx, network, addr)
	}

	// Clone DefaultTransport to preserve HTTP/2, keep-alive, and TLS settings
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.DialContext = dialContext
	baseTransport.ForceAttemptHTTP2 = false
	baseTransport.DisableKeepAlives = true

	strictTransport := baseTransport.Clone()

	insecureTransport := baseTransport.Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	plainTransport := baseTransport.Clone()

	// 5 seconds timeout from config.HTTPHeadTimeout
	timeout := 5 * time.Second

	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	strictClient := &http.Client{Timeout: timeout, Transport: strictTransport, CheckRedirect: noRedirect}
	insecureClient := &http.Client{Timeout: timeout, Transport: insecureTransport, CheckRedirect: noRedirect}
	plainClient := &http.Client{Timeout: timeout, Transport: plainTransport, CheckRedirect: noRedirect}

	defs := []probeDef{
		// Prefer HTTPS GET first as it yields the most complete headers
		{strictClient, "https://" + domain, http.MethodGet},
		{insecureClient, "https://" + domain, http.MethodGet},
		{strictClient, "https://" + domain, http.MethodHead},

		// Fallbacks
		{plainClient, "http://" + domain, http.MethodGet},
	}

	var validProbes []*Probe

	// Sequential execution. Stop as soon as we get a successful HTTP response.
	// This prevents Anti-DDoS / SYN-Flood WAFs from tarpitting us.
	for _, d := range defs {
		resp, err := doRequest(ctx, d.client, d.url, d.method)

		p := &Probe{
			URL:      d.url,
			Method:   d.method,
			Response: resp,
			Error:    err,
		}
		validProbes = append(validProbes, p)

		if err == nil && resp != nil {
			// If we got a valid response, no need to hammer the server anymore!
			break
		}
	}

	return validProbes
}
