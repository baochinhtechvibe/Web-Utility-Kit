package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"tools.bctechvibe.io.vn/server/ssl/internal/platform/shared"
)

type Handler struct {
	svc *Service
}

type CheckRequest struct {
	Domain string `json:"domain"`
}

// var ErrNoIP = errors.New("no ip")

func NewHandler() *Handler {
	return &Handler{
		svc: New(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		log.Printf("[%s] %s %s - took %v", r.Method, r.RequestURI, r.RemoteAddr, duration)
	}()

	var domain string

	switch r.Method {
	case http.MethodGet:
		domain = r.URL.Query().Get("domain")
	case http.MethodPost:
		// protect from huge bodies
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
		defer r.Body.Close()

		// basic content-type check
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "application/json") {
			shared.Error(w, "Content-Type không được hỗ trợ", http.StatusUnsupportedMediaType, domain)
			return
		}

		var req CheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Không thể parse request body: %v", err)
			shared.Error(w, "Dữ liệu request không hợp lệ", http.StatusBadRequest, domain)
			return
		}
		domain = req.Domain
	default:
		http.Error(w, "Phương thức HTTP không được hỗ trợ", http.StatusMethodNotAllowed)
		return
	}

	// parse + validate domain (returns ASCII/punycode or error)
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	d, err := shared.ParseDomain(domain)
	if err != nil {
		log.Printf("Tên miền không hợp lệ: %s (%v)", domain, err)
		shared.Error(w, "Định dạng tên miền không hợp lệ", http.StatusBadRequest, domain)
		return
	}

	// set a request timeout and pass context to service (requires Service.Check(ctx, domain) refactor)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	res, err := h.svc.Check(ctx, d)
	if err != nil {
		// blocked by rate limiter / breaker
		if err == shared.ErrBlocked {
			log.Printf("Tên miền bị chặn: %s", d)
			shared.Error(w, err.Error(), http.StatusTooManyRequests, domain)
			return
		}
		// DNS resolution failure
		var dnsErr *net.DNSError

		if errors.As(err, &dnsErr) {

			log.Printf("DNS error for %s: %v", d, err)

			shared.Error(
				w,
				fmt.Sprintf(
					"Tên miền %s chưa phân giải được địa chỉ IP. Vui lòng kiểm tra bản ghi DNS (A/AAAA).",
					d,
				),
				http.StatusUnprocessableEntity,
				domain,
			)

			return
		}

		// generic failure
		log.Printf("Kiểm tra SSL thất bại cho %s: %v", d, err)
		shared.Error(w, fmt.Sprintf("Kiểm tra SSL thất bại cho %s: %v", d, err), http.StatusInternalServerError, domain)
		return
	}

	shared.JSON(w, res)
}
