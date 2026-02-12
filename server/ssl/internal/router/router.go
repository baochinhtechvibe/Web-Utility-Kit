package router

import (
	"net/http"
	"os"
	"strings"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
	"tools.bctechvibe.io.vn/server/ssl/internal/platform/middleware"
	"tools.bctechvibe.io.vn/server/ssl/internal/tools/checker"
)

/* ===============================
   CORS
================================*/

var allowedOrigins = []string{
	"http://127.0.0.1:5500",
	"https://tools.bctechvibe.io.vn",
}

func setCORS(w http.ResponseWriter, r *http.Request) {

	origin := r.Header.Get("Origin")

	for _, o := range allowedOrigins {

		if origin == o {

			w.Header().Set(
				"Access-Control-Allow-Origin",
				o,
			)
			break
		}
	}

	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
}

/* ===============================
   ROUTER
================================*/

type Router struct {
	limiter *middleware.RateLimiter
}

func Register() *Router {

	limiter := middleware.NewRateLimiter(
		config.RateLimitRequests,
		config.RateLimitWindow,
		config.MaxRateLimitBuckets,
		config.TrustProxy,
	)

	loadWhitelist(limiter)

	handler := &RateLimitHandler{
		limiter:     limiter,
		nextHandler: checker.NewHandler(),
	}

	http.Handle("/api/ssl/check", handler)

	return &Router{
		limiter: limiter,
	}
}

func (r *Router) Shutdown() {

	if r.limiter != nil {
		r.limiter.Stop()
	}
}

/* ===============================
   HANDLER
================================*/

type RateLimitHandler struct {
	limiter     *middleware.RateLimiter
	nextHandler http.Handler
}

func (h *RateLimitHandler) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {

	setCORS(w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	ip := h.limiter.GetClientIP(
		r.RemoteAddr,
		r.Header,
	)

	if !h.limiter.IsAllowed(ip) {

		http.Error(
			w,
			"Too many requests",
			http.StatusTooManyRequests,
		)
		return
	}

	h.nextHandler.ServeHTTP(w, r)
}

/* ===============================
   WHITELIST
================================*/

func loadWhitelist(rl *middleware.RateLimiter) {

	raw := os.Getenv("RATE_LIMIT_WHITELIST")

	if raw == "" {
		return
	}

	for ip := range strings.SplitSeq(raw, ",") {

		ip = strings.TrimSpace(ip)

		if ip != "" {
			rl.AddWhitelist(ip)
		}
	}
}
