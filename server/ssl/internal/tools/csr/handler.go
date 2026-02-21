package csr

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"tools.bctechvibe.io.vn/server/ssl/internal/platform/shared"
)

type Handler struct {
	svc *Service
}

type DecodeRequest struct {
	CSR string `json:"csr"`
}

func NewHandler() *Handler {
	return &Handler{
		svc: New(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Validate Method
	if r.Method != http.MethodPost {
		http.Error(w, "Phương thức HTTP không được hỗ trợ", http.StatusMethodNotAllowed)
		return
	}

	// 2. Body Size Limit (1MB)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	// 3. Content-Type Check
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "application/json") {
		shared.Error(w, "Content-Type không được hỗ trợ", http.StatusUnsupportedMediaType, "")
		return
	}

	// 4. Decode Request
	var req DecodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Cannot parse CSR request body: %v", err)
		shared.Error(w, "Dữ liệu request không hợp lệ", http.StatusBadRequest, "")
		return
	}

	if strings.TrimSpace(req.CSR) == "" {
		shared.Error(w, "Nội dung CSR không được để trống", http.StatusBadRequest, "")
		return
	}

	// 5. Call Service
	// Context from request (wrapped by timeout middleware usually, or we can add timeout here if needed)
	// Review noted that main router has timeout.
	resp, err := h.svc.Decode(r.Context(), req.CSR)
	if err != nil {
		log.Printf("CSR decode failed: %v", err)
		// Return specific error message to user if safe, or generic
		shared.Error(w, fmt.Sprintf("Không thể giải mã CSR: %v", err), http.StatusBadRequest, "")
		return
	}

	// 6. Response
	shared.JSON(w, resp)
}
