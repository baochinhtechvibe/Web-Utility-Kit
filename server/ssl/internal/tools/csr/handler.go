package csr

import (
	"encoding/json"
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

func NewHandler(svc *Service) *Handler {
	return &Handler{
		svc: svc,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Validate Method
	if r.Method != http.MethodPost {
		shared.ErrorDecode(w, "Phương thức HTTP không được hỗ trợ", http.StatusMethodNotAllowed)
		return
	}

	// 2. Body Size Limit (1MB)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	// 3. Content-Type Check
	ct := r.Header.Get("Content-Type")
	if ct != "" {
		if !strings.HasPrefix(ct, "application/json") {
			shared.ErrorDecode(w, "Content-Type không được hỗ trợ", http.StatusUnsupportedMediaType)
			return
		}
	}

	// 4. Decode Request
	var req DecodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Cannot parse CSR request body: %v", err)
		shared.ErrorDecode(w, "Dữ liệu request không hợp lệ", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.CSR) == "" {
		shared.ErrorDecode(w, "Nội dung CSR không được để trống", http.StatusBadRequest)
		return
	}

	// Cho phép cả BEGIN CERTIFICATE REQUEST và BEGIN NEW CERTIFICATE REQUEST
	if !strings.Contains(req.CSR, "BEGIN CERTIFICATE REQUEST") {
		shared.ErrorDecode(w, `Định dạng csr không hợp lệ, csr cần bắt đầu bằng -----BEGIN CERTIFICATE REQUEST----- hoặc -----BEGIN NEW CERTIFICATE REQUEST----- và kết thúc bằng thẻ tương ứng, bạn có thể tìm hiểu thêm csr <a href="https://www.sectigo.com/blog/what-is-a-certificate-signing-request-csr" target="_blank" rel="noopener noreferrer">tại đây</a>`, http.StatusBadRequest)
		return
	}

	// 5. Call Service
	// Context from request (wrapped by timeout middleware usually, or we can add timeout here if needed)
	// Review noted that main router has timeout.
	resp, err := h.svc.Decode(r.Context(), req.CSR)
	if err != nil {
		log.Printf("CSR decode failed: %v", err)
		// Trả về thông báo lỗi thân thiện thay vì leak internal error
		shared.ErrorDecode(w, "CSR không hợp lệ hoặc bị lỗi định dạng", http.StatusBadRequest)
		return
	}

	// 6. Response
	shared.JSON(w, resp)
}
