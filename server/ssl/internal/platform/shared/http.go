package shared

import (
	"encoding/json"
	"net/http"
)

func JSON(w http.ResponseWriter, data any) {

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func Error(w http.ResponseWriter, msg string, code int, hostname string) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	json.NewEncoder(w).Encode(map[string]any{
		"hostname": hostname,
		"error":    msg,
		"success":  false,
		"code":     code,
	})
}

func ErrorDecode(w http.ResponseWriter, msg string, code int) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	json.NewEncoder(w).Encode(map[string]any{
		"error":   msg,
		"success": false,
		"code":    code,
	})
}
