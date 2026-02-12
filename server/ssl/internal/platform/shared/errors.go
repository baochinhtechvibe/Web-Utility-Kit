package shared

import "errors"

var (
	ErrBlocked = errors.New("Tên miền đã bị tạm thời giới hạn do gửi quá nhiều yêu cầu trong thời gian ngắn. Vui lòng thử lại sau 15 phút.")
	ErrTimeout = errors.New("Yêu cầu bị timeout do quá thời gian chờ phản hồi.")
)
