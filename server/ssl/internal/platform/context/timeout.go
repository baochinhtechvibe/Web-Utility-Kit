package contextutil

import (
	"context"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
)

func New() (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.Background(),
		config.ContextTimeout,
	)
}
