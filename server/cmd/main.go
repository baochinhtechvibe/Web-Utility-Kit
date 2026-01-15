// ============================================
// FILE: cmd/main.go
// Entry point của application
// ============================================
package main

import (
	"log"

	"tools.bctechvibe.io.vn/server/internal/handlers"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// CORS configuration
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept"}
	router.Use(cors.New(config))

	// Routes
	api := router.Group("/api")
	{
		api.POST("/dns/lookup", handlers.HandleDNSLookup)
		api.GET("/dns/blacklist-stream/:ip", handlers.HandleBlacklistStream)
	}

	log.Println("🚀 DNS Lookup Server started on :3101")
	router.Run(":3101")
}
