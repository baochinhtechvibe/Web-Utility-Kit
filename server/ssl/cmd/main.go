package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tools.bctechvibe.io.vn/server/ssl/internal/config"
	"tools.bctechvibe.io.vn/server/ssl/internal/router"
)

func main() {
	// Setup logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("Starting SSL Checker on %s", config.ServerPort)

	// Register routes and get router for cleanup
	r := router.Register()

	// Setup HTTP server
	server := &http.Server{
		Addr:           config.ServerPort,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Channel for shutdown errors
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Printf("SSL Checker listening on %s", config.ServerPort)
		serverErrors <- server.ListenAndServe()
	}()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	case sig := <-sigChan:
		log.Printf("Received signal: %v, shutting down gracefully...", sig)

		// Cleanup resources
		r.Shutdown()

		// Graceful shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error during shutdown: %v", err)
			os.Exit(1)
		}

		log.Println("Server shutdown successfully")
	}
}
