package server

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// To provide extended control custom server's used
type Server struct {
	httpServer *http.Server
}

func NewServer(addres string,
	handler http.Handler,
	readTimeout time.Duration,
	writeTimeout time.Duration) *Server {

	return &Server{
		httpServer: &http.Server{
			Addr:         addres,
			Handler:      handler,
			ReadTimeout:  readTimeout * time.Second,
			WriteTimeout: writeTimeout * time.Second,
		},
	}
}

func (s *Server) Close() error {
	return s.httpServer.Close()
}

func (s *Server) ShutDown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Run() {
	slog.Info("Server is running at", "address", s.httpServer.Addr)
	// if
	shutdownChan := make(chan bool, 1)

	go func() {
		if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP Server error: %v", err)
		}

		log.Println("Stopped serving new connection.")
		shutdownChan <- true
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), s.httpServer.ReadTimeout)
	defer shutdownRelease()

	if err := s.ShutDown(shutdownCtx); err != nil {
		log.Fatalf("HTTP server shutdown error: %v", err)
	}

	<-shutdownChan
	log.Println("Graceful shutdown complete.")
}
