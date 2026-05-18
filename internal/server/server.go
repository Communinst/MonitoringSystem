package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type Server struct {
	httpServer *http.Server
}

func NewServer(addr string,
	handler http.Handler,
	readTO time.Duration,
	writeTO time.Duration) *Server {

	return &Server{
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  readTO,
			WriteTimeout: writeTO,
		},
	}
}

func (s *Server) Close() error {
	return s.httpServer.Close()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
func (s *Server) Run() error {
	slog.Info("Server is starting", "address", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
