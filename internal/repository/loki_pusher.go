package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type LokiPusher struct {
	lokiURL  string
	nodeName string
	client   *http.Client
	batch    []lokiEntry
	mu       sync.Mutex
	stopMap  chan struct{}
}

type lokiEntry struct {
	ts   uint64
	line string
}

type LokiPayload struct {
	Streams []LokiStream `json:"streams"`
}

type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

func NewLokiPusher(lokiURL string, nodeName string) *LokiPusher {
	p := &LokiPusher{
		lokiURL:  lokiURL,
		nodeName: nodeName,
		client:   &http.Client{Timeout: 5 * time.Second},
		batch:    make([]lokiEntry, 0, 1000),
		stopMap:  make(chan struct{}),
	}
	return p
}

func (p *LokiPusher) Start(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.flush()
			return
		case <-p.stopMap:
			return
		case <-ticker.C:
			p.flush()
		}
	}
}

func (p *LokiPusher) Stop() {
	close(p.stopMap)
	p.flush()
}

func (p *LokiPusher) Add(tsNs uint64, line string) {
	p.mu.Lock()
	p.batch = append(p.batch, lokiEntry{ts: tsNs, line: line})
	needsFlush := len(p.batch) >= 1000
	p.mu.Unlock()

	if needsFlush {
		p.flush()
	}
}

func (p *LokiPusher) flush() {
	p.mu.Lock()
	if len(p.batch) == 0 {
		p.mu.Unlock()
		return
	}

	batchCopy := make([]lokiEntry, len(p.batch))
	copy(batchCopy, p.batch)
	p.batch = p.batch[:0]
	p.mu.Unlock()

	if p.lokiURL == "" {
		return
	}

	payload := LokiPayload{
		Streams: []LokiStream{
			{
				Stream: map[string]string{
					"job":  "dns-monitor",
					"node": p.nodeName,
				},
				Values: make([][]string, 0, len(batchCopy)),
			},
		},
	}

	for _, entry := range batchCopy {
		payload.Streams[0].Values = append(payload.Streams[0].Values, []string{
			fmt.Sprintf("%d", entry.ts),
			entry.line,
		})
	}

	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Failed to marshal Loki payload", "error", err)
		return
	}

	// Trim trailing slash from URL if present
	url := strings.TrimRight(p.lokiURL, "/")
	req, err := http.NewRequest("POST", url+"/loki/api/v1/push", bytes.NewBuffer(data))
	if err != nil {
		slog.Error("Failed to create Loki post request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// X-Scope-OrgID Is often required in multitenant mode, but breaks standard single-tenant
	// req.Header.Set("X-Scope-OrgID", "dns-monitor")

	resp, err := p.client.Do(req)
	if err != nil {
		slog.Error("Failed to send logs to Loki", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Error("Loki push rejected bad status", "status", resp.StatusCode)
	}
}
