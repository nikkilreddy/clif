package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// Lightweight HTTP server that triggers tcpblaster benchmarks on the VM.
// Streams live progress to the client, then prints a clean final summary.

const apiKey = "clif-bench-2026"

var (
	running   bool
	runningMu sync.Mutex
)

func benchmarkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Use GET or POST", http.StatusMethodNotAllowed)
		return
	}

	// API key authentication
	if r.URL.Query().Get("key") != apiKey {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "unauthorized",
			"error":  "Missing or invalid API key. Use ?key=YOUR_KEY",
		})
		return
	}

	runningMu.Lock()
	if running {
		runningMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "busy",
			"error":  "A benchmark is already running. Try again later.",
		})
		return
	}
	running = true
	runningMu.Unlock()

	defer func() {
		runningMu.Lock()
		running = false
		runningMu.Unlock()
	}()

	// Parse optional query params
	workers := 16
	if wStr := r.URL.Query().Get("workers"); wStr != "" {
		if v, err := strconv.Atoi(wStr); err == nil && v > 0 && v <= 64 {
			workers = v
		}
	}

	payloadFile := "/opt/clif/real_2m_payload.ndjson"
	if f := r.URL.Query().Get("file"); f != "" {
		// Only allow files under /opt/clif/ to prevent path traversal
		if strings.HasPrefix(f, "/opt/clif/") && !strings.Contains(f, "..") {
			payloadFile = f
		}
	}

	blasterPath := "/opt/clif/tcpblaster"

	log.Printf("Starting benchmark: workers=%d file=%s\n", workers, payloadFile)

	cmd := exec.Command(blasterPath,
		"-host", "127.0.0.1",
		"-port", "9514",
		"-workers", strconv.Itoa(workers),
		"-file", payloadFile,
	)

	// Pipe stdout for live streaming
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "Failed to create pipe: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

	if err := cmd.Start(); err != nil {
		http.Error(w, "Failed to start: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Stream output line-by-line with chunked transfer
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintln(w, line)
		flusher.Flush()
	}

	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(w, "\nERROR: %s\n", err)
		flusher.Flush()
	}

	log.Println("Benchmark finished")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	port := 9515

	http.HandleFunc("/benchmark", benchmarkHandler)
	http.HandleFunc("/health", healthHandler)

	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  CLIF Benchmark Trigger Service")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  Listening on :%d\n", port)
	fmt.Println("  GET /benchmark?key=KEY        — Run 2M benchmark (live stream)")
	fmt.Println("  GET /benchmark?key=KEY&workers=8 — Custom worker count")
	fmt.Println("  GET /health                  — Health check")
	fmt.Println("══════════════════════════════════════════════════════════════")

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
