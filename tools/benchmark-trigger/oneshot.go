package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// tcpblaster-oneshot: send an entire NDJSON file as fast as possible
// Optimized for maximum throughput: large buffers, no counting on hot path,
// pre-split payload per worker, minimal syscalls.

func main() {
	host := flag.String("host", "127.0.0.1", "Target host")
	port := flag.Int("port", 9514, "Target port")
	workers := flag.Int("workers", 16, "Parallel TCP connections")
	payloadFile := flag.String("file", "/opt/clif/real_2m_payload.ndjson", "NDJSON file")
	chunkKB := flag.Int("chunk-kb", 512, "TCP write chunk size in KB")
	writeBufMB := flag.Int("wbuf-mb", 4, "Per-connection write buffer in MB")
	tcpBufMB := flag.Int("tcpbuf-mb", 16, "TCP SO_SNDBUF size in MB")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	chunkSize := *chunkKB * 1024

	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println("  CLIF TCP Blaster — Oneshot Maximum-Speed Mode")
	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Printf("  Target:      %s\n", addr)
	fmt.Printf("  Workers:     %d TCP connections\n", *workers)
	fmt.Printf("  Chunk:       %d KB\n", *chunkKB)
	fmt.Printf("  Write buf:   %d MB per conn\n", *writeBufMB)
	fmt.Printf("  TCP sndbuf:  %d MB per conn\n", *tcpBufMB)
	fmt.Println()

	// ── Load payload ─────────────────────────────────────────────────────
	fmt.Printf("Loading %s...\n", *payloadFile)
	t0 := time.Now()
	data, err := os.ReadFile(*payloadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	totalLines := bytes.Count(data, []byte("\n"))
	sizeMB := float64(len(data)) / (1024 * 1024)
	fmt.Printf("Loaded: %s events, %.1f MB in %v\n\n", fmtInt(int64(totalLines)), sizeMB, time.Since(t0).Round(time.Millisecond))

	// ── Split into per-worker byte slices (split on newline boundaries) ──
	chunks := splitOnNewlines(data, *workers)
	var chunkEvents []int
	for _, c := range chunks {
		chunkEvents = append(chunkEvents, bytes.Count(c, []byte("\n")))
	}

	// ── Blast ────────────────────────────────────────────────────────────
	fmt.Printf("Sending with %d workers...\n", *workers)
	var totalBytesSent int64
	var totalEventsSent int64
	var totalErrors int64
	var wg sync.WaitGroup

	start := time.Now()

	// Progress reporter
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				ev := atomic.LoadInt64(&totalEventsSent)
				bs := atomic.LoadInt64(&totalBytesSent)
				elapsed := time.Since(start).Seconds()
				if elapsed > 0.5 {
					pct := float64(ev) / float64(totalLines) * 100
					fmt.Printf("  [%5.1fs] %12s events  %6.0f%% | %s EPS  %.0f MB/s\n",
						elapsed, fmtInt(ev), pct,
						fmtInt(int64(float64(ev)/elapsed)),
						float64(bs)/(1024*1024)/elapsed)
				}
			}
		}
	}()

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(id int, payload []byte) {
			defer wg.Done()
			sendAll(id, addr, payload, chunkSize,
				*writeBufMB*1024*1024, *tcpBufMB*1024*1024,
				&totalBytesSent, &totalEventsSent, &totalErrors)
		}(i, chunks[i])
	}

	wg.Wait()
	elapsed := time.Since(start)
	close(done)

	// ── Results ──────────────────────────────────────────────────────────
	sent := atomic.LoadInt64(&totalEventsSent)
	sentBytes := atomic.LoadInt64(&totalBytesSent)
	errs := atomic.LoadInt64(&totalErrors)
	eps := float64(sent) / elapsed.Seconds()
	mbps := float64(sentBytes) / (1024 * 1024) / elapsed.Seconds()

	fmt.Printf("\n══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  SEND COMPLETE\n")
	fmt.Printf("══════════════════════════════════════════════════════════════\n")
	fmt.Printf("  Events:     %s / %s\n", fmtInt(sent), fmtInt(int64(totalLines)))
	fmt.Printf("  Bytes:      %.1f MB\n", float64(sentBytes)/(1024*1024))
	fmt.Printf("  Time:       %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  EPS:        %s\n", fmtInt(int64(eps)))
	fmt.Printf("  Throughput: %.1f MB/s\n", mbps)
	fmt.Printf("  Errors:     %d\n", errs)
	fmt.Printf("══════════════════════════════════════════════════════════════\n")
}

func sendAll(id int, addr string, payload []byte, chunkSize, writeBuf, tcpBuf int,
	totalBytes, totalEvents, totalErrors *int64) {

	if len(payload) == 0 {
		return
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		atomic.AddInt64(totalErrors, 1)
		fmt.Fprintf(os.Stderr, "  Worker %d: connect failed: %v\n", id, err)
		return
	}
	defer conn.Close()

	// Maximize kernel send buffer + disable Nagle
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(false) // Let Nagle coalesce small writes → fewer packets
		tc.SetWriteBuffer(tcpBuf)
	}

	w := bufio.NewWriterSize(conn, writeBuf)

	// Blast the entire payload in chunkSize writes, counting events per chunk
	offset := 0
	var sentBytes int64
	var sentEvents int64
	flushEvery := 4 * 1024 * 1024 // flush every 4MB
	unflushed := 0

	for offset < len(payload) {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[offset:end]
		_, err := w.Write(chunk)
		if err != nil {
			// Try reconnect once
			w.Flush()
			conn.Close()
			conn2, err2 := net.DialTimeout("tcp", addr, 5*time.Second)
			if err2 != nil {
				fmt.Fprintf(os.Stderr, "  Worker %d: reconnect failed: %v\n", id, err2)
				return
			}
			conn = conn2
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetNoDelay(false)
				tc.SetWriteBuffer(tcpBuf)
			}
			w = bufio.NewWriterSize(conn, writeBuf)
			_, err = w.Write(chunk)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Worker %d: write failed after reconnect: %v\n", id, err)
				return
			}
		}

		// Count events in this chunk and report incrementally
		evInChunk := bytes.Count(chunk, []byte("\n"))
		sentBytes += int64(len(chunk))
		sentEvents += int64(evInChunk)
		atomic.AddInt64(totalBytes, int64(len(chunk)))
		atomic.AddInt64(totalEvents, int64(evInChunk))

		unflushed += len(chunk)
		if unflushed >= flushEvery {
			if err := w.Flush(); err != nil {
				fmt.Fprintf(os.Stderr, "  Worker %d: flush error: %v\n", id, err)
				return
			}
			unflushed = 0
		}

		offset = end
	}

	err = w.Flush()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Worker %d: final flush error: %v\n", id, err)
		return
	}
}

func splitOnNewlines(data []byte, n int) [][]byte {
	// Fast split: find n-1 split points at newline boundaries
	total := len(data)
	result := make([][]byte, n)
	targetChunk := total / n

	start := 0
	for i := 0; i < n-1; i++ {
		// Find newline nearest to target boundary
		boundary := start + targetChunk
		if boundary >= total {
			boundary = total - 1
		}
		// Scan forward for newline
		idx := bytes.IndexByte(data[boundary:], '\n')
		if idx < 0 {
			result[i] = data[start:]
			start = total
			continue
		}
		end := boundary + idx + 1 // include the newline
		result[i] = data[start:end]
		start = end
	}
	result[n-1] = data[start:]
	return result
}

// loadPayload reads file into memory using io.ReadAll for large files
func loadPayload(path string) ([]byte, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}
	return data, bytes.Count(data, []byte("\n")), nil
}

func fmtInt(n int64) string {
	if n < 0 {
		return "-" + fmtInt(-n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
