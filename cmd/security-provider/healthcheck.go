package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// runHealthcheck probes the readiness endpoint for Docker HEALTHCHECK and
// Kubernetes-style supervision. It exits 0 on ready, 1 otherwise, and
// prints nothing on success.
func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	addr := fs.String("addr", "", "override healthcheck address (host:port)")
	_ = fs.Parse(args)
	host := os.Getenv("SECURITY_PROVIDER_HTTP_ADDR")
	if *addr != "" {
		host = *addr
	}
	if host == "" {
		host = ":8080"
	}
	if len(host) > 0 && host[0] == ':' {
		host = "127.0.0.1" + host
	}
	url := fmt.Sprintf("http://%s/health/ready", host)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
