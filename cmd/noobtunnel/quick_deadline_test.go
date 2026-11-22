package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQuickCleanupAfterOrphanPrompt(t *testing.T) {
	for _, failure := range []error{nil, errors.New("existing agent preserved; Quick setup cancelled")} {
		original, cancel := context.WithCancel(context.Background())
		ctx := original
		result := failure
		func() {
			defer func() { finishQuickSetup(ctx, cancel, &result) }()
			// The prompt pauses the work deadline by replacing its context.
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		}()
		if result != failure {
			t.Fatalf("cleanup changed result %v to %v", failure, result)
		}
		if original.Err() != context.Canceled || ctx.Err() != context.Canceled {
			t.Fatal("both contexts must be released")
		}
	}
}

func TestQuickCleanupReportsOnlyFailedDeadline(t *testing.T) {
	for _, success := range []bool{false, true} {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		var result error
		if !success {
			result = errors.New("could not reach the control node")
		}
		finishQuickSetup(ctx, cancel, &result)
		if success && result != nil {
			t.Fatalf("completed setup became a failure: %v", result)
		}
		if !success && (result == nil || !strings.Contains(result.Error(), "deadline expired")) {
			t.Fatalf("missing deadline error: %v", result)
		}
	}
}

func TestQuickRequestsUseSharedDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	client := quickClient{ctx: ctx, endpoint: server.URL, ticket: "fixture", http: server.Client()}
	started := time.Now()
	if err := client.request("discover", map[string]any{}, &struct{}{}); err == nil {
		t.Fatal("request ignored deadline")
	}
	if time.Since(started) > time.Second {
		t.Fatal("request outlived shared deadline")
	}
}

func TestQuickExpiredDeadlineStopsBeforeDiscovery(t *testing.T) {
	started := time.Now()
	err := runQuick([]string{"--server", "127.0.0.1:1", "--pin", base64.StdEncoding.EncodeToString(make([]byte, 32)), "--ticket", "fixture", "--deadline", fmt.Sprint(time.Now().Add(-time.Second).Unix())})
	if err == nil || !strings.Contains(err.Error(), "deadline expired") {
		t.Fatalf("expired setup result: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("expired setup continued discovery")
	}
}
