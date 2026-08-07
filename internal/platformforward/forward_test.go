// SPDX-License-Identifier: Apache-2.0

package platformforward

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
)

func TestNew_Disabled(t *testing.T) {
	f := New("")
	if f.Enabled() {
		t.Error("expected forwarding to be disabled with empty URL")
	}
}

func TestNew_Enabled(t *testing.T) {
	f := New("http://localhost:9090/api/v1/events")
	if !f.Enabled() {
		t.Error("expected forwarding to be enabled with non-empty URL")
	}
}

func TestForward_Disabled_NoCall(t *testing.T) {
	f := New("")
	entry := auditlog.Entry{
		Direction: "request",
		Host:      "api.openai.com",
		TotalDets: 1,
	}
	f.Forward(entry)
	// No panic, no network call — just returns
}

func TestForward_Enabled_SendsEvent(t *testing.T) {
	var mu sync.Mutex
	var received PlatformEvent
	done := make(chan struct{}, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		if err := json.Unmarshal(body, &received); err != nil {
			mu.Unlock()
			t.Errorf("failed to unmarshal: %v", err)
			return
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		done <- struct{}{}
	}))
	defer server.Close()

	f := New(server.URL)
	fixedTime := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	f.nowFunc = func() time.Time { return fixedTime }

	entry := auditlog.Entry{
		Timestamp:     fixedTime,
		Direction:     "request",
		Host:          "api.openai.com",
		Path:          "/v1/chat/completions",
		TotalDets:     5,
		Blocked:       false,
		PIICategories: []string{"ssn"},
		SecretTypes:   []string{"AWS:aws_key"},
		MLScore:       0.92,
		Categories:    []string{"pii", "secret"},
		Severities:    []string{"critical", "high"},
		Rules:         []string{"pii_ssn", "secret_aws_key"},
	}

	f.Forward(entry)

	// Wait for async send
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for platform forward")
	}

	mu.Lock()
	defer mu.Unlock()

	if received.Source != "rampart" {
		t.Errorf("expected source 'rampart', got %s", received.Source)
	}
	if received.Host != "api.openai.com" {
		t.Errorf("expected host 'api.openai.com', got %s", received.Host)
	}
	if received.TotalDets != 5 {
		t.Errorf("expected 5 detections, got %d", received.TotalDets)
	}
	if received.Direction != "request" {
		t.Errorf("expected direction 'request', got %s", received.Direction)
	}
	if len(received.PIICategories) != 1 || received.PIICategories[0] != "ssn" {
		t.Errorf("expected pii_categories [ssn], got %v", received.PIICategories)
	}
}

func TestForward_NoSensitiveData(t *testing.T) {
	var mu sync.Mutex
	var bodyBytes []byte
	done := make(chan struct{}, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bodyBytes, _ = io.ReadAll(r.Body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		done <- struct{}{}
	}))
	defer server.Close()

	f := New(server.URL)

	entry := auditlog.Entry{
		Direction:  "request",
		Host:       "api.openai.com",
		TotalDets:  3,
		Categories: []string{"pii", "secret"},
		Rules:      []string{"pii_ssn", "secret_aws_key"},
	}

	f.Forward(entry)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for platform forward")
	}

	mu.Lock()
	body := string(bodyBytes)
	mu.Unlock()

	// SECURITY: verify no raw PII or secret values in forwarded payload
	sensitive := []string{"263-78-1234", "AKIAIOSFODNN7EXAMPLE", "password", "prompt", "body"}
	for _, s := range sensitive {
		if strings.Contains(body, s) {
			t.Errorf("SECURITY: forwarded payload contains sensitive text: %s", s)
		}
	}
}

func TestForward_ServerError_LogsOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	f := New(server.URL)

	entry := auditlog.Entry{
		Direction: "request",
		Host:      "api.openai.com",
		TotalDets: 1,
	}

	// Should not panic, just log
	f.Forward(entry)
	time.Sleep(200 * time.Millisecond)
}

func TestForward_ConnectionRefused(t *testing.T) {
	// Point to a port that's not listening
	f := New("http://localhost:59999/api/v1/events")

	entry := auditlog.Entry{
		Direction: "request",
		Host:      "api.openai.com",
		TotalDets: 1,
	}

	// Should not panic, just log
	f.Forward(entry)
	time.Sleep(200 * time.Millisecond)
}

func TestString(t *testing.T) {
	disabled := New("")
	if !strings.Contains(disabled.String(), "disabled") {
		t.Errorf("expected disabled string, got %s", disabled.String())
	}

	enabled := New("http://localhost:9090/api/v1/events")
	if !strings.Contains(enabled.String(), "localhost") {
		t.Errorf("expected URL in string, got %s", enabled.String())
	}
}
