package telemetry

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

func TestNewAirGap(t *testing.T) {
	cfg := &config.Config{PlatformURL: ""}
	tel := New(cfg)
	if tel == nil {
		t.Fatal("New returned nil")
	}
}

func TestNewWithPlatformURL(t *testing.T) {
	cfg := &config.Config{PlatformURL: "https://platform.example.com"}
	tel := New(cfg)
	if tel == nil {
		t.Fatal("New returned nil")
	}
}

func TestSendAirGap(t *testing.T) {
	cfg := &config.Config{PlatformURL: ""}
	tel := New(cfg)
	err := tel.Send(map[string]interface{}{
		"event": "test",
		"count": 42,
	})
	if err != nil {
		t.Errorf("Air-gap Send should be no-op, got error: %v", err)
	}
}

func TestSendWithPlatform(t *testing.T) {
	cfg := &config.Config{PlatformURL: "https://platform.example.com"}
	tel := New(cfg)
	// Should not block or fail the main workflow — connection will fail
	err := tel.Send(map[string]interface{}{"event": "test"})
	_ = err
}

func TestSendNilEvent(t *testing.T) {
	cfg := &config.Config{PlatformURL: ""}
	tel := New(cfg)
	err := tel.Send(nil)
	if err != nil {
		t.Errorf("Air-gap Send(nil) should be no-op, got: %v", err)
	}
}

func TestSendLargeEvent(t *testing.T) {
	cfg := &config.Config{PlatformURL: ""}
	tel := New(cfg)
	largeEvent := make(map[string]interface{})
	for i := 0; i < 1000; i++ {
		largeEvent[string(rune(i%26+'a'))] = i
	}
	err := tel.Send(largeEvent)
	if err != nil {
		t.Errorf("Air-gap Send with large event should be no-op, got: %v", err)
	}
}
