package notify

import (
	"testing"
)

func TestNew(t *testing.T) {
	n := New("")
	if n == nil {
		t.Fatal("New returned nil")
	}
	if !n.IsEnabled() {
		t.Error("Notifications should be enabled by default")
	}
}

func TestNewWithIcon(t *testing.T) {
	n := New("/path/to/icon.png")
	if n == nil {
		t.Fatal("New returned nil")
	}
}

func TestEnableDisable(t *testing.T) {
	n := New("")
	n.Disable()
	if n.IsEnabled() {
		t.Error("Notifications should be disabled after Disable()")
	}
	n.Enable()
	if !n.IsEnabled() {
		t.Error("Notifications should be enabled after Enable()")
	}
}

func TestSendDisabled(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.Send(Notification{Title: "Test", Body: "Disabled test"})
	if err != nil {
		t.Errorf("Send when disabled should be no-op, got: %v", err)
	}
}

func TestSendDetectionDisabled(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.SendDetection("api.openai.com", 5, []string{"pii", "secret"})
	if err != nil {
		t.Errorf("SendDetection when disabled should be no-op, got: %v", err)
	}
}

func TestSendBlockedDisabled(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.SendBlocked("api.openai.com", "SSN detected")
	if err != nil {
		t.Errorf("SendBlocked when disabled should be no-op, got: %v", err)
	}
}

func TestSendStartupDisabled(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.SendStartup(8080, 27)
	if err != nil {
		t.Errorf("SendStartup when disabled should be no-op, got: %v", err)
	}
}

func TestNotificationStruct(t *testing.T) {
	notif := Notification{
		Title:   "Test Title",
		Body:    "Test Body",
		Icon:    "/path/to/icon.png",
		Actions: []string{"open", "dismiss"},
	}
	if notif.Title != "Test Title" {
		t.Errorf("Title = %s", notif.Title)
	}
	if len(notif.Actions) != 2 {
		t.Errorf("Actions = %d, want 2", len(notif.Actions))
	}
}
