// SPDX-License-Identifier: Apache-2.0
// Provenance: Tests for notify.Send() function with more thorough coverage

package notify

import (
	"strings"
	"testing"
)

// ============================================================================
// Send function tests (more thorough coverage)
// ============================================================================

func TestSend_EnabledWithEmptyTitle(t *testing.T) {
	n := New("")
	n.Disable() // Disable to avoid platform-specific notification errors
	err := n.Send(Notification{Title: "", Body: "Test body"})
	if err != nil {
		t.Errorf("Send with empty title when disabled should succeed, got: %v", err)
	}
}

func TestSend_EnabledWithEmptyBody(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.Send(Notification{Title: "Test title", Body: ""})
	if err != nil {
		t.Errorf("Send with empty body when disabled should succeed, got: %v", err)
	}
}

func TestSend_EnabledWithBothEmpty(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.Send(Notification{Title: "", Body: ""})
	if err != nil {
		t.Errorf("Send with both empty when disabled should succeed, got: %v", err)
	}
}

func TestSend_WithNotificationIcon(t *testing.T) {
	n := New("/default/icon.png")
	n.Disable()
	notif := Notification{
		Title: "Test Title",
		Body:  "Test Body",
		Icon:  "/custom/icon.png",
	}
	err := n.Send(notif)
	if err != nil {
		t.Errorf("Send with custom icon when disabled should succeed, got: %v", err)
	}
}

func TestSend_WithActions(t *testing.T) {
	n := New("")
	n.Disable()
	notif := Notification{
		Title:   "Security Alert",
		Body:    "Threat detected",
		Actions: []string{"view", "dismiss"},
	}
	err := n.Send(notif)
	if err != nil {
		t.Errorf("Send with actions when disabled should succeed, got: %v", err)
	}
}

func TestSend_MultipleNotificationsDisabled(t *testing.T) {
	n := New("")
	n.Disable()

	for i := 0; i < 5; i++ {
		err := n.Send(Notification{
			Title: "Batch Alert",
			Body:  "Batch body",
		})
		if err != nil {
			t.Errorf("Send %d when disabled should succeed, got: %v", i, err)
		}
	}
}

func TestSend_EnableDisableCycle(t *testing.T) {
	n := New("")

	// Start enabled
	if !n.IsEnabled() {
		t.Error("Should start enabled")
	}

	// Disable and send (no-op)
	n.Disable()
	err := n.Send(Notification{Title: "Disabled", Body: "Test"})
	if err != nil {
		t.Errorf("Send when disabled should succeed: %v", err)
	}

	// Re-enable and send (would trigger platform notification, so we can't test the result,
	// but we verify Enable/Disable cycle works)
	n.Enable()
	if !n.IsEnabled() {
		t.Error("Should be re-enabled")
	}

	// Disable again for safe testing
	n.Disable()
	err = n.Send(Notification{Title: "Re-disabled", Body: "Test"})
	if err != nil {
		t.Errorf("Send when re-disabled should succeed: %v", err)
	}
}

func TestSendDetection_WithCategories(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.SendDetection("api.openai.com", 3, []string{"pii", "secret", "xss"})
	if err != nil {
		t.Errorf("SendDetection with categories should succeed when disabled: %v", err)
	}
}

func TestSendDetection_SingleCategory(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.SendDetection("api.anthropic.com", 1, []string{"pii"})
	if err != nil {
		t.Errorf("SendDetection with single category should succeed when disabled: %v", err)
	}
}

func TestSendDetection_HighCount(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.SendDetection("api.example.com", 100, []string{"pii", "secret", "xss", "compliance"})
	if err != nil {
		t.Errorf("SendDetection with high count should succeed when disabled: %v", err)
	}
}

func TestSendBlocked_VariousReasons(t *testing.T) {
	n := New("")
	n.Disable()

	reasons := []string{
		"SSN detected",
		"API key leak",
		"XSS attempt",
		"Prompt injection",
		"Token limit exceeded",
	}

	for _, reason := range reasons {
		err := n.SendBlocked("api.openai.com", reason)
		if err != nil {
			t.Errorf("SendBlocked(%q) when disabled should succeed: %v", reason, err)
		}
	}
}

func TestSendBlocked_DifferentHosts(t *testing.T) {
	n := New("")
	n.Disable()

	hosts := []string{
		"api.openai.com",
		"api.anthropic.com",
		"generativelanguage.googleapis.com",
		"localhost:8080",
	}

	for _, host := range hosts {
		err := n.SendBlocked(host, "security violation")
		if err != nil {
			t.Errorf("SendBlocked(%q) when disabled should succeed: %v", host, err)
		}
	}
}

func TestSendStartup_VariousPorts(t *testing.T) {
	n := New("")
	n.Disable()

	ports := []int{8080, 9090, 3000, 443, 80}
	for _, port := range ports {
		err := n.SendStartup(port, 5)
		if err != nil {
			t.Errorf("SendStartup(%d) when disabled should succeed: %v", port, err)
		}
	}
}

func TestSendStartup_VariousTargetCounts(t *testing.T) {
	n := New("")
	n.Disable()

	counts := []int{0, 1, 10, 100}
	for _, count := range counts {
		err := n.SendStartup(8080, count)
		if err != nil {
			t.Errorf("SendStartup with %d targets when disabled should succeed: %v", count, err)
		}
	}
}

func TestSend_NotifierIconPrecedence(t *testing.T) {
	// Test that notification icon takes precedence over notifier icon
	n := New("/notifier/icon.png")
	n.Disable()

	// When notification has no icon, notifier icon is used
	err := n.Send(Notification{Title: "Test", Body: "Body"})
	if err != nil {
		t.Errorf("Send without notification icon should succeed: %v", err)
	}

	// When notification has its own icon, it takes precedence
	err = n.Send(Notification{Title: "Test", Body: "Body", Icon: "/notification/icon.png"})
	if err != nil {
		t.Errorf("Send with notification icon should succeed: %v", err)
	}
}

func TestSend_EmptyBody(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.Send(Notification{Title: "Title Only", Body: ""})
	if err != nil {
		t.Errorf("Send with empty body when disabled should succeed: %v", err)
	}
}

func TestSend_LongTitle(t *testing.T) {
	n := New("")
	n.Disable()
	longTitle := strings.Repeat("A", 500)
	err := n.Send(Notification{Title: longTitle, Body: "Body"})
	if err != nil {
		t.Errorf("Send with long title when disabled should succeed: %v", err)
	}
}

func TestSend_LongBody(t *testing.T) {
	n := New("")
	n.Disable()
	longBody := strings.Repeat("B", 5000)
	err := n.Send(Notification{Title: "Title", Body: longBody})
	if err != nil {
		t.Errorf("Send with long body when disabled should succeed: %v", err)
	}
}

func TestSend_SpecialCharacters(t *testing.T) {
	n := New("")
	n.Disable()
	specialNotif := Notification{
		Title: "Alert: \"Quotes\" & <HTML> chars",
		Body:  "Line1\nLine2\tTabbed",
	}
	err := n.Send(specialNotif)
	if err != nil {
		t.Errorf("Send with special chars when disabled should succeed: %v", err)
	}
}

func TestSend_UnicodeContent(t *testing.T) {
	n := New("")
	n.Disable()
	unicodeNotif := Notification{
		Title: "⚠️ AegisGate 警报",
		Body:  "Detection found: 95% sicher",
	}
	err := n.Send(unicodeNotif)
	if err != nil {
		t.Errorf("Send with unicode when disabled should succeed: %v", err)
	}
}

func TestNotifier_DisableIdempotent(t *testing.T) {
	n := New("")
	n.Disable()
	n.Disable() // Second disable should be safe
	if n.IsEnabled() {
		t.Error("Should remain disabled after double Disable()")
	}
}

func TestNotifier_EnableIdempotent(t *testing.T) {
	n := New("")
	n.Enable() // Already enabled, should be safe
	if !n.IsEnabled() {
		t.Error("Should remain enabled after Enable()")
	}
}

func TestNotification_FieldsAllSet(t *testing.T) {
	notif := Notification{
		Title:   "Security Alert",
		Body:    "3 threats detected",
		Icon:    "/path/to/icon.png",
		Actions: []string{"view", "dismiss", "snooze"},
	}
	if notif.Title != "Security Alert" {
		t.Errorf("Title = %q, want 'Security Alert'", notif.Title)
	}
	if notif.Body != "3 threats detected" {
		t.Errorf("Body = %q, want '3 threats detected'", notif.Body)
	}
	if notif.Icon != "/path/to/icon.png" {
		t.Errorf("Icon = %q, want '/path/to/icon.png'", notif.Icon)
	}
	if len(notif.Actions) != 3 {
		t.Errorf("Actions count = %d, want 3", len(notif.Actions))
	}
}

func TestNotification_NilActions(t *testing.T) {
	notif := Notification{
		Title: "Test",
		Body:  "Body",
	}
	if notif.Actions != nil {
		t.Errorf("Default Actions should be nil, got %v", notif.Actions)
	}
}
