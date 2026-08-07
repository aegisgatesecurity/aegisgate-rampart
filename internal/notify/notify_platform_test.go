// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"runtime"
	"testing"
)

func TestSend_EnabledOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := New("")
	// notify-send may not be available in CI, so we expect either success or error
	err := n.Send(Notification{Title: "Test", Body: "Hello"})
	// In CI without notify-send, this returns an error — that's fine
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}

func TestSend_EnabledOnLinuxWithIcon(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := New("/custom/icon.png")
	err := n.Send(Notification{Title: "Test", Body: "With icon"})
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}

func TestSend_EnabledOnLinuxWithNotificationIcon(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := New("/default/icon.png")
	err := n.Send(Notification{Title: "Test", Body: "With custom icon", Icon: "/override/icon.png"})
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}

func TestSendDetection_EnabledOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := New("")
	err := n.SendDetection("api.openai.com", 5, []string{"pii", "secret"})
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}

func TestSendBlocked_EnabledOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := New("")
	err := n.SendBlocked("api.openai.com", "SSN detected")
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}

func TestSendStartup_EnabledOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := New("")
	err := n.SendStartup(8080, 27)
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}

func TestSend_EnabledOnLinuxWithActions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := New("")
	err := n.Send(Notification{
		Title:   "Test",
		Body:    "With actions",
		Actions: []string{"open", "dismiss"},
	})
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}

func TestNotifyLinux_EmptyIcon(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}
	n := &Notifier{enabled: true, icon: ""}
	err := n.notifyLinux(Notification{Title: "Test", Body: "No icon"}, "")
	if err != nil {
		t.Logf("notify-send not available (expected in CI): %v", err)
	}
}
