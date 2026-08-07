// SPDX-License-Identifier: Apache-2.0
//go:build windows

package notify

import (
	"os"
	"testing"
)

func skipUnlessIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("RAMPART_INTEGRATION") != "1" {
		t.Skip("Skipping integration test (set RAMPART_INTEGRATION=1 to run desktop notifications)")
	}
}

func TestNotifyWindows_Send(t *testing.T) {
	skipUnlessIntegration(t)
	n := New("")
	err := n.Send(Notification{Title: "Test", Body: "Windows notification"})
	t.Logf("notifyWindows: %v", err)
}

func TestNotifyWindows_Disabled(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.Send(Notification{Title: "Test", Body: "Disabled"})
	if err != nil {
		t.Errorf("Send while disabled should be no-op, got: %v", err)
	}
}
