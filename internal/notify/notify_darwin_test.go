// SPDX-License-Identifier: Apache-2.0
//go:build darwin

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

func TestNotifyDarwin_Send(t *testing.T) {
	skipUnlessIntegration(t)
	n := New("")
	err := n.Send(Notification{Title: "Test", Body: "Darwin notification"})
	t.Logf("notifyDarwin: %v", err)
}

func TestNotifyDarwin_Escaping(t *testing.T) {
	skipUnlessIntegration(t)
	n := New("")
	err := n.notifyDarwin(Notification{
		Title: `Test "with" quotes`,
		Body:  `Line "one" and 'two'`,
	})
	t.Logf("notifyDarwin escaping: %v", err)
}

func TestNotifyDarwin_Disabled(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.Send(Notification{Title: "Test", Body: "Disabled"})
	if err != nil {
		t.Errorf("Send while disabled should be no-op, got: %v", err)
	}
}
