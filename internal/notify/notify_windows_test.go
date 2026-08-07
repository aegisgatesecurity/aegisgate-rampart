// SPDX-License-Identifier: Apache-2.0
//go:build windows

package notify

import (
	"testing"
)

func TestNotifyWindows_Send(t *testing.T) {
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
