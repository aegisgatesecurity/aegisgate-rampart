// SPDX-License-Identifier: Apache-2.0
//go:build darwin

package notify

import (
	"testing"
)

func TestNotifyDarwin_Send(t *testing.T) {
	n := New("")
	err := n.Send(Notification{Title: "Test", Body: "Darwin notification"})
	t.Logf("notifyDarwin: %v", err)
}

func TestNotifyDarwin_Escaping(t *testing.T) {
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
