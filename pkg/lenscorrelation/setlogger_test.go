// SPDX-License-Identifier: Apache-2.0
// Test coverage for SetLogger in pkg/lenscorrelation

package lenscorrelation

import (
	"log/slog"
	"testing"
)

func TestSetLogger(t *testing.T) {
	r := &SignalReceiver{
		windowDuration: 60,
	}
	logger := slog.Default()
	r.SetLogger(logger)
	if r.logger != logger {
		t.Error("SetLogger did not set the logger")
	}
}
