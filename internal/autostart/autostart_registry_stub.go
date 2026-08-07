// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package autostart

// enableWindowsRegistry is a no-op stub on non-Windows platforms.
func enableWindowsRegistry(binPath string) error {
	return nil
}

// disableWindowsRegistry is a no-op stub on non-Windows platforms.
func disableWindowsRegistry() error {
	return nil
}

// isEnabledWindowsRegistry returns false on non-Windows platforms.
func isEnabledWindowsRegistry() bool {
	return false
}
