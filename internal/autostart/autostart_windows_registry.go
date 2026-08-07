// SPDX-License-Identifier: Apache-2.0
//go:build windows

package autostart

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
)

// enableWindowsRegistry writes directly to the Windows Registry Run key.
// This provides seamless auto-start without requiring the user to import a .reg file.
func enableWindowsRegistry(binPath string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening registry Run key: %w", err)
	}
	defer k.Close()

	if err := k.SetStringValue("AegisGateRampart", binPath+" --daemon"); err != nil {
		return fmt.Errorf("writing registry value: %w", err)
	}
	return nil
}

// disableWindowsRegistry removes the entry from the Windows Registry Run key.
func disableWindowsRegistry() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening registry Run key: %w", err)
	}
	defer k.Close()

	if err := k.DeleteValue("AegisGateRampart"); err != nil {
		// Value doesn't exist is not an error
		return nil
	}
	return nil
}

// isEnabledWindowsRegistry checks if the entry exists in the Windows Registry Run key.
func isEnabledWindowsRegistry() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()

	_, _, err = k.GetStringValue("AegisGateRampart")
	return err == nil
}
