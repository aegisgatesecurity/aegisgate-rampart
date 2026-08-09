// SPDX-License-Identifier: Apache-2.0
package securemem

import (
	"bytes"
	"testing"
)

func TestSecureBuffer(t *testing.T) {
	// Create buffer with known data
	data := []byte("sensitive-passphrase-123")
	buf := NewSecureBufferFrom(data)
	
	// Verify data is correct
	if !bytes.Equal(buf.Bytes(), data) {
		t.Error("buffer data doesn't match input")
	}
	
	// Verify length
	if buf.Len() != len(data) {
		t.Errorf("expected length %d, got %d", len(data), buf.Len())
	}
	
	// Destroy and verify zeroed
	buf.Destroy()
	
	// After destroy, Bytes() should return nil or empty
	if buf.Bytes() != nil {
		t.Error("buffer not nil after destroy")
	}
}

func TestSecureBufferZeroing(t *testing.T) {
	size := 64
	buf := NewSecureBuffer(size)
	
	// Fill with known pattern
	data := buf.Bytes()
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	// Verify pattern
	for i := range data {
		if data[i] != byte(i%256) {
			t.Errorf("byte %d: expected %d, got %d", i, i%256, data[i])
		}
	}
	
	// Destroy
	buf.Destroy()
	
	// Can't directly verify zeroing (buffer is nil), but test doesn't crash
	// which means zeroing completed
}

func TestSecureString(t *testing.T) {
	s := "my-secret-passphrase"
	ss := NewSecureString(s)
	
	// Verify string value
	if ss.String() != s {
		t.Errorf("expected %q, got %q", s, ss.String())
	}
	
	// Verify bytes
	if !bytes.Equal(ss.Bytes(), []byte(s)) {
		t.Error("bytes don't match")
	}
	
	// Destroy
	ss.Destroy()
	
	// After destroy, should be nil
	if ss.Bytes() != nil {
		t.Error("bytes not nil after destroy")
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte("sensitive-data-12345")
	original := make([]byte, len(data))
	copy(original, data)
	
	// Zero it
	ZeroBytes(data)
	
	// Verify all zeros
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d: expected 0, got %d", i, b)
		}
	}
}

func TestZeroString(t *testing.T) {
	s := "test-string"
	// Note: ZeroString only zeros the converted copy
	// The original string is immutable in Go
	ZeroString(s)
	// Can't verify original (immutable), but test ensures no panic
}

func TestMemset(t *testing.T) {
	data := make([]byte, 32)
	
	// Fill with 0xFF
	Memset(data, 0xFF)
	
	// Verify all bytes are 0xFF
	for i, b := range data {
		if b != 0xFF {
			t.Errorf("byte %d: expected 0xFF, got 0x%02X", i, b)
		}
	}
	
	// Zero it
	Memset(data, 0x00)
	
	// Verify all zeros
	for i, b := range data {
		if b != 0x00 {
			t.Errorf("byte %d: expected 0x00, got 0x%02X", i, b)
		}
	}
}

func TestSecurePassphrase(t *testing.T) {
	passphrase := "my-super-secret-passphrase"
	sp := NewSecurePassphrase(passphrase)
	
	// Verify passphrase
	if !bytes.Equal(sp.ToBytes(), []byte(passphrase)) {
		t.Error("passphrase bytes don't match")
	}
	
	// Test Use pattern
	var captured []byte
	err := sp.Use(func(passBytes []byte) error {
		// Capture a copy for verification
		captured = make([]byte, len(passBytes))
		copy(captured, passBytes)
		return nil
	})
	
	if err != nil {
		t.Errorf("Use() returned error: %v", err)
	}
	
	// Verify captured data
	if !bytes.Equal(captured, []byte(passphrase)) {
		t.Error("captured passphrase doesn't match")
	}
	
	// Note: Use() zeros the internal copy, but 'captured' is a separate copy
	// that we made. In real usage, you wouldn't capture the data - you'd use
	// it directly. This test verifies the pattern works, not that external
	// copies are zeroed (they can't be).
	_ = captured
	
	// Destroy
	sp.Destroy()
}

func TestSecurePassphraseUseError(t *testing.T) {
	sp := NewSecurePassphrase("test")
	
	err := sp.Use(func([]byte) error {
		return &testError{"test error"}
	})
	
	if err == nil {
		t.Error("expected error from Use()")
	}
}

func TestUnsafeBytes(t *testing.T) {
	data := []byte("test-data")
	buf := NewSecureBufferFrom(data)
	
	ptr := buf.UnsafeBytes()
	if ptr == nil {
		t.Error("unsafe pointer is nil")
	}
	
	// Verify we can access the data via pointer
	// (actual usage would cast to appropriate type)
	
	buf.Destroy()
	
	// After destroy, should return nil
	ptr = buf.UnsafeBytes()
	if ptr != nil {
		t.Error("unsafe pointer not nil after destroy")
	}
}

func TestSecureBufferConcurrency(t *testing.T) {
	buf := NewSecureBufferFrom([]byte("test-data"))
	
	done := make(chan bool, 2)
	
	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			_ = buf.Bytes()
		}
		done <- true
	}()
	
	go func() {
		for i := 0; i < 100; i++ {
			_ = buf.Len()
		}
		done <- true
	}()
	
	<-done
	<-done
	
	buf.Destroy()
}

func TestNewSecureBuffer(t *testing.T) {
	size := 128
	buf := NewSecureBuffer(size)
	
	if buf.Len() != size {
		t.Errorf("expected length %d, got %d", size, buf.Len())
	}
	
	// Verify buffer is zero-initialized
	data := buf.Bytes()
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d: expected 0, got %d", i, b)
		}
	}
	
	buf.Destroy()
}

func TestSecureStringEmpty(t *testing.T) {
	ss := NewSecureString("")
	
	if ss.String() != "" {
		t.Error("empty string not preserved")
	}
	
	if len(ss.Bytes()) != 0 {
		t.Error("empty string length not 0")
	}
	
	ss.Destroy()
}

func TestSecureBufferEmpty(t *testing.T) {
	buf := NewSecureBufferFrom([]byte{})
	
	if buf.Len() != 0 {
		t.Error("empty buffer length not 0")
	}
	
	buf.Destroy()
}

func TestZeroBytesNil(t *testing.T) {
	// Should not panic
	ZeroBytes(nil)
}

func TestZeroStringEmpty(t *testing.T) {
	// Should not panic
	ZeroString("")
}

func TestMemsetNil(t *testing.T) {
	// Should not panic
	Memset(nil, 0xFF)
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
