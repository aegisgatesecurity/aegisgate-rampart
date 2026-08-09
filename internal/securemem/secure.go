// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Secure Memory Handling
//
// Provides secure memory handling for sensitive data (passphrases, keys, secrets).
// Uses explicit zeroing and runtime.KeepAlive to prevent compiler optimizations.
//
// Limitations (Go GC):
// - Garbage collector may create copies we can't control
// - Stack-to-heap promotion may move data
// - This is best-effort protection, not cryptographic-grade security
//
// For higher security, consider:
// - OS-level protections (disable swap, core dumps, hibernation)
// - memguard library (mlock'd memory, but requires cgo)
// - Hardware enclaves (Intel SGX, AMD SEV)

package securemem

import (
	"runtime"
	"sync"
	"unsafe"
)

// SecureBuffer holds sensitive data that should be zeroed after use.
// Use NewSecureBuffer to create, and call Destroy() when done.
type SecureBuffer struct {
	data []byte
	mu   sync.Mutex
}

// NewSecureBuffer creates a new secure buffer of the given size.
// The buffer will be zeroed when Destroy() is called.
func NewSecureBuffer(size int) *SecureBuffer {
	return &SecureBuffer{
		data: make([]byte, size),
	}
}

// NewSecureBufferFrom creates a secure buffer from existing data.
// The original data is NOT zeroed - caller is responsible for that.
func NewSecureBufferFrom(data []byte) *SecureBuffer {
	buf := &SecureBuffer{
		data: make([]byte, len(data)),
	}
	copy(buf.data, data)
	return buf
}

// Bytes returns the underlying byte slice.
// Use this sparingly and avoid creating copies.
func (sb *SecureBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.data
}

// Len returns the length of the buffer.
func (sb *SecureBuffer) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return len(sb.data)
}

// Destroy zeros the buffer and marks it as destroyed.
// Call this explicitly when done with the sensitive data.
// After Destroy(), the buffer cannot be reused.
func (sb *SecureBuffer) Destroy() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	if sb.data != nil {
		// Explicitly zero the memory
		for i := range sb.data {
			sb.data[i] = 0
		}
		
		// Prevent compiler from optimizing away the zeroing
		runtime.KeepAlive(sb.data)
		
		// Clear the reference
		sb.data = nil
	}
}

// SecureString holds a sensitive string that should be zeroed after use.
// Convert to []byte for use, then destroy.
type SecureString struct {
	data []byte
	mu   sync.Mutex
}

// NewSecureString creates a secure string from a regular string.
func NewSecureString(s string) *SecureString {
	return &SecureString{
		data: []byte(s),
	}
}

// Bytes returns the underlying byte slice.
func (ss *SecureString) Bytes() []byte {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.data
}

// String returns the string value (creates a copy - use sparingly).
func (ss *SecureString) String() string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return string(ss.data)
}

// Destroy zeros the string and marks it as destroyed.
func (ss *SecureString) Destroy() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	
	if ss.data != nil {
		for i := range ss.data {
			ss.data[i] = 0
		}
		runtime.KeepAlive(ss.data)
		ss.data = nil
	}
}

// ZeroBytes explicitly zeros a byte slice.
// Use this for sensitive data that you need to clear immediately.
func ZeroBytes(data []byte) {
	if data == nil {
		return
	}
	
	for i := range data {
		data[i] = 0
	}
	
	// Prevent compiler optimization
	runtime.KeepAlive(data)
}

// ZeroString explicitly zeros a string by converting to []byte first.
// Note: This only zeros the converted copy, not the original string.
func ZeroString(s string) {
	if s == "" {
		return
	}
	
	data := []byte(s)
	ZeroBytes(data)
}

// Memset sets all bytes in a slice to a specific value.
// Useful for zeroing or filling with random data.
func Memset(data []byte, value byte) {
	if data == nil {
		return
	}
	
	for i := range data {
		data[i] = value
	}
	
	runtime.KeepAlive(data)
}

// SecurePassphrase is a specialized buffer for passphrases.
// Provides convenient methods for passphrase handling.
type SecurePassphrase struct {
	*SecureBuffer
}

// NewSecurePassphrase creates a secure passphrase buffer.
func NewSecurePassphrase(passphrase string) *SecurePassphrase {
	return &SecurePassphrase{
		SecureBuffer: NewSecureBufferFrom([]byte(passphrase)),
	}
}

// ToBytes returns the passphrase as bytes for use in key derivation.
func (sp *SecurePassphrase) ToBytes() []byte {
	return sp.Bytes()
}

// Use executes a function with the passphrase bytes, then zeros them.
// This is the safest pattern - passphrase never escapes this scope.
func (sp *SecurePassphrase) Use(fn func([]byte) error) error {
	sp.mu.Lock()
	data := make([]byte, len(sp.data))
	copy(data, sp.data)
	sp.mu.Unlock()
	
	defer func() {
		ZeroBytes(data)
	}()
	
	return fn(data)
}

// UnsafeBytes returns a pointer to the underlying data.
// Use with extreme caution - bypasses safety checks.
func (sb *SecureBuffer) UnsafeBytes() unsafe.Pointer {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if len(sb.data) == 0 {
		return nil
	}
	return unsafe.Pointer(&sb.data[0])
}
