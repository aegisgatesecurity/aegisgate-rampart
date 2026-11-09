// SPDX-License-Identifier: Apache-2.0
// Test coverage for HashDomainForTest in pkg/metrics

package metrics

import "testing"

func TestHashDomainForTest(t *testing.T) {
	c := NewCollector(false, "")

	// Should return a hash for a domain
	h1 := c.HashDomainForTest("example.com")
	if h1 == "" {
		t.Error("HashDomainForTest returned empty string")
	}
	if h1 == "example.com" {
		t.Error("HashDomainForTest should hash, not return plaintext")
	}

	// Same domain should produce same hash
	h2 := c.HashDomainForTest("example.com")
	if h1 != h2 {
		t.Error("HashDomainForTest should be deterministic")
	}

	// Different domains should produce different hashes
	h3 := c.HashDomainForTest("other.com")
	if h1 == h3 {
		t.Error("HashDomainForTest should produce different hashes for different domains")
	}

	// Empty domain should not panic
	h4 := c.HashDomainForTest("")
	_ = h4 // just ensure no panic
}
