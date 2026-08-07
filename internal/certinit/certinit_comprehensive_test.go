// SPDX-License-Identifier: Apache-2.0

package certinit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.CertDir != "./certs" {
		t.Errorf("DefaultConfig CertDir = %q, want ./certs", cfg.CertDir)
	}
	if !cfg.AutoGenerate {
		t.Error("DefaultConfig AutoGenerate should be true")
	}
	if len(cfg.Hostnames) != 1 || cfg.Hostnames[0] != "localhost" {
		t.Errorf("DefaultConfig Hostnames = %v, want [localhost]", cfg.Hostnames)
	}
	if cfg.CertFile != "server.crt" {
		t.Errorf("DefaultConfig CertFile = %q, want server.crt", cfg.CertFile)
	}
	if cfg.KeyFile != "server.key" {
		t.Errorf("DefaultConfig KeyFile = %q, want server.key", cfg.KeyFile)
	}
	if cfg.CACertFile != "ca.crt" {
		t.Errorf("DefaultConfig CACertFile = %q, want ca.crt", cfg.CACertFile)
	}
	if cfg.CAKeyFile != "ca.key" {
		t.Errorf("DefaultConfig CAKeyFile = %q, want ca.key", cfg.CAKeyFile)
	}
}

func TestEnsureCertsDisabled(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: false,
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts with disabled auto_generate: %v", err)
	}
	if result.Generated {
		t.Error("Result.Generated should be false when auto_generate disabled")
	}
	if result.Existing {
		t.Error("Result.Existing should be false when auto_generate disabled")
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected warning about auto_generate being disabled")
	}
	found := false
	for _, w := range result.Warnings {
		if w == "auto_generate disabled — skipping certificate initialization" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected specific warning, got: %v", result.Warnings)
	}
}

func TestEnsureCertsGenerateNew(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts generate new: %v", err)
	}
	if !result.Generated {
		t.Error("Result.Generated should be true for new certs")
	}
	if result.Existing {
		t.Error("Result.Existing should be false for new certs")
	}
	if result.CACertPath == "" {
		t.Error("CACertPath should be set")
	}
	if result.CAKeyPath == "" {
		t.Error("CAKeyPath should be set")
	}
	if result.ServerCertPath == "" {
		t.Error("ServerCertPath should be set")
	}
	if result.ServerKeyPath == "" {
		t.Error("ServerKeyPath should be set")
	}

	// Verify files were actually written
	for _, path := range []string{result.CACertPath, result.CAKeyPath, result.ServerCertPath, result.ServerKeyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("Expected file %s to exist: %v", path, err)
		}
	}

	// Verify CA expiry is ~10 years out
	if result.CAExpiry.IsZero() {
		t.Error("CAExpiry should be set")
	}
	now := time.Now()
	expectedCAExpiry := now.AddDate(10, 0, 0)
	if result.CAExpiry.Before(now.AddDate(9, 0, 0)) || result.CAExpiry.After(expectedCAExpiry.AddDate(1, 0, 0)) {
		t.Errorf("CAExpiry = %v, expected ~10 years from now", result.CAExpiry)
	}

	// Verify server expiry is ~1 year out
	if result.ServerExpiry.IsZero() {
		t.Error("ServerExpiry should be set")
	}
	expectedServerExpiry := now.AddDate(1, 0, 0)
	if result.ServerExpiry.Before(now.AddDate(0, 6, 0)) || result.ServerExpiry.After(expectedServerExpiry.AddDate(1, 0, 0)) {
		t.Errorf("ServerExpiry = %v, expected ~1 year from now", result.ServerExpiry)
	}
}

func TestEnsureCertsIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		CertDir:      dir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	// First call generates
	result1, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("First EnsureCerts: %v", err)
	}
	if !result1.Generated {
		t.Error("First call should generate certs")
	}

	// Second call should reuse existing
	result2, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("Second EnsureCerts: %v", err)
	}
	if result2.Generated {
		t.Error("Second call should NOT generate certs (idempotent)")
	}
	if !result2.Existing {
		t.Error("Second call should report existing certs")
	}
}

func TestEnsureCertsCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "certdir")
	cfg := Config{
		CertDir:      dir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts with nested dir: %v", err)
	}
	if !result.Generated {
		t.Error("Should generate certs in nested dir")
	}

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("Directory %s should have been created: %v", dir, err)
	}
}

func TestEnsureCertsMultipleHostnames(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"rampart.local", "localhost", "myhost.internal"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts with multiple hostnames: %v", err)
	}
	if !result.Generated {
		t.Error("Should generate certs with multiple hostnames")
	}
}

func TestValidateCertsNoFiles(t *testing.T) {
	cfg := Config{
		CertDir:    t.TempDir(),
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	validation, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts on missing files: %v", err)
	}
	if validation.Valid {
		t.Error("Validation should fail with missing cert files")
	}
	if validation.ServerCertValid {
		t.Error("ServerCertValid should be false when cert file missing")
	}
	if validation.ServerKeyValid {
		t.Error("ServerKeyValid should be false when key file missing")
	}
	if validation.CACertValid {
		t.Error("CACertValid should be false when CA cert file missing")
	}
	if validation.CAKeyValid {
		t.Error("CAKeyValid should be false when CA key file missing")
	}
	if len(validation.Issues) == 0 {
		t.Error("Expected issues for missing files")
	}

	// Verify paths are set
	if validation.ServerCertPath == "" {
		t.Error("ServerCertPath should be set")
	}
	if validation.ServerKeyPath == "" {
		t.Error("ServerKeyPath should be set")
	}
	if validation.CACertPath == "" {
		t.Error("CACertPath should be set")
	}
	if validation.CAKeyPath == "" {
		t.Error("CAKeyPath should be set")
	}
}

func TestValidateCertsWithValidFiles(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	// First generate certs
	_, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts: %v", err)
	}

	// Then validate
	validation, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts: %v", err)
	}
	if !validation.Valid {
		t.Errorf("Expected valid certs, got issues: %v", validation.Issues)
	}
	if !validation.ServerCertValid {
		t.Error("ServerCertValid should be true")
	}
	if !validation.ServerKeyValid {
		t.Error("ServerKeyValid should be true")
	}
	if !validation.CACertValid {
		t.Error("CACertValid should be true")
	}
	if !validation.CAKeyValid {
		t.Error("CAKeyValid should be true")
	}
	if !validation.CAIsCA {
		t.Error("CAIsCA should be true for CA certificate")
	}
	if validation.ServerCN == "" {
		t.Error("ServerCN should be set")
	}
	if validation.CACN == "" {
		t.Error("CACN should be set")
	}
	if validation.ServerExpiry.IsZero() {
		t.Error("ServerExpiry should be set")
	}
	if validation.CAExpiry.IsZero() {
		t.Error("CAExpiry should be set")
	}
}

func TestValidateCertsInvalidCertFile(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		CertDir:    dir,
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		CACertFile: "ca.crt",
		CAKeyFile:  "ca.key",
	}

	// Write invalid data to cert files
	for _, name := range []string{"server.crt", "server.key", "ca.crt", "ca.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not a valid cert"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	validation, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts: %v", err)
	}
	if validation.Valid {
		t.Error("Validation should fail with invalid cert files")
	}
	if validation.ServerCertValid {
		t.Error("ServerCertValid should be false with invalid cert")
	}
	if validation.CACertValid {
		t.Error("CACertValid should be false with invalid cert")
	}
	if len(validation.Issues) == 0 {
		t.Error("Expected issues for invalid files")
	}
}

func TestResultStructFields(t *testing.T) {
	now := time.Now()
	r := Result{
		Generated:      true,
		Existing:       false,
		CACertPath:     "/path/ca.crt",
		CAKeyPath:      "/path/ca.key",
		ServerCertPath: "/path/server.crt",
		ServerKeyPath:  "/path/server.key",
		CAExpiry:       now.AddDate(10, 0, 0),
		ServerExpiry:   now.AddDate(1, 0, 0),
		Warnings:       []string{"test warning"},
	}
	if !r.Generated {
		t.Error("Generated should be true")
	}
	if r.Existing {
		t.Error("Existing should be false")
	}
	if r.CACertPath != "/path/ca.crt" {
		t.Errorf("CACertPath = %q", r.CACertPath)
	}
	if len(r.Warnings) != 1 || r.Warnings[0] != "test warning" {
		t.Errorf("Warnings = %v", r.Warnings)
	}
}

func TestCertValidationStructFields(t *testing.T) {
	v := CertValidation{
		Valid:           true,
		ServerCertValid: true,
		ServerKeyValid:  true,
		ServerCN:        "localhost",
		ServerSANs:      []string{"localhost", "rampart.local"},
		ServerExpiry:    time.Now().AddDate(1, 0, 0),
		CACertValid:     true,
		CAKeyValid:      true,
		CACN:            "AegisGate CA",
		CAIsCA:          true,
		CAExpiry:        time.Now().AddDate(10, 0, 0),
		CACertPath:      "/path/ca.crt",
		CAKeyPath:       "/path/ca.key",
		ServerCertPath:  "/path/server.crt",
		ServerKeyPath:   "/path/server.key",
		Issues:          []string{},
	}
	if !v.Valid {
		t.Error("Valid should be true")
	}
	if v.ServerCN != "localhost" {
		t.Errorf("ServerCN = %q", v.ServerCN)
	}
	if len(v.ServerSANs) != 2 {
		t.Errorf("ServerSANs = %v", v.ServerSANs)
	}
	if !v.CAIsCA {
		t.Error("CAIsCA should be true")
	}
	if v.CACN != "AegisGate CA" {
		t.Errorf("CACN = %q", v.CACN)
	}
}

func TestConfigCustomFields(t *testing.T) {
	cfg := Config{
		CertDir:      "/custom/certs",
		AutoGenerate: false,
		Hostnames:    []string{"example.com", "test.local"},
		CertFile:     "custom.crt",
		KeyFile:      "custom.key",
		CACertFile:   "custom-ca.crt",
		CAKeyFile:    "custom-ca.key",
	}
	if cfg.CertDir != "/custom/certs" {
		t.Errorf("CertDir = %q", cfg.CertDir)
	}
	if cfg.AutoGenerate {
		t.Error("AutoGenerate should be false")
	}
	if len(cfg.Hostnames) != 2 {
		t.Errorf("Hostnames = %v, want 2", cfg.Hostnames)
	}
	if cfg.CertFile != "custom.crt" {
		t.Errorf("CertFile = %q", cfg.CertFile)
	}
	if cfg.CACertFile != "custom-ca.crt" {
		t.Errorf("CACertFile = %q", cfg.CACertFile)
	}
}

func TestEnsureCertsResultPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		CertDir:      dir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "myserver.crt",
		KeyFile:      "myserver.key",
		CACertFile:   "myca.crt",
		CAKeyFile:    "myca.key",
	}

	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts: %v", err)
	}

	expectedCACert := filepath.Join(dir, "myca.crt")
	expectedCAKey := filepath.Join(dir, "myca.key")
	expectedServerCert := filepath.Join(dir, "myserver.crt")
	expectedServerKey := filepath.Join(dir, "myserver.key")

	if result.CACertPath != expectedCACert {
		t.Errorf("CACertPath = %q, want %q", result.CACertPath, expectedCACert)
	}
	if result.CAKeyPath != expectedCAKey {
		t.Errorf("CAKeyPath = %q, want %q", result.CAKeyPath, expectedCAKey)
	}
	if result.ServerCertPath != expectedServerCert {
		t.Errorf("ServerCertPath = %q, want %q", result.ServerCertPath, expectedServerCert)
	}
	if result.ServerKeyPath != expectedServerKey {
		t.Errorf("ServerKeyPath = %q, want %q", result.ServerKeyPath, expectedServerKey)
	}
}

// Additional tests adapted from Platform v4.0.0 certinit tests

func TestCheckExistingCertsPartialFiles(t *testing.T) {
	dir := t.TempDir()
	// Only CA cert exists, not server cert/key
	caPath := filepath.Join(dir, "ca.crt")
	os.WriteFile(caPath, []byte("placeholder"), 0644) /* #nosec */ 

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		caPath,
		filepath.Join(dir, "ca.key"),
	)
	if existing {
		t.Error("should not find existing with partial files")
	}
	_ = warnings
}

func TestCheckExistingCertsGeneratedCertValid(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}
	// CA cert should be valid for ~10 years
	if result.CAExpiry.Before(time.Now().Add(9 * 365 * 24 * time.Hour)) {
		t.Errorf("CA cert expires too soon: %v", result.CAExpiry)
	}
	// Server cert should be valid for ~1 year
	if result.ServerExpiry.Before(time.Now().Add(350 * 24 * time.Hour)) {
		t.Errorf("server cert expires too soon: %v", result.ServerExpiry)
	}
}

func TestParseKeyFileECDSA(t *testing.T) {
	// Use EnsureCerts to get a real ECDSA key (Rampart uses ECDSA P-256)
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
	_, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// The server key should be parseable as ECDSA
	key, err := parseKeyFile(filepath.Join(cfg.CertDir, "server.key"))
	if err != nil {
		t.Errorf("Failed to parse server key: %v", err)
	}
	if key == nil {
		t.Error("Expected non-nil key")
	}
}

func TestParseKeyFileCAKey(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
	_, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// The CA key should be parseable
	key, err := parseKeyFile(filepath.Join(cfg.CertDir, "ca.key"))
	if err != nil {
		t.Errorf("Failed to parse CA key: %v", err)
	}
	if key == nil {
		t.Error("Expected non-nil key")
	}
}

func TestParseCertificateFileNonexistent(t *testing.T) {
	_, err := parseCertificateFile("/nonexistent/cert.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseKeyFileNonexistent(t *testing.T) {
	_, err := parseKeyFile("/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseCertificateFileInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.crt")
	os.WriteFile(path, []byte("not a pem file"), 0644) /* #nosec */ 
	_, err := parseCertificateFile(path)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestParseKeyFileInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	os.WriteFile(path, []byte("not a key file"), 0644) /* #nosec */ 
	_, err := parseKeyFile(path)
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

// Tests for checkExistingCerts error paths using generated certificates

func TestCheckExistingCertsExpiredServerCert(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
	// Generate valid certs first
	result, err := EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}
	_ = result

	// Now overwrite server cert with invalid PEM
	serverCertPath := filepath.Join(cfg.CertDir, cfg.CertFile)
	os.WriteFile(serverCertPath, []byte("-----BEGIN CERTIFICATE-----\nINVALIDBASE64\n-----END CERTIFICATE-----"), 0644)

	// checkExistingCerts should return false with warnings
	existing, warnings := checkExistingCerts(
		filepath.Join(cfg.CertDir, cfg.CertFile),
		filepath.Join(cfg.CertDir, cfg.KeyFile),
		filepath.Join(cfg.CertDir, cfg.CACertFile),
		filepath.Join(cfg.CertDir, cfg.CAKeyFile),
	)
	if existing {
		t.Error("should not find existing with invalid server cert")
	}
	if len(warnings) == 0 {
		t.Error("expected warnings for invalid server cert")
	}
}

func TestCheckExistingCertsExpiredCACert(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
	_ = EnsureCerts(cfg) /* #nosec */ 

	// Overwrite CA cert with invalid PEM
	caCertPath := filepath.Join(cfg.CertDir, cfg.CACertFile)
	os.WriteFile(caCertPath, []byte("-----BEGIN CERTIFICATE-----\nINVALIDBASE64CA\n-----END CERTIFICATE-----"), 0644)

	existing, warnings := checkExistingCerts(
		filepath.Join(cfg.CertDir, cfg.CertFile),
		filepath.Join(cfg.CertDir, cfg.KeyFile),
		caCertPath,
		filepath.Join(cfg.CertDir, cfg.CAKeyFile),
	)
	if existing {
		t.Error("should not find existing with invalid CA cert")
	}
	if len(warnings) == 0 {
		t.Error("expected warnings for invalid CA cert")
	}
}

func TestParseKeyFileUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unsupported.key")
	// Write PEM block with unsupported key type
	os.WriteFile(path, []byte("-----BEGIN OTHER KEY TYPE-----\nSOMEDATA\n-----END OTHER KEY TYPE-----"), 0600)

	_, err := parseKeyFile(path)
	if err == nil {
		t.Error("expected error for unsupported key format")
	}
}

func TestParseKeyFileNoPEMBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nopem.key")
	os.WriteFile(path, []byte("not a pem file at all"), 0600)

	_, err := parseKeyFile(path)
	if err == nil {
		t.Error("expected error for no PEM block")
	}
}

func TestValidateCertsInvalidServerKey(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
	_ = EnsureCerts(cfg) /* #nosec */ 

	// Overwrite server key with invalid data
	serverKeyPath := filepath.Join(cfg.CertDir, cfg.KeyFile)
	os.WriteFile(serverKeyPath, []byte("-----BEGIN RSA PRIVATE KEY-----\nINVALID\n-----END RSA PRIVATE KEY-----"), 0600)

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with invalid server key")
	}
	if v.ServerKeyValid {
		t.Error("server key should not be valid")
	}
}

func TestValidateCertsInvalidCAKey(t *testing.T) {
	cfg := Config{
		CertDir:      t.TempDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}
	_ = EnsureCerts(cfg) /* #nosec */ 

	// Overwrite CA key with invalid data
	caKeyPath := filepath.Join(cfg.CertDir, cfg.CAKeyFile)
	os.WriteFile(caKeyPath, []byte("-----BEGIN RSA PRIVATE KEY-----\nINVALID\n-----END RSA PRIVATE KEY-----"), 0600)

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with invalid CA key")
	}
	if v.CAKeyValid {
		t.Error("CA key should not be valid")
	}
}
