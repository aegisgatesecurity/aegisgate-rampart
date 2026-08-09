// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — LLM Presets Tests

package llm

import (
	"testing"
)

func TestGetPresets(t *testing.T) {
	presets := GetPresets()

	if len(presets) == 0 {
		t.Fatal("Expected at least one preset")
	}

	// Verify we have the expected presets
	expectedPresets := []string{"ollama", "lm-studio", "localai", "vllm", "text-generation-webui"}
	foundPresets := make(map[string]bool)

	for _, p := range presets {
		foundPresets[p.Name] = true

		// Verify all presets have required fields
		if p.Name == "" {
			t.Error("Preset name should not be empty")
		}
		if p.URL == "" {
			t.Errorf("Preset %q URL should not be empty", p.Name)
		}
		if p.Type == "" {
			t.Errorf("Preset %q type should not be empty", p.Name)
		}
		if p.Description == "" {
			t.Errorf("Preset %q description should not be empty", p.Name)
		}
		if len(p.DefaultModels) == 0 {
			t.Errorf("Preset %q should have at least one default model", p.Name)
		}
	}

	// Verify all expected presets are present
	for _, expected := range expectedPresets {
		if !foundPresets[expected] {
			t.Errorf("Expected preset %q not found", expected)
		}
	}
}

func TestGetPreset_Ollama(t *testing.T) {
	preset, err := GetPreset("ollama")
	if err != nil {
		t.Fatalf("GetPreset(ollama) failed: %v", err)
	}

	if preset.Name != "ollama" {
		t.Errorf("Expected name 'ollama', got %q", preset.Name)
	}
	if preset.URL != "http://localhost:11434/v1" {
		t.Errorf("Expected URL 'http://localhost:11434/v1', got %q", preset.URL)
	}
	if preset.Type != "openai-compatible" {
		t.Errorf("Expected type 'openai-compatible', got %q", preset.Type)
	}
	if len(preset.DefaultModels) == 0 {
		t.Error("Expected default models for ollama")
	}
}

func TestGetPreset_LMStudio(t *testing.T) {
	preset, err := GetPreset("lm-studio")
	if err != nil {
		t.Fatalf("GetPreset(lm-studio) failed: %v", err)
	}

	if preset.URL != "http://localhost:1234/v1" {
		t.Errorf("Expected URL 'http://localhost:1234/v1', got %q", preset.URL)
	}
}

func TestGetPreset_LocalAI(t *testing.T) {
	preset, err := GetPreset("localai")
	if err != nil {
		t.Fatalf("GetPreset(localai) failed: %v", err)
	}

	if preset.URL != "http://localhost:8080/v1" {
		t.Errorf("Expected URL 'http://localhost:8080/v1', got %q", preset.URL)
	}
}

func TestGetPreset_VLLM(t *testing.T) {
	preset, err := GetPreset("vllm")
	if err != nil {
		t.Fatalf("GetPreset(vllm) failed: %v", err)
	}

	if preset.URL != "http://localhost:8000/v1" {
		t.Errorf("Expected URL 'http://localhost:8000/v1', got %q", preset.URL)
	}
}

func TestGetPreset_TextGenerationWebUI(t *testing.T) {
	preset, err := GetPreset("text-generation-webui")
	if err != nil {
		t.Fatalf("GetPreset(text-generation-webui) failed: %v", err)
	}

	if preset.URL != "http://localhost:5000/v1" {
		t.Errorf("Expected URL 'http://localhost:5000/v1', got %q", preset.URL)
	}
}

func TestGetPreset_NotFound(t *testing.T) {
	preset, err := GetPreset("nonexistent-preset")
	if err == nil {
		t.Error("GetPreset should fail for nonexistent preset")
	}
	if preset != nil {
		t.Error("Expected nil preset for nonexistent preset")
	}
}

func TestGetPreset_CaseSensitive(t *testing.T) {
	// Preset names should be case-sensitive
	_, err := GetPreset("OLLAMA")
	if err == nil {
		t.Error("GetPreset should be case-sensitive")
	}

	_, err = GetPreset("Ollama")
	if err == nil {
		t.Error("GetPreset should be case-sensitive")
	}
}

func TestAllPresetsAreOpenAICompatible(t *testing.T) {
	presets := GetPresets()

	for _, p := range presets {
		if p.Type != "openai-compatible" {
			t.Errorf("Preset %q should have type 'openai-compatible', got %q", p.Name, p.Type)
		}
	}
}

func TestPresetURLsAreLocalhost(t *testing.T) {
	presets := GetPresets()

	for _, p := range presets {
		if p.URL == "" {
			t.Errorf("Preset %q URL should not be empty", p.Name)
		}
		// All presets should point to localhost
		if !containsString(p.URL, "localhost") && !containsString(p.URL, "127.0.0.1") {
			t.Errorf("Preset %q URL should point to localhost: %q", p.Name, p.URL)
		}
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestGetPresets_ReturnsNewSlice(t *testing.T) {
	// Verify GetPresets returns a new slice each time (not a shared reference)
	presets1 := GetPresets()
	presets2 := GetPresets()

	// Modifying one should not affect the other
	if len(presets1) > 0 {
		originalName := presets1[0].Name
		presets1[0].Name = "modified"

		if presets2[0].Name == "modified" {
			t.Error("GetPresets should return a new slice, not a shared reference")
		}

		// Restore for other tests
		presets1[0].Name = originalName
	}
}
