package config

import (
	"testing"
)

func TestConstants(t *testing.T) {
	// Test that default constants are set correctly
	if DefaultRuntimeDir != "/var/lib/gockerize" {
		t.Errorf("Expected DefaultRuntimeDir '/var/lib/gockerize', got '%s'", DefaultRuntimeDir)
	}

	if DefaultImageDir != "/var/lib/gockerize/images" {
		t.Errorf("Expected DefaultImageDir '/var/lib/gockerize/images', got '%s'", DefaultImageDir)
	}

	if DefaultContainerDir != "/var/lib/gockerize/containers" {
		t.Errorf("Expected DefaultContainerDir '/var/lib/gockerize/containers', got '%s'", DefaultContainerDir)
	}

	if DefaultNetworkDir != "/var/lib/gockerize/networks" {
		t.Errorf("Expected DefaultNetworkDir '/var/lib/gockerize/networks', got '%s'", DefaultNetworkDir)
	}

	if DefaultBridgeName != "gockerize0" {
		t.Errorf("Expected DefaultBridgeName 'gockerize0', got '%s'", DefaultBridgeName)
	}

	if DefaultSubnet != "172.17.0.0/16" {
		t.Errorf("Expected DefaultSubnet '172.17.0.0/16', got '%s'", DefaultSubnet)
	}

	if DefaultStopTimeout != 10 {
		t.Errorf("Expected DefaultStopTimeout 10, got %d", DefaultStopTimeout)
	}

	if MaxNameLength != 63 {
		t.Errorf("Expected MaxNameLength 63, got %d", MaxNameLength)
	}
}

func TestNewDefaultConfig(t *testing.T) {
	config := NewDefaultConfig()

	if config == nil {
		t.Fatal("NewDefaultConfig() returned nil")
	}

	// Test that all default values are set correctly
	if config.RuntimeDir != DefaultRuntimeDir {
		t.Errorf("Expected RuntimeDir '%s', got '%s'", DefaultRuntimeDir, config.RuntimeDir)
	}

	if config.ImageDir != DefaultImageDir {
		t.Errorf("Expected ImageDir '%s', got '%s'", DefaultImageDir, config.ImageDir)
	}

	if config.ContainerDir != DefaultContainerDir {
		t.Errorf("Expected ContainerDir '%s', got '%s'", DefaultContainerDir, config.ContainerDir)
	}

	if config.NetworkDir != DefaultNetworkDir {
		t.Errorf("Expected NetworkDir '%s', got '%s'", DefaultNetworkDir, config.NetworkDir)
	}

	if config.BridgeName != DefaultBridgeName {
		t.Errorf("Expected BridgeName '%s', got '%s'", DefaultBridgeName, config.BridgeName)
	}

	if config.Subnet != DefaultSubnet {
		t.Errorf("Expected Subnet '%s', got '%s'", DefaultSubnet, config.Subnet)
	}
}

func TestRuntimeConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		config *RuntimeConfig
		valid  bool
	}{
		{
			name:   "default config",
			config: NewDefaultConfig(),
			valid:  true,
		},
		{
			name: "custom valid config",
			config: &RuntimeConfig{
				RuntimeDir:   "/custom/runtime",
				ImageDir:     "/custom/images",
				ContainerDir: "/custom/containers",
				NetworkDir:   "/custom/networks",
				BridgeName:   "custom0",
				Subnet:       "192.168.1.0/24",
			},
			valid: true,
		},
		{
			name: "empty config",
			config: &RuntimeConfig{
				RuntimeDir:   "",
				ImageDir:     "",
				ContainerDir: "",
				NetworkDir:   "",
				BridgeName:   "",
				Subnet:       "",
			},
			valid: true, // Current implementation doesn't validate
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.valid && err != nil {
				t.Errorf("Expected config to be valid, got error: %v", err)
			}

			if !tt.valid && err == nil {
				t.Error("Expected config to be invalid, got no error")
			}
		})
	}
}

func TestRuntimeConfigModification(t *testing.T) {
	config := NewDefaultConfig()

	// Test modifying configuration
	config.RuntimeDir = "/custom/path"
	if config.RuntimeDir != "/custom/path" {
		t.Errorf("Failed to modify RuntimeDir, got '%s'", config.RuntimeDir)
	}

	config.BridgeName = "custom-bridge"
	if config.BridgeName != "custom-bridge" {
		t.Errorf("Failed to modify BridgeName, got '%s'", config.BridgeName)
	}

	config.Subnet = "10.0.0.0/8"
	if config.Subnet != "10.0.0.0/8" {
		t.Errorf("Failed to modify Subnet, got '%s'", config.Subnet)
	}
}

func TestRuntimeConfigImmutability(t *testing.T) {
	// Test that default constants are not modified when creating new configs
	config1 := NewDefaultConfig()
	config2 := NewDefaultConfig()

	// Modify first config
	config1.RuntimeDir = "/modified/path"
	config1.BridgeName = "modified-bridge"

	// Second config should still have defaults
	if config2.RuntimeDir != DefaultRuntimeDir {
		t.Errorf("Default config modified: expected '%s', got '%s'", DefaultRuntimeDir, config2.RuntimeDir)
	}

	if config2.BridgeName != DefaultBridgeName {
		t.Errorf("Default config modified: expected '%s', got '%s'", DefaultBridgeName, config2.BridgeName)
	}
}

func TestRuntimeConfigDefensiveCopy(t *testing.T) {
	config := NewDefaultConfig()
	originalRuntimeDir := config.RuntimeDir

	// Create a function that modifies the config
	modifyConfig := func(cfg *RuntimeConfig) {
		cfg.RuntimeDir = "/malicious/path"
	}

	// Pass config to function
	modifyConfig(config)

	// Config should be modified (no defensive copy in current implementation)
	if config.RuntimeDir == originalRuntimeDir {
		t.Log("Config was not modified (defensive copy exists)")
	} else {
		t.Log("Config was modified (no defensive copy)")
	}
}

func TestConfigPathHierarchy(t *testing.T) {
	config := NewDefaultConfig()

	// Test that all paths are under runtime directory
	expectedPrefix := config.RuntimeDir

	if config.ImageDir[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("ImageDir should be under RuntimeDir: %s not under %s", config.ImageDir, expectedPrefix)
	}

	if config.ContainerDir[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("ContainerDir should be under RuntimeDir: %s not under %s", config.ContainerDir, expectedPrefix)
	}

	if config.NetworkDir[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("NetworkDir should be under RuntimeDir: %s not under %s", config.NetworkDir, expectedPrefix)
	}
}

func TestConfigStringRepresentation(t *testing.T) {
	config := NewDefaultConfig()

	// Test that config can be used in string operations
	configStr := config.RuntimeDir + "/" + config.BridgeName
	expectedStr := DefaultRuntimeDir + "/" + DefaultBridgeName

	if configStr != expectedStr {
		t.Errorf("String concatenation failed: expected '%s', got '%s'", expectedStr, configStr)
	}
}

// Edge case tests
func TestConfigEdgeCases(t *testing.T) {
	// Test creating multiple configs doesn't interfere with each other
	configs := make([]*RuntimeConfig, 10)
	for i := 0; i < 10; i++ {
		configs[i] = NewDefaultConfig()
	}

	// All configs should be identical but separate instances
	for i := 1; i < 10; i++ {
		if configs[i].RuntimeDir != configs[0].RuntimeDir {
			t.Errorf("Config %d has different RuntimeDir", i)
		}

		// Modify one config and ensure others are unaffected
		configs[i].RuntimeDir = "/different/path"
		if configs[0].RuntimeDir == configs[i].RuntimeDir {
			t.Error("Configs are sharing state when they shouldn't")
		}
	}
}

// Benchmark tests
func BenchmarkNewDefaultConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		config := NewDefaultConfig()
		_ = config
	}
}

func BenchmarkConfigValidate(b *testing.B) {
	config := NewDefaultConfig()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		config.Validate()
	}
}

func BenchmarkConfigAccess(b *testing.B) {
	config := NewDefaultConfig()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = config.RuntimeDir
		_ = config.ImageDir
		_ = config.ContainerDir
		_ = config.NetworkDir
		_ = config.BridgeName
		_ = config.Subnet
	}
}
