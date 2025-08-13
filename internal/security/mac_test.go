package security

import (
	"testing"
)

func TestNewMACManager(t *testing.T) {
	manager := NewMACManager()

	if manager == nil {
		t.Fatal("NewMACManager() returned nil")
	}

	// Check that available type is set to a valid value
	validTypes := map[MACType]bool{
		MACTypeNone:     true,
		MACTypeAppArmor: true,
		MACTypeSELinux:  true,
	}

	if !validTypes[manager.availableType] {
		t.Errorf("Invalid available type: %s", manager.availableType)
	}

	// If AppArmor is detected, profiles directory should be set
	if manager.availableType == MACTypeAppArmor {
		expectedDir := "/etc/apparmor.d"
		if manager.profilesDir != expectedDir {
			t.Errorf("Expected profiles dir %s, got %s", expectedDir, manager.profilesDir)
		}
	}
}

func TestGetAvailableType(t *testing.T) {
	manager := NewMACManager()

	availableType := manager.GetAvailableType()

	// Should match the internal available type
	if availableType != manager.availableType {
		t.Errorf("GetAvailableType() returned %s, expected %s", availableType, manager.availableType)
	}
}

func TestApplyProfileWithNone(t *testing.T) {
	manager := NewMACManager()

	// Test with nil config
	err := manager.ApplyProfile(nil, 1234)
	if err != nil {
		t.Errorf("ApplyProfile() with nil config failed: %v", err)
	}

	// Test with MACTypeNone
	config := &MACConfig{Type: MACTypeNone}
	err = manager.ApplyProfile(config, 1234)
	if err != nil {
		t.Errorf("ApplyProfile() with MACTypeNone failed: %v", err)
	}
}

func TestApplyProfileWithUnavailableMAC(t *testing.T) {
	manager := &MACManager{
		availableType: MACTypeNone,
	}

	// Test requesting AppArmor when none is available
	config := &MACConfig{
		Type:    MACTypeAppArmor,
		Profile: "test-profile",
	}

	err := manager.ApplyProfile(config, 1234)
	if err == nil {
		t.Error("Expected error when requesting MAC with none available")
	}

	expectedMsg := "MAC requested but no MAC system available"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestApplyProfileWithMismatchedType(t *testing.T) {
	manager := &MACManager{
		availableType: MACTypeAppArmor,
	}

	// Test requesting SELinux when AppArmor is available
	config := &MACConfig{
		Type:  MACTypeSELinux,
		Label: "test-label",
	}

	err := manager.ApplyProfile(config, 1234)
	if err == nil {
		t.Error("Expected error when requesting mismatched MAC type")
	}

	expectedStart := "MAC type selinux requested but only apparmor is available"
	if err.Error() != expectedStart {
		t.Errorf("Expected error containing '%s', got '%s'", expectedStart, err.Error())
	}
}

func TestApplyProfileWithUnsupportedType(t *testing.T) {
	manager := &MACManager{
		availableType: MACType("unknown"),
	}

	config := &MACConfig{
		Type: MACType("unknown"),
	}

	err := manager.ApplyProfile(config, 1234)
	if err == nil {
		t.Error("Expected error for unsupported MAC type")
	}

	expectedStart := "unsupported MAC type"
	if !containsString(err.Error(), expectedStart) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedStart, err.Error())
	}
}

func TestCreateDefaultProfile(t *testing.T) {
	manager := NewMACManager()

	err := manager.CreateDefaultProfile()

	// This might fail in test environment, which is acceptable
	if err != nil {
		t.Logf("CreateDefaultProfile() failed as expected in test environment: %v", err)
	} else {
		t.Log("CreateDefaultProfile() succeeded")
	}
}

func TestCreateDefaultProfileWithNone(t *testing.T) {
	manager := &MACManager{
		availableType: MACTypeNone,
	}

	err := manager.CreateDefaultProfile()
	if err != nil {
		t.Errorf("CreateDefaultProfile() with MACTypeNone should not fail, got: %v", err)
	}
}

func TestGetDefaultConfig(t *testing.T) {
	// Test with AppArmor
	managerAppArmor := &MACManager{
		availableType: MACTypeAppArmor,
	}

	config := managerAppArmor.GetDefaultConfig()
	if config == nil {
		t.Fatal("GetDefaultConfig() returned nil for AppArmor")
	}

	if config.Type != MACTypeAppArmor {
		t.Errorf("Expected type %s, got %s", MACTypeAppArmor, config.Type)
	}

	if config.Profile != "gockerize-default" {
		t.Errorf("Expected profile 'gockerize-default', got '%s'", config.Profile)
	}

	// Test with SELinux
	managerSELinux := &MACManager{
		availableType: MACTypeSELinux,
	}

	config = managerSELinux.GetDefaultConfig()
	if config == nil {
		t.Fatal("GetDefaultConfig() returned nil for SELinux")
	}

	if config.Type != MACTypeSELinux {
		t.Errorf("Expected type %s, got %s", MACTypeSELinux, config.Type)
	}

	if config.Label != "container_t" {
		t.Errorf("Expected label 'container_t', got '%s'", config.Label)
	}

	// Test with None
	managerNone := &MACManager{
		availableType: MACTypeNone,
	}

	config = managerNone.GetDefaultConfig()
	if config == nil {
		t.Fatal("GetDefaultConfig() returned nil for None")
	}

	if config.Type != MACTypeNone {
		t.Errorf("Expected type %s, got %s", MACTypeNone, config.Type)
	}
}

func TestMACConfig(t *testing.T) {
	// Test AppArmor config
	appArmorConfig := &MACConfig{
		Type:    MACTypeAppArmor,
		Profile: "test-profile",
	}

	if appArmorConfig.Type != MACTypeAppArmor {
		t.Errorf("Expected type %s, got %s", MACTypeAppArmor, appArmorConfig.Type)
	}

	if appArmorConfig.Profile != "test-profile" {
		t.Errorf("Expected profile 'test-profile', got '%s'", appArmorConfig.Profile)
	}

	// Test SELinux config
	selinuxConfig := &MACConfig{
		Type:  MACTypeSELinux,
		Label: "test-label",
	}

	if selinuxConfig.Type != MACTypeSELinux {
		t.Errorf("Expected type %s, got %s", MACTypeSELinux, selinuxConfig.Type)
	}

	if selinuxConfig.Label != "test-label" {
		t.Errorf("Expected label 'test-label', got '%s'", selinuxConfig.Label)
	}
}

func TestMACTypeConstants(t *testing.T) {
	// Test that MAC type constants have expected values
	if MACTypeNone != "none" {
		t.Errorf("Expected MACTypeNone to be 'none', got '%s'", MACTypeNone)
	}

	if MACTypeAppArmor != "apparmor" {
		t.Errorf("Expected MACTypeAppArmor to be 'apparmor', got '%s'", MACTypeAppArmor)
	}

	if MACTypeSELinux != "selinux" {
		t.Errorf("Expected MACTypeSELinux to be 'selinux', got '%s'", MACTypeSELinux)
	}
}

func TestIsAppArmorAvailable(t *testing.T) {
	result := isAppArmorAvailable()

	// Log the result for informational purposes
	if result {
		t.Log("AppArmor is available on this system")
	} else {
		t.Log("AppArmor is not available on this system")
	}

	// This is just informational, not a failure
}

func TestIsSELinuxAvailable(t *testing.T) {
	result := isSELinuxAvailable()

	// Log the result for informational purposes
	if result {
		t.Log("SELinux is available on this system")
	} else {
		t.Log("SELinux is not available on this system")
	}

	// This is just informational, not a failure
}

func TestMACManagerProfilesDir(t *testing.T) {
	manager := NewMACManager()

	if manager.availableType == MACTypeAppArmor {
		expectedDir := "/etc/apparmor.d"
		if manager.profilesDir != expectedDir {
			t.Errorf("Expected profiles dir %s, got %s", expectedDir, manager.profilesDir)
		}
	} else {
		// For non-AppArmor systems, profiles dir should be empty
		if manager.profilesDir != "" {
			t.Errorf("Expected empty profiles dir for non-AppArmor system, got %s", manager.profilesDir)
		}
	}
}

func TestApplyProfileFlow(t *testing.T) {
	manager := NewMACManager()

	// Test the complete flow with the actual available type
	config := manager.GetDefaultConfig()

	// This might fail in test environment without proper privileges
	err := manager.ApplyProfile(config, 1234)
	if err != nil {
		t.Logf("ApplyProfile() failed as expected in test environment: %v", err)
	} else {
		t.Log("ApplyProfile() succeeded")
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && containsStringHelper(s[1:], substr)
}

func containsStringHelper(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	if s[:len(substr)] == substr {
		return true
	}
	return containsStringHelper(s[1:], substr)
}

// Benchmark tests
func BenchmarkNewMACManager(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewMACManager()
	}
}

func BenchmarkGetAvailableType(b *testing.B) {
	manager := NewMACManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.GetAvailableType()
	}
}

func BenchmarkGetDefaultConfig(b *testing.B) {
	manager := NewMACManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.GetDefaultConfig()
	}
}
