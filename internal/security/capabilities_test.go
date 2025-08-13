package security

import (
	"testing"

	"github.com/syndtr/gocapability/capability"
)

func TestNewCapabilityManager(t *testing.T) {
	cm := NewCapabilityManager()
	if cm == nil {
		t.Error("NewCapabilityManager() returned nil")
	}
}

func TestDefaultCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	caps := cm.DefaultCapabilities()

	expectedCaps := []string{
		"chown",
		"dac_override",
		"fsetid",
		"fowner",
		"mknod",
		"net_raw",
		"setgid",
		"setuid",
		"setfcap",
		"setpcap",
		"net_bind_service",
		"sys_chroot",
		"kill",
		"audit_write",
	}

	if len(caps) != len(expectedCaps) {
		t.Errorf("DefaultCapabilities() returned %d capabilities, expected %d", len(caps), len(expectedCaps))
	}

	capMap := make(map[string]bool)
	for _, cap := range caps {
		capMap[cap] = true
	}

	for _, expectedCap := range expectedCaps {
		if !capMap[expectedCap] {
			t.Errorf("DefaultCapabilities() missing expected capability: %s", expectedCap)
		}
	}

	// Ensure no duplicates
	if len(caps) != len(capMap) {
		t.Error("DefaultCapabilities() contains duplicate capabilities")
	}
}

func TestAllCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	caps := cm.AllCapabilities()

	// Should return at least some capabilities
	if len(caps) == 0 {
		t.Error("AllCapabilities() returned empty slice")
	}

	// Verify all returned capabilities are valid
	validCaps := make(map[string]bool)
	for _, cap := range capability.List() {
		validCaps[cap.String()] = true
	}

	for _, cap := range caps {
		if !validCaps[cap] {
			t.Errorf("AllCapabilities() returned invalid capability: %s", cap)
		}
	}

	// Check for duplicates
	capMap := make(map[string]bool)
	for _, cap := range caps {
		if capMap[cap] {
			t.Errorf("AllCapabilities() contains duplicate capability: %s", cap)
		}
		capMap[cap] = true
	}
}

func TestDangerousCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	dangerous := cm.DangerousCapabilities()

	expectedDangerous := []string{
		"sys_admin",
		"sys_module",
		"sys_time",
		"sys_boot",
		"sys_nice",
		"sys_resource",
		"sys_rawio",
		"net_admin",
	}

	if len(dangerous) != len(expectedDangerous) {
		t.Errorf("DangerousCapabilities() returned %d capabilities, expected %d", len(dangerous), len(expectedDangerous))
	}

	dangerousMap := make(map[string]bool)
	for _, cap := range dangerous {
		dangerousMap[cap] = true
	}

	for _, expectedCap := range expectedDangerous {
		if !dangerousMap[expectedCap] {
			t.Errorf("DangerousCapabilities() missing expected capability: %s", expectedCap)
		}
	}
}

func TestValidateCapability(t *testing.T) {
	cm := NewCapabilityManager()

	tests := []struct {
		name       string
		capability string
		hasError   bool
	}{
		{
			name:       "valid capability",
			capability: "chown",
			hasError:   false,
		},
		{
			name:       "valid capability with CAP_ prefix",
			capability: "CAP_CHOWN",
			hasError:   false,
		},
		{
			name:       "valid capability uppercase",
			capability: "CHOWN",
			hasError:   false,
		},
		{
			name:       "invalid capability",
			capability: "invalid_cap",
			hasError:   true,
		},
		{
			name:       "empty capability",
			capability: "",
			hasError:   true,
		},
		{
			name:       "sys_admin capability",
			capability: "sys_admin",
			hasError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cm.ValidateCapability(tt.capability)

			if tt.hasError {
				if err == nil {
					t.Errorf("ValidateCapability() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ValidateCapability() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCalculateFinalCapabilities(t *testing.T) {
	cm := NewCapabilityManager()

	tests := []struct {
		name             string
		capAdd           []string
		capDrop          []string
		privileged       bool
		hasError         bool
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:          "default capabilities",
			capAdd:        []string{},
			capDrop:       []string{},
			privileged:    false,
			hasError:      false,
			shouldContain: []string{"chown", "setuid"},
		},
		{
			name:          "privileged container",
			capAdd:        []string{},
			capDrop:       []string{},
			privileged:    true,
			hasError:      false,
			shouldContain: []string{"sys_admin", "chown"},
		},
		{
			name:          "add capability",
			capAdd:        []string{"sys_time"},
			capDrop:       []string{},
			privileged:    false,
			hasError:      false,
			shouldContain: []string{"chown", "sys_time"},
		},
		{
			name:             "drop capability",
			capAdd:           []string{},
			capDrop:          []string{"chown"},
			privileged:       false,
			hasError:         false,
			shouldNotContain: []string{"chown"},
		},
		{
			name:             "drop all capabilities",
			capAdd:           []string{},
			capDrop:          []string{"ALL"},
			privileged:       false,
			hasError:         false,
			shouldNotContain: []string{"chown", "setuid"},
		},
		{
			name:       "invalid capability in add",
			capAdd:     []string{"invalid_cap"},
			capDrop:    []string{},
			privileged: false,
			hasError:   true,
		},
		{
			name:       "invalid capability in drop",
			capAdd:     []string{},
			capDrop:    []string{"invalid_cap"},
			privileged: false,
			hasError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cm.CalculateFinalCapabilities(tt.capAdd, tt.capDrop, tt.privileged)

			if tt.hasError {
				if err == nil {
					t.Errorf("CalculateFinalCapabilities() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("CalculateFinalCapabilities() unexpected error: %v", err)
				return
			}

			resultMap := make(map[string]bool)
			for _, cap := range result {
				resultMap[cap] = true
			}

			for _, cap := range tt.shouldContain {
				if !resultMap[cap] {
					t.Errorf("CalculateFinalCapabilities() should contain %s but doesn't", cap)
				}
			}

			for _, cap := range tt.shouldNotContain {
				if resultMap[cap] {
					t.Errorf("CalculateFinalCapabilities() should not contain %s but does", cap)
				}
			}
		})
	}
}

func TestDropCapabilities(t *testing.T) {
	cm := NewCapabilityManager()

	// Note: This test may require root privileges to actually drop capabilities
	// We'll test the function exists and doesn't panic with basic input
	capsToDrop := []string{"sys_admin", "sys_module"}

	err := cm.DropCapabilities(capsToDrop)
	// The function should not panic, error handling depends on system state
	if err != nil {
		t.Logf("DropCapabilities() returned error (may be expected if not root): %v", err)
	}
}

func TestApplyCapabilities(t *testing.T) {
	cm := NewCapabilityManager()

	// Note: This test may require root privileges to actually apply capabilities
	// We'll test the function exists and doesn't panic with basic input
	capsToApply := []string{"chown", "setuid"}

	err := cm.ApplyCapabilities(capsToApply)
	// The function should not panic, error handling depends on system state
	if err != nil {
		t.Logf("ApplyCapabilities() returned error (may be expected if not root): %v", err)
	}
}

func TestGetCurrentCapabilities(t *testing.T) {
	cm := NewCapabilityManager()

	caps, err := cm.GetCurrentCapabilities()
	if err != nil {
		t.Errorf("GetCurrentCapabilities() returned error: %v", err)
		return
	}

	// Should return a slice (empty slice is acceptable for unprivileged processes)
	if caps == nil {
		t.Log("GetCurrentCapabilities() returned nil slice (acceptable for unprivileged processes)")
		return
	}

	// All returned capabilities should be valid
	for _, cap := range caps {
		if err := cm.ValidateCapability(cap); err != nil {
			t.Errorf("GetCurrentCapabilities() returned invalid capability: %s", cap)
		}
	}

	// Log the number of capabilities for debugging
	t.Logf("Current process has %d effective capabilities", len(caps))
}

func TestLogCapabilities(t *testing.T) {
	cm := NewCapabilityManager()

	// This should not panic or error
	cm.LogCapabilities()
}

// Benchmark tests
func BenchmarkDefaultCapabilities(b *testing.B) {
	cm := NewCapabilityManager()
	for i := 0; i < b.N; i++ {
		cm.DefaultCapabilities()
	}
}

func BenchmarkCalculateFinalCapabilities(b *testing.B) {
	cm := NewCapabilityManager()
	for i := 0; i < b.N; i++ {
		cm.CalculateFinalCapabilities([]string{"sys_time"}, []string{"chown"}, false)
	}
}

func BenchmarkValidateCapability(b *testing.B) {
	cm := NewCapabilityManager()
	for i := 0; i < b.N; i++ {
		cm.ValidateCapability("chown")
	}
}
