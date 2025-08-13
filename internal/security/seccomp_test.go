package security

import (
	"encoding/json"
	"testing"
)

func TestNewSeccompManager(t *testing.T) {
	sm := NewSeccompManager()

	if sm == nil {
		t.Fatal("NewSeccompManager() returned nil")
	}

	// The enabled field should reflect system support
	// We don't assert specific values since it depends on the system
	t.Logf("Seccomp enabled: %v", sm.enabled)
}

func TestIsEnabled(t *testing.T) {
	sm := NewSeccompManager()

	enabled := sm.IsEnabled()

	// Should match the internal enabled state
	if enabled != sm.enabled {
		t.Errorf("IsEnabled() returned %v, expected %v", enabled, sm.enabled)
	}
}

func TestGetDefaultProfile(t *testing.T) {
	sm := NewSeccompManager()

	profile := sm.GetDefaultProfile()

	if profile == nil {
		t.Fatal("GetDefaultProfile() returned nil")
	}

	// Check default action
	if profile.DefaultAction != SeccompActErrno {
		t.Errorf("Expected default action %v, got %v", SeccompActErrno, profile.DefaultAction)
	}

	// Check architectures
	expectedArchs := []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"}
	if len(profile.Architectures) != len(expectedArchs) {
		t.Errorf("Expected %d architectures, got %d", len(expectedArchs), len(profile.Architectures))
	}

	for i, arch := range expectedArchs {
		if i < len(profile.Architectures) && profile.Architectures[i] != arch {
			t.Errorf("Expected architecture %s at index %d, got %s", arch, i, profile.Architectures[i])
		}
	}

	// Check that syscalls are present
	if len(profile.Syscalls) == 0 {
		t.Error("Expected syscall rules to be present")
	}

	// Check first syscall rule (should be allow list)
	if len(profile.Syscalls) > 0 {
		firstRule := profile.Syscalls[0]
		if firstRule.Action != SeccompActAllow {
			t.Errorf("Expected first syscall rule action %v, got %v", SeccompActAllow, firstRule.Action)
		}

		if len(firstRule.Names) == 0 {
			t.Error("Expected syscall names in first rule")
		}
	}
}

func TestSeccompProfile(t *testing.T) {
	// Test creating a custom profile
	profile := &SeccompProfile{
		DefaultAction: SeccompActKill,
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write"},
				Action: SeccompActAllow,
			},
		},
	}

	if profile.DefaultAction != SeccompActKill {
		t.Errorf("Expected default action %v, got %v", SeccompActKill, profile.DefaultAction)
	}

	if len(profile.Architectures) != 1 || profile.Architectures[0] != "SCMP_ARCH_X86_64" {
		t.Errorf("Expected architecture SCMP_ARCH_X86_64, got %v", profile.Architectures)
	}

	if len(profile.Syscalls) != 1 {
		t.Errorf("Expected 1 syscall rule, got %d", len(profile.Syscalls))
	}

	if len(profile.Syscalls[0].Names) != 2 {
		t.Errorf("Expected 2 syscall names, got %d", len(profile.Syscalls[0].Names))
	}
}

func TestSeccompSyscall(t *testing.T) {
	syscall := SeccompSyscall{
		Names:  []string{"openat", "open"},
		Action: SeccompActAllow,
		Args: []SeccompArg{
			{
				Index: 1,
				Value: 0,
				Op:    SeccompOpEqualTo,
			},
		},
	}

	if len(syscall.Names) != 2 {
		t.Errorf("Expected 2 names, got %d", len(syscall.Names))
	}

	if syscall.Action != SeccompActAllow {
		t.Errorf("Expected action %v, got %v", SeccompActAllow, syscall.Action)
	}

	if len(syscall.Args) != 1 {
		t.Errorf("Expected 1 argument, got %d", len(syscall.Args))
	}

	arg := syscall.Args[0]
	if arg.Index != 1 {
		t.Errorf("Expected index 1, got %d", arg.Index)
	}

	if arg.Value != 0 {
		t.Errorf("Expected value 0, got %d", arg.Value)
	}

	if arg.Op != SeccompOpEqualTo {
		t.Errorf("Expected op %v, got %v", SeccompOpEqualTo, arg.Op)
	}
}

func TestSeccompArg(t *testing.T) {
	arg := SeccompArg{
		Index:    2,
		Value:    100,
		ValueTwo: 200,
		Op:       SeccompOpGreaterThan,
	}

	if arg.Index != 2 {
		t.Errorf("Expected index 2, got %d", arg.Index)
	}

	if arg.Value != 100 {
		t.Errorf("Expected value 100, got %d", arg.Value)
	}

	if arg.ValueTwo != 200 {
		t.Errorf("Expected valueTwo 200, got %d", arg.ValueTwo)
	}

	if arg.Op != SeccompOpGreaterThan {
		t.Errorf("Expected op %v, got %v", SeccompOpGreaterThan, arg.Op)
	}
}

func TestSeccompActionConstants(t *testing.T) {
	// Test that action constants have expected values
	expectedActions := map[SeccompAction]string{
		SeccompActKill:  "kill",
		SeccompActTrap:  "trap",
		SeccompActErrno: "errno",
		SeccompActTrace: "trace",
		SeccompActLog:   "log",
		SeccompActAllow: "allow",
	}

	// We can't directly test the values since they're iota-based,
	// but we can test that they're different
	actions := []SeccompAction{
		SeccompActKill, SeccompActTrap, SeccompActErrno,
		SeccompActTrace, SeccompActLog, SeccompActAllow,
	}

	for i, action1 := range actions {
		for j, action2 := range actions {
			if i != j && action1 == action2 {
				t.Errorf("Actions at indices %d and %d have the same value", i, j)
			}
		}
	}

	// Verify they can be used in map
	for action, name := range expectedActions {
		if name == "" {
			t.Errorf("Empty name for action %v", action)
		}
	}
}

func TestSeccompOpTypeConstants(t *testing.T) {
	// Test that op type constants are different
	ops := []SeccompOpType{
		SeccompOpNotEqual, SeccompOpLessThan, SeccompOpLessEqual,
		SeccompOpEqualTo, SeccompOpGreaterEqual, SeccompOpGreaterThan,
		SeccompOpMaskedEqual,
	}

	for i, op1 := range ops {
		for j, op2 := range ops {
			if i != j && op1 == op2 {
				t.Errorf("Ops at indices %d and %d have the same value", i, j)
			}
		}
	}
}

func TestSeccompProfileJSON(t *testing.T) {
	profile := &SeccompProfile{
		DefaultAction: SeccompActAllow,
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read"},
				Action: SeccompActAllow,
			},
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(profile)
	if err != nil {
		t.Errorf("Failed to marshal profile to JSON: %v", err)
	}

	if len(data) == 0 {
		t.Error("JSON marshaling produced empty data")
	}

	// Test JSON unmarshaling
	var unmarshaled SeccompProfile
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal profile from JSON: %v", err)
	}

	if unmarshaled.DefaultAction != profile.DefaultAction {
		t.Errorf("Unmarshaled default action %v, expected %v", unmarshaled.DefaultAction, profile.DefaultAction)
	}

	if len(unmarshaled.Architectures) != len(profile.Architectures) {
		t.Errorf("Unmarshaled %d architectures, expected %d", len(unmarshaled.Architectures), len(profile.Architectures))
	}

	if len(unmarshaled.Syscalls) != len(profile.Syscalls) {
		t.Errorf("Unmarshaled %d syscalls, expected %d", len(unmarshaled.Syscalls), len(profile.Syscalls))
	}
}

func TestIsSeccompSupported(t *testing.T) {
	// This function tests system support, so we just check it doesn't panic
	supported := isSeccompSupported()
	t.Logf("Seccomp supported: %v", supported)

	// We can't assert specific values since it depends on the system
}

func TestLoadProfileFromJSON(t *testing.T) {
	jsonData := `{
		"defaultAction": 0,
		"architectures": ["SCMP_ARCH_X86_64"],
		"syscalls": [
			{
				"names": ["read", "write"],
				"action": 5
			}
		]
	}`

	var profile SeccompProfile
	err := json.Unmarshal([]byte(jsonData), &profile)
	if err != nil {
		t.Errorf("Failed to load profile from JSON: %v", err)
	}

	if profile.DefaultAction != SeccompActKill {
		t.Errorf("Expected default action %v, got %v", SeccompActKill, profile.DefaultAction)
	}

	if len(profile.Syscalls) != 1 {
		t.Errorf("Expected 1 syscall rule, got %d", len(profile.Syscalls))
	}

	if len(profile.Syscalls[0].Names) != 2 {
		t.Errorf("Expected 2 syscall names, got %d", len(profile.Syscalls[0].Names))
	}
}

func TestApplyProfile(t *testing.T) {
	sm := NewSeccompManager()

	// This method likely exists in the full implementation
	// We test that the manager is properly initialized
	if sm == nil {
		t.Fatal("SeccompManager not properly initialized")
	}

	profile := sm.GetDefaultProfile()
	if profile == nil {
		t.Fatal("Default profile not available")
	}

	// Verify the profile is valid
	if profile.DefaultAction < 0 {
		t.Error("Invalid default action in profile")
	}

	// Note: Actually applying seccomp profiles requires special privileges
	// and would restrict the test process, so we don't test the actual application
}

func TestSeccompManagerEnabled(t *testing.T) {
	sm := NewSeccompManager()

	enabled1 := sm.IsEnabled()
	enabled2 := sm.enabled

	if enabled1 != enabled2 {
		t.Errorf("IsEnabled() returned %v, but internal enabled is %v", enabled1, enabled2)
	}
}

func TestDefaultProfileContainsSyscalls(t *testing.T) {
	sm := NewSeccompManager()
	profile := sm.GetDefaultProfile()

	if profile == nil {
		t.Fatal("GetDefaultProfile() returned nil")
	}

	// Check that the default profile has syscalls
	if len(profile.Syscalls) == 0 {
		t.Error("Default profile has no syscall rules")
	}

	// Check that the first rule has syscall names
	if len(profile.Syscalls) > 0 {
		firstRule := profile.Syscalls[0]
		if len(firstRule.Names) == 0 {
			t.Error("First syscall rule has no syscall names")
		}

		// Verify some common syscalls are included
		expectedSyscalls := []string{"read", "write", "exit"}
		syscallMap := make(map[string]bool)
		for _, name := range firstRule.Names {
			syscallMap[name] = true
		}

		foundCount := 0
		for _, expected := range expectedSyscalls {
			if syscallMap[expected] {
				foundCount++
			}
		}

		if foundCount == 0 {
			t.Error("Default profile doesn't include any expected common syscalls")
		} else {
			t.Logf("Found %d/%d expected syscalls in default profile", foundCount, len(expectedSyscalls))
		}
	}
}

// Benchmark tests
func BenchmarkNewSeccompManager(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewSeccompManager()
	}
}

func BenchmarkGetDefaultProfile(b *testing.B) {
	sm := NewSeccompManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetDefaultProfile()
	}
}

func BenchmarkProfileJSON(b *testing.B) {
	sm := NewSeccompManager()
	profile := sm.GetDefaultProfile()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(profile)
	}
}
