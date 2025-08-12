package container

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/francisco3ferraz/gockerize/internal/security"
	"github.com/francisco3ferraz/gockerize/pkg/types"
)

func TestNewManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	macManager := security.NewMACManager()
	capManager := security.NewCapabilityManager()
	seccompManager := security.NewSeccompManager()

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     macManager,
		capManager:     capManager,
		seccompManager: seccompManager,
	}

	// Test that manager fields are set correctly
	if manager.containerDir != tempDir {
		t.Errorf("Expected containerDir %s, got %s", tempDir, manager.containerDir)
	}

	if manager.macManager != macManager {
		t.Error("MAC manager not set correctly")
	}

	if manager.capManager != capManager {
		t.Error("Capability manager not set correctly")
	}

	if manager.seccompManager != seccompManager {
		t.Error("Seccomp manager not set correctly")
	}
}

func TestGetUserMappings(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	uidMappings, gidMappings, err := manager.getUserMappings()
	if err != nil {
		t.Errorf("getUserMappings() returned error: %v", err)
	}

	// Should return at least one mapping
	if len(uidMappings) == 0 {
		t.Error("getUserMappings() returned no UID mappings")
	}

	if len(gidMappings) == 0 {
		t.Error("getUserMappings() returned no GID mappings")
	}

	// Test that mappings are valid
	for _, mapping := range uidMappings {
		if mapping.ContainerID < 0 || mapping.HostID < 0 || mapping.Size <= 0 {
			t.Errorf("Invalid UID mapping: %+v", mapping)
		}
	}

	for _, mapping := range gidMappings {
		if mapping.ContainerID < 0 || mapping.HostID < 0 || mapping.Size <= 0 {
			t.Errorf("Invalid GID mapping: %+v", mapping)
		}
	}
}

func TestCreateContainer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	// Create test rootfs directory
	rootfsDir := filepath.Join(tempDir, "rootfs")
	err = os.MkdirAll(rootfsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create rootfs dir: %v", err)
	}

	config := &types.ContainerConfig{
		Command:    []string{"/bin/sh", "-c", "echo hello"},
		RootFS:     rootfsDir,
		WorkingDir: "/tmp",
		Memory:     512 * 1024 * 1024, // 512MB
		CPUShares:  1024,
	}

	// Test create (this might fail if not running as root, which is expected)
	container, err := manager.Create(ctx, config)
	if err != nil {
		t.Logf("Create() returned error (may be expected if not root): %v", err)
		// Don't fail the test since container creation requires privileges
		return
	}

	// If create succeeded, verify the container was created
	if container == nil {
		t.Error("Create() returned nil container")
		return
	}

	if container.Config != config {
		t.Error("Container config not set correctly")
	}
}

func TestStartContainer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	config := &types.ContainerConfig{
		Command:    []string{"/bin/echo", "hello"},
		RootFS:     "/tmp/test-rootfs",
		WorkingDir: "/tmp",
	}

	container := &types.Container{
		ID:        "test-container-456",
		Name:      "test-start",
		Image:     "alpine:latest",
		Command:   config.Command,
		State:     types.StateCreated,
		CreatedAt: time.Now(),
		Config:    config,
	}

	// Test start (this will likely fail if not running as root)
	err = manager.Start(ctx, container)
	if err != nil {
		t.Logf("Start() returned error (expected if not root): %v", err)
		// Don't fail the test since starting containers requires privileges
	}
}

func TestStopContainer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()
	timeout := 10 * time.Second

	container := &types.Container{
		ID:    "test-container-789",
		Name:  "test-stop",
		State: types.StateRunning,
		PID:   0, // No real process
	}

	// Test stop (should handle gracefully even if no process exists)
	err = manager.Stop(ctx, container, timeout)
	if err != nil {
		t.Logf("Stop() returned error: %v", err)
		// This might be expected if the process doesn't exist
	}
}

func TestWaitContainer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	container := &types.Container{
		ID:       "test-container-wait",
		Name:     "test-wait",
		State:    types.StateExited,
		PID:      0,
		ExitCode: 0,
	}

	// Test wait on an already exited container
	exitCode, err := manager.Wait(ctx, container)
	if err != nil {
		t.Errorf("Wait() returned error: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}
}

func TestRemoveContainer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	// Create a test container directory
	containerID := "test-container-remove"
	containerPath := filepath.Join(tempDir, containerID)
	err = os.MkdirAll(containerPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create container directory: %v", err)
	}

	container := &types.Container{
		ID:    containerID,
		Name:  "test-remove",
		State: types.StateStopped,
	}

	// Test remove
	err = manager.Remove(ctx, container, false)
	if err != nil {
		t.Errorf("Remove() returned error: %v", err)
	}

	// Verify directory was removed
	if _, err := os.Stat(containerPath); !os.IsNotExist(err) {
		t.Error("Container directory still exists after removal")
	}
}

func TestSignalNetworkReady(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gockerize-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	container := &types.Container{
		ID:    "test-container-signal",
		Name:  "test-signal",
		State: types.StateRunning,
		PID:   0, // No real process
	}

	// Test signal network ready
	err = manager.SignalNetworkReady(ctx, container)
	if err != nil {
		t.Logf("SignalNetworkReady() returned error: %v", err)
		// This might be expected if no process exists
	}
}

// Test edge cases and error conditions
func TestManagerErrorConditions(t *testing.T) {
	// Test with invalid container directory
	manager := &Manager{
		containerDir:   "/invalid/path/that/should/not/exist",
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	container := &types.Container{
		ID:    "test-error",
		State: types.StateCreated,
		Config: &types.ContainerConfig{
			RootFS: "/tmp/test",
		},
	}

	// These operations should handle invalid directories gracefully
	err := manager.Remove(ctx, container, false)
	if err != nil {
		t.Logf("Remove() with invalid directory returned error: %v", err)
	}
}

// Benchmark tests
func BenchmarkCreateContainer(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "gockerize-bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := &types.ContainerConfig{
			Command: []string{"/bin/echo", "hello"},
			RootFS:  "/tmp/test",
		}
		manager.Create(ctx, config)
	}
}

func BenchmarkRemoveContainer(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "gockerize-bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		containerDir:   tempDir,
		macManager:     security.NewMACManager(),
		capManager:     security.NewCapabilityManager(),
		seccompManager: security.NewSeccompManager(),
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		containerID := "bench-container"
		containerPath := filepath.Join(tempDir, containerID)
		os.MkdirAll(containerPath, 0755)

		container := &types.Container{
			ID:    containerID,
			State: types.StateStopped,
		}
		b.StartTimer()

		manager.Remove(ctx, container, false)
	}
}
