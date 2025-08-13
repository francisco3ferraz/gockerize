package types

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestContainerStateValues(t *testing.T) {
	states := []ContainerState{
		StateCreated,
		StateRunning,
		StateStopped,
		StateExited,
		StatePaused,
	}

	expectedValues := []string{
		"created",
		"running",
		"stopped",
		"exited",
		"paused",
	}

	for i, state := range states {
		if string(state) != expectedValues[i] {
			t.Errorf("State %d: expected %s, got %s", i, expectedValues[i], string(state))
		}
	}
}

func TestContainerCreation(t *testing.T) {
	now := time.Now()

	container := &Container{
		ID:        "test-container-123",
		Name:      "test-container",
		Image:     "alpine:latest",
		Command:   []string{"/bin/sh", "-c", "echo hello"},
		State:     StateCreated,
		CreatedAt: now,
		Config: &ContainerConfig{
			Command:    []string{"/bin/sh"},
			Memory:     512 * 1024 * 1024, // 512MB
			CPUShares:  1024,
			WorkingDir: "/app",
			RootFS:     "/var/lib/gockerize/containers/test-container-123/rootfs",
		},
	}

	// Test basic container properties
	if container.ID != "test-container-123" {
		t.Errorf("Expected ID 'test-container-123', got '%s'", container.ID)
	}

	if container.Name != "test-container" {
		t.Errorf("Expected Name 'test-container', got '%s'", container.Name)
	}

	if container.Image != "alpine:latest" {
		t.Errorf("Expected Image 'alpine:latest', got '%s'", container.Image)
	}

	if container.State != StateCreated {
		t.Errorf("Expected State '%s', got '%s'", StateCreated, container.State)
	}

	if container.CreatedAt != now {
		t.Errorf("Expected CreatedAt '%v', got '%v'", now, container.CreatedAt)
	}

	// Test config
	if container.Config == nil {
		t.Fatal("Expected Config to be non-nil")
	}

	if container.Config.Memory != 512*1024*1024 {
		t.Errorf("Expected Memory '536870912', got '%d'", container.Config.Memory)
	}

	if container.Config.CPUShares != 1024 {
		t.Errorf("Expected CPUShares '1024', got '%d'", container.Config.CPUShares)
	}

	if container.Config.WorkingDir != "/app" {
		t.Errorf("Expected WorkingDir '/app', got '%s'", container.Config.WorkingDir)
	}
}

func TestContainerStateTransitions(t *testing.T) {
	container := &Container{
		ID:        "state-test",
		State:     StateCreated,
		CreatedAt: time.Now(),
	}

	// Test state transitions
	container.State = StateRunning
	if container.State != StateRunning {
		t.Errorf("Failed to transition to running state")
	}

	container.State = StateStopped
	if container.State != StateStopped {
		t.Errorf("Failed to transition to stopped state")
	}

	container.State = StateExited
	if container.State != StateExited {
		t.Errorf("Failed to transition to exited state")
	}
}

func TestContainerConfigDefaults(t *testing.T) {
	config := &ContainerConfig{
		RootFS: "/tmp/test-rootfs",
	}

	// Test that required fields are set
	if config.RootFS == "" {
		t.Error("RootFS should not be empty")
	}

	// Test default values for optional fields
	if config.Memory < 0 {
		t.Error("Memory should not be negative")
	}

	if config.CPUShares < 0 {
		t.Error("CPUShares should not be negative")
	}
}

func TestNetworkInfoCreation(t *testing.T) {
	networkInfo := &NetworkInfo{
		Bridge:    "gockerize0",
		IPAddress: "172.17.0.2",
		Gateway:   "172.17.0.1",
		Ports:     map[string]string{"80": "8080", "443": "8443"},
	}

	if networkInfo.Bridge != "gockerize0" {
		t.Errorf("Expected Bridge 'gockerize0', got '%s'", networkInfo.Bridge)
	}

	if networkInfo.IPAddress != "172.17.0.2" {
		t.Errorf("Expected IPAddress '172.17.0.2', got '%s'", networkInfo.IPAddress)
	}

	if networkInfo.Gateway != "172.17.0.1" {
		t.Errorf("Expected Gateway '172.17.0.1', got '%s'", networkInfo.Gateway)
	}

	if networkInfo.Ports["80"] != "8080" {
		t.Errorf("Expected port mapping '80' -> '8080', got '%s'", networkInfo.Ports["80"])
	}
}

func TestPortMappingCreation(t *testing.T) {
	portMapping := &PortMapping{
		HostPort:      8080,
		ContainerPort: 80,
		Protocol:      "tcp",
	}

	if portMapping.HostPort != 8080 {
		t.Errorf("Expected HostPort 8080, got %d", portMapping.HostPort)
	}

	if portMapping.ContainerPort != 80 {
		t.Errorf("Expected ContainerPort 80, got %d", portMapping.ContainerPort)
	}

	if portMapping.Protocol != "tcp" {
		t.Errorf("Expected Protocol 'tcp', got '%s'", portMapping.Protocol)
	}
}

func TestVolumeCreation(t *testing.T) {
	volume := &Volume{
		Source:      "/host/data",
		Destination: "/container/data",
		ReadOnly:    false,
	}

	if volume.Source != "/host/data" {
		t.Errorf("Expected Source '/host/data', got '%s'", volume.Source)
	}

	if volume.Destination != "/container/data" {
		t.Errorf("Expected Destination '/container/data', got '%s'", volume.Destination)
	}

	if volume.ReadOnly != false {
		t.Errorf("Expected ReadOnly false, got %t", volume.ReadOnly)
	}

	// Test read-only volume
	readOnlyVolume := &Volume{
		Source:      "/host/config",
		Destination: "/container/config",
		ReadOnly:    true,
	}

	if readOnlyVolume.ReadOnly != true {
		t.Errorf("Expected ReadOnly true, got %t", readOnlyVolume.ReadOnly)
	}
}

func TestContainerWithCompleteConfig(t *testing.T) {
	now := time.Now()
	started := now.Add(1 * time.Second)

	container := &Container{
		ID:        "complete-test",
		Name:      "complete-container",
		Image:     "ubuntu:20.04",
		Command:   []string{"/bin/bash", "-c", "sleep 3600"},
		State:     StateRunning,
		PID:       12345,
		CreatedAt: now,
		StartedAt: &started,
		Config: &ContainerConfig{
			Command:    []string{"/bin/bash"},
			Memory:     1024 * 1024 * 1024, // 1GB
			CPUShares:  2048,
			CPUQuota:   100000, // 100ms
			CPUPeriod:  100000, // 100ms
			WorkingDir: "/workspace",
			RootFS:     "/var/lib/gockerize/containers/complete-test/rootfs",
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"HOME=/root",
			},
			Hostname: "test-container",
			Ports: []PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 80,
					Protocol:      "tcp",
				},
				{
					HostPort:      8443,
					ContainerPort: 443,
					Protocol:      "tcp",
				},
			},
			Volumes: []Volume{
				{
					Source:      "/host/data",
					Destination: "/data",
					ReadOnly:    false,
				},
				{
					Source:      "/host/config",
					Destination: "/etc/app",
					ReadOnly:    true,
				},
			},
		},
		NetworkInfo: &NetworkInfo{
			Bridge:    "gockerize0",
			IPAddress: "172.17.0.10",
			Gateway:   "172.17.0.1",
			Ports:     map[string]string{"80": "8080", "443": "8443"},
		},
	}

	// Verify all fields are set correctly
	if container.PID != 12345 {
		t.Errorf("Expected PID 12345, got %d", container.PID)
	}

	if container.StartedAt == nil {
		t.Error("Expected StartedAt to be non-nil")
	} else if *container.StartedAt != started {
		t.Errorf("Expected StartedAt '%v', got '%v'", started, *container.StartedAt)
	}

	// Verify environment variables
	if len(container.Config.Env) != 2 {
		t.Errorf("Expected 2 environment variables, got %d", len(container.Config.Env))
	}

	pathFound := false
	for _, env := range container.Config.Env {
		if strings.HasPrefix(env, "PATH=") {
			pathFound = true
			break
		}
	}
	if !pathFound {
		t.Error("Expected PATH environment variable to be set")
	}

	// Verify port mappings
	if len(container.Config.Ports) != 2 {
		t.Errorf("Expected 2 port mappings, got %d", len(container.Config.Ports))
	}

	// Verify volumes
	if len(container.Config.Volumes) != 2 {
		t.Errorf("Expected 2 volumes, got %d", len(container.Config.Volumes))
	}

	// Test read-only volume
	readOnlyVolume := container.Config.Volumes[1]
	if !readOnlyVolume.ReadOnly {
		t.Error("Expected second volume to be read-only")
	}
}

// Mock implementation for testing interface compliance
type mockRuntime struct{}

func (m *mockRuntime) CreateContainer(ctx context.Context, config *ContainerConfig) (*Container, error) {
	return &Container{
		ID:        "mock-container",
		State:     StateCreated,
		CreatedAt: time.Now(),
		Config:    config,
	}, nil
}

func (m *mockRuntime) StartContainer(ctx context.Context, containerID string) error {
	return nil
}

func (m *mockRuntime) StopContainer(ctx context.Context, containerID string, timeout time.Duration) error {
	return nil
}

func (m *mockRuntime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	return nil
}

func (m *mockRuntime) WaitContainer(ctx context.Context, containerID string) (int, error) {
	return 0, nil
}

func (m *mockRuntime) GetContainer(containerID string) (*Container, error) {
	return &Container{
		ID:    containerID,
		State: StateRunning,
	}, nil
}

func (m *mockRuntime) ListContainers(ctx context.Context, all bool) ([]*Container, error) {
	return []*Container{
		{
			ID:    "container1",
			State: StateRunning,
		},
		{
			ID:    "container2",
			State: StateStopped,
		},
	}, nil
}

func (m *mockRuntime) PullImage(ctx context.Context, name string) (*Image, error) {
	return &Image{
		ID:   "mock-image",
		Name: name,
		Tag:  "latest",
	}, nil
}

func (m *mockRuntime) ListImages(ctx context.Context) ([]*Image, error) {
	return []*Image{
		{
			ID:   "image1",
			Name: "alpine",
			Tag:  "latest",
		},
	}, nil
}

func (m *mockRuntime) RemoveImage(ctx context.Context, imageID string, force bool) error {
	return nil
}

func (m *mockRuntime) PruneImages(ctx context.Context, all bool) ([]string, int64, error) {
	return []string{}, 0, nil
}

func (m *mockRuntime) Cleanup() error {
	return nil
}

func TestRuntimeInterface(t *testing.T) {
	// Test that our mock implements the Runtime interface
	var _ Runtime = (*mockRuntime)(nil)

	runtime := &mockRuntime{}
	ctx := context.Background()

	// Test CreateContainer
	config := &ContainerConfig{
		RootFS: "/tmp/test",
	}
	container, err := runtime.CreateContainer(ctx, config)
	if err != nil {
		t.Errorf("CreateContainer failed: %v", err)
	}
	if container == nil {
		t.Error("CreateContainer returned nil container")
	}

	// Test ListContainers
	containers, err := runtime.ListContainers(ctx, true)
	if err != nil {
		t.Errorf("ListContainers failed: %v", err)
	}
	if len(containers) != 2 {
		t.Errorf("Expected 2 containers, got %d", len(containers))
	}
}

// Benchmark tests
func BenchmarkContainerCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		container := &Container{
			ID:        "bench-test",
			State:     StateCreated,
			CreatedAt: time.Now(),
			Config: &ContainerConfig{
				RootFS: "/tmp/test",
			},
		}
		_ = container
	}
}

func BenchmarkContainerConfigCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		config := &ContainerConfig{
			Command:    []string{"/bin/sh"},
			Memory:     512 * 1024 * 1024,
			CPUShares:  1024,
			WorkingDir: "/app",
			RootFS:     "/tmp/test",
			Env: []string{
				"PATH=/usr/bin",
			},
		}
		_ = config
	}
}
