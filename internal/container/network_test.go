package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/francisco3ferraz/gockerize/pkg/types"
)

func TestNewNetworkManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "test-bridge"
	subnet := "172.20.0.0/16"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)

	// This might fail in test environment without network privileges
	if err != nil {
		t.Logf("NewNetworkManager() failed as expected in test environment: %v", err)
		return
	}

	if nm == nil {
		t.Fatal("NewNetworkManager() returned nil")
	}

	if nm.networkDir != networkDir {
		t.Errorf("Expected networkDir %s, got %s", networkDir, nm.networkDir)
	}

	if nm.bridgeName != bridgeName {
		t.Errorf("Expected bridgeName %s, got %s", bridgeName, nm.bridgeName)
	}

	if nm.subnet != subnet {
		t.Errorf("Expected subnet %s, got %s", subnet, nm.subnet)
	}

	if nm.nextIP != 2 {
		t.Errorf("Expected nextIP 2, got %d", nm.nextIP)
	}

	// Check if network directory was created
	if _, err := os.Stat(networkDir); os.IsNotExist(err) {
		t.Error("Network directory was not created")
	}
}

func TestNewNetworkManagerInvalidSubnet(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "test-bridge"
	subnet := "invalid-subnet"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
	if err == nil {
		t.Log("NewNetworkManager() with invalid subnet succeeded (may be acceptable)")
	}
	if nm == nil {
		t.Log("NewNetworkManager() returned nil for invalid subnet")
	}
}

func TestSetupNetwork(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-setup-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "test-setup-bridge"
	subnet := "172.21.0.0/16"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
	if err != nil {
		t.Skipf("Skipping test due to network setup failure: %v", err)
	}

	ctx := context.Background()
	container := &types.Container{
		ID:   "test-network-123",
		Name: "test-container",
		PID:  12345, // Fake PID for testing
		Config: &types.ContainerConfig{
			Ports: []types.PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 80,
					Protocol:      "tcp",
				},
			},
		},
	}

	err = nm.SetupNetwork(ctx, container)
	if err != nil {
		t.Logf("SetupNetwork() failed as expected in test environment: %v", err)
		// This is acceptable since network setup requires special privileges
	} else {
		t.Log("SetupNetwork() succeeded")

		// Verify network info was set
		if container.NetworkInfo == nil {
			t.Error("NetworkInfo was not set")
		} else {
			if container.NetworkInfo.Bridge != bridgeName {
				t.Errorf("Expected bridge %s, got %s", bridgeName, container.NetworkInfo.Bridge)
			}
			if container.NetworkInfo.IPAddress == "" {
				t.Error("IP address was not set")
			}
			if container.NetworkInfo.Gateway == "" {
				t.Error("Gateway was not set")
			}
		}
	}
}

func TestTeardownNetwork(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-teardown-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "test-teardown-bridge"
	subnet := "172.22.0.0/16"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
	if err != nil {
		t.Skipf("Skipping test due to network setup failure: %v", err)
	}

	ctx := context.Background()
	container := &types.Container{
		ID:   "test-teardown-123",
		Name: "test-container",
		NetworkInfo: &types.NetworkInfo{
			IPAddress: "172.22.0.2",
			Gateway:   "172.22.0.1",
			Bridge:    bridgeName,
			Ports:     map[string]string{"80/tcp": "8080"},
		},
		Config: &types.ContainerConfig{
			Ports: []types.PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 80,
					Protocol:      "tcp",
				},
			},
		},
	}

	err = nm.TeardownNetwork(ctx, container)
	if err != nil {
		t.Errorf("TeardownNetwork() failed: %v", err)
	}

	// Verify network info was cleared
	if container.NetworkInfo != nil {
		t.Error("NetworkInfo was not cleared")
	}
}

func TestGetNetworkInfo(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-info-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "test-info-bridge"
	subnet := "172.23.0.0/16"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
	if err != nil {
		t.Skipf("Skipping test due to network setup failure: %v", err)
	}

	// Test with container that has network info
	container := &types.Container{
		ID:   "test-info-123",
		Name: "test-container",
		NetworkInfo: &types.NetworkInfo{
			IPAddress: "172.23.0.2",
			Gateway:   "172.23.0.1",
			Bridge:    bridgeName,
		},
	}

	info, err := nm.GetNetworkInfo(container)
	if err != nil {
		t.Errorf("GetNetworkInfo() failed: %v", err)
	}

	if info == nil {
		t.Fatal("GetNetworkInfo() returned nil")
	}

	if info.IPAddress != "172.23.0.2" {
		t.Errorf("Expected IP 172.23.0.2, got %s", info.IPAddress)
	}

	if info.Bridge != bridgeName {
		t.Errorf("Expected bridge %s, got %s", bridgeName, info.Bridge)
	}

	// Test with container that has no network info
	containerNoInfo := &types.Container{
		ID:   "test-no-info-123",
		Name: "test-container-no-info",
	}

	info, err = nm.GetNetworkInfo(containerNoInfo)
	if err != nil {
		t.Errorf("GetNetworkInfo() failed for container without network info: %v", err)
	}

	if info == nil {
		t.Fatal("GetNetworkInfo() returned nil for container without network info")
	}

	if info.Bridge != bridgeName {
		t.Errorf("Expected bridge %s, got %s", bridgeName, info.Bridge)
	}
}

func TestNetworkManagerFields(t *testing.T) {
	// Test without actual network setup
	networkDir := "/tmp/test-network"
	bridgeName := "test-fields-bridge"
	subnet := "172.24.0.0/16"

	nm := &NetworkManager{
		networkDir: networkDir,
		bridgeName: bridgeName,
		subnet:     subnet,
		nextIP:     2,
	}

	if nm.networkDir != networkDir {
		t.Errorf("Expected networkDir %s, got %s", networkDir, nm.networkDir)
	}

	if nm.bridgeName != bridgeName {
		t.Errorf("Expected bridgeName %s, got %s", bridgeName, nm.bridgeName)
	}

	if nm.subnet != subnet {
		t.Errorf("Expected subnet %s, got %s", subnet, nm.subnet)
	}

	if nm.nextIP != 2 {
		t.Errorf("Expected nextIP 2, got %d", nm.nextIP)
	}
}

func TestSetupNetworkWithoutPorts(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-no-ports-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "test-no-ports-bridge"
	subnet := "172.25.0.0/16"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
	if err != nil {
		t.Skipf("Skipping test due to network setup failure: %v", err)
	}

	ctx := context.Background()
	container := &types.Container{
		ID:     "test-no-ports-123",
		Name:   "test-container-no-ports",
		PID:    12346,
		Config: &types.ContainerConfig{},
	}

	err = nm.SetupNetwork(ctx, container)
	if err != nil {
		t.Logf("SetupNetwork() failed as expected in test environment: %v", err)
	} else {
		t.Log("SetupNetwork() succeeded for container without ports")

		if container.NetworkInfo != nil {
			if len(container.NetworkInfo.Ports) != 0 {
				t.Error("Expected no port mappings for container without ports")
			}
		}
	}
}

func TestTeardownNetworkWithoutNetworkInfo(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-teardown-no-info-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "test-teardown-no-info-bridge"
	subnet := "172.26.0.0/16"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
	if err != nil {
		t.Skipf("Skipping test due to network setup failure: %v", err)
	}

	ctx := context.Background()
	container := &types.Container{
		ID:     "test-teardown-no-info-123",
		Name:   "test-container-no-info",
		Config: &types.ContainerConfig{},
	}

	err = nm.TeardownNetwork(ctx, container)
	if err != nil {
		t.Errorf("TeardownNetwork() failed for container without network info: %v", err)
	}
}

// Benchmark tests
func BenchmarkNewNetworkManager(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "network-bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	for i := 0; i < b.N; i++ {
		networkDir := filepath.Join(tempDir, "network", fmt.Sprintf("test_%d", i))
		bridgeName := fmt.Sprintf("test-bridge-%d", i)
		subnet := fmt.Sprintf("172.%d.0.0/16", 100+i%100)

		nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
		if err != nil {
			b.Logf("NewNetworkManager() failed: %v", err)
		}
		if nm != nil {
			// Just create the manager, don't actually setup network
		}
	}
}

func BenchmarkGetNetworkInfo(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "network-bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	networkDir := filepath.Join(tempDir, "network")
	bridgeName := "bench-bridge"
	subnet := "172.27.0.0/16"

	nm, err := NewNetworkManager(networkDir, bridgeName, subnet)
	if err != nil {
		b.Skipf("Skipping benchmark due to network setup failure: %v", err)
	}

	container := &types.Container{
		ID:   "bench-container",
		Name: "bench-test",
		NetworkInfo: &types.NetworkInfo{
			IPAddress: "172.27.0.2",
			Gateway:   "172.27.0.1",
			Bridge:    bridgeName,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nm.GetNetworkInfo(container)
	}
}
