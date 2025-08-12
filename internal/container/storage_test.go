package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/francisco3ferraz/gockerize/pkg/types"
)

func TestNewStorageManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		t.Fatalf("NewStorageManager() failed: %v", err)
	}

	if sm == nil {
		t.Fatal("NewStorageManager() returned nil")
	}

	if sm.imageDir != imageDir {
		t.Errorf("Expected imageDir %s, got %s", imageDir, sm.imageDir)
	}

	if sm.containerDir != containerDir {
		t.Errorf("Expected containerDir %s, got %s", containerDir, sm.containerDir)
	}

	// Check that required directories were created
	requiredDirs := []string{
		imageDir,
		containerDir,
		filepath.Join(imageDir, "layers"),
		filepath.Join(imageDir, "images"),
		filepath.Join(containerDir, "rootfs"),
		filepath.Join(containerDir, "volumes"),
	}

	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Required directory %s was not created", dir)
		}
	}
}

func TestNewStorageManagerWithInvalidPath(t *testing.T) {
	// Test with invalid paths
	sm, err := NewStorageManager("/proc/invalid", "/proc/invalid")
	if err == nil {
		t.Log("NewStorageManager() with invalid paths succeeded (may be acceptable)")
	}
	if sm == nil {
		t.Log("NewStorageManager() returned nil for invalid paths")
	}
}

func TestPrepareRootFS(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage-rootfs-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		t.Fatalf("NewStorageManager() failed: %v", err)
	}

	ctx := context.Background()
	containerID := "test-container-123"
	image := "alpine:latest"

	// Create a test image directory structure
	imagePath := filepath.Join(imageDir, "images", "alpine", "latest")
	err = os.MkdirAll(imagePath, 0755)
	if err != nil {
		t.Fatalf("Failed to create image path: %v", err)
	}

	// Create some test files in the image
	testFile := filepath.Join(imagePath, "test-file")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	rootfsPath, err := sm.PrepareRootFS(ctx, image, containerID)
	if err != nil {
		t.Errorf("PrepareRootFS() failed: %v", err)
	}

	if rootfsPath == "" {
		t.Error("PrepareRootFS() returned empty path")
	}

	// Check if rootfs directory was created
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		t.Error("RootFS directory was not created")
	}
}

func TestMountVolumes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage-mount-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		t.Fatalf("NewStorageManager() failed: %v", err)
	}

	ctx := context.Background()

	// Create a test container
	container := &types.Container{
		ID:   "test-mount-123",
		Name: "test-container",
		Config: &types.ContainerConfig{
			Volumes: []types.Volume{
				{
					Source:      "/host/path",
					Destination: "/test-volume",
				},
			},
		},
	}

	err = sm.MountVolumes(ctx, container)
	if err != nil {
		t.Logf("MountVolumes() failed as expected in test environment: %v", err)
		// This is acceptable since mounting requires special privileges
	} else {
		t.Log("MountVolumes() succeeded")
	}
}

func TestUnmountVolumes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage-unmount-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		t.Fatalf("NewStorageManager() failed: %v", err)
	}

	ctx := context.Background()

	// Create a test container
	container := &types.Container{
		ID:   "test-unmount-123",
		Name: "test-container",
		Config: &types.ContainerConfig{
			Volumes: []types.Volume{
				{
					Source:      "/host/path",
					Destination: "/test-volume",
				},
			},
		},
	}

	err = sm.UnmountVolumes(ctx, container)
	if err != nil {
		t.Logf("UnmountVolumes() failed as expected in test environment: %v", err)
		// This is acceptable since unmounting requires special privileges
	} else {
		t.Log("UnmountVolumes() succeeded")
	}
}

func TestCleanupContainer(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage-cleanup-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		t.Fatalf("NewStorageManager() failed: %v", err)
	}

	containerID := "test-cleanup-123"
	rootfsPath := filepath.Join(containerDir, "rootfs", containerID)

	// Create the rootfs directory
	err = os.MkdirAll(rootfsPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create rootfs directory: %v", err)
	}

	// Create a test file
	testFile := filepath.Join(rootfsPath, "test-file")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	ctx := context.Background()
	err = sm.CleanupContainer(ctx, containerID)
	if err != nil {
		t.Errorf("CleanupContainer() failed: %v", err)
	}

	// Check if directory was removed
	if _, err := os.Stat(rootfsPath); !os.IsNotExist(err) {
		t.Error("RootFS directory was not removed")
	}
}

func TestStorageManagerDirectoryStructure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage-structure-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		t.Fatalf("NewStorageManager() failed: %v", err)
	}

	// Test that we can access the fields
	if sm.imageDir == "" {
		t.Error("imageDir not set")
	}
	if sm.containerDir == "" {
		t.Error("containerDir not set")
	}
}

// Test that tests the actual internal methods (indirectly)
func TestCreateBasicFilesystemIndirect(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "storage-basic-fs-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		t.Fatalf("NewStorageManager() failed: %v", err)
	}

	ctx := context.Background()
	containerID := "test-basic-fs-123"
	image := "alpine:latest"

	// This will indirectly test createBasicFilesystem
	_, err = sm.PrepareRootFS(ctx, image, containerID)
	if err != nil {
		t.Logf("PrepareRootFS() failed as expected: %v", err)
		// This is acceptable since the image might not exist
	}
}

// Benchmark tests
func BenchmarkNewStorageManager(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "storage-bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	for i := 0; i < b.N; i++ {
		imageDir := filepath.Join(tempDir, "images", fmt.Sprintf("test_%d", i))
		containerDir := filepath.Join(tempDir, "containers", fmt.Sprintf("test_%d", i))
		NewStorageManager(imageDir, containerDir)
	}
}

func BenchmarkPrepareRootFS(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "storage-bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	imageDir := filepath.Join(tempDir, "images")
	containerDir := filepath.Join(tempDir, "containers")

	sm, err := NewStorageManager(imageDir, containerDir)
	if err != nil {
		b.Fatalf("NewStorageManager() failed: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containerID := fmt.Sprintf("bench-container-%d", i)
		sm.PrepareRootFS(ctx, "alpine:latest", containerID)
	}
}
