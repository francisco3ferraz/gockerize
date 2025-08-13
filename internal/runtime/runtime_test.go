package runtime

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/francisco3ferraz/gockerize/pkg/types"
)

func TestNew(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if runtime == nil {
		t.Fatal("New() returned nil")
	}

	// Check that containers map is initialized
	if runtime.containers == nil {
		t.Error("containers map not initialized")
	}

	// Check that images map is initialized
	if runtime.images == nil {
		t.Error("images map not initialized")
	}

	// Check that session ID was generated
	if runtime.sessionID == "" {
		t.Error("session ID not generated")
	}

	// Check that session start time is set
	if runtime.sessionStartTime.IsZero() {
		t.Error("session start time not set")
	}

	// Check that session containers map is initialized
	if runtime.sessionContainers == nil {
		t.Error("session containers map not initialized")
	}
}

func TestRuntimeDirectories(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Check that directory paths are set
	if runtime.runtimeDir == "" {
		t.Error("runtime directory not set")
	}

	if runtime.imageDir == "" {
		t.Error("image directory not set")
	}

	if runtime.containerDir == "" {
		t.Error("container directory not set")
	}

	if runtime.networkDir == "" {
		t.Error("network directory not set")
	}

	// Check that directories exist
	directories := []string{
		runtime.runtimeDir,
		runtime.imageDir,
		runtime.containerDir,
		runtime.networkDir,
	}

	for _, dir := range directories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory %s does not exist", dir)
		}
	}
}

func TestRuntimeManagers(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Check that managers are initialized
	if runtime.containerMgr == nil {
		t.Error("Container manager not initialized")
	}

	if runtime.networkMgr == nil {
		t.Error("Network manager not initialized")
	}

	if runtime.storageMgr == nil {
		t.Error("Storage manager not initialized")
	}

	if runtime.macMgr == nil {
		t.Error("MAC manager not initialized")
	}
}

func TestListContainers(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	// Test empty list
	containers, err := runtime.ListContainers(ctx, true)
	if err != nil {
		t.Errorf("ListContainers() failed: %v", err)
	}
	if len(containers) != 0 {
		t.Errorf("Expected 0 containers, got %d", len(containers))
	}

	// Add a test container
	testContainer := &types.Container{
		ID:        "test-123",
		Name:      "test-container",
		Image:     "alpine:latest",
		State:     types.StateCreated,
		CreatedAt: time.Now(),
	}
	runtime.containers["test-123"] = testContainer

	containers, err = runtime.ListContainers(ctx, true)
	if err != nil {
		t.Errorf("ListContainers() failed: %v", err)
	}
	if len(containers) != 1 {
		t.Errorf("Expected 1 container, got %d", len(containers))
	}

	if containers[0].Name != "test-container" {
		t.Errorf("Expected container name 'test-container', got '%s'", containers[0].Name)
	}
}

func TestGetContainer(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test getting non-existent container
	container, err := runtime.GetContainer("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent container")
	}
	if container != nil {
		t.Error("Expected nil container for non-existent container")
	}

	// Add a test container
	testContainer := &types.Container{
		ID:        "test-456",
		Name:      "test-container-2",
		Image:     "ubuntu:20.04",
		State:     types.StateCreated,
		CreatedAt: time.Now(),
	}
	runtime.containers["test-456"] = testContainer

	// Test getting existing container
	container, err = runtime.GetContainer("test-456")
	if err != nil {
		t.Errorf("GetContainer() failed: %v", err)
	}
	if container == nil {
		t.Fatal("GetContainer() returned nil")
	}
	if container.Name != "test-container-2" {
		t.Errorf("Expected container name 'test-container-2', got '%s'", container.Name)
	}
}

func TestListImages(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	// Test empty list
	images, err := runtime.ListImages(ctx)
	if err != nil {
		t.Errorf("ListImages() failed: %v", err)
	}
	if len(images) != 0 {
		t.Errorf("Expected 0 images, got %d", len(images))
	}

	// Add a test image
	testImage := &types.Image{
		ID:      "img-123",
		Name:    "alpine",
		Tag:     "latest",
		Size:    1024,
		Created: time.Now(),
	}
	runtime.images["alpine:latest"] = testImage

	images, err = runtime.ListImages(ctx)
	if err != nil {
		t.Errorf("ListImages() failed: %v", err)
	}
	if len(images) != 1 {
		t.Errorf("Expected 1 image, got %d", len(images))
	}

	if images[0].Name != "alpine" {
		t.Errorf("Expected image name 'alpine', got '%s'", images[0].Name)
	}
}

func TestGenerateID(t *testing.T) {
	// Generate multiple IDs to ensure they're unique
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateID()

		if len(id) == 0 {
			t.Error("generateID() returned empty string")
		}

		if ids[id] {
			t.Errorf("generateID() returned duplicate ID: %s", id)
		}
		ids[id] = true

		// Small delay to ensure different timestamps
		time.Sleep(time.Nanosecond)
	}
}

func TestRuntimeSessionTracking(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Check session tracking fields
	if runtime.sessionID == "" {
		t.Error("Session ID not set")
	}

	if runtime.sessionStartTime.IsZero() {
		t.Error("Session start time not set")
	}

	if runtime.sessionContainers == nil {
		t.Error("Session containers map not initialized")
	}

	// Test adding container to session
	runtime.sessionContainers["test-container-123"] = true

	if !runtime.sessionContainers["test-container-123"] {
		t.Error("Container not tracked in session")
	}
}

func TestRuntimeCleanup(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Add test containers to session
	runtime.sessionContainers["container-1"] = true
	runtime.sessionContainers["container-2"] = true

	// Test cleanup
	err = runtime.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() failed: %v", err)
	}

	// Verify cleanup was called (this mainly tests that the method exists and doesn't panic)
	t.Log("Cleanup completed successfully")
}

func TestRuntimeConcurrency(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test concurrent access to containers map
	const numGoroutines = 10
	doneCh := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			ctx := context.Background()
			// Read operation
			runtime.ListContainers(ctx, true)

			// Write operation
			runtime.mu.Lock()
			containerID := generateID()
			runtime.containers[containerID] = &types.Container{
				ID:        containerID,
				Name:      "concurrent-test",
				State:     types.StateCreated,
				CreatedAt: time.Now(),
			}
			runtime.mu.Unlock()

			doneCh <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-doneCh
	}

	// Verify all containers were added
	ctx := context.Background()
	containers, err := runtime.ListContainers(ctx, true)
	if err != nil {
		t.Errorf("ListContainers() failed: %v", err)
	}
	if len(containers) != numGoroutines {
		t.Errorf("Expected %d containers, got %d", numGoroutines, len(containers))
	}
}

func TestRuntimeStateMethods(t *testing.T) {
	runtime, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	// Test that all state methods exist and can be called
	containers, err := runtime.ListContainers(ctx, true)
	if err != nil {
		t.Errorf("ListContainers() failed: %v", err)
	}
	if containers == nil {
		t.Error("ListContainers() returned nil")
	}

	images, err := runtime.ListImages(ctx)
	if err != nil {
		t.Errorf("ListImages() failed: %v", err)
	}
	if images == nil {
		t.Error("ListImages() returned nil")
	}

	// Test GetContainer with non-existent ID
	_, err = runtime.GetContainer("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent container")
	}
}

// Benchmark tests
func BenchmarkListContainers(b *testing.B) {
	runtime, err := New()
	if err != nil {
		b.Fatalf("New() failed: %v", err)
	}

	// Add some test containers
	for i := 0; i < 100; i++ {
		containerID := generateID()
		runtime.containers[containerID] = &types.Container{
			ID:        containerID,
			Name:      "bench-container",
			State:     types.StateCreated,
			CreatedAt: time.Now(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		runtime.ListContainers(ctx, true)
	}
}

func BenchmarkGenerateID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateID()
	}
}
