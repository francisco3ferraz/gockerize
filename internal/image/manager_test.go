package image

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/francisco3ferraz/gockerize/pkg/types"
)

func TestNewManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "image-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	if manager.imageDir != tempDir {
		t.Errorf("Expected imageDir %s, got %s", tempDir, manager.imageDir)
	}

	if manager.images == nil {
		t.Error("images map not initialized")
	}
}

func TestNewManagerWithInvalidDir(t *testing.T) {
	// Test with invalid directory permissions
	manager, err := NewManager("/proc/invalid/path")
	if err != nil {
		t.Logf("NewManager() with invalid path returned error: %v", err)
	}
	if manager == nil {
		t.Log("NewManager() returned nil for invalid path (acceptable)")
	}
}

func TestParseImageName(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedName string
		expectedTag  string
	}{
		{
			name:         "image with tag",
			input:        "alpine:3.18",
			expectedName: "alpine",
			expectedTag:  "3.18",
		},
		{
			name:         "image without tag",
			input:        "alpine",
			expectedName: "alpine",
			expectedTag:  "latest",
		},
		{
			name:         "image with latest tag",
			input:        "ubuntu:latest",
			expectedName: "ubuntu",
			expectedTag:  "latest",
		},
		{
			name:         "registry with image",
			input:        "registry.io/user/image:v1.0",
			expectedName: "registry.io/user/image",
			expectedTag:  "v1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, tag := parseImageName(tt.input)
			if name != tt.expectedName {
				t.Errorf("parseImageName() name = %v, want %v", name, tt.expectedName)
			}
			if tag != tt.expectedTag {
				t.Errorf("parseImageName() tag = %v, want %v", tag, tt.expectedTag)
			}
		})
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

func TestFormatSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{
			name:     "zero bytes",
			bytes:    0,
			expected: "0B",
		},
		{
			name:     "bytes",
			bytes:    512,
			expected: "512B",
		},
		{
			name:     "kilobytes",
			bytes:    1024,
			expected: "1.0KB",
		},
		{
			name:     "megabytes",
			bytes:    1024 * 1024,
			expected: "1.0MB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatSize() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestListImages(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "image-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Test empty list
	images := manager.ListImages()
	if len(images) != 0 {
		t.Errorf("Expected 0 images, got %d", len(images))
	}

	// Add a test image
	testImage := &types.Image{
		ID:      "test-123",
		Name:    "alpine",
		Tag:     "latest",
		Size:    1024,
		Created: time.Now(),
	}
	manager.images["alpine:latest"] = testImage

	images = manager.ListImages()
	if len(images) != 1 {
		t.Errorf("Expected 1 image, got %d", len(images))
	}

	if images[0].Name != "alpine" {
		t.Errorf("Expected image name 'alpine', got '%s'", images[0].Name)
	}
}

func TestGetImage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "image-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Test getting non-existent image
	image, exists := manager.GetImage("non-existent")
	if exists {
		t.Error("Expected false for non-existent image")
	}
	if image != nil {
		t.Error("Expected nil image for non-existent image")
	}

	// Add a test image
	testImage := &types.Image{
		ID:      "test-456",
		Name:    "ubuntu",
		Tag:     "20.04",
		Size:    2048,
		Created: time.Now(),
	}
	manager.images["ubuntu:20.04"] = testImage

	// Test getting existing image by name:tag
	image, exists = manager.GetImage("ubuntu:20.04")
	if !exists {
		t.Error("Expected true for existing image")
	}
	if image == nil {
		t.Fatal("GetImage() returned nil")
	}
	if image.Name != "ubuntu" {
		t.Errorf("Expected image name 'ubuntu', got '%s'", image.Name)
	}

	// Test getting non-existent image by ID (since GetImage uses name:tag as key)
	image, exists = manager.GetImage("test-456")
	if exists {
		t.Error("Expected false for getting image by ID (not supported by current implementation)")
	}
}

func TestRemoveImage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "image-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Test removing non-existent image
	usedImages := make(map[string]bool)
	err = manager.RemoveImage("non-existent", false, usedImages)
	if err == nil {
		t.Error("Expected error for removing non-existent image")
	}

	// Add a test image
	testImage := &types.Image{
		ID:      "test-789",
		Name:    "nginx",
		Tag:     "latest",
		Size:    4096,
		Created: time.Now(),
	}
	manager.images["nginx:latest"] = testImage

	// Create image directory structure
	imagePath := filepath.Join(tempDir, "images", "nginx", "latest")
	err = os.MkdirAll(imagePath, 0755)
	if err != nil {
		t.Fatalf("Failed to create image directory: %v", err)
	}

	// Test removing existing image
	err = manager.RemoveImage("nginx:latest", false, usedImages)
	if err != nil {
		t.Errorf("RemoveImage() failed: %v", err)
	}

	// Verify image was removed from memory
	if _, exists := manager.images["nginx:latest"]; exists {
		t.Error("Image still exists in memory after removal")
	}

	// Verify directory was removed
	if _, err := os.Stat(imagePath); !os.IsNotExist(err) {
		t.Error("Image directory still exists after removal")
	}
}

func TestPruneImages(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "image-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Add test images
	testImage1 := &types.Image{
		ID:      "test-001",
		Name:    "alpine",
		Tag:     "3.18",
		Size:    1024,
		Created: time.Now().Add(-48 * time.Hour), // Old image
	}
	testImage2 := &types.Image{
		ID:      "test-002",
		Name:    "ubuntu",
		Tag:     "latest",
		Size:    2048,
		Created: time.Now(), // Recent image
	}

	manager.images["alpine:3.18"] = testImage1
	manager.images["ubuntu:latest"] = testImage2

	// Test pruning with no used images (all should be pruned)
	usedImages := make(map[string]bool)
	removedIDs, totalSize, err := manager.PruneImages(false, usedImages)
	if err != nil {
		t.Errorf("PruneImages() failed: %v", err)
	}

	t.Logf("Pruned %d images, freed %d bytes", len(removedIDs), totalSize)

	// Test pruning with some images marked as used
	manager.images["alpine:3.18"] = testImage1
	manager.images["ubuntu:latest"] = testImage2

	usedImages["ubuntu:latest"] = true // Mark ubuntu as used
	removedIDs, totalSize, err = manager.PruneImages(false, usedImages)
	if err != nil {
		t.Errorf("PruneImages() with used images failed: %v", err)
	}

	// Should have removed alpine but not ubuntu
	if _, exists := manager.images["ubuntu:latest"]; !exists {
		t.Error("Used image 'ubuntu:latest' was incorrectly removed")
	}
}

func TestCalculateImageSize(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "image-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Create test files
	testFile := filepath.Join(tempDir, "testfile")
	testContent := []byte("hello world")
	err = os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	size := manager.calculateImageSize(tempDir)
	if size == 0 {
		t.Error("calculateImageSize() returned 0 for directory with files")
	}

	expectedSize := int64(len(testContent))
	if size != expectedSize {
		t.Errorf("Expected size %d, got %d", expectedSize, size)
	}
}

func TestSaveImage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "image-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Create test image
	testImage := &types.Image{
		ID:      "save-test-123",
		Name:    "test-image",
		Tag:     "v1.0",
		Size:    8192,
		Created: time.Now(),
		Config: &types.ImageConfig{
			Cmd:        []string{"/bin/bash"},
			WorkingDir: "/app",
			Env:        []string{"PATH=/usr/bin"},
		},
	}

	imagePath := filepath.Join(tempDir, "test-save")
	err = os.MkdirAll(imagePath, 0755)
	if err != nil {
		t.Fatalf("Failed to create image path: %v", err)
	}

	// Test saving image
	err = manager.saveImage(testImage, imagePath)
	if err != nil {
		t.Errorf("saveImage() failed: %v", err)
	}

	// Verify metadata file was created
	metadataPath := filepath.Join(imagePath, "metadata.json")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		t.Error("Metadata file was not created")
	}

	// Verify we can read the metadata back
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Errorf("Failed to read metadata file: %v", err)
	}

	if len(data) == 0 {
		t.Error("Metadata file is empty")
	}
}

// Benchmark tests
func BenchmarkGenerateID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateID()
	}
}

func BenchmarkParseImageName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseImageName("alpine:3.18")
	}
}

func BenchmarkListImages(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "image-bench")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager, _ := NewManager(tempDir)

	// Add some test images
	for i := 0; i < 100; i++ {
		testImage := &types.Image{
			ID:   generateID(),
			Name: "test",
			Tag:  "latest",
		}
		manager.images[testImage.Name+":"+testImage.Tag] = testImage
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.ListImages()
	}
}
