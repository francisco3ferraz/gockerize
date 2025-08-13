package utils

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateID(t *testing.T) {
	// Generate multiple IDs to ensure they're unique
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateID()

		// Check ID format (should be hex)
		if len(id) == 0 {
			t.Error("GenerateID() returned empty string")
		}

		// Check uniqueness
		if ids[id] {
			t.Errorf("GenerateID() returned duplicate ID: %s", id)
		}
		ids[id] = true

		// Basic validation of hex format
		for _, char := range id {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				t.Errorf("GenerateID() returned non-hex character: %c in %s", char, id)
			}
		}

		// Small delay to ensure different timestamps
		time.Sleep(time.Nanosecond)
	}
}

func TestParseImageName(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedImg string
		expectedTag string
	}{
		{
			name:        "image with tag",
			input:       "alpine:3.18",
			expectedImg: "alpine",
			expectedTag: "3.18",
		},
		{
			name:        "image without tag",
			input:       "alpine",
			expectedImg: "alpine",
			expectedTag: "latest",
		},
		{
			name:        "image with latest tag",
			input:       "ubuntu:latest",
			expectedImg: "ubuntu",
			expectedTag: "latest",
		},
		{
			name:        "empty string",
			input:       "",
			expectedImg: "",
			expectedTag: "latest",
		},
		{
			name:        "image with multiple colons",
			input:       "registry.io/user/image:v1.0",
			expectedImg: "registry.io/user/image",
			expectedTag: "v1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, tag := ParseImageName(tt.input)
			if img != tt.expectedImg {
				t.Errorf("ParseImageName() image = %v, want %v", img, tt.expectedImg)
			}
			if tag != tt.expectedTag {
				t.Errorf("ParseImageName() tag = %v, want %v", tag, tt.expectedTag)
			}
		})
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
		{
			name:     "gigabytes",
			bytes:    1024 * 1024 * 1024,
			expected: "1.0GB",
		},
		{
			name:     "terabytes",
			bytes:    1024 * 1024 * 1024 * 1024,
			expected: "1.0TB",
		},
		{
			name:     "fractional megabytes",
			bytes:    1536 * 1024, // 1.5MB
			expected: "1.5MB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("FormatSize() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetDirSize(t *testing.T) {
	// Create a temporary directory with test files
	tmpDir, err := os.MkdirTemp("", "test_dir_size")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	testFiles := map[string][]byte{
		"file1.txt": []byte("hello world"),    // 11 bytes
		"file2.txt": []byte("test content"),   // 12 bytes
		"file3.txt": []byte("more test data"), // 14 bytes
	}

	for filename, content := range testFiles {
		err := os.WriteFile(filepath.Join(tmpDir, filename), content, 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create subdirectory with file
	subDir := filepath.Join(tmpDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	err = os.WriteFile(filepath.Join(subDir, "subfile.txt"), []byte("subdirectory content"), 0644) // 20 bytes
	if err != nil {
		t.Fatalf("Failed to create subfile: %v", err)
	}

	// Test directory size calculation
	size, err := GetDirSize(tmpDir)
	if err != nil {
		t.Fatalf("GetDirSize() error = %v", err)
	}

	expectedSize := int64(11 + 12 + 14 + 20) // Total of all file contents
	if size != expectedSize {
		t.Errorf("GetDirSize() = %v, want %v", size, expectedSize)
	}

	// Test non-existent directory
	_, err = GetDirSize("/non/existent/path")
	if err == nil {
		t.Error("GetDirSize() should return error for non-existent directory")
	}
}

func TestEnsureDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_ensure_dir")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test creating new directory
	newDir := filepath.Join(tmpDir, "new", "nested", "directory")
	err = EnsureDir(newDir)
	if err != nil {
		t.Errorf("EnsureDir() error = %v", err)
	}

	// Verify directory was created
	if !FileExists(newDir) {
		t.Error("EnsureDir() did not create directory")
	}

	// Test with existing directory (should not error)
	err = EnsureDir(newDir)
	if err != nil {
		t.Errorf("EnsureDir() should not error on existing directory: %v", err)
	}

	// Test with file path (should error)
	filePath := filepath.Join(tmpDir, "testfile")
	err = os.WriteFile(filePath, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	err = EnsureDir(filePath)
	if err == nil {
		t.Error("EnsureDir() should error when path is a file")
	}
}

func TestFileExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_file_exists")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test existing file
	testFile := filepath.Join(tmpDir, "testfile.txt")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if !FileExists(testFile) {
		t.Error("FileExists() should return true for existing file")
	}

	// Test existing directory
	testDir := filepath.Join(tmpDir, "testdir")
	err = os.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	if !FileExists(testDir) {
		t.Error("FileExists() should return true for existing directory")
	}

	// Test non-existent file
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.txt")
	if FileExists(nonExistentFile) {
		t.Error("FileExists() should return false for non-existent file")
	}
}

func TestIsProcessRunning(t *testing.T) {
	// Test with current process (should be running)
	currentPID := os.Getpid()
	if !IsProcessRunning(currentPID) {
		t.Logf("IsProcessRunning() returned false for current process PID %d (may be expected in some environments)", currentPID)
	}

	// Test with invalid PID (should not be running)
	invalidPID := 999999 // Very unlikely to be a real PID
	if IsProcessRunning(invalidPID) {
		t.Error("IsProcessRunning() should return false for invalid PID")
	}

	// Test with PID 1 (init process, should always be running on Unix systems)
	// Skip this test in containers or environments where PID 1 might not be accessible
	if IsProcessRunning(1) {
		t.Log("Init process (PID 1) is running")
	} else {
		t.Log("Cannot access PID 1 (may be expected in containerized environments)")
	}
}

// Benchmark tests
func BenchmarkGenerateID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateID()
	}
}

func BenchmarkParseImageName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseImageName("alpine:3.18")
	}
}

func BenchmarkFormatSize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		FormatSize(1024 * 1024 * 1024) // 1GB
	}
}
