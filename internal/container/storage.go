package container

import (
	"fmt"
	"os"
	"path/filepath"
)

// StorageManager handles container filesystem operations
type StorageManager struct {
	imageDir     string
	containerDir string
}

// NewStorageManager creates a new storage manager
func NewStorageManager(imageDir, containerDir string) (*StorageManager, error) {
	sm := &StorageManager{
		imageDir:     imageDir,
		containerDir: containerDir,
	}

	// Create required directories
	dirs := []string{
		imageDir,
		containerDir,
		filepath.Join(imageDir, "layers"),
		filepath.Join(imageDir, "images"),
		filepath.Join(containerDir, "rootfs"),
		filepath.Join(containerDir, "volumes"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return sm, nil
}
