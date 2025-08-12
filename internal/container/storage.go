package container

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/francisco3ferraz/gockerize/pkg/types"
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

// PrepareRootFS prepares the root filesystem for a container
func (sm *StorageManager) PrepareRootFS(ctx context.Context, image string, containerID string) (string, error) {
	slog.Info("preparing rootfs for container", "container", containerID, "image", image)

	// Container rootfs directory
	rootfsDir := filepath.Join(sm.containerDir, "rootfs", containerID)

	// Create rootfs directory
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create rootfs directory: %w", err)
	}

	// For now, we'll create a simple Alpine-like filesystem
	// In a real implementation, you would extract image layers here
	if err := sm.createBasicFilesystem(rootfsDir, image); err != nil {
		return "", fmt.Errorf("failed to create basic filesystem: %w", err)
	}

	return rootfsDir, nil
}

// MountVolumes mounts volumes for a container
func (sm *StorageManager) MountVolumes(ctx context.Context, container *types.Container) error {
	if len(container.Config.Volumes) == 0 {
		return nil
	}

	for _, volume := range container.Config.Volumes {
		// Resolve destination path relative to container rootfs
		destPath := filepath.Join(container.Config.RootFS, strings.TrimPrefix(volume.Destination, "/"))

		// Create destination directory
		if err := os.MkdirAll(destPath, 0755); err != nil {
			return fmt.Errorf("failed to create volume destination %s: %w", destPath, err)
		}

		// Mount flags
		flags := uintptr(syscall.MS_BIND)
		if volume.ReadOnly {
			flags |= syscall.MS_RDONLY
		}

		// Bind mount the volume
		if err := syscall.Mount(volume.Source, destPath, "", flags, ""); err != nil {
			return fmt.Errorf("failed to mount volume %s -> %s: %w", volume.Source, destPath, err)
		}

		slog.Debug("volume mounted",
			"source", volume.Source,
			"destination", volume.Destination,
			"readonly", volume.ReadOnly)
	}

	return nil
}

// UnmountVolumes unmounts volumes for a container
func (sm *StorageManager) UnmountVolumes(ctx context.Context, container *types.Container) error {
	if len(container.Config.Volumes) == 0 {
		return nil
	}

	for _, volume := range container.Config.Volumes {
		destPath := filepath.Join(container.Config.RootFS, strings.TrimPrefix(volume.Destination, "/"))

		if err := syscall.Unmount(destPath, 0); err != nil {
			slog.Warn("failed to unmount volume",
				"path", destPath,
				"error", err)
		}
	}

	return nil
}

// CleanupContainer cleans up container storage
func (sm *StorageManager) CleanupContainer(ctx context.Context, containerID string) error {
	// Remove container rootfs
	rootfsDir := filepath.Join(sm.containerDir, "rootfs", containerID)
	if err := os.RemoveAll(rootfsDir); err != nil {
		slog.Warn("failed to remove rootfs directory", "path", rootfsDir, "error", err)
	}

	// Remove any container-specific volume directories
	volumeDir := filepath.Join(sm.containerDir, "volumes", containerID)
	if err := os.RemoveAll(volumeDir); err != nil {
		slog.Warn("failed to remove volume directory", "path", volumeDir, "error", err)
	}

	return nil
}

// parseImageName extracts the image name and tag from a full image reference
func parseImageName(image string) (string, string) {
	parts := strings.Split(image, ":")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return image, "latest"
}

// createBasicFilesystem creates a minimal filesystem structure
func (sm *StorageManager) createBasicFilesystem(rootfsDir, image string) error {
	slog.Debug("creating basic filesystem", "rootfs", rootfsDir, "image", image)

	// Parse image name to get correct path
	// Convert "redis:latest" to "redis/latest"
	imageName, tag := parseImageName(image)
	imageSubPath := filepath.Join(imageName, tag)

	// Check if we have a real image directory to copy from
	imagePath := filepath.Join(sm.imageDir, "images", imageSubPath)
	slog.Debug("checking image path", "imagePath", imagePath)
	if _, err := os.Stat(imagePath); err == nil {
		slog.Info("found image directory, copying to rootfs", "imagePath", imagePath, "rootfs", rootfsDir)
		// Copy from existing image
		return sm.copyImageToRootfs(imagePath, rootfsDir)
	}

	// Return error instead of falling back to basic filesystem
	return fmt.Errorf("image not found: %s. Use 'gockerize pull %s' to download it", image, image)
}

// copyImageToRootfs copies an image directory to the container rootfs
func (sm *StorageManager) copyImageToRootfs(imagePath, rootfsDir string) error {
	slog.Debug("copying image to rootfs", "image", imagePath, "rootfs", rootfsDir)

	// Use cp command for efficient copying
	cmd := exec.Command("cp", "-a", imagePath+"/.", rootfsDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy image: %w", err)
	}

	return nil
}
