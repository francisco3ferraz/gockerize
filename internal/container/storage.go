package container

import (
	"context"
	"fmt"
	"io"
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

	slog.Info("rootfs prepared", "container", containerID, "path", rootfsDir)
	return rootfsDir, nil
}

// MountVolumes mounts volumes for a container
func (sm *StorageManager) MountVolumes(ctx context.Context, container *types.Container) error {
	if len(container.Config.Volumes) == 0 {
		return nil
	}

	slog.Info("mounting volumes for container", "container", container.ID, "count", len(container.Config.Volumes))

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

	slog.Info("unmounting volumes for container", "container", container.ID)

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
	slog.Info("cleaning up storage for container", "container", containerID)

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

// createBasicFilesystem creates a minimal filesystem structure
func (sm *StorageManager) createBasicFilesystem(rootfsDir, image string) error {
	slog.Debug("creating basic filesystem", "rootfs", rootfsDir, "image", image)

	// Check if we have a real image directory to copy from
	imagePath := filepath.Join(sm.imageDir, "images", image)
	if _, err := os.Stat(imagePath); err == nil {
		// Copy from existing image
		return sm.copyImageToRootfs(imagePath, rootfsDir)
	}

	// Create basic directory structure
	dirs := []string{
		"bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin",
		"etc", "etc/ssl/certs",
		"lib", "usr/lib", "usr/local/lib",
		"var", "var/log", "var/tmp",
		"tmp",
		"root", "home",
		"dev", "proc", "sys",
		"mnt", "media",
		"opt", "srv",
	}

	for _, dir := range dirs {
		dirPath := filepath.Join(rootfsDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
		}
	}

	// Create basic files
	files := map[string]string{
		"etc/passwd": `root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
`,
		"etc/group": `root:x:0:
nobody:x:65534:
`,
		"etc/shadow": `root:*:0:0:99999:7:::
nobody:*:0:0:99999:7:::
`,
		"etc/hosts": `127.0.0.1	localhost
::1		localhost ip6-localhost ip6-loopback
`,
		"etc/hostname": "gockerize-container\n",
		"etc/resolv.conf": `nameserver 8.8.8.8
nameserver 8.8.4.4
`,
	}

	for filePath, content := range files {
		fullPath := filepath.Join(rootfsDir, filePath)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to create file %s: %w", fullPath, err)
		}
	}

	// Try to copy some essential binaries from the host system
	if err := sm.copyEssentialBinaries(rootfsDir); err != nil {
		slog.Warn("failed to copy essential binaries", "error", err)
		// Not fatal - container might still work with statically linked binaries
	}

	// Set proper permissions for sensitive files
	sensitiveFiles := map[string]os.FileMode{
		"etc/passwd": 0644,
		"etc/group":  0644,
		"etc/shadow": 0600,
	}

	for filePath, mode := range sensitiveFiles {
		fullPath := filepath.Join(rootfsDir, filePath)
		if err := os.Chmod(fullPath, mode); err != nil {
			slog.Warn("failed to set permissions", "file", fullPath, "error", err)
		}
	}

	return nil
}

// copyEssentialBinaries copies essential binaries to the container rootfs
func (sm *StorageManager) copyEssentialBinaries(rootfsDir string) error {
	// List of essential binaries to try to copy
	essentialBinaries := []string{
		"/bin/sh",
		"/bin/bash",
		"/bin/ls",
		"/bin/cat",
		"/bin/echo",
		"/bin/mkdir",
		"/bin/rm",
		"/bin/cp",
		"/bin/mv",
		"/usr/bin/env",
	}

	for _, binPath := range essentialBinaries {
		if _, err := os.Stat(binPath); err != nil {
			continue // Skip if binary doesn't exist on host
		}

		// Determine destination path
		destPath := filepath.Join(rootfsDir, binPath)
		destDir := filepath.Dir(destPath)

		// Create destination directory
		if err := os.MkdirAll(destDir, 0755); err != nil {
			continue
		}

		// Copy binary
		if err := sm.copyFile(binPath, destPath); err != nil {
			continue
		}

		// Make executable
		if err := os.Chmod(destPath, 0755); err != nil {
			continue
		}
		
		// Copy dependencies for this binary
		sm.copyBinaryDependencies(binPath, rootfsDir)
	}

	return nil
}

// copyBinaryDependencies copies shared library dependencies for a binary
func (sm *StorageManager) copyBinaryDependencies(binPath, rootfsDir string) {
	// Use ldd to find dependencies
	cmd := exec.Command("ldd", binPath)
	output, err := cmd.Output()
	if err != nil {
		return // Not a dynamically linked binary or ldd failed
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse ldd output: 
		// libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x...)
		// or: /lib64/ld-linux-x86-64.so.2 (0x...)
		var libPath string
		if strings.Contains(line, "=>") {
			parts := strings.Split(line, "=>")
			if len(parts) >= 2 {
				pathPart := strings.TrimSpace(parts[1])
				pathPart = strings.Split(pathPart, " ")[0] // Remove address part
				libPath = pathPart
			}
		} else if strings.HasPrefix(line, "/") {
			libPath = strings.Split(line, " ")[0]
		}

		if libPath == "" || libPath == "(0x" {
			continue
		}

		// Copy the library
		if _, err := os.Stat(libPath); err == nil {
			destPath := filepath.Join(rootfsDir, libPath)
			destDir := filepath.Dir(destPath)
			
			if err := os.MkdirAll(destDir, 0755); err == nil {
				sm.copyFile(libPath, destPath)
			}
		}
	}
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

// copyFile copies a file from src to dest
func (sm *StorageManager) copyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Get source file info for permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	// Copy file content
	if _, err := io.Copy(destFile, srcFile); err != nil {
		return err
	}

	return os.Chmod(dest, srcInfo.Mode())
}
