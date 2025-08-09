package runtime

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/francisco3ferraz/gockerize/internal/container"
	"github.com/francisco3ferraz/gockerize/pkg/types"
)

const (
	// Default paths
	DefaultRuntimeDir   = "/var/lib/gockerize"
	DefaultImageDir     = "/var/lib/gockerize/images"
	DefaultContainerDir = "/var/lib/gockerize/containers"
	DefaultNetworkDir   = "/var/lib/gockerize/networks"

	// Configuration
	DefaultBridgeName = "gockerize0"
	DefaultSubnet     = "172.17.0.0/16"
)

// Runtime implements the container runtime
type Runtime struct {
	mu         sync.RWMutex
	containers map[string]*types.Container
	images     map[string]*types.Image

	// Managers
	containerMgr types.ContainerManager
	networkMgr   types.NetworkManager
	storageMgr   types.StorageManager

	// Session tracking
	sessionID         string
	sessionStartTime  time.Time
	sessionContainers map[string]bool // Track containers started by this session

	// Configuration
	runtimeDir   string
	imageDir     string
	containerDir string
	networkDir   string
}

// New creates a new runtime instance
func New() (*Runtime, error) {
	rt := &Runtime{
		containers:        make(map[string]*types.Container),
		images:            make(map[string]*types.Image),
		sessionID:         generateID(),
		sessionStartTime:  time.Now(),
		sessionContainers: make(map[string]bool),
		runtimeDir:        DefaultRuntimeDir,
		imageDir:          DefaultImageDir,
		containerDir:      DefaultContainerDir,
		networkDir:        DefaultNetworkDir,
	}

	// Create runtime directories
	if err := rt.createDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create runtime directories: %w", err)
	}

	// Initialize managers
	containerMgr, err := container.NewManager(rt.containerDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create container manager: %w", err)
	}
	rt.containerMgr = containerMgr

	networkMgr, err := container.NewNetworkManager(rt.networkDir, DefaultBridgeName, DefaultSubnet)
	if err != nil {
		return nil, fmt.Errorf("failed to create network manager: %w", err)
	}
	rt.networkMgr = networkMgr

	storageMgr, err := container.NewStorageManager(rt.imageDir, rt.containerDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage manager: %w", err)
	}
	rt.storageMgr = storageMgr

	// Load existing containers
	if err := rt.loadContainers(); err != nil {
		slog.Warn("failed to load existing containers", "error", err)
	}

	// Load existing images
	if err := rt.loadImages(); err != nil {
		slog.Warn("failed to load existing images", "error", err)
	}

	return rt, nil
}

// isProcessRunning checks if a process with the given PID is still running
func (r *Runtime) isProcessRunning(pid int) bool {
	// Check if the process exists by sending signal 0
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// CreateContainer creates a new container
func (r *Runtime) CreateContainer(ctx context.Context, config *types.ContainerConfig) (*types.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate container ID and name
	containerID := generateID()
	containerName := fmt.Sprintf("gockerize_%s", containerID[:12])

	// Create container object
	container := &types.Container{
		ID:        containerID,
		Name:      containerName,
		Image:     config.RootFS,  // For now, image name is the rootfs path
		Command:   config.Command, // Use command from config
		State:     types.StateCreated,
		CreatedAt: time.Now(),
		Config:    config,
	}

	// Create container using manager
	createdContainer, err := r.containerMgr.Create(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Update container with created info
	container.ID = createdContainer.ID
	container.Name = createdContainer.Name

	// Prepare rootfs
	rootfs, err := r.storageMgr.PrepareRootFS(ctx, config.RootFS, container.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rootfs: %w", err)
	}
	container.Config.RootFS = rootfs

	// Store container
	r.containers[container.ID] = container

	// Persist container state
	if err := r.saveContainer(container); err != nil {
		slog.Warn("failed to persist container state", "container", container.ID, "error", err)
	}

	return container, nil
}

// StartContainer starts a container
func (r *Runtime) StartContainer(ctx context.Context, containerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	container, exists := r.containers[containerID]
	if !exists {
		return fmt.Errorf("container not found: %s", containerID)
	}

	if container.State == types.StateRunning {
		return fmt.Errorf("container already running: %s", containerID)
	}

	// Start container first to get the PID
	if err := r.containerMgr.Start(ctx, container); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Setup networking after container is started (so we have the PID)
	if err := r.networkMgr.SetupNetwork(ctx, container); err != nil {
		// Cleanup container on network failure
		r.containerMgr.Stop(ctx, container, 5*time.Second)
		return fmt.Errorf("failed to setup network: %w", err)
	}

	// Signal the container that network setup is complete
	if err := r.containerMgr.SignalNetworkReady(ctx, container); err != nil {
		slog.Warn("failed to signal network ready", "container", container.ID, "error", err)
	}

	// Track that this container was started by this session
	r.sessionContainers[container.ID] = true

	// Update container state
	now := time.Now()
	container.State = types.StateRunning
	container.StartedAt = &now

	networkInfo, err := r.networkMgr.GetNetworkInfo(container)
	if err != nil {
		slog.Warn("failed to get network info", "container", container.ID, "error", err)
	} else {
		container.NetworkInfo = networkInfo
	}

	// Persist state
	if err := r.saveContainer(container); err != nil {
		slog.Warn("failed to persist container state", "container", container.ID, "error", err)
	}

	return nil
}

// StopContainer stops a container
func (r *Runtime) StopContainer(ctx context.Context, containerID string, timeout time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	container, exists := r.containers[containerID]
	if !exists {
		return fmt.Errorf("container not found: %s", containerID)
	}

	if container.State != types.StateRunning {
		return fmt.Errorf("container not running: %s", containerID)
	}

	// Stop container
	if err := r.containerMgr.Stop(ctx, container, timeout); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// Teardown networking
	if err := r.networkMgr.TeardownNetwork(ctx, container); err != nil {
		slog.Warn("failed to teardown network", "container", container.ID, "error", err)
	}

	// Update container state
	now := time.Now()
	container.State = types.StateStopped
	container.FinishedAt = &now

	// Persist state
	if err := r.saveContainer(container); err != nil {
		slog.Warn("failed to persist container state", "container", container.ID, "error", err)
	}

	return nil
}

// RemoveContainer removes a container
func (r *Runtime) RemoveContainer(ctx context.Context, containerID string, force bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	container, exists := r.containers[containerID]
	if !exists {
		return fmt.Errorf("container not found: %s", containerID)
	}

	if container.State == types.StateRunning && !force {
		return fmt.Errorf("cannot remove running container: %s (use --force)", containerID)
	}

	// Stop container if running
	if container.State == types.StateRunning {
		if err := r.containerMgr.Stop(ctx, container, 10*time.Second); err != nil {
			slog.Warn("failed to stop container during removal", "container", container.ID, "error", err)
		}
		if err := r.networkMgr.TeardownNetwork(ctx, container); err != nil {
			slog.Warn("failed to teardown network during removal", "container", container.ID, "error", err)
		}
	}

	// Remove container
	if err := r.containerMgr.Remove(ctx, container, force); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	// Clean up storage
	if err := r.storageMgr.CleanupContainer(ctx, container.ID); err != nil {
		slog.Warn("failed to cleanup container storage", "container", container.ID, "error", err)
	}

	// Remove from memory and disk
	delete(r.containers, containerID)
	delete(r.sessionContainers, containerID) // Clean up session tracking
	r.removeContainerFile(containerID)

	return nil
}

// GetContainer returns a container by ID
func (r *Runtime) GetContainer(containerID string) (*types.Container, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	container, exists := r.containers[containerID]
	if !exists {
		return nil, fmt.Errorf("container not found: %s", containerID)
	}

	return container, nil
}

// WaitContainer waits for a container to exit and returns the exit code
func (r *Runtime) WaitContainer(ctx context.Context, containerID string) (int, error) {
	container, err := r.GetContainer(containerID)
	if err != nil {
		return -1, err
	}

	// Wait for the container to exit
	exitCode, err := r.containerMgr.Wait(ctx, container)
	if err != nil {
		return -1, fmt.Errorf("failed to wait for container: %w", err)
	}

	// Update container state
	r.mu.Lock()
	container.State = types.StateExited
	container.ExitCode = exitCode
	now := time.Now()
	container.FinishedAt = &now
	r.mu.Unlock()

	// Persist state
	if err := r.saveContainer(container); err != nil {
		slog.Warn("failed to persist container state", "container", container.ID, "error", err)
	}

	return exitCode, nil
}

// ListContainers returns all containers
func (r *Runtime) ListContainers(ctx context.Context, all bool) ([]*types.Container, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	containers := make([]*types.Container, 0, len(r.containers))
	for _, container := range r.containers {
		if all || container.State == types.StateRunning {
			containers = append(containers, container)
		}
	}

	return containers, nil
}

// Image management methods
func (r *Runtime) PullImage(ctx context.Context, name string) (*types.Image, error) {
	// Parse image name and tag
	imageName, tag := parseImageName(name)

	slog.Info("pulling image", "image", imageName, "tag", tag)

	// Check if image already exists
	r.mu.RLock()
	for _, image := range r.images {
		if image.Name == imageName && image.Tag == tag {
			r.mu.RUnlock()
			slog.Info("image already exists", "image", imageName, "tag", tag)
			return image, nil
		}
	}
	r.mu.RUnlock()

	// Download and extract image
	imageID := generateID()
	imagePath := filepath.Join(r.imageDir, "images", imageName, tag)

	// Create image directory
	if err := os.MkdirAll(imagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create image directory: %w", err)
	}

	// Download the image
	if err := r.downloadImage(ctx, imageName, tag, imagePath); err != nil {
		return nil, fmt.Errorf("failed to download image: %w", err)
	}

	// Create image metadata
	image := &types.Image{
		ID:      imageID,
		Name:    imageName,
		Tag:     tag,
		Size:    r.calculateImageSize(imagePath),
		Created: time.Now(),
		Layers:  []string{"base"}, // TODO: implement proper layer tracking
		Config: &types.ImageConfig{
			Cmd:        []string{"/bin/sh"},
			WorkingDir: "/",
		},
	}

	// Store image
	r.mu.Lock()
	r.images[imageID] = image
	r.mu.Unlock()

	// Persist image metadata
	if err := r.saveImage(image, imagePath); err != nil {
		slog.Warn("failed to save image metadata", "image", imageName, "error", err)
	}

	slog.Info("image pulled successfully", "image", imageName, "tag", tag, "size", formatSize(image.Size))
	return image, nil
}

func (r *Runtime) ListImages(ctx context.Context) ([]*types.Image, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	images := make([]*types.Image, 0, len(r.images))
	for _, image := range r.images {
		images = append(images, image)
	}

	return images, nil
}

func (r *Runtime) RemoveImage(ctx context.Context, imageID string, force bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.images, imageID)
	return nil
}

// Cleanup releases runtime resources
func (r *Runtime) Cleanup() error {
	// Only stop containers that were started by this runtime session
	r.mu.Lock()
	containersToStop := make([]*types.Container, 0)
	for containerID, wasStartedBySession := range r.sessionContainers {
		if wasStartedBySession {
			if container, exists := r.containers[containerID]; exists && container.State == types.StateRunning {
				containersToStop = append(containersToStop, container)
			}
		}
	}
	r.mu.Unlock()

	// Stop containers started by this session
	for _, container := range containersToStop {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := r.StopContainer(ctx, container.ID, 10*time.Second); err != nil {
			slog.Warn("failed to stop container during cleanup", "container", container.ID, "error", err)
		}
		cancel()
	}

	return nil
}

// Helper methods
func (r *Runtime) createDirectories() error {
	dirs := []string{
		r.runtimeDir,
		r.imageDir,
		r.containerDir,
		r.networkDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func (r *Runtime) saveContainer(container *types.Container) error {
	containerFile := filepath.Join(r.containerDir, container.ID+".json")
	data, err := json.Marshal(container)
	if err != nil {
		return err
	}
	return os.WriteFile(containerFile, data, 0644)
}

func (r *Runtime) loadContainers() error {
	entries, err := os.ReadDir(r.containerDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			containerFile := filepath.Join(r.containerDir, entry.Name())
			data, err := os.ReadFile(containerFile)
			if err != nil {
				continue
			}

			var container types.Container
			if err := json.Unmarshal(data, &container); err != nil {
				continue
			}

			// Check if running containers are actually still running
			if container.State == types.StateRunning && container.PID > 0 {
				if r.isProcessRunning(container.PID) {
					// Process is still running, keep as running
				} else {
					// Process died, mark as stopped
					container.State = types.StateExited
					container.ExitCode = -1 // Unknown exit code
					now := time.Now()
					container.FinishedAt = &now
				}
			}

			r.containers[container.ID] = &container
		}
	}

	return nil
}

func (r *Runtime) loadImages() error {
	imagesDir := filepath.Join(r.imageDir, "images")

	// Check if images directory exists
	if _, err := os.Stat(imagesDir); os.IsNotExist(err) {
		return nil // No images to load
	}

	// Walk through the images directory structure: images/<name>/<tag>/
	return filepath.Walk(imagesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for metadata.json files
		if info.Name() == "metadata.json" && !info.IsDir() {
			// Load the image metadata
			data, err := os.ReadFile(path)
			if err != nil {
				slog.Warn("failed to read image metadata", "path", path, "error", err)
				return nil // Continue walking, don't fail completely
			}

			var image types.Image
			if err := json.Unmarshal(data, &image); err != nil {
				slog.Warn("failed to parse image metadata", "path", path, "error", err)
				return nil // Continue walking
			}

			// Add image to runtime registry
			r.images[image.ID] = &image
			slog.Debug("loaded image", "name", image.Name, "tag", image.Tag, "id", image.ID)
		}

		return nil
	})
}

func (r *Runtime) removeContainerFile(containerID string) {
	containerFile := filepath.Join(r.containerDir, containerID+".json")
	os.Remove(containerFile)
}

// generateID generates a random container/image ID
func generateID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// parseImageName parses an image name like "alpine:3.18" into name and tag
func parseImageName(name string) (string, string) {
	parts := strings.Split(name, ":")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return name, "latest"
}

// downloadImage downloads an image from a registry (simplified implementation)
func (r *Runtime) downloadImage(ctx context.Context, imageName, tag, imagePath string) error {
	// For now, let's implement a simplified version that downloads Alpine images
	// This is a basic implementation - a production version would use proper OCI registry API

	if imageName != "alpine" {
		return fmt.Errorf("only alpine images are currently supported")
	}

	// Download Alpine minirootfs
	url := "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.4-x86_64.tar.gz"
	if tag != "latest" {
		// For specific versions, try to construct URL (simplified)
		url = "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.4-x86_64.tar.gz"
	}

	slog.Info("downloading image", "url", url, "destination", imagePath)

	// Download the file
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download image: HTTP %d", resp.StatusCode)
	}

	// Extract directly to the image path
	return r.extractTarGz(resp.Body, imagePath)
}

// extractTarGz extracts a tar.gz archive to a destination directory
func (r *Runtime) extractTarGz(src io.Reader, destDir string) error {
	// Create gzip reader
	gzReader, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip directories with ".." in path for security
		if strings.Contains(header.Name, "..") {
			continue
		}

		destPath := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", destPath, err)
			}
		case tar.TypeReg:
			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", destPath, err)
			}

			// Create file
			file, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", destPath, err)
			}

			// Copy file content
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to extract file %s: %w", destPath, err)
			}
			file.Close()
		case tar.TypeSymlink:
			// Create symlink
			if err := os.Symlink(header.Linkname, destPath); err != nil {
				// Ignore symlink errors for now as they might point to non-existent targets
				slog.Warn("failed to create symlink", "path", destPath, "target", header.Linkname, "error", err)
			}
		}
	}

	return nil
}

// calculateImageSize calculates the size of an image directory
func (r *Runtime) calculateImageSize(imagePath string) int64 {
	var size int64

	err := filepath.Walk(imagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	if err != nil {
		slog.Warn("failed to calculate image size", "path", imagePath, "error", err)
		return 0
	}

	return size
}

// saveImage saves image metadata to disk
func (r *Runtime) saveImage(image *types.Image, imagePath string) error {
	metadataPath := filepath.Join(imagePath, "metadata.json")
	data, err := json.Marshal(image)
	if err != nil {
		return fmt.Errorf("failed to marshal image metadata: %w", err)
	}

	return os.WriteFile(metadataPath, data, 0644)
}

// formatSize formats a byte size as human readable string
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f%s", float64(bytes)/float64(div), units[exp])
}
