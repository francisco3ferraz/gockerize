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
	"github.com/francisco3ferraz/gockerize/internal/security"
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
	macMgr       *security.MACManager

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

	// Initialize MAC manager
	rt.macMgr = security.NewMACManager()

	// Create default MAC profile if needed
	if err := rt.macMgr.CreateDefaultProfile(); err != nil {
		slog.Warn("failed to create default MAC profile", "error", err)
	}

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

	// Create container using manager
	container, err := r.containerMgr.Create(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Prepare rootfs
	rootfs, err := r.storageMgr.PrepareRootFS(ctx, config.RootFS, container.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rootfs: %w", err)
	}
	container.Config.RootFS = rootfs

	// Mount volumes into the container's rootfs before starting
	if err := r.storageMgr.MountVolumes(ctx, container); err != nil {
		return nil, fmt.Errorf("failed to mount volumes: %w", err)
	}

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
	// Skip tracking for detached containers so they don't get stopped during cleanup
	if !container.Config.Detached {
		r.sessionContainers[container.ID] = true
	}

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

	// Unmount volumes 
	if err := r.storageMgr.UnmountVolumes(ctx, container); err != nil {
		slog.Warn("failed to unmount volumes", "container", container.ID, "error", err)
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
	imageKey := imageName + ":" + tag // Use name:tag as the key
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
		ID:      generateID(), // Keep ID for display purposes
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

	// Store image using name:tag as key
	r.mu.Lock()
	r.images[imageKey] = image
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

	// Check if image exists
	_, exists := r.images[imageID]
	if !exists {
		return fmt.Errorf("image not found: %s", imageID)
	}

	// Check if any containers are using this image
	if !force {
		for _, container := range r.containers {
			if container.Image == imageID {
				return fmt.Errorf("image is being used by container %s, use -f to force removal", container.ID)
			}
		}
	}

	// Parse image name to get directory path
	imageName, tag := parseImageName(imageID)
	imageDir := filepath.Join(r.imageDir, "images", imageName, tag)

	// Remove image directory from filesystem
	if err := os.RemoveAll(imageDir); err != nil {
		slog.Warn("failed to remove image directory", "path", imageDir, "error", err)
	}

	// Remove from in-memory map
	delete(r.images, imageID)

	slog.Info("image removed", "image", imageID, "path", imageDir)
	return nil
}

func (r *Runtime) PruneImages(ctx context.Context, all bool) ([]string, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var removedImages []string
	var totalSize int64

	// Get list of images used by containers
	usedImages := make(map[string]bool)
	for _, container := range r.containers {
		usedImages[container.Image] = true
	}

	for imageID := range r.images {
		shouldRemove := false

		if all {
			// Remove all unused images
			shouldRemove = !usedImages[imageID]
		} else {
			// For now, just remove unused images (in a real implementation,
			// you'd also check for dangling images with no tags)
			shouldRemove = !usedImages[imageID]
		}

		if shouldRemove {
			// Parse image name to get directory path
			imageName, tag := parseImageName(imageID)
			imageDir := filepath.Join(r.imageDir, "images", imageName, tag)

			// Get size before removal
			if stat, err := os.Stat(imageDir); err == nil && stat.IsDir() {
				if size, err := getDirSize(imageDir); err == nil {
					totalSize += size
				}
			}

			// Remove image directory
			if err := os.RemoveAll(imageDir); err != nil {
				slog.Warn("failed to remove image directory", "path", imageDir, "error", err)
				continue
			}

			removedImages = append(removedImages, imageID)
			delete(r.images, imageID)
			slog.Info("pruned image", "image", imageID, "path", imageDir)
		}
	}

	return removedImages, totalSize, nil
}

// getDirSize calculates the total size of a directory
func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
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

			// Add image to runtime registry using name:tag as key
			imageKey := image.Name + ":" + image.Tag
			r.images[imageKey] = &image
			slog.Debug("loaded image", "name", image.Name, "tag", image.Tag, "key", imageKey)
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

// downloadImage downloads an image from an OCI-compliant registry
func (r *Runtime) downloadImage(ctx context.Context, imageName, tag, imagePath string) error {
	// Parse image reference to determine registry
	registry, namespace, name := parseImageReference(imageName)

	slog.Info("downloading image from OCI registry",
		"registry", registry, "namespace", namespace, "image", name, "tag", tag, "destination", imagePath)

	// Create OCI registry client
	client := &OCIRegistryClient{
		registry:  registry,
		userAgent: "gockerize/1.0",
	}

	// Download and extract the image
	return client.PullImage(ctx, namespace, name, tag, imagePath)
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

// OCI Registry Implementation

// OCIManifest represents an OCI image manifest
type OCIManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        OCIDescriptor   `json:"config"`
	Layers        []OCIDescriptor `json:"layers"`
}

// OCIIndex represents an OCI image index (multi-platform manifest)
type OCIIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []OCIDescriptor `json:"manifests"`
}

// OCIDescriptor represents a content descriptor
type OCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// OCIRegistryClient handles OCI registry operations
type OCIRegistryClient struct {
	registry  string
	userAgent string
	client    *http.Client
}

// parseImageReference parses image references like "alpine", "library/alpine", "docker.io/library/alpine"
func parseImageReference(imageName string) (registry, namespace, name string) {
	// Default to Docker Hub if no registry specified
	registry = "registry-1.docker.io"
	namespace = "library"
	name = imageName

	// Handle different image reference formats
	parts := strings.Split(imageName, "/")

	switch len(parts) {
	case 1:
		// Just image name: "alpine" -> docker.io/library/alpine
		name = parts[0]
	case 2:
		// namespace/name: "library/alpine" -> docker.io/library/alpine
		namespace = parts[0]
		name = parts[1]
	case 3:
		// registry/namespace/name: "docker.io/library/alpine"
		registry = parts[0]
		namespace = parts[1]
		name = parts[2]
	}

	return registry, namespace, name
}

// PullImage downloads an image from an OCI registry
func (c *OCIRegistryClient) PullImage(ctx context.Context, namespace, name, tag, destPath string) error {
	if c.client == nil {
		c.client = &http.Client{
			Timeout: 300 * time.Second, // 5 minute timeout for downloads
		}
	}

	imageRef := fmt.Sprintf("%s/%s", namespace, name)

	// Step 1: Get the manifest
	manifest, err := c.getManifest(ctx, imageRef, tag)
	if err != nil {
		return fmt.Errorf("failed to get manifest: %w", err)
	}

	// Step 2: Download and extract layers
	for i, layer := range manifest.Layers {
		slog.Info("downloading layer", "layer", i+1, "total", len(manifest.Layers), "digest", layer.Digest)

		if err := c.downloadLayer(ctx, imageRef, layer, destPath); err != nil {
			return fmt.Errorf("failed to download layer %s: %w", layer.Digest, err)
		}
	}

	return nil
}

// getManifest retrieves the image manifest from the registry
func (c *OCIRegistryClient) getManifest(ctx context.Context, imageRef, tag string) (*OCIManifest, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", c.registry, imageRef, tag)

	slog.Info("getting manifest", "url", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set required headers for OCI registry API
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	slog.Info("manifest response", "status", resp.StatusCode)

	var token string
	if resp.StatusCode == http.StatusUnauthorized {
		// Try to get auth token and retry
		authURL := resp.Header.Get("Www-Authenticate")
		if authURL != "" {
			slog.Info("getting auth token for manifest")
			token, err = c.getAuthToken(ctx, authURL, imageRef)
			if err != nil {
				return nil, fmt.Errorf("failed to get auth token: %w", err)
			}

			// Retry with token
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err = c.client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			slog.Info("manifest response after auth", "status", resp.StatusCode)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get manifest: HTTP %d", resp.StatusCode)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// First, try to decode as a manifest to check the media type
	var rawManifest struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(bodyBytes, &rawManifest); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	slog.Info("manifest media type", "mediaType", rawManifest.MediaType)

	// Handle image index (multi-platform manifest)
	if rawManifest.MediaType == "application/vnd.oci.image.index.v1+json" ||
		rawManifest.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {

		var index OCIIndex
		if err := json.Unmarshal(bodyBytes, &index); err != nil {
			return nil, fmt.Errorf("failed to decode image index: %w", err)
		}

		slog.Info("image index decoded", "manifests", len(index.Manifests))

		// Find the linux/amd64 manifest (or first one if no platform specified)
		var selectedDigest string
		for _, manifestDesc := range index.Manifests {
			// For simplicity, just take the first manifest
			// In a full implementation, you'd check platform.architecture and platform.os
			selectedDigest = manifestDesc.Digest
			break
		}

		if selectedDigest == "" {
			return nil, fmt.Errorf("no suitable manifest found in index")
		}

		slog.Info("resolving platform-specific manifest", "digest", selectedDigest)

		// Fetch the platform-specific manifest using the same token
		return c.getManifestByDigest(ctx, imageRef, selectedDigest, token)
	}

	// Regular manifest
	var manifest OCIManifest
	if err := json.Unmarshal(bodyBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	slog.Info("manifest decoded", "layers", len(manifest.Layers), "mediaType", manifest.MediaType)

	return &manifest, nil
}

// getManifestByDigest retrieves a specific manifest by digest
func (c *OCIRegistryClient) getManifestByDigest(ctx context.Context, imageRef, digest, token string) (*OCIManifest, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", c.registry, imageRef, digest)

	slog.Info("getting manifest by digest", "url", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set required headers for OCI registry API
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json")
	req.Header.Set("User-Agent", c.userAgent)

	// Add auth token if provided
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get manifest by digest: HTTP %d", resp.StatusCode)
	}

	var manifest OCIManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	slog.Info("platform manifest decoded", "layers", len(manifest.Layers), "mediaType", manifest.MediaType)

	return &manifest, nil
} // getAuthToken obtains an authentication token from the registry
func (c *OCIRegistryClient) getAuthToken(ctx context.Context, authHeader, imageRef string) (string, error) {
	// Parse Www-Authenticate header: Bearer realm="...",service="...",scope="..."
	// This is a simplified implementation
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("unsupported auth type")
	}

	// For Docker Hub, construct auth URL
	scope := fmt.Sprintf("repository:%s:pull", imageRef)
	authURL := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=%s", scope)

	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth request failed: HTTP %d", resp.StatusCode)
	}

	var authResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", err
	}

	return authResp.Token, nil
}

// downloadLayer downloads and extracts a layer to the destination path
func (c *OCIRegistryClient) downloadLayer(ctx context.Context, imageRef string, layer OCIDescriptor, destPath string) error {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", c.registry, imageRef, layer.Digest)

	slog.Info("downloading layer", "url", url, "digest", layer.Digest, "size", layer.Size)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	slog.Info("layer download response", "status", resp.StatusCode, "content-length", resp.ContentLength)

	if resp.StatusCode == http.StatusUnauthorized {
		// Try to get auth token and retry
		authURL := resp.Header.Get("Www-Authenticate")
		if authURL != "" {
			slog.Info("getting auth token for layer download")
			token, err := c.getAuthToken(ctx, authURL, imageRef)
			if err != nil {
				return fmt.Errorf("failed to get auth token for layer: %w", err)
			}

			// Retry with token
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err = c.client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to retry request with auth: %w", err)
			}
			defer resp.Body.Close()

			slog.Info("layer download response after auth", "status", resp.StatusCode, "content-length", resp.ContentLength)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download layer: HTTP %d", resp.StatusCode)
	}

	// Verify content length if provided
	if resp.ContentLength > 0 && resp.ContentLength != layer.Size {
		slog.Warn("layer size mismatch", "expected", layer.Size, "actual", resp.ContentLength)
	}

	slog.Info("extracting layer", "mediaType", layer.MediaType, "destPath", destPath)

	// Extract layer based on media type
	switch layer.MediaType {
	case "application/vnd.docker.image.rootfs.diff.tar.gzip",
		"application/vnd.oci.image.layer.v1.tar+gzip":
		// This is a compressed tar layer, extract it
		return extractTarGz(resp.Body, destPath)
	case "application/vnd.docker.image.rootfs.diff.tar":
		// Uncompressed tar layer
		return extractTar(resp.Body, destPath)
	default:
		slog.Warn("unknown layer media type, attempting tar.gz extraction", "mediaType", layer.MediaType)
		return extractTarGz(resp.Body, destPath)
	}
} // extractTar extracts an uncompressed tar archive
func extractTar(src io.Reader, destDir string) error {
	tarReader := tar.NewReader(src)
	return extractTarReader(tarReader, destDir)
}

// extractTarGz extracts a gzip-compressed tar archive
func extractTarGz(src io.Reader, destDir string) error {
	gzReader, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	return extractTarReader(tarReader, destDir)
}

// extractTarReader extracts files from a tar reader
func extractTarReader(tarReader *tar.Reader, destDir string) error {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Security check: prevent path traversal
		if strings.Contains(header.Name, "..") {
			slog.Warn("skipping file with .. in path", "file", header.Name)
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
				// Log but don't fail on symlink errors
				slog.Warn("failed to create symlink", "path", destPath, "target", header.Linkname, "error", err)
			}
		case tar.TypeLink:
			// Hard link
			linkTarget := filepath.Join(destDir, header.Linkname)
			if err := os.Link(linkTarget, destPath); err != nil {
				slog.Warn("failed to create hard link", "path", destPath, "target", linkTarget, "error", err)
			}
		}
	}

	return nil
}
