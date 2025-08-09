package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
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

	// Configuration
	runtimeDir   string
	imageDir     string
	containerDir string
	networkDir   string
}

// New creates a new runtime instance
func New() (*Runtime, error) {
	rt := &Runtime{
		containers:   make(map[string]*types.Container),
		images:       make(map[string]*types.Image),
		runtimeDir:   DefaultRuntimeDir,
		imageDir:     DefaultImageDir,
		containerDir: DefaultContainerDir,
		networkDir:   DefaultNetworkDir,
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

	slog.Info("runtime initialized", "runtime_dir", rt.runtimeDir)
	return rt, nil
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

	slog.Info("container created", "id", container.ID, "name", container.Name, "image", container.Image)
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

	// TODO: Temporarily skip network setup to debug container init
	slog.Info("skipping network setup for debugging")
	/*
		// Setup networking after container is started (so we have the PID)
		if err := r.networkMgr.SetupNetwork(ctx, container); err != nil {
			// Cleanup container on network failure
			r.containerMgr.Stop(ctx, container, 5*time.Second)
			return fmt.Errorf("failed to setup network: %w", err)
		}
	*/

	// Update container state
	now := time.Now()
	container.State = types.StateRunning
	container.StartedAt = &now

	// Get network info (skipped for now)
	/*
		networkInfo, err := r.networkMgr.GetNetworkInfo(container)
		if err != nil {
			slog.Warn("failed to get network info", "container", container.ID, "error", err)
		} else {
			container.NetworkInfo = networkInfo
		}
	*/

	// Persist state
	if err := r.saveContainer(container); err != nil {
		slog.Warn("failed to persist container state", "container", container.ID, "error", err)
	}

	slog.Info("container started", "id", container.ID, "name", container.Name, "pid", container.PID)
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

	slog.Info("container stopped", "id", container.ID, "name", container.Name)
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
	r.removeContainerFile(containerID)

	slog.Info("container removed", "id", container.ID, "name", container.Name)
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

// Image management methods (simplified for now)
func (r *Runtime) PullImage(ctx context.Context, name string) (*types.Image, error) {
	// For now, we'll create a simple alpine-like image
	imageID := generateID()
	image := &types.Image{
		ID:      imageID,
		Name:    name,
		Tag:     "latest",
		Size:    5 * 1024 * 1024, // 5MB
		Created: time.Now(),
		Layers:  []string{"base"},
		Config: &types.ImageConfig{
			Cmd:        []string{"/bin/sh"},
			WorkingDir: "/",
		},
	}

	r.mu.Lock()
	r.images[imageID] = image
	r.mu.Unlock()

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
	slog.Info("cleaning up runtime")

	// Stop all running containers
	for _, container := range r.containers {
		if container.State == types.StateRunning {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := r.StopContainer(ctx, container.ID, 10*time.Second); err != nil {
				slog.Warn("failed to stop container during cleanup", "container", container.ID, "error", err)
			}
			cancel()
		}
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

			// Reset running containers to stopped (they died when gockerize stopped)
			if container.State == types.StateRunning {
				container.State = types.StateStopped
				now := time.Now()
				container.FinishedAt = &now
			}

			r.containers[container.ID] = &container
		}
	}

	return nil
}

func (r *Runtime) loadImages() error {
	// For now, just load some default images
	return nil
}

func (r *Runtime) removeContainerFile(containerID string) {
	containerFile := filepath.Join(r.containerDir, containerID+".json")
	os.Remove(containerFile)
}

// generateID generates a random container/image ID
func generateID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
