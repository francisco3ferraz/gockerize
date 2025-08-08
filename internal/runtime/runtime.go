package runtime

import (
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

// generateID generates a random container/image ID
func generateID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
