package container

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/francisco3ferraz/gockerize/pkg/types"
)

// Manager handles container lifecycle operations
type Manager struct {
	containerDir string
}

// NewManager creates a new container manager
func NewManager(containerDir string) (*Manager, error) {
	return &Manager{
		containerDir: containerDir,
	}, nil
}

// Create creates a new container
func (m *Manager) Create(ctx context.Context, config *types.ContainerConfig) (*types.Container, error) {
	// Generate container ID
	containerID := generateContainerID()
	containerName := fmt.Sprintf("gockerize_%s", containerID[:12])

	container := &types.Container{
		ID:        containerID,
		Name:      containerName,
		Image:     config.RootFS,
		Command:   []string{"/bin/sh"}, // Default for now
		State:     types.StateCreated,
		CreatedAt: time.Now(),
		Config:    config,
	}

	// Create container directory
	containerPath := filepath.Join(m.containerDir, containerID)
	if err := os.MkdirAll(containerPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create container directory: %w", err)
	}

	slog.Info("container created", "id", containerID, "name", containerName)
	return container, nil
}

// generateContainerID generates a unique container ID
func generateContainerID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
