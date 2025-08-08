package container

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// Start starts a container with proper namespace isolation
func (m *Manager) Start(ctx context.Context, container *types.Container) error {
	if container.State != types.StateCreated && container.State != types.StateStopped {
		return fmt.Errorf("cannot start container in state: %s", container.State)
	}

	// Prepare the container process
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "container-init")

	// Set up namespaces - this is where the magic happens
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | // Mount namespace
			syscall.CLONE_NEWPID | // PID namespace
			syscall.CLONE_NEWNET | // Network namespace
			syscall.CLONE_NEWUTS | // UTS namespace (hostname)
			syscall.CLONE_NEWIPC, // IPC namespace
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			},
		},
	}

	// Set environment variables for container init
	cmd.Env = []string{
		fmt.Sprintf("CONTAINER_ID=%s", container.ID),
		fmt.Sprintf("CONTAINER_ROOTFS=%s", container.Config.RootFS),
		fmt.Sprintf("CONTAINER_CMD=%s", strings.Join(container.Command, " ")),
		fmt.Sprintf("CONTAINER_HOSTNAME=%s", container.Config.Hostname),
	}

	// Add user-defined environment variables
	cmd.Env = append(cmd.Env, container.Config.Env...)

	// Set working directory
	if container.Config.WorkingDir != "" {
		cmd.Dir = container.Config.WorkingDir
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start container process: %w", err)
	}

	// Update container with process info
	container.PID = cmd.Process.Pid
	container.State = types.StateRunning
	now := time.Now()
	container.StartedAt = &now

	// Setup cgroups for resource management
	if err := m.setupCgroups(container); err != nil {
		slog.Warn("failed to setup cgroups", "container", container.ID, "error", err)
	}

	slog.Info("container started",
		"id", container.ID,
		"name", container.Name,
		"pid", container.PID)

	return nil
}

// setupCgroups creates and configures cgroups for the container
func (m *Manager) setupCgroups(container *types.Container) error {
	cgroupPath := filepath.Join("/sys/fs/cgroup", "gockerize", container.ID)

	// Create cgroup directory
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup directory: %w", err)
	}

	// Add process to cgroup
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(container.PID)), 0644); err != nil {
		return fmt.Errorf("failed to add process to cgroup: %w", err)
	}

	// Set memory limit if specified
	if container.Config.Memory > 0 {
		memoryLimit := filepath.Join(cgroupPath, "memory.max")
		if err := os.WriteFile(memoryLimit, []byte(strconv.FormatInt(container.Config.Memory, 10)), 0644); err != nil {
			slog.Warn("failed to set memory limit", "container", container.ID, "error", err)
		}
	}

	// Set CPU limits if specified
	if container.Config.CPUQuota > 0 && container.Config.CPUPeriod > 0 {
		cpuMax := filepath.Join(cgroupPath, "cpu.max")
		cpuMaxValue := fmt.Sprintf("%d %d", container.Config.CPUQuota, container.Config.CPUPeriod)
		if err := os.WriteFile(cpuMax, []byte(cpuMaxValue), 0644); err != nil {
			slog.Warn("failed to set CPU limit", "container", container.ID, "error", err)
		}
	}

	return nil
}

// generateContainerID generates a unique container ID
func generateContainerID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
