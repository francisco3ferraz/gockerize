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
			syscall.CLONE_NEWUTS, // UTS namespace (hostname)
		// Remove user namespaces for now to simplify debugging
		/*
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
		*/
	}

	// Set environment variables for container init
	cmd.Env = []string{
		fmt.Sprintf("CONTAINER_ID=%s", container.ID),
		fmt.Sprintf("CONTAINER_ROOTFS=%s", container.Config.RootFS),
		fmt.Sprintf("CONTAINER_CMD=%s", strings.Join(container.Command, " ")),
		fmt.Sprintf("CONTAINER_HOSTNAME=%s", container.Config.Hostname),
	}

	slog.Debug("starting container process",
		"container", container.ID,
		"command", container.Command,
		"rootfs", container.Config.RootFS)

	// Add user-defined environment variables
	cmd.Env = append(cmd.Env, container.Config.Env...)

	// Set working directory
	if container.Config.WorkingDir != "" {
		cmd.Dir = container.Config.WorkingDir
	}

	// Start the process
	slog.Debug("about to start container process", "container", container.ID, "cmd", cmd.Args)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start container process: %w", err)
	}

	slog.Debug("container process started", "container", container.ID, "pid", cmd.Process.Pid)

	// Update container with process info
	container.PID = cmd.Process.Pid
	container.State = types.StateRunning
	now := time.Now()
	container.StartedAt = &now

	// Check if process is still alive immediately
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		slog.Error("container process exited immediately",
			"container", container.ID,
			"exit_code", cmd.ProcessState.ExitCode())
		return fmt.Errorf("container process exited immediately with code %d", cmd.ProcessState.ExitCode())
	}

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

// Stop stops a running container
func (m *Manager) Stop(ctx context.Context, container *types.Container, timeout time.Duration) error {
	if container.State != types.StateRunning {
		return fmt.Errorf("container not running: %s", container.ID)
	}

	if container.PID == 0 {
		return fmt.Errorf("container has no PID: %s", container.ID)
	}

	// Find the process
	process, err := os.FindProcess(container.PID)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", container.PID, err)
	}

	// Try graceful shutdown first (SIGTERM)
	slog.Info("sending SIGTERM to container", "id", container.ID, "pid", container.PID)
	if err := process.Signal(syscall.SIGTERM); err != nil {
		slog.Warn("failed to send SIGTERM", "container", container.ID, "error", err)
	}

	// Wait for graceful shutdown
	done := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			slog.Warn("process wait error", "container", container.ID, "error", err)
		}
	case <-time.After(timeout):
		// Force kill if timeout exceeded
		slog.Info("timeout exceeded, sending SIGKILL", "id", container.ID, "pid", container.PID)
		if err := process.Signal(syscall.SIGKILL); err != nil {
			slog.Warn("failed to send SIGKILL", "container", container.ID, "error", err)
		}
		// Wait a bit more for SIGKILL to take effect
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			slog.Warn("container may still be running after SIGKILL", "id", container.ID)
		}
	}

	// Update container state
	container.State = types.StateStopped
	container.PID = 0
	now := time.Now()
	container.FinishedAt = &now

	// Cleanup cgroups
	if err := m.cleanupCgroups(container); err != nil {
		slog.Warn("failed to cleanup cgroups", "container", container.ID, "error", err)
	}

	slog.Info("container stopped", "id", container.ID, "name", container.Name)
	return nil
}

// Remove removes a container and its resources
func (m *Manager) Remove(ctx context.Context, container *types.Container, force bool) error {
	// Ensure container is stopped
	if container.State == types.StateRunning {
		if !force {
			return fmt.Errorf("cannot remove running container: %s", container.ID)
		}
		if err := m.Stop(ctx, container, 10*time.Second); err != nil {
			slog.Warn("failed to stop container during removal", "container", container.ID, "error", err)
		}
	}

	// Remove container directory
	containerPath := filepath.Join(m.containerDir, container.ID)
	if err := os.RemoveAll(containerPath); err != nil {
		slog.Warn("failed to remove container directory", "container", container.ID, "error", err)
	}

	slog.Info("container removed", "id", container.ID, "name", container.Name)
	return nil
}

// Wait waits for a container to exit and returns the exit code
func (m *Manager) Wait(ctx context.Context, container *types.Container) (int, error) {
	if container.State != types.StateRunning || container.PID == 0 {
		return container.ExitCode, nil
	}

	process, err := os.FindProcess(container.PID)
	if err != nil {
		return -1, fmt.Errorf("failed to find process %d: %w", container.PID, err)
	}

	// Wait for the process to exit with context cancellation support
	done := make(chan struct{})
	var processState *os.ProcessState
	var waitErr error

	go func() {
		defer close(done)
		processState, waitErr = process.Wait()
	}()

	select {
	case <-done:
		if waitErr != nil {
			return -1, fmt.Errorf("failed to wait for process: %w", waitErr)
		}

		exitCode := processState.ExitCode()
		container.ExitCode = exitCode
		container.State = types.StateExited
		now := time.Now()
		container.FinishedAt = &now

		return exitCode, nil
	case <-ctx.Done():
		// Context cancelled, terminate the process
		slog.Info("wait cancelled, terminating container", "id", container.ID, "pid", container.PID)

		// Send SIGTERM first
		if err := process.Signal(syscall.SIGTERM); err != nil {
			slog.Warn("failed to send SIGTERM", "container", container.ID, "error", err)
		}

		// Wait a bit for graceful shutdown
		select {
		case <-done:
			// Process exited gracefully
			if waitErr != nil {
				return -1, waitErr
			}
			return processState.ExitCode(), nil
		case <-time.After(2 * time.Second):
			// Force kill if it doesn't exit gracefully
			slog.Info("force killing container", "id", container.ID, "pid", container.PID)
			if err := process.Signal(syscall.SIGKILL); err != nil {
				slog.Warn("failed to send SIGKILL", "container", container.ID, "error", err)
			}

			// Wait a bit more for SIGKILL
			select {
			case <-done:
				return -128, nil // Indicate killed
			case <-time.After(1 * time.Second):
				return -1, fmt.Errorf("container did not exit after SIGKILL")
			}
		}
	}
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

// cleanupCgroups removes the container's cgroup
func (m *Manager) cleanupCgroups(container *types.Container) error {
	cgroupPath := filepath.Join("/sys/fs/cgroup", "gockerize", container.ID)
	return os.RemoveAll(cgroupPath)
}

// generateContainerID generates a unique container ID
func generateContainerID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
