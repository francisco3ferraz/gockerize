package types

import (
	"context"
	"time"
)

// ContainerState represents the current state of a container
type ContainerState string

const (
	StateCreated ContainerState = "created"
	StateRunning ContainerState = "running"
	StateStopped ContainerState = "stopped"
	StateExited  ContainerState = "exited"
	StatePaused  ContainerState = "paused"
)

// Container represents a container instance
type Container struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Image       string           `json:"image"`
	Command     []string         `json:"command"`
	State       ContainerState   `json:"state"`
	PID         int              `json:"pid,omitempty"`
	ExitCode    int              `json:"exit_code,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	StartedAt   *time.Time       `json:"started_at,omitempty"`
	FinishedAt  *time.Time       `json:"finished_at,omitempty"`
	Config      *ContainerConfig `json:"config"`
	NetworkInfo *NetworkInfo     `json:"network_info,omitempty"`
}

// ContainerConfig holds container configuration
type ContainerConfig struct {
	// Command and args
	Command []string `json:"command,omitempty"`

	// Resource limits
	Memory    int64 `json:"memory,omitempty"`     // bytes
	CPUShares int64 `json:"cpu_shares,omitempty"` // relative weight
	CPUQuota  int64 `json:"cpu_quota,omitempty"`  // microseconds per period
	CPUPeriod int64 `json:"cpu_period,omitempty"` // microseconds

	// Filesystem
	WorkingDir string   `json:"working_dir,omitempty"`
	RootFS     string   `json:"rootfs"`
	Volumes    []Volume `json:"volumes,omitempty"`

	// Network
	NetworkMode string        `json:"network_mode,omitempty"`
	Ports       []PortMapping `json:"ports,omitempty"`
	Hostname    string        `json:"hostname,omitempty"`

	// Environment
	Env  []string `json:"env,omitempty"`
	User string   `json:"user,omitempty"`

	// Security
	Privileged   bool     `json:"privileged,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// Volume represents a mounted volume
type Volume struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only,omitempty"`
}

// PortMapping represents a port forwarding rule
type PortMapping struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"` // tcp, udp
}

// NetworkInfo contains networking details for a container
type NetworkInfo struct {
	IPAddress string            `json:"ip_address,omitempty"`
	Gateway   string            `json:"gateway,omitempty"`
	Bridge    string            `json:"bridge,omitempty"`
	Ports     map[string]string `json:"ports,omitempty"` // container_port -> host_port
}

// Image represents a container image
type Image struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Tag     string       `json:"tag"`
	Size    int64        `json:"size"`
	Created time.Time    `json:"created"`
	Layers  []string     `json:"layers"`
	Config  *ImageConfig `json:"config"`
}

// ImageConfig holds image configuration
type ImageConfig struct {
	Env          []string `json:"env,omitempty"`
	Cmd          []string `json:"cmd,omitempty"`
	Entrypoint   []string `json:"entrypoint,omitempty"`
	WorkingDir   string   `json:"working_dir,omitempty"`
	User         string   `json:"user,omitempty"`
	ExposedPorts []string `json:"exposed_ports,omitempty"`
}

// Runtime defines the interface for container runtime operations
type Runtime interface {
	// Container lifecycle
	CreateContainer(ctx context.Context, config *ContainerConfig) (*Container, error)
	StartContainer(ctx context.Context, containerID string) error
	StopContainer(ctx context.Context, containerID string, timeout time.Duration) error
	RemoveContainer(ctx context.Context, containerID string, force bool) error
	WaitContainer(ctx context.Context, containerID string) (int, error)

	// Container queries
	GetContainer(containerID string) (*Container, error)
	ListContainers(ctx context.Context, all bool) ([]*Container, error)

	// Image management
	PullImage(ctx context.Context, name string) (*Image, error)
	ListImages(ctx context.Context) ([]*Image, error)
	RemoveImage(ctx context.Context, imageID string, force bool) error

	// Cleanup
	Cleanup() error
}

// ContainerManager handles container lifecycle operations
type ContainerManager interface {
	Create(ctx context.Context, config *ContainerConfig) (*Container, error)
	Start(ctx context.Context, container *Container) error
	Stop(ctx context.Context, container *Container, timeout time.Duration) error
	Remove(ctx context.Context, container *Container, force bool) error
	Wait(ctx context.Context, container *Container) (int, error)
	SignalNetworkReady(ctx context.Context, container *Container) error
}

// NetworkManager handles container networking
type NetworkManager interface {
	SetupNetwork(ctx context.Context, container *Container) error
	TeardownNetwork(ctx context.Context, container *Container) error
	GetNetworkInfo(container *Container) (*NetworkInfo, error)
}

// StorageManager handles container filesystem operations
type StorageManager interface {
	PrepareRootFS(ctx context.Context, image string, containerID string) (string, error)
	MountVolumes(ctx context.Context, container *Container) error
	UnmountVolumes(ctx context.Context, container *Container) error
	CleanupContainer(ctx context.Context, containerID string) error
}
