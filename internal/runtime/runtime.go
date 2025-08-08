package runtime

import (
	"sync"

	"github.com/francisco3ferraz/gockerize/pkg/types"
)

const (
	// Default paths
	DefaultRuntimeDir   = "/var/lib/dockerize"
	DefaultImageDir     = "/var/lib/dockerize/images"
	DefaultContainerDir = "/var/lib/dockerize/containers"
	DefaultNetworkDir   = "/var/lib/dockerize/networks"

	// Configuration
	DefaultBridgeName = "dockerize0"
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

	// TODO: Initialize managers

	return rt, nil
}
