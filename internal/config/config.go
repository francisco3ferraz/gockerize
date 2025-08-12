package config

const (
	// Default paths
	DefaultRuntimeDir   = "/var/lib/gockerize"
	DefaultImageDir     = "/var/lib/gockerize/images"
	DefaultContainerDir = "/var/lib/gockerize/containers"
	DefaultNetworkDir   = "/var/lib/gockerize/networks"

	// Network configuration
	DefaultBridgeName = "gockerize0"
	DefaultSubnet     = "172.17.0.0/16"

	// Runtime configuration
	DefaultStopTimeout = 10 // seconds
	MaxNameLength      = 63 // Docker-compatible max name length
)

// RuntimeConfig holds runtime configuration
type RuntimeConfig struct {
	RuntimeDir   string
	ImageDir     string
	ContainerDir string
	NetworkDir   string
	BridgeName   string
	Subnet       string
}

// NewDefaultConfig returns a default runtime configuration
func NewDefaultConfig() *RuntimeConfig {
	return &RuntimeConfig{
		RuntimeDir:   DefaultRuntimeDir,
		ImageDir:     DefaultImageDir,
		ContainerDir: DefaultContainerDir,
		NetworkDir:   DefaultNetworkDir,
		BridgeName:   DefaultBridgeName,
		Subnet:       DefaultSubnet,
	}
}

// Validate checks if the configuration is valid
func (c *RuntimeConfig) Validate() error {
	return nil
}
