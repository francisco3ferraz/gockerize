package container

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
)

// NetworkManager handles container networking
type NetworkManager struct {
	networkDir string
	bridgeName string
	subnet     string
	nextIP     int
	mu         sync.Mutex
}

// NewNetworkManager creates a new network manager
func NewNetworkManager(networkDir, bridgeName, subnet string) (*NetworkManager, error) {
	nm := &NetworkManager{
		networkDir: networkDir,
		bridgeName: bridgeName,
		subnet:     subnet,
		nextIP:     2, // Start from .2 (.1 is gateway)
	}

	// Create network directory
	if err := os.MkdirAll(networkDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create network directory: %w", err)
	}

	// Setup bridge network
	if err := nm.setupBridge(); err != nil {
		return nil, fmt.Errorf("failed to setup bridge: %w", err)
	}

	return nm, nil
}

// setupBridge creates and configures the container bridge
func (nm *NetworkManager) setupBridge() error {
	slog.Info("setting up bridge network", "bridge", nm.bridgeName, "subnet", nm.subnet)

	// Check if bridge already exists
	if nm.bridgeExists() {
		slog.Info("bridge already exists", "bridge", nm.bridgeName)
		return nil
	}

	// Create bridge
	cmd := exec.Command("ip", "link", "add", "name", nm.bridgeName, "type", "bridge")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create bridge: %w", err)
	}

	// Assign IP to bridge (gateway)
	gatewayIP := nm.getGatewayIP()
	cmd = exec.Command("ip", "addr", "add", gatewayIP+"/24", "dev", nm.bridgeName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to assign IP to bridge: %w", err)
	}

	// Bring bridge up
	if err := nm.linkUp(nm.bridgeName); err != nil {
		return fmt.Errorf("failed to bring up bridge: %w", err)
	}

	// Enable IP forwarding
	if err := nm.enableIPForwarding(); err != nil {
		slog.Warn("failed to enable IP forwarding", "error", err)
	}

	// Setup NAT for internet access
	if err := nm.setupNAT(); err != nil {
		slog.Warn("failed to setup NAT", "error", err)
	}

	return nil
}

// linkUp brings up a network interface
func (nm *NetworkManager) linkUp(iface string) error {
	cmd := exec.Command("ip", "link", "set", iface, "up")
	return cmd.Run()
}

func (nm *NetworkManager) getGatewayIP() string {
	// Parse subnet to get network part
	_, ipnet, err := net.ParseCIDR(nm.subnet)
	if err != nil {
		return "172.17.0.1" // Fallback
	}

	// Gateway is network IP + 1
	networkIP := ipnet.IP
	gatewayIP := make(net.IP, len(networkIP))
	copy(gatewayIP, networkIP)
	gatewayIP[len(gatewayIP)-1] += 1

	return gatewayIP.String()
}

// Checks if the bridge network exists
func (nm *NetworkManager) bridgeExists() bool {
	cmd := exec.Command("ip", "link", "show", nm.bridgeName)
	return cmd.Run() == nil
}

// Enables IP forwarding
func (nm *NetworkManager) enableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func (nm *NetworkManager) setupNAT() error {
	// Add masquerade rule for outgoing traffic from containers
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", nm.subnet,
		"!", "-o", nm.bridgeName,
		"-j", "MASQUERADE")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add masquerade rule: %w", err)
	}

	// Add forward rule for established connections
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-o", nm.bridgeName,
		"-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT")

	if err := cmd.Run(); err != nil {
		slog.Warn("failed to add conntrack forward rule", "error", err)
	}

	// Add forward rule for bridge traffic
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", nm.bridgeName,
		"!", "-o", nm.bridgeName,
		"-j", "ACCEPT")

	if err := cmd.Run(); err != nil {
		slog.Warn("failed to add bridge forward rule", "error", err)
	}

	// Add forward rule for bridge to bridge traffic
	cmd = exec.Command("iptables", "-A", "FORWARD",
		"-i", nm.bridgeName,
		"-o", nm.bridgeName,
		"-j", "ACCEPT")

	if err := cmd.Run(); err != nil {
		slog.Warn("failed to add bridge-to-bridge forward rule", "error", err)
	}

	return nil
}
