package container

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/francisco3ferraz/gockerize/pkg/types"
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

// SetupNetwork sets up networking for a container
func (nm *NetworkManager) SetupNetwork(ctx context.Context, container *types.Container) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	slog.Info("setting up network for container", "id", container.ID, "pid", container.PID)

	// Generate unique veth pair names
	vethHost := fmt.Sprintf("veth%s", container.ID[:8])
	vethGuest := fmt.Sprintf("vethg%s", container.ID[:7])

	slog.Debug("creating veth pair", "host", vethHost, "guest", vethGuest)
	// Create veth pair
	if err := nm.createVethPair(vethHost, vethGuest); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	slog.Debug("attaching veth to bridge", "veth", vethHost, "bridge", nm.bridgeName)
	// Attach host veth to bridge
	if err := nm.attachToBridge(vethHost); err != nil {
		nm.deleteVethPair(vethHost) // Cleanup on failure
		return fmt.Errorf("failed to attach to bridge: %w", err)
	}

	slog.Debug("bringing up host veth", "veth", vethHost)
	// Bring up host veth
	if err := nm.linkUp(vethHost); err != nil {
		nm.deleteVethPair(vethHost)
		return fmt.Errorf("failed to bring up host veth: %w", err)
	}

	slog.Debug("moving guest veth to container netns", "veth", vethGuest, "pid", container.PID)
	// Move guest veth to container network namespace
	if err := nm.moveToNetNS(vethGuest, container.PID); err != nil {
		nm.deleteVethPair(vethHost)
		return fmt.Errorf("failed to move veth to container netns: %w", err)
	}

	// Assign IP to container interface
	containerIP := nm.getNextIP()
	slog.Debug("configuring container interface", "veth", vethGuest, "ip", containerIP, "pid", container.PID)
	if err := nm.configureContainerInterface(container.PID, vethGuest, containerIP); err != nil {
		nm.deleteVethPair(vethHost)
		return fmt.Errorf("failed to configure container interface: %w", err)
	}

	// Setup port forwarding if needed
	if err := nm.setupPortForwarding(container, containerIP); err != nil {
		slog.Warn("failed to setup port forwarding", "container", container.ID, "error", err)
	}

	// Store network info
	container.NetworkInfo = &types.NetworkInfo{
		IPAddress: containerIP,
		Gateway:   nm.getGatewayIP(),
		Bridge:    nm.bridgeName,
		Ports:     make(map[string]string),
	}

	// Store port mappings
	for _, port := range container.Config.Ports {
		portKey := fmt.Sprintf("%d/%s", port.ContainerPort, port.Protocol)
		portValue := fmt.Sprintf("%d", port.HostPort)
		container.NetworkInfo.Ports[portKey] = portValue
	}

	slog.Info("network setup complete",
		"container", container.ID,
		"ip", containerIP,
		"bridge", nm.bridgeName)

	return nil
}

// TeardownNetwork tears down networking for a container
func (nm *NetworkManager) TeardownNetwork(ctx context.Context, container *types.Container) error {
	slog.Info("tearing down network for container", "id", container.ID)

	// Remove port forwarding rules
	if err := nm.removePortForwarding(container); err != nil {
		slog.Warn("failed to remove port forwarding", "container", container.ID, "error", err)
	}

	// Delete veth pair (this also removes it from the bridge)
	vethHost := fmt.Sprintf("veth%s", container.ID[:8])
	if err := nm.deleteVethPair(vethHost); err != nil {
		slog.Warn("failed to delete veth pair", "container", container.ID, "error", err)
	}

	return nil
}

// GetNetworkInfo returns network information for a container
func (nm *NetworkManager) GetNetworkInfo(container *types.Container) (*types.NetworkInfo, error) {
	if container.NetworkInfo != nil {
		return container.NetworkInfo, nil
	}

	return &types.NetworkInfo{
		Bridge:  nm.bridgeName,
		Gateway: nm.getGatewayIP(),
	}, nil
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

// createVethPair creates a veth pair
func (nm *NetworkManager) createVethPair(vethHost, vethGuest string) error {
	cmd := exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethGuest)
	return cmd.Run()
}

// deleteVethPair deletes a veth pair
func (nm *NetworkManager) deleteVethPair(vethHost string) error {
	cmd := exec.Command("ip", "link", "delete", vethHost)
	return cmd.Run()
}

// attachToBridge attaches an interface to the bridge
func (nm *NetworkManager) attachToBridge(iface string) error {
	cmd := exec.Command("ip", "link", "set", iface, "master", nm.bridgeName)
	return cmd.Run()
}

// linkUp brings up a network interface
func (nm *NetworkManager) linkUp(iface string) error {
	cmd := exec.Command("ip", "link", "set", iface, "up")
	return cmd.Run()
}

// moveToNetNS moves an interface to a network namespace
func (nm *NetworkManager) moveToNetNS(iface string, pid int) error {
	cmd := exec.Command("ip", "link", "set", iface, "netns", strconv.Itoa(pid))
	return cmd.Run()
}

// configureContainerInterface configures the network interface inside the container
func (nm *NetworkManager) configureContainerInterface(pid int, iface, ip string) error {
	slog.Debug("configuring container interface", "pid", pid, "iface", iface, "ip", ip)

	// Run commands inside the container's network namespace
	nsenterCmd := func(args ...string) *exec.Cmd {
		fullArgs := append([]string{"-t", strconv.Itoa(pid), "-n", "--"}, args...)
		return exec.Command("nsenter", fullArgs...)
	}

	slog.Debug("renaming interface to eth0", "from", iface)
	// Rename interface to eth0
	cmd := nsenterCmd("ip", "link", "set", iface, "name", "eth0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to rename interface: %w", err)
	}

	// Assign IP address
	cmd = nsenterCmd("ip", "addr", "add", ip+"/24", "dev", "eth0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to assign IP: %w", err)
	}

	// Bring interface up
	cmd = nsenterCmd("ip", "link", "set", "eth0", "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// Add default route
	gatewayIP := nm.getGatewayIP()
	cmd = nsenterCmd("ip", "route", "add", "default", "via", gatewayIP, "dev", "eth0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}

	// Setup loopback
	cmd = nsenterCmd("ip", "link", "set", "lo", "up")
	if err := cmd.Run(); err != nil {
		slog.Warn("failed to bring up loopback", "error", err)
	}

	return nil
}

// setupPortForwarding sets up port forwarding rules using iptables
func (nm *NetworkManager) setupPortForwarding(container *types.Container, containerIP string) error {
	for _, port := range container.Config.Ports {
		// Add DNAT rule for incoming traffic
		cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
			"-p", port.Protocol,
			"--dport", strconv.Itoa(port.HostPort),
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", containerIP, port.ContainerPort))

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add DNAT rule for port %d: %w", port.HostPort, err)
		}

		// Add FORWARD rule to allow the traffic
		cmd = exec.Command("iptables", "-A", "FORWARD",
			"-d", containerIP,
			"-p", port.Protocol,
			"--dport", strconv.Itoa(port.ContainerPort),
			"-j", "ACCEPT")

		if err := cmd.Run(); err != nil {
			slog.Warn("failed to add FORWARD rule", "port", port.HostPort, "error", err)
		}
	}

	return nil
}

// removePortForwarding removes port forwarding rules
func (nm *NetworkManager) removePortForwarding(container *types.Container) error {
	if container.NetworkInfo == nil {
		return nil
	}

	containerIP := container.NetworkInfo.IPAddress
	for _, port := range container.Config.Ports {
		// Remove DNAT rule
		cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
			"-p", port.Protocol,
			"--dport", strconv.Itoa(port.HostPort),
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", containerIP, port.ContainerPort))

		if err := cmd.Run(); err != nil {
			slog.Warn("failed to remove DNAT rule", "port", port.HostPort, "error", err)
		}

		// Remove FORWARD rule
		cmd = exec.Command("iptables", "-D", "FORWARD",
			"-d", containerIP,
			"-p", port.Protocol,
			"--dport", strconv.Itoa(port.ContainerPort),
			"-j", "ACCEPT")

		if err := cmd.Run(); err != nil {
			slog.Warn("failed to remove FORWARD rule", "port", port.HostPort, "error", err)
		}
	}

	return nil
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

func (nm *NetworkManager) getNextIP() string {
	// Parse subnet to get network part
	_, ipnet, err := net.ParseCIDR(nm.subnet)
	if err != nil {
		// Fallback to simple IP assignment
		ip := fmt.Sprintf("172.17.0.%d", nm.nextIP)
		nm.nextIP++
		return ip
	}

	// Get network IP
	networkIP := ipnet.IP

	// Create IP by incrementing the last octet
	ip := make(net.IP, len(networkIP))
	copy(ip, networkIP)
	ip[len(ip)-1] += byte(nm.nextIP)

	nm.nextIP++
	return ip.String()
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
