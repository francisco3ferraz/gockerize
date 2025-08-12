package security

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/syndtr/gocapability/capability"
)

// CapabilityManager handles Linux capability management for containers
type CapabilityManager struct {
}

// NewCapabilityManager creates a new capability manager
func NewCapabilityManager() *CapabilityManager {
	return &CapabilityManager{}
}

// DefaultCapabilities returns the default set of capabilities for containers
// This mirrors Docker's default capability set for security
func (cm *CapabilityManager) DefaultCapabilities() []string {
	return []string{
		"chown",            // Change file ownership
		"dac_override",     // Bypass file read/write/execute permission checks
		"fsetid",           // Don't clear set-user-ID and set-group-ID bits
		"fowner",           // Bypass permission checks on operations that normally require filesystem UID
		"mknod",            // Create special files using mknod
		"net_raw",          // Use RAW and PACKET sockets
		"setgid",           // Make arbitrary manipulations of process GIDs
		"setuid",           // Make arbitrary manipulations of process UIDs
		"setfcap",          // Set file capabilities
		"setpcap",          // Grant or remove any capability in the caller's permitted capability set
		"net_bind_service", // Bind a socket to Internet domain privileged ports
		"sys_chroot",       // Use chroot()
		"kill",             // Bypass permission checks for sending signals
		"audit_write",      // Write records to kernel auditing log
	}
}

// AllCapabilities returns all available Linux capabilities
func (cm *CapabilityManager) AllCapabilities() []string {
	var caps []string
	for _, cap := range capability.List() {
		caps = append(caps, cap.String())
	}
	return caps
}

// DangerousCapabilities returns capabilities that should never be granted in normal containers
func (cm *CapabilityManager) DangerousCapabilities() []string {
	return []string{
		"sys_admin",    // Perform a range of system administration operations
		"sys_module",   // Load and unload kernel modules
		"sys_time",     // Set system clock
		"sys_boot",     // Use reboot() and kexec_load()
		"sys_nice",     // Raise process nice value, set real-time scheduling policies
		"sys_resource", // Override resource limits
		"sys_rawio",    // Perform I/O port operations and iopl/ioperm
		"net_admin",    // Perform various network-related operations
	}
}

// ValidateCapability checks if a capability name is valid
func (cm *CapabilityManager) ValidateCapability(capName string) error {
	// Normalize capability name - remove CAP_ prefix if present and convert to lowercase
	normalizedName := strings.ToLower(capName)
	normalizedName = strings.TrimPrefix(normalizedName, "cap_")

	// Check if capability exists
	for _, cap := range capability.List() {
		if cap.String() == normalizedName {
			return nil
		}
	}

	return fmt.Errorf("invalid capability: %s", capName)
}

// CalculateFinalCapabilities determines the final set of capabilities based on defaults, additions, and drops
func (cm *CapabilityManager) CalculateFinalCapabilities(capAdd, capDrop []string, privileged bool) ([]string, error) {
	var finalCaps []string

	if privileged {
		// Privileged containers get all capabilities
		slog.Warn("Running container in privileged mode - all capabilities granted")
		return cm.AllCapabilities(), nil
	}

	// Start with default capabilities
	capSet := make(map[string]bool)
	for _, cap := range cm.DefaultCapabilities() {
		capSet[cap] = true
	}

	// Process capability drops first
	for _, capName := range capDrop {
		if strings.ToUpper(capName) == "ALL" {
			// Drop all capabilities
			capSet = make(map[string]bool)
			slog.Info("Dropping all capabilities")
			break
		}

		// Normalize capability name - remove CAP_ prefix and lowercase
		normalizedName := strings.ToLower(capName)
		normalizedName = strings.TrimPrefix(normalizedName, "cap_")

		if err := cm.ValidateCapability(normalizedName); err != nil {
			return nil, fmt.Errorf("invalid capability to drop: %w", err)
		}

		delete(capSet, normalizedName)
		slog.Info("Dropping capability", "capability", normalizedName)
	}

	// Process capability additions
	for _, capName := range capAdd {
		// Normalize capability name - remove CAP_ prefix and lowercase
		normalizedName := strings.ToLower(capName)
		normalizedName = strings.TrimPrefix(normalizedName, "cap_")

		if err := cm.ValidateCapability(normalizedName); err != nil {
			return nil, fmt.Errorf("invalid capability to add: %w", err)
		}

		// Warn about dangerous capabilities
		for _, dangerous := range cm.DangerousCapabilities() {
			if normalizedName == dangerous {
				slog.Warn("Adding dangerous capability - this may compromise container security", "capability", normalizedName)
				break
			}
		}

		capSet[normalizedName] = true
		slog.Info("Adding capability", "capability", normalizedName)
	}

	// Convert map to slice
	for cap := range capSet {
		finalCaps = append(finalCaps, cap)
	}

	return finalCaps, nil
}

// ApplyCapabilities applies the specified capabilities to the current process
// This should be called after creating namespaces but before exec
func (cm *CapabilityManager) ApplyCapabilities(caps []string) error {
	slog.Info("Applying capabilities", "capabilities", caps)

	// Get current capabilities
	currentCaps, err := capability.NewPid2(0) // Use 0 for current process
	if err != nil {
		return fmt.Errorf("failed to get current capabilities: %w", err)
	}

	// Load current capability state
	if err := currentCaps.Load(); err != nil {
		return fmt.Errorf("failed to load current capabilities: %w", err)
	}

	// Clear all capabilities first
	currentCaps.Clear(capability.CAPS)

	// Convert capability names to capability.Cap and set them
	for _, capName := range caps {
		var cap capability.Cap
		found := false

		// Find the capability by name (capName should already be normalized)
		for _, c := range capability.List() {
			if c.String() == capName {
				cap = c
				found = true
				break
			}
		}

		if !found {
			slog.Warn("Capability not found, skipping", "capability", capName)
			continue
		}

		// Set the capability in permitted and effective sets
		currentCaps.Set(capability.PERMITTED, cap)
		currentCaps.Set(capability.EFFECTIVE, cap)
		// Don't set inheritable by default for security
	}

	// Apply the capabilities
	if err := currentCaps.Apply(capability.CAPS); err != nil {
		// If we can't apply capabilities, log a warning but don't fail
		// This might happen in some environments where capability management is restricted
		slog.Warn("Failed to apply capabilities, continuing anyway", "error", err)
		return nil
	}

	slog.Info("Capabilities applied successfully")
	return nil
}

// DropCapabilities drops all capabilities except those specified
// This is a convenience function for the common use case
func (cm *CapabilityManager) DropCapabilities(keepCaps []string) error {
	allCaps := cm.AllCapabilities()
	var dropCaps []string

	// Find capabilities to drop
	keepSet := make(map[string]bool)
	for _, cap := range keepCaps {
		keepSet[cap] = true
	}

	for _, cap := range allCaps {
		if !keepSet[cap] {
			dropCaps = append(dropCaps, cap)
		}
	}

	// Calculate final capabilities (empty additions, drop the unwanted ones)
	finalCaps, err := cm.CalculateFinalCapabilities([]string{}, dropCaps, false)
	if err != nil {
		return err
	}

	return cm.ApplyCapabilities(finalCaps)
}

// GetCurrentCapabilities returns the current process capabilities
func (cm *CapabilityManager) GetCurrentCapabilities() ([]string, error) {
	caps, err := capability.NewPid2(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("failed to get current capabilities: %w", err)
	}

	if err := caps.Load(); err != nil {
		return nil, fmt.Errorf("failed to load current capabilities: %w", err)
	}

	var result []string
	for _, cap := range capability.List() {
		if caps.Get(capability.EFFECTIVE, cap) {
			result = append(result, cap.String())
		}
	}

	return result, nil
}

// LogCapabilities logs the current capability state for debugging
func (cm *CapabilityManager) LogCapabilities() {
	caps, err := cm.GetCurrentCapabilities()
	if err != nil {
		slog.Error("Failed to get current capabilities", "error", err)
		return
	}

	slog.Info("Current effective capabilities", "capabilities", caps)
}
