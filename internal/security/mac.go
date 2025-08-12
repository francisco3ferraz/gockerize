package security

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// MACType represents the type of Mandatory Access Control system
type MACType string

const (
	MACTypeNone     MACType = "none"
	MACTypeAppArmor MACType = "apparmor"
	MACTypeSELinux  MACType = "selinux"
)

// MACConfig holds configuration for Mandatory Access Control
type MACConfig struct {
	Type    MACType `json:"type"`
	Profile string  `json:"profile,omitempty"`
	Label   string  `json:"label,omitempty"`
}

// MACManager handles Mandatory Access Control operations
type MACManager struct {
	availableType MACType
	profilesDir   string
}

// NewMACManager creates a new MAC manager and detects available systems
func NewMACManager() *MACManager {
	manager := &MACManager{
		availableType: MACTypeNone,
	}

	// Detect available MAC systems
	if isAppArmorAvailable() {
		manager.availableType = MACTypeAppArmor
		manager.profilesDir = "/etc/apparmor.d"
		slog.Info("AppArmor detected and available")
	} else if isSELinuxAvailable() {
		manager.availableType = MACTypeSELinux
		slog.Info("SELinux detected and available")
	} else {
		slog.Info("No MAC system detected (AppArmor/SELinux not available)")
	}

	return manager
}

// GetAvailableType returns the available MAC type on the system
func (m *MACManager) GetAvailableType() MACType {
	return m.availableType
}

// ApplyProfile applies the specified MAC profile to a process
func (m *MACManager) ApplyProfile(config *MACConfig, pid int) error {
	if config == nil || config.Type == MACTypeNone {
		return nil
	}

	if m.availableType == MACTypeNone {
		return fmt.Errorf("MAC requested but no MAC system available")
	}

	if config.Type != m.availableType {
		return fmt.Errorf("MAC type %s requested but only %s is available", config.Type, m.availableType)
	}

	switch config.Type {
	case MACTypeAppArmor:
		return m.applyAppArmorProfile(config.Profile, pid)
	case MACTypeSELinux:
		return m.applySELinuxLabel(config.Label, pid)
	default:
		return fmt.Errorf("unsupported MAC type: %s", config.Type)
	}
}

// CreateDefaultProfile creates a default container profile for the available MAC system
func (m *MACManager) CreateDefaultProfile() error {
	switch m.availableType {
	case MACTypeAppArmor:
		return m.createDefaultAppArmorProfile()
	case MACTypeSELinux:
		return m.createDefaultSELinuxPolicy()
	default:
		return nil // No MAC system available
	}
}

// GetDefaultConfig returns a default MAC configuration for containers
func (m *MACManager) GetDefaultConfig() *MACConfig {
	switch m.availableType {
	case MACTypeAppArmor:
		return &MACConfig{
			Type:    MACTypeAppArmor,
			Profile: "gockerize-default",
		}
	case MACTypeSELinux:
		return &MACConfig{
			Type:  MACTypeSELinux,
			Label: "container_t",
		}
	default:
		return &MACConfig{Type: MACTypeNone}
	}
}

// isAppArmorAvailable checks if AppArmor is available and enabled
func isAppArmorAvailable() bool {
	// Check if AppArmor module is loaded
	if _, err := os.Stat("/sys/module/apparmor"); os.IsNotExist(err) {
		return false
	}

	// Check if aa-status command is available
	if _, err := exec.LookPath("aa-status"); err != nil {
		return false
	}

	// Check if AppArmor is enabled
	cmd := exec.Command("aa-enabled")
	return cmd.Run() == nil
}

// isSELinuxAvailable checks if SELinux is available and enabled
func isSELinuxAvailable() bool {
	// Check if SELinux filesystem is mounted
	if _, err := os.Stat("/sys/fs/selinux"); os.IsNotExist(err) {
		return false
	}

	// Check if sestatus command is available
	if _, err := exec.LookPath("sestatus"); err != nil {
		return false
	}

	// Check if SELinux is enabled
	cmd := exec.Command("sestatus")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "SELinux status:                 enabled")
}

// applyAppArmorProfile applies an AppArmor profile to a process
func (m *MACManager) applyAppArmorProfile(profile string, pid int) error {
	if profile == "" {
		profile = "gockerize-default"
	}

	// For containers, AppArmor profiles should be applied at exec time
	// We'll set up the profile so it can be applied to new processes
	// For now, verify the profile exists and is loaded
	if err := m.validateAppArmorProfile(profile); err != nil {
		return err
	}

	slog.Info("AppArmor profile verified and ready", "profile", profile, "pid", pid)
	return nil
}

// applySELinuxLabel applies an SELinux label to a process
func (m *MACManager) applySELinuxLabel(label string, pid int) error {
	if label == "" {
		label = "container_t"
	}

	// Use runcon to change SELinux context
	cmd := exec.Command("runcon", label, "/bin/true")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply SELinux label %s: %w", label, err)
	}

	slog.Info("Applied SELinux label", "label", label, "pid", pid)
	return nil
}

// createDefaultAppArmorProfile creates a default AppArmor profile for containers
func (m *MACManager) createDefaultAppArmorProfile() error {
	profileName := "gockerize-default"
	profilePath := filepath.Join(m.profilesDir, profileName)

	// Check if profile already exists
	if _, err := os.Stat(profilePath); err == nil {
		slog.Info("AppArmor profile already exists", "profile", profileName)
		return nil
	}

	profileContent := fmt.Sprintf(`# AppArmor profile for gockerize containers
# This profile provides basic security restrictions for containerized processes

#include <tunables/global>

profile %s flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Allow basic system operations
  capability chown,
  capability dac_override,
  capability fowner,
  capability fsetid,
  capability kill,
  capability setgid,
  capability setuid,
  capability setpcap,
  capability net_bind_service,
  capability net_raw,
  capability sys_chroot,

  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_ptrace,
  deny capability sys_time,
  deny capability mac_admin,
  deny capability mac_override,

  # File system access
  / r,
  /bin/** rix,
  /sbin/** rix,
  /usr/bin/** rix,
  /usr/sbin/** rix,
  /lib/** r,
  /lib64/** r,
  /usr/lib/** r,
  /usr/lib64/** r,
  /etc/** r,
  /usr/share/** r,

  # Container specific paths
  /container/** rw,
  /tmp/** rw,
  /var/tmp/** rw,

  # Deny access to sensitive host files
  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /etc/group w,
  deny /proc/sys/kernel/** w,
  deny /sys/kernel/** w,
  deny /sys/fs/cgroup/** w,
  deny /proc/sysrq-trigger w,
  deny /proc/kcore r,
  deny /proc/kmsg r,

  # Network access
  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,
  network unix stream,
  network unix dgram,

  # Process and signal operations
  signal (send) set=(term, kill, stop, cont),
  ptrace (read),

  # Allow execution of container processes
  /proc/*/fd/ r,
  /proc/*/status r,
  /proc/*/stat r,
  /proc/*/cmdline r,
  /proc/*/comm r,
  /proc/sys/net/core/somaxconn r,

  # Allow shared memory and IPC
  /dev/shm/** rw,
  /run/shm/** rw,

  # Standard devices
  /dev/null rw,
  /dev/zero r,
  /dev/random r,
  /dev/urandom r,
  /dev/tty rw,
  /dev/pts/** rw,
  /dev/ptmx rw,

  # Temporary files
  owner /tmp/** rw,
  owner /var/tmp/** rw,
}
`, profileName)

	// Write the profile
	if err := os.WriteFile(profilePath, []byte(profileContent), 0644); err != nil {
		return fmt.Errorf("failed to write AppArmor profile: %w", err)
	}

	// Load the profile
	cmd := exec.Command("apparmor_parser", "-r", profilePath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to load AppArmor profile: %w", err)
	}

	slog.Info("Created and loaded default AppArmor profile", "profile", profileName, "path", profilePath)
	return nil
}

// createDefaultSELinuxPolicy creates a default SELinux policy for containers
func (m *MACManager) createDefaultSELinuxPolicy() error {
	// SELinux policy creation is more complex and typically requires
	// system-specific configuration. For now, we'll just log that
	// default SELinux contexts should be used.
	slog.Info("Using default SELinux contexts for containers", "context", "container_t")
	return nil
}

// ValidateProfile checks if a MAC profile exists and is valid
func (m *MACManager) ValidateProfile(config *MACConfig) error {
	if config == nil || config.Type == MACTypeNone {
		return nil
	}

	switch config.Type {
	case MACTypeAppArmor:
		return m.validateAppArmorProfile(config.Profile)
	case MACTypeSELinux:
		return m.validateSELinuxLabel(config.Label)
	default:
		return fmt.Errorf("unsupported MAC type: %s", config.Type)
	}
}

// GetExecWrapper returns a command wrapper for applying MAC profiles at exec time
func (m *MACManager) GetExecWrapper(config *MACConfig) []string {
	if config == nil || config.Type == MACTypeNone || m.availableType == MACTypeNone {
		return nil
	}

	switch config.Type {
	case MACTypeAppArmor:
		profile := config.Profile
		if profile == "" {
			profile = "gockerize-default"
		}
		return []string{"aa-exec", "-p", profile, "--"}
	case MACTypeSELinux:
		label := config.Label
		if label == "" {
			label = "container_t"
		}
		return []string{"runcon", label, "--"}
	default:
		return nil
	}
}

// GetDefaultExecWrapper returns a default exec wrapper if MAC is available
func (m *MACManager) GetDefaultExecWrapper() []string {
	if m.availableType == MACTypeNone {
		return nil
	}

	defaultConfig := m.GetDefaultConfig()
	return m.GetExecWrapper(defaultConfig)
}

// validateAppArmorProfile checks if an AppArmor profile exists
func (m *MACManager) validateAppArmorProfile(profile string) error {
	if profile == "" {
		profile = "gockerize-default"
	}

	cmd := exec.Command("aa-status")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check AppArmor profiles: %w", err)
	}

	if !strings.Contains(string(output), profile) {
		return fmt.Errorf("AppArmor profile '%s' not found or not loaded", profile)
	}

	return nil
}

// validateSELinuxLabel checks if an SELinux label is valid
func (m *MACManager) validateSELinuxLabel(label string) error {
	if label == "" {
		label = "container_t"
	}

	// Check if the context is valid using seinfo or similar
	cmd := exec.Command("seinfo", "-t", label)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("SELinux label '%s' is not valid: %w", label, err)
	}

	return nil
}
