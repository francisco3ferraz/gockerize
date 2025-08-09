package runtime

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ContainerInit is called when the main binary is executed with "container-init"
// This runs inside the container's namespaces and sets up the container environment
func ContainerInit() error {
	// Write debug info to a file since logging might not work in namespace
	debugFile := "/tmp/container-init-debug.log"
	f, err := os.OpenFile(debugFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("container-init started at %v\n", time.Now()))
	}

	slog.Info("initializing container environment")

	// Get container configuration from environment
	containerID := os.Getenv("CONTAINER_ID")
	rootfs := os.Getenv("CONTAINER_ROOTFS")
	cmdStr := os.Getenv("CONTAINER_CMD")
	hostname := os.Getenv("CONTAINER_HOSTNAME")

	if f != nil {
		f.WriteString(fmt.Sprintf("env vars: ID=%s, rootfs=%s, cmd=%s, hostname=%s\n",
			containerID, rootfs, cmdStr, hostname))
	}

	slog.Debug("container init environment",
		"id", containerID,
		"rootfs", rootfs,
		"cmd", cmdStr,
		"hostname", hostname)

	if containerID == "" || rootfs == "" {
		if f != nil {
			f.WriteString("ERROR: missing required environment variables\n")
		}
		return fmt.Errorf("missing required container environment variables")
	}

	// Set hostname if provided
	if hostname != "" {
		if err := syscall.Sethostname([]byte(hostname)); err != nil {
			slog.Warn("failed to set hostname", "hostname", hostname, "error", err)
			if f != nil {
				f.WriteString(fmt.Sprintf("hostname failed: %v\n", err))
			}
		}
	}

	if f != nil {
		f.WriteString("about to setup filesystem\n")
	}
	slog.Debug("setting up filesystem")
	// Setup filesystem isolation
	if err := setupFilesystem(rootfs); err != nil {
		if f != nil {
			f.WriteString(fmt.Sprintf("filesystem setup failed: %v\n", err))
		}
		return fmt.Errorf("failed to setup filesystem: %w", err)
	}

	if f != nil {
		f.WriteString("filesystem setup complete, about to setup mounts\n")
	}
	slog.Debug("setting up mounts")
	// Setup essential mounts
	if err := setupMounts(); err != nil {
		if f != nil {
			f.WriteString(fmt.Sprintf("mounts setup failed: %v\n", err))
		}
		return fmt.Errorf("failed to setup mounts: %w", err)
	}

	// Parse command
	var cmd []string
	if cmdStr != "" {
		cmd = strings.Fields(cmdStr)
	} else {
		cmd = []string{"/bin/sh"}
	}

	if f != nil {
		f.WriteString(fmt.Sprintf("about to execute command: %v\n", cmd))
	}
	slog.Debug("about to execute command", "cmd", cmd) // Execute the container command
	return execContainerCommand(cmd)
}

// setupFilesystem sets up the container's filesystem using pivot_root
func setupFilesystem(rootfs string) error {
	slog.Debug("setting up filesystem", "rootfs", rootfs)

	// Ensure rootfs exists
	if _, err := os.Stat(rootfs); os.IsNotExist(err) {
		return fmt.Errorf("rootfs does not exist: %s", rootfs)
	}

	// Create old_root directory inside new root
	oldRoot := filepath.Join(rootfs, ".old_root")
	if err := os.MkdirAll(oldRoot, 0755); err != nil {
		return fmt.Errorf("failed to create old_root directory: %w", err)
	}

	// Make rootfs a mount point
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to bind mount rootfs: %w", err)
	}

	// Pivot root
	if err := syscall.PivotRoot(rootfs, oldRoot); err != nil {
		return fmt.Errorf("failed to pivot root: %w", err)
	}

	// Change to new root
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("failed to change to new root: %w", err)
	}

	// Unmount old root
	if err := syscall.Unmount("/.old_root", syscall.MNT_DETACH); err != nil {
		slog.Warn("failed to unmount old root", "error", err)
	}

	// Remove old root directory
	if err := os.RemoveAll("/.old_root"); err != nil {
		slog.Warn("failed to remove old root directory", "error", err)
	}

	return nil
}

// setupMounts creates essential mounts inside the container
func setupMounts() error {
	slog.Debug("setting up essential mounts")

	// Essential mounts for container
	mounts := []struct {
		source string
		target string
		fstype string
		flags  uintptr
		data   string
	}{
		// /proc filesystem
		{"proc", "/proc", "proc", syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV, ""},

		// /dev filesystem
		{"tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID | syscall.MS_STRICTATIME, "mode=755"},

		// /dev/pts for pseudo terminals
		{"devpts", "/dev/pts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"},

		// /dev/shm for shared memory
		{"tmpfs", "/dev/shm", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, ""},

		// /tmp as tmpfs
		{"tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, ""},

		// /sys filesystem (read-only)
		{"sysfs", "/sys", "sysfs", syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV, ""},
	}

	for _, mount := range mounts {
		// Create target directory if it doesn't exist
		if err := os.MkdirAll(mount.target, 0755); err != nil {
			slog.Warn("failed to create mount target", "target", mount.target, "error", err)
			continue
		}

		// Mount the filesystem
		err := syscall.Mount(mount.source, mount.target, mount.fstype, mount.flags, mount.data)
		if err != nil {
			slog.Warn("failed to mount filesystem",
				"source", mount.source,
				"target", mount.target,
				"fstype", mount.fstype,
				"error", err)
			continue
		}

		slog.Debug("mounted filesystem", "target", mount.target, "fstype", mount.fstype)
	}

	// Create essential device files
	if err := createDeviceFiles(); err != nil {
		slog.Warn("failed to create device files", "error", err)
	}

	return nil
}

// createDeviceFiles creates essential device files in /dev
func createDeviceFiles() error {
	devices := []struct {
		path  string
		mode  uint32
		major int
		minor int
	}{
		{"/dev/null", syscall.S_IFCHR | 0666, 1, 3},
		{"/dev/zero", syscall.S_IFCHR | 0666, 1, 5},
		{"/dev/full", syscall.S_IFCHR | 0666, 1, 7},
		{"/dev/random", syscall.S_IFCHR | 0666, 1, 8},
		{"/dev/urandom", syscall.S_IFCHR | 0666, 1, 9},
		{"/dev/tty", syscall.S_IFCHR | 0666, 5, 0},
	}

	for _, dev := range devices {
		if err := syscall.Mknod(dev.path, dev.mode, int(makedev(dev.major, dev.minor))); err != nil {
			slog.Debug("failed to create device", "path", dev.path, "error", err)
		}
	}

	// Create /dev/ptmx symlink
	if err := os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil {
		slog.Debug("failed to create ptmx symlink", "error", err)
	}

	// Create standard stream symlinks
	streams := map[string]string{
		"/dev/stdin":  "/proc/self/fd/0",
		"/dev/stdout": "/proc/self/fd/1",
		"/dev/stderr": "/proc/self/fd/2",
	}

	for link, target := range streams {
		if err := os.Symlink(target, link); err != nil {
			slog.Debug("failed to create stream symlink", "link", link, "error", err)
		}
	}

	return nil
}

// execContainerCommand replaces the current process with the container command
func execContainerCommand(cmd []string) error {
	slog.Info("executing container command", "cmd", cmd)

	if len(cmd) == 0 {
		return fmt.Errorf("no command specified")
	}

	// For debugging, try to use absolute path for common commands
	var cmdPath string
	switch cmd[0] {
	case "echo":
		cmdPath = "/bin/echo"
	case "sh":
		cmdPath = "/bin/sh"
	case "bash":
		cmdPath = "/bin/bash"
	default:
		cmdPath = cmd[0]
	}

	// Check if the command file exists and is executable
	if stat, err := os.Stat(cmdPath); err != nil {
		slog.Error("command file does not exist", "path", cmdPath, "error", err)
		// Try to look in PATH as fallback
		if pathCmd, pathErr := exec.LookPath(cmd[0]); pathErr == nil {
			cmdPath = pathCmd
			slog.Debug("command found in PATH", "cmd", cmd[0], "path", cmdPath)
		} else {
			return fmt.Errorf("command file does not exist: %s (%w)", cmdPath, err)
		}
	} else {
		slog.Debug("command file found", "path", cmdPath, "mode", stat.Mode())
	}

	// Prepare arguments (including argv[0])
	args := cmd

	// Prepare environment - for debugging, let's simplify the environment
	env := []string{
		"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
		"HOME=/root",
		"TERM=xterm",
	}

	slog.Info("about to exec", "path", cmdPath, "args", args, "env", env)

	// Replace current process with container command
	return syscall.Exec(cmdPath, args, env)
}

// makedev creates a device number from major and minor numbers
func makedev(major, minor int) uint64 {
	return uint64(((major & 0xfff) << 8) | (minor & 0xff) | ((minor & 0xfff00) << 12))
}
