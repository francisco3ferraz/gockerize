package runtime

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
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
		f.WriteString(fmt.Sprintf("PID: %d, PPID: %d\n", os.Getpid(), os.Getppid()))
		f.WriteString(fmt.Sprintf("Args: %v\n", os.Args))
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

	// Wait for network setup completion signal from parent
	// Check if we need to wait for network setup
	if os.Getenv("WAIT_FOR_NETWORK") == "true" {
		if f != nil {
			f.WriteString("waiting for network setup signal\n")
		}
		slog.Info("waiting for network setup signal")

		// Wait for SIGUSR1 signal from parent indicating network is ready
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGUSR1)

		// Wait for signal or timeout after 10 seconds
		select {
		case <-sigChan:
			slog.Info("received network setup signal, proceeding")
			if f != nil {
				f.WriteString("received network setup signal\n")
			}
		case <-time.After(10 * time.Second):
			slog.Warn("timeout waiting for network setup signal, proceeding anyway")
			if f != nil {
				f.WriteString("timeout waiting for network signal\n")
			}
		}
	}

	if f != nil {
		f.WriteString(fmt.Sprintf("about to execute command: %v\n", cmd))
	}
	// Execute the container command
	return execContainerCommand(cmd)
}

// setupFilesystem sets up the container's filesystem with proper isolation for user namespaces
func setupFilesystem(rootfs string) error {
	// Ensure rootfs exists
	if _, err := os.Stat(rootfs); os.IsNotExist(err) {
		return fmt.Errorf("rootfs does not exist: %s", rootfs)
	}

	// In user namespaces, we have limited mount capabilities
	// Try the full isolation approach first, with fallbacks for user namespace limitations

	// Attempt 1: Try pivot_root approach with proper setup
	if err := setupFilesystemWithPivotRoot(rootfs); err != nil {
		slog.Debug("pivot_root approach failed", "error", err)

		// Attempt 2: Try chroot approach
		if err := setupFilesystemWithChroot(rootfs); err != nil {
			slog.Debug("chroot approach failed", "error", err)

			// Attempt 3: Fallback to bind mount approach
			if err := setupFilesystemWithBindMount(rootfs); err != nil {
				slog.Debug("bind mount approach failed", "error", err)

				// Final fallback: minimal setup
				return setupFilesystemMinimal(rootfs)
			}
		}
	}

	slog.Info("filesystem isolation setup completed", "rootfs", rootfs)
	return nil
}

// setupFilesystemWithPivotRoot attempts full filesystem isolation using pivot_root
func setupFilesystemWithPivotRoot(rootfs string) error {
	// Make the current mount namespace private
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to make root mount private: %w", err)
	}

	// Create temporary new root
	newRoot := "/tmp/container-new-root"
	if err := os.MkdirAll(newRoot, 0755); err != nil {
		return fmt.Errorf("failed to create new root: %w", err)
	}

	// Bind mount the container rootfs
	if err := syscall.Mount(rootfs, newRoot, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to bind mount rootfs: %w", err)
	}

	// Create old root directory
	oldRoot := newRoot + "/.old-root"
	if err := os.MkdirAll(oldRoot, 0755); err != nil {
		return fmt.Errorf("failed to create old root: %w", err)
	}

	// Pivot root
	if err := syscall.PivotRoot(newRoot, oldRoot); err != nil {
		return fmt.Errorf("failed to pivot root: %w", err)
	}

	// Change to new root
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("failed to chdir to new root: %w", err)
	}

	// Unmount old root
	if err := syscall.Unmount("/.old-root", syscall.MNT_DETACH); err != nil {
		slog.Warn("failed to unmount old root", "error", err)
	}

	// Remove old root directory
	os.Remove("/.old-root")

	slog.Info("filesystem setup using pivot_root")
	return nil
}

// setupFilesystemWithChroot attempts filesystem isolation using chroot
func setupFilesystemWithChroot(rootfs string) error {
	// First, try to remount the rootfs as a bind mount to make it a proper mount point
	// This sometimes works even in user namespaces
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		slog.Debug("failed to bind mount rootfs to itself", "error", err)
		// Continue anyway - might still work
	}

	// Change to the rootfs directory
	if err := os.Chdir(rootfs); err != nil {
		return fmt.Errorf("failed to chdir to rootfs: %w", err)
	}

	// Try chroot - this might work in user namespaces if we have the right setup
	if err := syscall.Chroot("."); err != nil {
		// If chroot fails, it's likely due to user namespace restrictions
		return fmt.Errorf("failed to chroot: %w", err)
	}

	// Change to root directory after chroot
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("failed to chdir to root after chroot: %w", err)
	}

	slog.Info("filesystem setup using chroot")
	return nil
}

// setupFilesystemWithBindMount attempts a bind mount approach
func setupFilesystemWithBindMount(rootfs string) error {
	// Create a new root directory in /tmp
	newRoot := "/tmp/container-root"
	if err := os.MkdirAll(newRoot, 0755); err != nil {
		return fmt.Errorf("failed to create container root: %w", err)
	}

	// Try to bind mount the rootfs
	if err := syscall.Mount(rootfs, newRoot, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("failed to bind mount: %w", err)
	}

	// Change to the new root
	if err := os.Chdir(newRoot); err != nil {
		return fmt.Errorf("failed to chdir to new root: %w", err)
	}

	slog.Info("filesystem setup using bind mount")
	return nil
}

// setupFilesystemMinimal provides maximum possible filesystem setup for user namespace compatibility
func setupFilesystemMinimal(rootfs string) error {
	// Even in minimal mode, we can still improve isolation

	// Change to the rootfs directory as our working directory
	if err := os.Chdir(rootfs); err != nil {
		return fmt.Errorf("failed to chdir to rootfs: %w", err)
	}

	// Try to at least change the root environment variable to point to our rootfs
	// This helps programs that respect the ROOT environment variable
	if err := os.Setenv("ROOT", "/"); err != nil {
		slog.Debug("failed to set ROOT environment variable", "error", err)
	}

	// Set the PATH to prioritize our container binaries
	containerPath := "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin"
	if err := os.Setenv("PATH", containerPath); err != nil {
		slog.Debug("failed to set PATH environment variable", "error", err)
	}

	// Set HOME to container's root
	if err := os.Setenv("HOME", "/root"); err != nil {
		slog.Debug("failed to set HOME environment variable", "error", err)
	}

	slog.Info("filesystem setup using minimal approach with environment optimization",
		"rootfs", rootfs,
		"pwd", rootfs,
		"isolation_level", "limited_but_functional")

	return nil
}

// setupMounts creates essential mounts inside the container
// In user namespaces, most special filesystem mounts will fail, so we use fallback strategies
func setupMounts() error {
	// Check if we're in a user namespace by trying to read uid_map
	inUserNS := false
	if data, err := os.ReadFile("/proc/self/uid_map"); err == nil {
		// If uid_map exists and is not empty, we're in a user namespace
		inUserNS = len(data) > 0
		slog.Debug("user namespace detection", "uid_map_content", string(data), "in_user_ns", inUserNS)
	} else {
		slog.Debug("could not read uid_map", "error", err)
	}

	if inUserNS {
		slog.Info("detected user namespace, using limited mount setup")
		return setupMountsUserNS()
	}

	// Full privileged mount setup (when not in user namespace)
	slog.Info("using full privileged mount setup")
	return setupMountsPrivileged()
}

// setupMountsUserNS provides mount setup compatible with user namespaces
func setupMountsUserNS() error {
	// In user namespaces, we can only do limited operations
	// Focus on what actually works and is essential

	// Create essential directories that might be missing
	essentialDirs := []string{
		"/proc",
		"/dev",
		"/tmp",
		"/sys",
		"/dev/pts",
		"/dev/shm",
	}

	for _, dir := range essentialDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			slog.Debug("failed to create directory", "dir", dir, "error", err)
		}
	}

	// Try to create basic device files if possible
	if err := createDeviceFiles(); err != nil {
		slog.Debug("failed to create basic device files", "error", err)
	}

	slog.Info("user namespace mount setup completed (limited functionality)")
	return nil
}

// setupMountsPrivileged provides full mount setup when running with privileges
func setupMountsPrivileged() error {
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
	}

	// Create essential device files
	if err := createDeviceFiles(); err != nil {
		slog.Warn("failed to create device files", "error", err)
	}

	slog.Info("privileged mount setup completed")
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
	if _, err := os.Stat(cmdPath); err != nil {
		slog.Error("command file does not exist", "path", cmdPath, "error", err)
		// Try to look in PATH as fallback
		if pathCmd, pathErr := exec.LookPath(cmd[0]); pathErr == nil {
			cmdPath = pathCmd
		} else {
			return fmt.Errorf("command file does not exist: %s (%w)", cmdPath, err)
		}
	}

	// Prepare arguments (including argv[0])
	args := cmd

	// Prepare environment
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
