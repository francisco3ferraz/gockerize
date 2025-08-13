package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/francisco3ferraz/gockerize/internal/security"
	"github.com/francisco3ferraz/gockerize/pkg/types"
)

// expandCombinedFlags processes arguments to expand combined flags like -it into -i -t
func expandCombinedFlags(args []string) []string {
	var result []string
	
	// Flags that take values (can't be combined with others)
	valueFlags := map[rune]bool{
		'w': true, // workdir
		'v': true, // volume  
		'e': true, // env
		'p': true, // ports
		'm': true, // memory
	}
	
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
			// This is a potentially combined flag (starts with single dash, more than 2 chars)
			expanded := false
			flags := arg[1:] // Remove the leading dash
			
			// Check if any flag takes a value - if so, don't expand
			hasValueFlag := false
			for _, char := range flags {
				if valueFlags[char] {
					hasValueFlag = true
					break
				}
			}
			
			if !hasValueFlag {
				// Check if all characters are valid single-letter flags
				validFlags := "dit" // Only boolean flags can be combined
				allValid := true
				for _, char := range flags {
					if !strings.ContainsRune(validFlags, char) {
						allValid = false
						break
					}
				}
				
				if allValid {
					// Expand the combined flags
					for _, char := range flags {
						result = append(result, "-"+string(char))
					}
					expanded = true
				}
			}
			
			if !expanded {
				result = append(result, arg)
			}
		} else {
			result = append(result, arg)
		}
	}
	
	return result
}

// Handler handles CLI commands
type Handler struct {
	runtime types.Runtime
}

// New creates a new CLI handler
func New(runtime types.Runtime) *Handler {
	return &Handler{
		runtime: runtime,
	}
}

// Run handles the 'run' command
func (h *Handler) Run(ctx context.Context, args []string) error {
	// Parse run command flags
	runFlags := flag.NewFlagSet("run", flag.ExitOnError)

	var (
		detach      = runFlags.Bool("d", false, "run in detached mode")
		interactive = runFlags.Bool("i", false, "run in interactive mode")
		tty         = runFlags.Bool("t", false, "allocate a pseudo-TTY")
		name        = runFlags.String("name", "", "container name")
		hostname    = runFlags.String("hostname", "", "container hostname")
		memory      = runFlags.String("m", "", "memory limit (e.g., 512m, 1g)")
		cpuShares   = runFlags.Int64("cpu-shares", 0, "CPU shares (relative weight)")
		workdir     = runFlags.String("w", "", "working directory")
		env         = runFlags.String("e", "", "environment variables (comma-separated key=value pairs)")
		ports       = runFlags.String("p", "", "port mappings (e.g., 8080:80)")
		volumes     = runFlags.String("v", "", "volume mounts (e.g., /host:/container)")
		userNS      = runFlags.Bool("user-ns", false, "enable user namespace isolation (enhanced security)")
		secProfile  = runFlags.String("security-profile", "", "AppArmor/SELinux profile (e.g., 'apparmor:my-profile' or 'selinux:container_t')")
		capAdd      = runFlags.String("cap-add", "", "add Linux capabilities (comma-separated)")
		capDrop     = runFlags.String("cap-drop", "", "drop Linux capabilities (comma-separated)")
		privileged  = runFlags.Bool("privileged", false, "give extended privileges to container (insecure)")
		seccompOpt  = runFlags.String("security-opt", "", "security options (seccomp=profile.json or seccomp=unconfined)")
	)

	runFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize run [OPTIONS] IMAGE [COMMAND]

			Run a new container

			Options:
			-d, --detach          Run in detached mode
			-i, --interactive     Run in interactive mode
			-t, --tty             Allocate a pseudo-TTY
			--name string         Container name
			--hostname string     Container hostname
			-m, --memory string   Memory limit (e.g., 512m, 1g)
			--cpu-shares int      CPU shares (relative weight)
			-w, --workdir string  Working directory inside container
			-e, --env string      Environment variables (comma-separated key=value)
			-p, --ports string    Port mappings (host:container)
			-v, --volume string   Volume mounts (host:container)
			--user-ns             Enable user namespace isolation (enhanced security)
			--security-profile    AppArmor/SELinux profile (apparmor:profile or selinux:label)
			--cap-add string      Add Linux capabilities (comma-separated)
			--cap-drop string     Drop Linux capabilities (comma-separated, or 'ALL')
			--privileged          Give extended privileges to container (insecure)
			--security-opt        Security options (seccomp=profile.json or seccomp=unconfined)

			Examples:
			gockerize run alpine:latest
			gockerize run -i -t alpine:latest /bin/sh
			gockerize run -d -p 8080:80 --name web nginx:latest
			gockerize run --user-ns -v /tmp:/data -e "KEY=value" ubuntu:latest /bin/bash
			gockerize run --security-profile apparmor:gockerize-default ubuntu:latest
			gockerize run --cap-drop ALL --cap-add CHOWN,SETUID alpine:latest
			gockerize run --cap-drop NET_RAW ubuntu:latest
			gockerize run --security-opt seccomp=unconfined ubuntu:latest
			gockerize run --security-opt seccomp=/path/to/profile.json ubuntu:latest
	`)
	}

	// Pre-process args to handle combined flags like -it
	processedArgs := expandCombinedFlags(args)

	if err := runFlags.Parse(processedArgs); err != nil {
		return err
	}

	remainingArgs := runFlags.Args()
	if len(remainingArgs) == 0 {
		runFlags.Usage()
		return fmt.Errorf("image name required")
	}

	imageName := remainingArgs[0]
	command := []string{"/bin/sh"}
	if len(remainingArgs) > 1 {
		command = remainingArgs[1:]
	}

	// Build container configuration
	config := &types.ContainerConfig{
		Name:          *name,
		Command:       command,   // Set the command in config
		RootFS:        imageName, // For now, image name is the rootfs
		WorkingDir:    *workdir,
		Hostname:      *hostname,
		Interactive:   *interactive,
		TTY:           *tty,
		Detached:      *detach, // Add detached flag
		UserNamespace: *userNS, // Add user namespace option
	}

	// Parse memory limit
	if *memory != "" {
		memBytes, err := parseMemory(*memory)
		if err != nil {
			return fmt.Errorf("invalid memory format: %w", err)
		}
		config.Memory = memBytes
	}

	// Set CPU shares
	if *cpuShares > 0 {
		config.CPUShares = *cpuShares
	}

	// Parse environment variables
	if *env != "" {
		config.Env = strings.Split(*env, ",")
	}

	// Parse port mappings
	if *ports != "" {
		portMappings, err := parsePorts(*ports)
		if err != nil {
			return fmt.Errorf("invalid port format: %w", err)
		}
		config.Ports = portMappings
	}

	// Parse volume mounts
	if *volumes != "" {
		volumeMounts, err := parseVolumes(*volumes)
		if err != nil {
			return fmt.Errorf("invalid volume format: %w", err)
		}
		config.Volumes = volumeMounts
	}

	// Parse security profile
	if *secProfile != "" {
		macConfig, err := parseSecurityProfile(*secProfile)
		if err != nil {
			return fmt.Errorf("invalid security profile format: %w", err)
		}
		config.MACConfig = macConfig
	}

	// Parse capabilities
	config.Privileged = *privileged
	if *capAdd != "" {
		config.CapAdd = parseCapabilities(*capAdd)
	}
	if *capDrop != "" {
		config.CapDrop = parseCapabilities(*capDrop)
	}

	// Parse security options (including Seccomp)
	if *seccompOpt != "" {
		seccompProfile, err := parseSecurityOptions(*seccompOpt)
		if err != nil {
			return fmt.Errorf("invalid security option: %w", err)
		}
		config.SeccompProfile = seccompProfile
	}

	// Create container
	container, err := h.runtime.CreateContainer(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	// Start container
	if err := h.runtime.StartContainer(ctx, container.ID); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	if *detach {
		fmt.Println(container.ID)
	} else {
		if config.Interactive {
			// In interactive mode, don't print container started message
			// Just wait for the container to exit
			exitCode, err := h.runtime.WaitContainer(ctx, container.ID)
			if err != nil {
				// If context was cancelled, that's expected behavior
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("failed to wait for container: %w", err)
			}
			if exitCode != 0 && exitCode != -128 { // -128 indicates killed by signal
				return fmt.Errorf("container exited with code %d", exitCode)
			}
		} else {
			fmt.Printf("Container %s started\n", container.ID[:12])
			// Wait for container to exit
			exitCode, err := h.runtime.WaitContainer(ctx, container.ID)
			if err != nil {
				// If context was cancelled, that's expected behavior
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("failed to wait for container: %w", err)
			}
			if exitCode != 0 && exitCode != -128 { // -128 indicates killed by signal
				return fmt.Errorf("container exited with code %d", exitCode)
			}
		}
	}

	return nil
}

// List handles the 'ps' command
func (h *Handler) List(ctx context.Context, args []string) error {
	// Parse ps command flags
	psFlags := flag.NewFlagSet("ps", flag.ExitOnError)
	all := psFlags.Bool("a", false, "show all containers (default shows just running)")

	psFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize ps [OPTIONS]

List containers

Options:
  -a, --all    Show all containers (default shows just running)
`)
	}

	if err := psFlags.Parse(args); err != nil {
		return err
	}

	// Get containers
	containers, err := h.runtime.ListContainers(ctx, *all)
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	// Display containers in table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CONTAINER ID\tNAME\tIMAGE\tSTATUS\tCREATED\tPORTS")

	for _, container := range containers {
		containerID := container.ID
		if len(containerID) > 12 {
			containerID = containerID[:12]
		}

		status := string(container.State)
		if container.State == types.StateRunning && container.StartedAt != nil {
			elapsed := time.Since(*container.StartedAt)
			status = fmt.Sprintf("Up %s", formatDuration(elapsed))
		} else if container.State == types.StateStopped && container.FinishedAt != nil {
			elapsed := time.Since(*container.FinishedAt)
			status = fmt.Sprintf("Exited %s ago", formatDuration(elapsed))
		}

		created := formatDuration(time.Since(container.CreatedAt)) + " ago"

		// Format ports
		ports := ""
		if container.NetworkInfo != nil && len(container.NetworkInfo.Ports) > 0 {
			portStrings := make([]string, 0, len(container.NetworkInfo.Ports))
			for containerPort, hostPort := range container.NetworkInfo.Ports {
				portStrings = append(portStrings, fmt.Sprintf("%s->%s", hostPort, containerPort))
			}
			ports = strings.Join(portStrings, ", ")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			containerID, container.Name, container.Image, status, created, ports)
	}

	return w.Flush()
}

// Stop handles the 'stop' command
func (h *Handler) Stop(ctx context.Context, args []string) error {
	// Parse stop command flags
	stopFlags := flag.NewFlagSet("stop", flag.ExitOnError)
	timeout := stopFlags.Duration("t", 10*time.Second, "timeout before force killing")

	stopFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize stop [OPTIONS] CONTAINER [CONTAINER...]

Stop one or more running containers

Options:
  -t, --time duration   Seconds to wait for stop before killing (default 10s)
`)
	}

	if err := stopFlags.Parse(args); err != nil {
		return err
	}

	containerIDs := stopFlags.Args()
	if len(containerIDs) == 0 {
		stopFlags.Usage()
		return fmt.Errorf("container ID required")
	}

	// Stop each container
	for _, containerID := range containerIDs {
		// Resolve container ID (support short IDs)
		container, err := h.resolveContainer(containerID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			continue
		}

		if err := h.runtime.StopContainer(ctx, container.ID, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping container %s: %v\n", containerID, err)
			continue
		}

		fmt.Println(containerID)
	}

	return nil
}

// Remove handles the 'rm' command
func (h *Handler) Remove(ctx context.Context, args []string) error {
	// Parse rm command flags
	rmFlags := flag.NewFlagSet("rm", flag.ExitOnError)
	force := rmFlags.Bool("f", false, "force removal of running container")
	all := rmFlags.Bool("a", false, "remove all containers")

	rmFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize rm [OPTIONS] CONTAINER [CONTAINER...]

Remove one or more containers

Options:
  -f, --force    Force removal of running container
  -a, --all      Remove all containers
`)
	}

	if err := rmFlags.Parse(args); err != nil {
		return err
	}

	containerIDs := rmFlags.Args()

	// If --all flag is used, get all container IDs
	if *all {
		containers, err := h.runtime.ListContainers(ctx, true) // true = include all containers (running + stopped)
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		if len(containers) == 0 {
			fmt.Println("No containers to remove")
			return nil
		}

		containerIDs = make([]string, len(containers))
		for i, container := range containers {
			containerIDs[i] = container.ID
		}
	} else if len(containerIDs) == 0 {
		rmFlags.Usage()
		return fmt.Errorf("container ID required")
	}

	// Remove each container
	for _, containerID := range containerIDs {
		// Resolve container ID
		container, err := h.resolveContainer(containerID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			continue
		}

		if err := h.runtime.RemoveContainer(ctx, container.ID, *force); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing container %s: %v\n", containerID, err)
			continue
		}

		fmt.Println(containerID)
	}

	return nil
}

// Images handles the 'images' command
func (h *Handler) Images(ctx context.Context, args []string) error {
	images, err := h.runtime.ListImages(ctx)
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}

	// Display images in table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "REPOSITORY\tTAG\tIMAGE ID\tCREATED\tSIZE")

	for _, image := range images {
		imageID := image.ID
		if len(imageID) > 12 {
			imageID = imageID[:12]
		}

		created := formatDuration(time.Since(image.Created)) + " ago"
		size := formatSize(image.Size)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			image.Name, image.Tag, imageID, created, size)
	}

	return w.Flush()
}

// Rmi handles the 'rmi' command to remove images
func (h *Handler) Rmi(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no image specified")
	}

	rmiFlags := flag.NewFlagSet("rmi", flag.ExitOnError)
	force := rmiFlags.Bool("f", false, "force removal of the image")

	rmiFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize rmi [OPTIONS] IMAGE [IMAGE...]

Remove one or more images

Options:
  -f, --force    Force removal of the image
`)
	}

	if err := rmiFlags.Parse(args); err != nil {
		return err
	}

	images := rmiFlags.Args()
	if len(images) == 0 {
		return fmt.Errorf("no image specified")
	}

	for _, image := range images {
		if err := h.runtime.RemoveImage(ctx, image, *force); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing image %s: %v\n", image, err)
			continue
		}
		fmt.Printf("Deleted: %s\n", image)
	}

	return nil
}

// ImagePrune handles the 'image prune' command to remove unused images
func (h *Handler) ImagePrune(ctx context.Context, args []string) error {
	pruneFlags := flag.NewFlagSet("prune", flag.ExitOnError)
	all := pruneFlags.Bool("a", false, "remove all unused images, not just dangling ones")
	force := pruneFlags.Bool("f", false, "do not prompt for confirmation")

	pruneFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize image prune [OPTIONS]

Remove unused images

Options:
  -a, --all      Remove all unused images, not just dangling ones
  -f, --force    Do not prompt for confirmation
`)
	}

	if err := pruneFlags.Parse(args); err != nil {
		return err
	}

	if !*force {
		fmt.Print("WARNING! This will remove all unused images.\nAre you sure you want to continue? [y/N] ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	removedImages, totalSize, err := h.runtime.PruneImages(ctx, *all)
	if err != nil {
		return fmt.Errorf("failed to prune images: %w", err)
	}

	if len(removedImages) == 0 {
		fmt.Println("No images to remove")
		return nil
	}

	for _, image := range removedImages {
		fmt.Printf("Deleted: %s\n", image)
	}
	fmt.Printf("Total reclaimed space: %s\n", formatSize(totalSize))

	return nil
}

// Helper functions

func (h *Handler) resolveContainer(containerID string) (*types.Container, error) {
	// Try exact match first
	container, err := h.runtime.GetContainer(containerID)
	if err == nil {
		return container, nil
	}

	// Try to find by short ID or name
	containers, err := h.runtime.ListContainers(context.Background(), true)
	if err != nil {
		return nil, err
	}

	var matches []*types.Container
	for _, c := range containers {
		if strings.HasPrefix(c.ID, containerID) || c.Name == containerID {
			matches = append(matches, c)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("container not found: %s", containerID)
	}

	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple containers match: %s", containerID)
	}

	return matches[0], nil
}

func parseMemory(memory string) (int64, error) {
	if memory == "" {
		return 0, nil
	}

	// Remove any whitespace
	memory = strings.TrimSpace(strings.ToLower(memory))

	// Parse suffix
	var multiplier int64 = 1
	var numStr string

	if strings.HasSuffix(memory, "k") || strings.HasSuffix(memory, "kb") {
		multiplier = 1024
		numStr = strings.TrimSuffix(strings.TrimSuffix(memory, "kb"), "k")
	} else if strings.HasSuffix(memory, "m") || strings.HasSuffix(memory, "mb") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(strings.TrimSuffix(memory, "mb"), "m")
	} else if strings.HasSuffix(memory, "g") || strings.HasSuffix(memory, "gb") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(strings.TrimSuffix(memory, "gb"), "g")
	} else {
		numStr = memory
	}

	// Parse number
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory format: %s", memory)
	}

	return int64(num * float64(multiplier)), nil
}

func parsePorts(ports string) ([]types.PortMapping, error) {
	if ports == "" {
		return nil, nil
	}

	var portMappings []types.PortMapping
	portSpecs := strings.Split(ports, ",")

	for _, spec := range portSpecs {
		spec = strings.TrimSpace(spec)
		parts := strings.Split(spec, ":")

		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port format: %s (expected host:container)", spec)
		}

		hostPort, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid host port: %s", parts[0])
		}

		containerPort, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid container port: %s", parts[1])
		}

		portMappings = append(portMappings, types.PortMapping{
			HostPort:      hostPort,
			ContainerPort: containerPort,
			Protocol:      "tcp", // Default to TCP
		})
	}

	return portMappings, nil
}

func parseVolumes(volumes string) ([]types.Volume, error) {
	if volumes == "" {
		return nil, nil
	}

	var volumeMounts []types.Volume
	volumeSpecs := strings.Split(volumes, ",")

	for _, spec := range volumeSpecs {
		spec = strings.TrimSpace(spec)
		parts := strings.Split(spec, ":")

		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid volume format: %s (expected host:container[:ro])", spec)
		}

		volume := types.Volume{
			Source:      parts[0],
			Destination: parts[1],
			ReadOnly:    false,
		}

		if len(parts) == 3 && parts[2] == "ro" {
			volume.ReadOnly = true
		}

		volumeMounts = append(volumeMounts, volume)
	}

	return volumeMounts, nil
}

// parseSecurityProfile parses security profile specifications
func parseSecurityProfile(profile string) (*security.MACConfig, error) {
	if profile == "" {
		return nil, nil
	}

	parts := strings.SplitN(profile, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid security profile format: %s (expected type:profile, e.g., 'apparmor:my-profile' or 'selinux:container_t')", profile)
	}

	profileType := strings.ToLower(parts[0])
	profileValue := parts[1]

	switch profileType {
	case "apparmor":
		return &security.MACConfig{
			Type:    security.MACTypeAppArmor,
			Profile: profileValue,
		}, nil
	case "selinux":
		return &security.MACConfig{
			Type:  security.MACTypeSELinux,
			Label: profileValue,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported security profile type: %s (supported: apparmor, selinux)", profileType)
	}
}

// parseCapabilities parses capability specifications from CLI
func parseCapabilities(capString string) []string {
	if capString == "" {
		return nil
	}

	var capabilities []string
	parts := strings.Split(capString, ",")

	for _, part := range parts {
		cap := strings.TrimSpace(part)
		if cap != "" {
			// Special case for ALL
			if strings.ToUpper(cap) == "ALL" {
				capabilities = append(capabilities, "ALL")
			} else {
				// Normalize capability name - remove CAP_ prefix and lowercase
				normalizedName := strings.ToLower(cap)
				normalizedName = strings.TrimPrefix(normalizedName, "cap_")
				capabilities = append(capabilities, normalizedName)
			}
		}
	}

	return capabilities
}

// parseSecurityOptions parses security options like seccomp profiles
func parseSecurityOptions(secOpt string) (string, error) {
	if secOpt == "" {
		return "", nil
	}

	// Parse security options in the format "key=value"
	parts := strings.SplitN(secOpt, "=", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid security option format: %s (expected key=value)", secOpt)
	}

	key := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	switch key {
	case "seccomp":
		// Handle seccomp profile specification
		if value == "unconfined" {
			return "unconfined", nil
		}
		// For file paths, validate they exist
		if _, err := os.Stat(value); err != nil {
			return "", fmt.Errorf("seccomp profile file not found: %s", value)
		}
		return value, nil
	default:
		return "", fmt.Errorf("unsupported security option: %s (supported: seccomp)", key)
	}
}

// Attach attaches to a running container
func (h *Handler) Attach(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("container ID or name required")
	}

	containerID := args[0]

	// Resolve container
	container, err := h.resolveContainer(containerID)
	if err != nil {
		return fmt.Errorf("failed to resolve container: %w", err)
	}

	if container.State != types.StateRunning {
		return fmt.Errorf("container %s is not running (state: %s)", container.ID[:12], container.State)
	}

	// Get the container PID
	if container.PID <= 0 {
		return fmt.Errorf("container %s has invalid PID", container.ID[:12])
	}

	fmt.Printf("Attaching to container %s...\n", container.ID[:12])
	fmt.Printf("Use Ctrl+P, Ctrl+Q to detach without stopping the container\n")

	// Create a new bash process in the container's namespace
	return h.attachToContainer(container)
}

func (h *Handler) attachToContainer(container *types.Container) error {
	// Use nsenter to enter the container's namespace and spawn a new shell
	pid := container.PID

	// Create nsenter command to join the container's namespaces
	cmd := fmt.Sprintf("nsenter -t %d -p -m -n /bin/sh", pid)

	// Execute the command in the current terminal
	return syscall.Exec("/bin/sh", []string{"/bin/sh", "-c", cmd}, os.Environ())
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.0fh", d.Hours())
	} else {
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	}
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f%s", float64(bytes)/float64(div), units[exp])
}

// Pull handles the 'pull' command
func (h *Handler) Pull(ctx context.Context, args []string) error {
	// Parse pull command flags
	pullFlags := flag.NewFlagSet("pull", flag.ExitOnError)
	showRegistries := pullFlags.Bool("registries", false, "show supported registries")

	pullFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize pull [OPTIONS] IMAGE

Pull an image from a registry

Options:
  --registries    Show supported registries and exit

Examples:
  gockerize pull alpine:latest                    # Docker Hub (default)
  gockerize pull docker.io/library/alpine:latest # Docker Hub (explicit)
  gockerize pull ghcr.io/owner/image:tag         # GitHub Container Registry
  gockerize pull quay.io/owner/image:tag         # Quay.io
  gockerize pull gcr.io/project/image:tag        # Google Container Registry
  gockerize pull myregistry.com/image:tag        # Custom registry

Supported Registries:
  - Docker Hub (docker.io, registry-1.docker.io) - default
  - GitHub Container Registry (ghcr.io)
  - Quay.io (quay.io)
  - Google Container Registry (gcr.io)
  - Any OCI-compliant registry
`)
	}

	if err := pullFlags.Parse(args); err != nil {
		return err
	}

	if *showRegistries {
		fmt.Println("Supported Container Registries:")
		fmt.Println()
		fmt.Println("Well-known registries:")

		// Import the registry package to use its functions
		registries := []struct {
			name        string
			description string
			example     string
		}{
			{"docker.io (default)", "Docker Hub - the default registry", "alpine:latest"},
			{"ghcr.io", "GitHub Container Registry", "ghcr.io/owner/image:tag"},
			{"quay.io", "Red Hat Quay.io", "quay.io/owner/image:tag"},
			{"gcr.io", "Google Container Registry", "gcr.io/project/image:tag"},
		}

		for _, reg := range registries {
			fmt.Printf("  %-25s %s\n", reg.name, reg.description)
			fmt.Printf("  %-25s Example: %s\n", "", reg.example)
			fmt.Println()
		}

		fmt.Println("Custom registries:")
		fmt.Println("  Any OCI-compliant registry can be used by specifying the full hostname")
		fmt.Println("  Example: myregistry.com/namespace/image:tag")
		fmt.Println()
		return nil
	}

	remainingArgs := pullFlags.Args()
	if len(remainingArgs) == 0 {
		pullFlags.Usage()
		return fmt.Errorf("image name required")
	}

	imageName := remainingArgs[0]
	fmt.Printf("Pulling image: %s\n", imageName)

	// Use the runtime's PullImage method
	image, err := h.runtime.PullImage(ctx, imageName)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	fmt.Printf("Successfully pulled %s:%s (%s)\n", image.Name, image.Tag, formatSize(image.Size))
	return nil
}
