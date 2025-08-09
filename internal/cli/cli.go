package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/francisco3ferraz/gockerize/pkg/types"
)

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
		detach    = runFlags.Bool("d", false, "run in detached mode")
		hostname  = runFlags.String("hostname", "", "container hostname")
		memory    = runFlags.String("m", "", "memory limit (e.g., 512m, 1g)")
		cpuShares = runFlags.Int64("cpu-shares", 0, "CPU shares (relative weight)")
		workdir   = runFlags.String("w", "", "working directory")
		env       = runFlags.String("e", "", "environment variables (comma-separated key=value pairs)")
		ports     = runFlags.String("p", "", "port mappings (e.g., 8080:80)")
		volumes   = runFlags.String("v", "", "volume mounts (e.g., /host:/container)")
	)

	runFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize run [OPTIONS] IMAGE [COMMAND]

			Run a new container

			Options:
			-d, --detach          Run in detached mode
			--name string         Container name
			--hostname string     Container hostname
			-m, --memory string   Memory limit (e.g., 512m, 1g)
			--cpu-shares int      CPU shares (relative weight)
			-w, --workdir string  Working directory inside container
			-e, --env string      Environment variables (comma-separated key=value)
			-p, --ports string    Port mappings (host:container)
			-v, --volume string   Volume mounts (host:container)

			Examples:
			gockerize run alpine:latest
			gockerize run -d -p 8080:80 --name web nginx:latest
			gockerize run -v /tmp:/data -e "KEY=value" ubuntu:latest /bin/bash
	`)
	}

	if err := runFlags.Parse(args); err != nil {
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
		Command:    command,    // Set the command in config
		RootFS:     imageName, // For now, image name is the rootfs
		WorkingDir: *workdir,
		Hostname:   *hostname,
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

	rmFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gockerize rm [OPTIONS] CONTAINER [CONTAINER...]

Remove one or more containers

Options:
  -f, --force    Force removal of running container
`)
	}

	if err := rmFlags.Parse(args); err != nil {
		return err
	}

	containerIDs := rmFlags.Args()
	if len(containerIDs) == 0 {
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
