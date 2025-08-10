package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/francisco3ferraz/gockerize/internal/cli"
	"github.com/francisco3ferraz/gockerize/internal/runtime"
)

const (
	version = "0.1.0"
	usage   = `gockerize - A lightweight container runtime

Usage:
gockerize <command> [options]

Commands:
run     Run a new container
ps      List running containers
stop    Stop a container
rm      Remove a container
attach  Attach to a running container
pull    Pull an image from a registry
images  List available images
version Show version information

Global Options:
-v, --verbose    Enable verbose logging
-h, --help       Show help

Examples:
gockerize run alpine:latest /bin/sh
gockerize ps
gockerize stop container_id
gockerize rm container_id
gockerize rm -a  # Remove all containers
gockerize attach container_id
gockerize pull alpine:latest
gockerize images
gockerize version
`
)

func main() {
	// Special case: if called with "container-init", run container initialization
	if len(os.Args) > 1 && os.Args[1] == "container-init" {
		if err := runtime.ContainerInit(); err != nil {
			slog.Error("container initialization failed", "error", err)
			os.Exit(1)
		}
		return
	}

	var (
		verbose = flag.Bool("v", false, "enable verbose logging")
		help    = flag.Bool("h", false, "show help")
	)
	flag.Parse()

	if *help {
		fmt.Print(usage)
		return
	}

	// Setup structured logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Check if running as root
	if os.Geteuid() != 0 {
		slog.Error("gockerize requires root privileges")
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(1)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("received shutdown signal")
		cancel()
	}()

	// Initialize runtime
	rt, err := runtime.New()
	if err != nil {
		slog.Error("failed to initialize runtime", "error", err)
		os.Exit(1)
	}
	defer rt.Cleanup()

	// Initialize CLI
	cliHandler := cli.New(rt)

	// Route commands
	command := args[0]
	commandArgs := args[1:]

	err = routeCommand(ctx, cliHandler, command, commandArgs)
	if err != nil {
		slog.Error("command failed", "command", command, "error", err)
		os.Exit(1)
	}
}

func routeCommand(ctx context.Context, cli *cli.Handler, command string, args []string) error {
	switch command {
	case "run":
		return cli.Run(ctx, args)
	case "ps":
		return cli.List(ctx, args)
	case "stop":
		return cli.Stop(ctx, args)
	case "rm":
		return cli.Remove(ctx, args)
	case "attach":
		return cli.Attach(ctx, args)
	case "pull":
		return cli.Pull(ctx, args)
	case "images":
		return cli.Images(ctx, args)
	case "rmi":
		return cli.Rmi(ctx, args)
	case "image":
		// Handle subcommands for image
		if len(args) == 0 {
			return fmt.Errorf("image command requires a subcommand (prune)")
		}
		switch args[0] {
		case "prune":
			return cli.ImagePrune(ctx, args[1:])
		default:
			return fmt.Errorf("unknown image subcommand: %s", args[0])
		}
	case "version":
		fmt.Printf("gockerize version %s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}
