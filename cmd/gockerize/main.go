package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

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
				gockerize images
				gockerize version
				`
)

func main() {
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
}
