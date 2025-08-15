# Gockerize

[![Go Version](https://img.shields.io/badge/go-1.24.5-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/francisco3ferraz/gockerize)

A lightweight, educational container runtime implementation written in Go. Gockerize provides Docker-like functionality with a focus on simplicity and understanding the fundamentals of container technology.

## 🚀 Features

### Core Container Operations
- **Container Lifecycle Management**: Create, start, stop, and remove containers
- **Interactive & Detached Modes**: Support for both interactive (`-it`) and background (`-d`) execution
- **Process Management**: Container process isolation and monitoring
- **Graceful Shutdown**: Proper signal handling and cleanup

### Image Management
- **OCI Registry Support**: Pull images from Docker Hub and OCI-compliant registries
- **Image Storage**: Local image caching and management
- **Image Operations**: List, remove, and prune unused images
- **Multi-layer Support**: Proper handling of image layers and extraction

### Networking
- **Bridge Networking**: Custom bridge network (`gockerize0`) with automatic IP assignment
- **Port Forwarding**: Map container ports to host ports (`-p` flag)
- **Network Isolation**: Each container gets its own network namespace
- **VETH Pairs**: Virtual Ethernet devices for container connectivity

### Storage & Filesystem
- **Root Filesystem Isolation**: Each container gets its own root filesystem
- **Volume Mounting**: Bind mount host directories into containers (`-v` flag)
- **Overlay Filesystem**: Efficient layered filesystem implementation
- **Automatic Cleanup**: Proper cleanup of container filesystems

### Security
- **Linux Capabilities**: Fine-grained capability management with sensible defaults
- **Seccomp Profiles**: System call filtering for enhanced security
- **MAC (Mandatory Access Control)**: AppArmor/SELinux integration
- **User Namespaces**: Optional user namespace isolation
- **Root Filesystem Protection**: Read-only root filesystem support

### Advanced Features
- **Resource Limits**: Memory and CPU resource constraints
- **Environment Variables**: Custom environment variable injection (`-e` flag)
- **Working Directory**: Custom working directory support (`-w` flag)
- **Health Monitoring**: Container health status tracking
- **Session Management**: Automatic cleanup of session containers

## 📋 Requirements

- **Operating System**: Linux (Ubuntu 20.04+, CentOS 7+, or similar)
- **Privileges**: Must run as root (required for namespace operations)
- **Go Version**: 1.24.5 or later (for building from source)
- **System Dependencies**:
  - `bridge-utils` (for network bridge management)
  - `iptables` (for port forwarding)
  - `cgroups` (for resource management)

## 🛠️ Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/francisco3ferraz/gockerize.git
cd gockerize

# Build the binary
make build

# Install (optional)
sudo cp gockerize /usr/local/bin/
```

### System Requirements Setup

```bash
# Install required system packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install bridge-utils iptables

# Enable cgroups (if not already enabled)
sudo systemctl enable systemd-cgroup
```

## 🚀 Quick Start

### Pull an Image
```bash
sudo gockerize pull alpine:latest
```

### Run a Container
```bash
# Interactive container
sudo gockerize run -it alpine:latest /bin/sh

# Detached container
sudo gockerize run -d alpine:latest sleep 300

# With port forwarding
sudo gockerize run -d -p 8080:80 nginx:latest

# With volume mounting
sudo gockerize run -it -v /host/path:/container/path alpine:latest /bin/sh
```

### Manage Containers
```bash
# List running containers
sudo gockerize ps

# List all containers (including stopped)
sudo gockerize ps -a

# Stop a container
sudo gockerize stop <container_id>

# Remove a container
sudo gockerize rm <container_id>

# Attach to a running container
sudo gockerize attach <container_id>
```

### Manage Images
```bash
# List images
sudo gockerize images

# Remove an image
sudo gockerize rmi <image_id>

# Prune unused images
sudo gockerize image prune
```

## 📖 Usage Examples

### Basic Web Server
```bash
# Pull and run Nginx
sudo gockerize pull nginx:latest
sudo gockerize run -d -p 8080:80 --name web-server nginx:latest

# Check if it's running
curl http://localhost:8080
```

### Development Environment
```bash
# Run a development container with volume mounting
sudo gockerize run -it \
  -v /home/user/project:/workspace \
  -w /workspace \
  -e NODE_ENV=development \
  node:18 /bin/bash
```

### Database Container
```bash
# Run PostgreSQL with custom configuration
sudo gockerize run -d \
  -p 5432:5432 \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=myapp \
  --name database \
  postgres:13
```

### Multi-container Application
```bash
# Start a Redis cache
sudo gockerize run -d -p 6379:6379 --name cache redis:alpine

# Start application server
sudo gockerize run -d \
  -p 3000:3000 \
  -e REDIS_URL=redis://172.17.0.1:6379 \
  --name app-server \
  node:18 npm start
```

## 🏗️ Architecture

### Project Structure
```
gockerize/
├── cmd/gockerize/          # Main application entry point
├── internal/
│   ├── cli/                # Command-line interface handling
│   ├── config/             # Configuration management
│   ├── container/          # Container lifecycle, networking, storage
│   ├── image/              # Image management and registry operations
│   ├── registry/           # OCI registry client implementation
│   ├── runtime/            # Core runtime engine
│   ├── security/           # Security features (capabilities, seccomp, MAC)
│   └── utils/              # Utility functions and helpers
├── pkg/types/              # Public types and interfaces
├── Makefile               # Build automation
├── go.mod                 # Go module definition
└── go.sum                 # Go module checksums
```

### Core Components

#### Runtime Engine (`internal/runtime/`)
The heart of Gockerize, responsible for:
- Container and image lifecycle management
- Coordination between different managers
- State persistence and recovery
- Session management and cleanup

#### Container Manager (`internal/container/`)
Handles all container-related operations:
- **Container Lifecycle**: Creation, starting, stopping, removal
- **Network Management**: Bridge setup, IP allocation, port forwarding
- **Storage Management**: Root filesystem preparation, volume mounting
- **Process Management**: Container process execution and monitoring

#### Security Manager (`internal/security/`)
Implements container security features:
- **Capabilities**: Linux capability management with secure defaults
- **Seccomp**: System call filtering and profiles
- **MAC**: Mandatory Access Control (AppArmor/SELinux) integration

#### Image Manager (`internal/image/`)
Manages container images:
- OCI registry communication (Docker Hub, etc.)
- Image layer download and extraction
- Local image storage and caching
- Image metadata management

#### CLI Handler (`internal/cli/`)
Provides the command-line interface:
- Command parsing and validation
- Flag handling and expansion
- User interaction and output formatting
- Error reporting and help messages

## 🔧 Configuration

### Runtime Configuration
Gockerize stores its data in `/var/lib/gockerize/` by default:

```
/var/lib/gockerize/
├── containers/             # Container metadata and state
├── images/                 # Downloaded image layers and metadata
└── networks/               # Network configuration and state
```

### Environment Variables
- `GOCKERIZE_ROOT`: Override the default runtime directory
- `GOCKERIZE_BRIDGE`: Override the default bridge name
- `GOCKERIZE_SUBNET`: Override the default subnet (172.17.0.0/16)

### Network Configuration
- **Default Bridge**: `gockerize0`
- **Default Subnet**: `172.17.0.0/16`
- **IP Range**: 172.17.0.2 - 172.17.255.254
- **Gateway**: 172.17.0.1

## 🔒 Security Features

### Default Security Posture
Gockerize implements secure defaults:

- **Capabilities**: Restricted to essential capabilities only
- **Seccomp**: System call filtering enabled by default
- **Namespaces**: PID, network, mount, and UTS isolation
- **User Namespaces**: Optional user namespace support
- **Root Filesystem**: Read-only when possible

### Capability Management
Default allowed capabilities:
- `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`
- `CAP_FSETID`, `CAP_KILL`, `CAP_SETGID`
- `CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_BIND_SERVICE`
- `CAP_NET_RAW`, `CAP_SYS_CHROOT`, `CAP_MKNOD`
- `CAP_AUDIT_WRITE`, `CAP_SETFCAP`

Dangerous capabilities like `CAP_SYS_ADMIN` are excluded by default.

## 🧪 Development

### Building from Source
```bash
# Install dependencies
go mod download

# Run tests
make test

# Run with verbose testing
make test-verbose

# Check code coverage
make coverage

# Format code
make fmt

# Lint code
make lint

# Build for development
make build

# Clean build artifacts
make clean
```

### Running Tests
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/container/

# Run benchmarks
go test -bench=. ./...
```

### Contributing Guidelines

1. **Code Style**: Follow Go conventions and use `gofmt`
2. **Testing**: Add tests for new features and bug fixes
3. **Documentation**: Update documentation for user-facing changes
4. **Security**: Consider security implications of all changes
5. **Performance**: Profile performance-critical code paths

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Gockerize requires root privileges
sudo gockerize <command>
```

#### Bridge Network Issues
```bash
# Check if bridge exists
ip link show gockerize0

# Recreate bridge if needed
sudo ip link del gockerize0
sudo gockerize run alpine:latest echo "test"
```

#### Image Pull Failures
```bash
# Check internet connectivity
curl -I https://registry-1.docker.io/

# Try pulling with verbose logging
sudo gockerize -v pull alpine:latest
```

#### Container Start Failures
```bash
# Check logs with verbose mode
sudo gockerize -v run alpine:latest /bin/sh

# Check available resources
df -h /var/lib/gockerize/
```

### Debug Mode
Enable verbose logging for detailed debugging:
```bash
sudo gockerize -v <command>
```

### Log Files
Gockerize uses structured logging. Check system logs:
```bash
journalctl -u gockerize
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- **Docker**: Inspiration for container runtime design
- **OCI**: Open Container Initiative specifications
- **Linux Kernel**: Container primitives and namespaces
- **Go Community**: Excellent tooling and libraries

---

**Note**: Gockerize is an educational project designed to demonstrate container runtime concepts. While functional, it may not be suitable for production workloads. For production use, consider established runtimes like Docker, containerd, or CRI-O.
