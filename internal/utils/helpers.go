package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateID generates a random ID based on current time
func GenerateID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// ParseImageName parses an image name like "alpine:3.18" into name and tag
func ParseImageName(name string) (string, string) {
	parts := strings.Split(name, ":")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return name, "latest"
}

// FormatSize formats a byte size as human readable string
func FormatSize(bytes int64) string {
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

// GetDirSize calculates the total size of a directory
func GetDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// EnsureDir creates a directory if it doesn't exist
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// IsProcessRunning checks if a process with the given PID is still running
func IsProcessRunning(pid int) bool {
	// Check if the process exists by sending signal 0
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix systems, signal 0 can be used to check if process exists
	err = process.Signal(os.Signal(nil))
	return err == nil
}
