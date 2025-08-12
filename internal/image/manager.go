package image

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/francisco3ferraz/gockerize/internal/registry"
	"github.com/francisco3ferraz/gockerize/pkg/types"
)

// Manager handles image operations
type Manager struct {
	imageDir string
	images   map[string]*types.Image
}

// NewManager creates a new image manager
func NewManager(imageDir string) (*Manager, error) {
	manager := &Manager{
		imageDir: imageDir,
		images:   make(map[string]*types.Image),
	}

	// Load existing images
	if err := manager.loadImages(); err != nil {
		slog.Warn("failed to load existing images", "error", err)
	}

	return manager, nil
}

// PullImage downloads an image from a registry
func (m *Manager) PullImage(ctx context.Context, name string) (*types.Image, error) {
	// Parse image name and tag
	imageName, tag := parseImageName(name)

	slog.Info("pulling image", "image", imageName, "tag", tag)

	// Check if image already exists
	imageKey := imageName + ":" + tag
	if image, exists := m.images[imageKey]; exists {
		slog.Info("image already exists", "image", imageName, "tag", tag)
		return image, nil
	}

	// Download and extract image
	imagePath := filepath.Join(m.imageDir, "images", imageName, tag)

	// Create image directory
	if err := os.MkdirAll(imagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create image directory: %w", err)
	}

	// Download the image
	if err := m.downloadImage(ctx, imageName, tag, imagePath); err != nil {
		return nil, fmt.Errorf("failed to download image: %w", err)
	}

	// Create image metadata
	image := &types.Image{
		ID:      generateID(),
		Name:    imageName,
		Tag:     tag,
		Size:    m.calculateImageSize(imagePath),
		Created: time.Now(),
		Layers:  []string{"base"}, // TODO: implement proper layer tracking
		Config: &types.ImageConfig{
			Cmd:        []string{"/bin/sh"},
			WorkingDir: "/",
		},
	}

	// Store image using name:tag as key
	m.images[imageKey] = image

	// Persist image metadata
	if err := m.saveImage(image, imagePath); err != nil {
		slog.Warn("failed to save image metadata", "image", imageName, "error", err)
	}

	slog.Info("image pulled successfully", "image", imageName, "tag", tag, "size", formatSize(image.Size))
	return image, nil
}

// ListImages returns all images
func (m *Manager) ListImages() []*types.Image {
	images := make([]*types.Image, 0, len(m.images))
	for _, image := range m.images {
		images = append(images, image)
	}
	return images
}

// RemoveImage removes an image
func (m *Manager) RemoveImage(imageID string, force bool, usedImages map[string]bool) error {
	// Check if image exists
	_, exists := m.images[imageID]
	if !exists {
		return fmt.Errorf("image not found: %s", imageID)
	}

	// Check if any containers are using this image
	if !force && usedImages[imageID] {
		return fmt.Errorf("image is being used by container, use -f to force removal")
	}

	// Parse image name to get directory path
	imageName, tag := parseImageName(imageID)
	imageDir := filepath.Join(m.imageDir, "images", imageName, tag)

	// Remove image directory from filesystem
	if err := os.RemoveAll(imageDir); err != nil {
		slog.Warn("failed to remove image directory", "path", imageDir, "error", err)
	}

	// Remove from in-memory map
	delete(m.images, imageID)

	slog.Info("image removed", "image", imageID, "path", imageDir)
	return nil
}

// PruneImages removes unused images
func (m *Manager) PruneImages(all bool, usedImages map[string]bool) ([]string, int64, error) {
	var removedImages []string
	var totalSize int64

	for imageID := range m.images {
		shouldRemove := false

		if all {
			// Remove all unused images
			shouldRemove = !usedImages[imageID]
		} else {
			// For now, just remove unused images
			shouldRemove = !usedImages[imageID]
		}

		if shouldRemove {
			// Parse image name to get directory path
			imageName, tag := parseImageName(imageID)
			imageDir := filepath.Join(m.imageDir, "images", imageName, tag)

			// Get size before removal
			if stat, err := os.Stat(imageDir); err == nil && stat.IsDir() {
				if size, err := getDirSize(imageDir); err == nil {
					totalSize += size
				}
			}

			// Remove image directory
			if err := os.RemoveAll(imageDir); err != nil {
				slog.Warn("failed to remove image directory", "path", imageDir, "error", err)
				continue
			}

			removedImages = append(removedImages, imageID)
			delete(m.images, imageID)
			slog.Info("pruned image", "image", imageID, "path", imageDir)
		}
	}

	return removedImages, totalSize, nil
}

// GetImage returns an image by name
func (m *Manager) GetImage(name string) (*types.Image, bool) {
	image, exists := m.images[name]
	return image, exists
}

// downloadImage downloads an image from an OCI-compliant registry
func (m *Manager) downloadImage(ctx context.Context, imageName, tag, imagePath string) error {
	// Parse image reference to determine registry
	registryURL, namespace, name := registry.ParseImageReference(imageName)

	slog.Info("downloading image from OCI registry",
		"registry", registryURL, "namespace", namespace, "image", name, "tag", tag, "destination", imagePath)

	// Create OCI registry client
	client := registry.NewClient(registryURL)

	// Download and extract the image
	return client.PullImage(ctx, namespace, name, tag, imagePath)
}

// calculateImageSize calculates the size of an image directory
func (m *Manager) calculateImageSize(imagePath string) int64 {
	var size int64

	err := filepath.Walk(imagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	if err != nil {
		slog.Warn("failed to calculate image size", "path", imagePath, "error", err)
		return 0
	}

	return size
}

// saveImage saves image metadata to disk
func (m *Manager) saveImage(image *types.Image, imagePath string) error {
	metadataPath := filepath.Join(imagePath, "metadata.json")
	data, err := json.Marshal(image)
	if err != nil {
		return fmt.Errorf("failed to marshal image metadata: %w", err)
	}

	return os.WriteFile(metadataPath, data, 0644)
}

// loadImages loads existing images from disk
func (m *Manager) loadImages() error {
	imagesDir := filepath.Join(m.imageDir, "images")

	// Check if images directory exists
	if _, err := os.Stat(imagesDir); os.IsNotExist(err) {
		return nil // No images to load
	}

	// Walk through the images directory structure: images/<name>/<tag>/
	return filepath.Walk(imagesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for metadata.json files
		if info.Name() == "metadata.json" && !info.IsDir() {
			// Load the image metadata
			data, err := os.ReadFile(path)
			if err != nil {
				slog.Warn("failed to read image metadata", "path", path, "error", err)
				return nil // Continue walking, don't fail completely
			}

			var image types.Image
			if err := json.Unmarshal(data, &image); err != nil {
				slog.Warn("failed to parse image metadata", "path", path, "error", err)
				return nil // Continue walking
			}

			// Add image to registry using name:tag as key
			imageKey := image.Name + ":" + image.Tag
			m.images[imageKey] = &image
			slog.Debug("loaded image", "name", image.Name, "tag", image.Tag, "key", imageKey)
		}

		return nil
	})
}

// Helper functions

// parseImageName parses an image name like "alpine:3.18" into name and tag
func parseImageName(name string) (string, string) {
	parts := strings.Split(name, ":")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return name, "latest"
}

// generateID generates a random ID
func generateID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// formatSize formats a byte size as human readable string
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

// getDirSize calculates the total size of a directory
func getDirSize(path string) (int64, error) {
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
