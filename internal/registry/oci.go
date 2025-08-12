package registry

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OCIManifest represents an OCI image manifest
type OCIManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        OCIDescriptor   `json:"config"`
	Layers        []OCIDescriptor `json:"layers"`
}

// OCIIndex represents an OCI image index (multi-platform manifest)
type OCIIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []OCIDescriptor `json:"manifests"`
}

// OCIDescriptor represents a content descriptor
type OCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// RegistryType represents different types of container registries
type RegistryType string

const (
	RegistryTypeDockerHub RegistryType = "dockerhub"
	RegistryTypeGitHub    RegistryType = "github"
	RegistryTypeQuay      RegistryType = "quay"
	RegistryTypeGCR       RegistryType = "gcr"
	RegistryTypeGeneric   RegistryType = "generic"
)

// RegistryConfig holds configuration for different registry types
type RegistryConfig struct {
	Type         RegistryType
	URL          string
	AuthURL      string
	Service      string
	DefaultScope string
}

// Well-known registry configurations
var registryConfigs = map[string]RegistryConfig{
	"registry-1.docker.io": {
		Type:         RegistryTypeDockerHub,
		URL:          "https://registry-1.docker.io",
		AuthURL:      "https://auth.docker.io/token",
		Service:      "registry.docker.io",
		DefaultScope: "repository:%s:pull",
	},
	"docker.io": {
		Type:         RegistryTypeDockerHub,
		URL:          "https://registry-1.docker.io",
		AuthURL:      "https://auth.docker.io/token",
		Service:      "registry.docker.io",
		DefaultScope: "repository:%s:pull",
	},
	"ghcr.io": {
		Type:         RegistryTypeGitHub,
		URL:          "https://ghcr.io",
		AuthURL:      "https://ghcr.io/token",
		Service:      "ghcr.io",
		DefaultScope: "repository:%s:pull",
	},
	"quay.io": {
		Type:         RegistryTypeQuay,
		URL:          "https://quay.io",
		AuthURL:      "https://quay.io/v2/auth",
		Service:      "quay.io",
		DefaultScope: "repository:%s:pull",
	},
	"gcr.io": {
		Type:         RegistryTypeGCR,
		URL:          "https://gcr.io",
		AuthURL:      "https://gcr.io/v2/token",
		Service:      "gcr.io",
		DefaultScope: "repository:%s:pull",
	},
}

// Client handles OCI registry operations
type Client struct {
	registry     string
	registryType RegistryType
	config       RegistryConfig
	userAgent    string
	client       *http.Client
}

// NewClient creates a new OCI registry client
func NewClient(registry string) *Client {
	// Get registry configuration or use generic
	config, exists := registryConfigs[registry]
	if !exists {
		// For unknown registries, assume generic OCI v2 API
		config = RegistryConfig{
			Type:         RegistryTypeGeneric,
			URL:          "https://" + registry,
			AuthURL:      "https://" + registry + "/v2/token",
			Service:      registry,
			DefaultScope: "repository:%s:pull",
		}
	}

	return &Client{
		registry:     registry,
		registryType: config.Type,
		config:       config,
		userAgent:    "gockerize/1.0",
		client: &http.Client{
			Timeout: 300 * time.Second, // 5 minute timeout for downloads
		},
	}
}

// PullImage downloads an image from an OCI registry
func (c *Client) PullImage(ctx context.Context, namespace, name, tag, destPath string) error {
	imageRef := fmt.Sprintf("%s/%s", namespace, name)

	// Step 1: Get the manifest
	manifest, err := c.getManifest(ctx, imageRef, tag)
	if err != nil {
		return fmt.Errorf("failed to get manifest: %w", err)
	}

	// Step 2: Download and extract layers
	for i, layer := range manifest.Layers {
		slog.Info("downloading layer", "layer", i+1, "total", len(manifest.Layers), "digest", layer.Digest)

		if err := c.downloadLayer(ctx, imageRef, layer, destPath); err != nil {
			return fmt.Errorf("failed to download layer %s: %w", layer.Digest, err)
		}
	}

	return nil
}

// getManifest retrieves the image manifest from the registry
func (c *Client) getManifest(ctx context.Context, imageRef, tag string) (*OCIManifest, error) {
	// Use configured registry URL
	registryURL := strings.TrimPrefix(c.config.URL, "https://")
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registryURL, imageRef, tag)

	slog.Info("getting manifest", "url", url, "registry_type", c.registryType)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set required headers for OCI registry API
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	slog.Info("manifest response", "status", resp.StatusCode)

	var token string
	if resp.StatusCode == http.StatusUnauthorized {
		// Try to get auth token and retry
		authURL := resp.Header.Get("Www-Authenticate")
		if authURL != "" {
			slog.Info("getting auth token for manifest")
			token, err = c.getAuthToken(ctx, authURL, imageRef)
			if err != nil {
				return nil, fmt.Errorf("failed to get auth token: %w", err)
			}

			// Retry with token
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err = c.client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			slog.Info("manifest response after auth", "status", resp.StatusCode)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get manifest: HTTP %d", resp.StatusCode)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// First, try to decode as a manifest to check the media type
	var rawManifest struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(bodyBytes, &rawManifest); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	slog.Info("manifest media type", "mediaType", rawManifest.MediaType)

	// Handle image index (multi-platform manifest)
	if rawManifest.MediaType == "application/vnd.oci.image.index.v1+json" ||
		rawManifest.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {

		var index OCIIndex
		if err := json.Unmarshal(bodyBytes, &index); err != nil {
			return nil, fmt.Errorf("failed to decode image index: %w", err)
		}

		slog.Info("image index decoded", "manifests", len(index.Manifests))

		// Find the linux/amd64 manifest (or first one if no platform specified)
		var selectedDigest string
		for _, manifestDesc := range index.Manifests {
			// For simplicity, just take the first manifest
			// In a full implementation, you'd check platform.architecture and platform.os
			selectedDigest = manifestDesc.Digest
			break
		}

		if selectedDigest == "" {
			return nil, fmt.Errorf("no suitable manifest found in index")
		}

		slog.Info("resolving platform-specific manifest", "digest", selectedDigest)

		// Fetch the platform-specific manifest using the same token
		return c.getManifestByDigest(ctx, imageRef, selectedDigest, token)
	}

	// Regular manifest
	var manifest OCIManifest
	if err := json.Unmarshal(bodyBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	slog.Info("manifest decoded", "layers", len(manifest.Layers), "mediaType", manifest.MediaType)

	return &manifest, nil
}

// getManifestByDigest retrieves a specific manifest by digest
func (c *Client) getManifestByDigest(ctx context.Context, imageRef, digest, token string) (*OCIManifest, error) {
	registryURL := strings.TrimPrefix(c.config.URL, "https://")
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registryURL, imageRef, digest)

	slog.Info("getting manifest by digest", "url", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set required headers for OCI registry API
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json")
	req.Header.Set("User-Agent", c.userAgent)

	// Add auth token if provided
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get manifest by digest: HTTP %d", resp.StatusCode)
	}

	var manifest OCIManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	slog.Info("platform manifest decoded", "layers", len(manifest.Layers), "mediaType", manifest.MediaType)

	return &manifest, nil
}

// getAuthToken obtains an authentication token from the registry
func (c *Client) getAuthToken(ctx context.Context, authHeader, imageRef string) (string, error) {
	// Parse Www-Authenticate header: Bearer realm="...",service="...",scope="..."
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("unsupported auth type")
	}

	// Try to parse the auth header for realm, service, and scope
	realm, service, scope := c.parseAuthHeader(authHeader, imageRef)

	// If we couldn't parse, use the configured auth URL
	if realm == "" {
		realm = c.config.AuthURL
		service = c.config.Service
		scope = fmt.Sprintf(c.config.DefaultScope, imageRef)
	}

	// Construct auth URL
	authURL := fmt.Sprintf("%s?service=%s&scope=%s", realm, url.QueryEscape(service), url.QueryEscape(scope))

	slog.Info("requesting auth token", "url", authURL, "registry_type", c.registryType)

	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth request failed: HTTP %d", resp.StatusCode)
	}

	var authResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"` // Some registries use this field
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", err
	}

	// Return whichever token field is populated
	if authResp.Token != "" {
		return authResp.Token, nil
	}
	return authResp.AccessToken, nil
}

// parseAuthHeader parses the WWW-Authenticate header to extract realm, service, and scope
func (c *Client) parseAuthHeader(authHeader, imageRef string) (realm, service, scope string) {
	// Remove "Bearer " prefix
	authContent := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse key=value pairs
	pairs := strings.Split(authContent, ",")
	values := make(map[string]string)

	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 {
			key := kv[0]
			value := strings.Trim(kv[1], `"`)
			values[key] = value
		}
	}

	realm = values["realm"]
	service = values["service"]
	scope = values["scope"]

	// If no scope provided, use default
	if scope == "" {
		scope = fmt.Sprintf(c.config.DefaultScope, imageRef)
	}

	return realm, service, scope
}

// downloadLayer downloads and extracts a layer to the destination path
func (c *Client) downloadLayer(ctx context.Context, imageRef string, layer OCIDescriptor, destPath string) error {
	registryURL := strings.TrimPrefix(c.config.URL, "https://")
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registryURL, imageRef, layer.Digest)

	slog.Info("downloading layer", "url", url, "digest", layer.Digest, "size", layer.Size)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	slog.Info("layer download response", "status", resp.StatusCode, "content-length", resp.ContentLength)

	if resp.StatusCode == http.StatusUnauthorized {
		// Try to get auth token and retry
		authURL := resp.Header.Get("Www-Authenticate")
		if authURL != "" {
			slog.Info("getting auth token for layer download")
			token, err := c.getAuthToken(ctx, authURL, imageRef)
			if err != nil {
				return fmt.Errorf("failed to get auth token for layer: %w", err)
			}

			// Retry with token
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err = c.client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to retry request with auth: %w", err)
			}
			defer resp.Body.Close()

			slog.Info("layer download response after auth", "status", resp.StatusCode, "content-length", resp.ContentLength)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download layer: HTTP %d", resp.StatusCode)
	}

	// Verify content length if provided
	if resp.ContentLength > 0 && resp.ContentLength != layer.Size {
		slog.Warn("layer size mismatch", "expected", layer.Size, "actual", resp.ContentLength)
	}

	slog.Info("extracting layer", "mediaType", layer.MediaType, "destPath", destPath)

	// Extract layer based on media type
	switch layer.MediaType {
	case "application/vnd.docker.image.rootfs.diff.tar.gzip",
		"application/vnd.oci.image.layer.v1.tar+gzip":
		// This is a compressed tar layer, extract it
		return extractTarGz(resp.Body, destPath)
	case "application/vnd.docker.image.rootfs.diff.tar":
		// Uncompressed tar layer
		return extractTar(resp.Body, destPath)
	default:
		slog.Warn("unknown layer media type, attempting tar.gz extraction", "mediaType", layer.MediaType)
		return extractTarGz(resp.Body, destPath)
	}
}

// extractTar extracts an uncompressed tar archive
func extractTar(src io.Reader, destDir string) error {
	tarReader := tar.NewReader(src)
	return extractTarReader(tarReader, destDir)
}

// extractTarGz extracts a gzip-compressed tar archive
func extractTarGz(src io.Reader, destDir string) error {
	gzReader, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	return extractTarReader(tarReader, destDir)
}

// extractTarReader extracts files from a tar reader
func extractTarReader(tarReader *tar.Reader, destDir string) error {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Security check: prevent path traversal
		if strings.Contains(header.Name, "..") {
			slog.Warn("skipping file with .. in path", "file", header.Name)
			continue
		}

		destPath := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", destPath, err)
			}
		case tar.TypeReg:
			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", destPath, err)
			}

			// Create file
			file, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", destPath, err)
			}

			// Copy file content
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to extract file %s: %w", destPath, err)
			}
			file.Close()
		case tar.TypeSymlink:
			// Create symlink
			if err := os.Symlink(header.Linkname, destPath); err != nil {
				// Log but don't fail on symlink errors
				slog.Warn("failed to create symlink", "path", destPath, "target", header.Linkname, "error", err)
			}
		case tar.TypeLink:
			// Hard link
			linkTarget := filepath.Join(destDir, header.Linkname)
			if err := os.Link(linkTarget, destPath); err != nil {
				slog.Warn("failed to create hard link", "path", destPath, "target", linkTarget, "error", err)
			}
		}
	}

	return nil
}

// ParseImageReference parses image references and supports multiple registries
func ParseImageReference(imageName string) (registry, namespace, name string) {
	// Default to Docker Hub if no registry specified
	registry = "registry-1.docker.io"
	namespace = "library"
	name = imageName

	// Handle different image reference formats
	parts := strings.Split(imageName, "/")

	switch len(parts) {
	case 1:
		// Just image name: "alpine" -> docker.io/library/alpine
		name = parts[0]
	case 2:
		// Check if first part looks like a registry (contains dot or port)
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			// registry/name: "ghcr.io/alpine" -> ghcr.io/library/alpine
			registry = parts[0]
			namespace = "library"
			name = parts[1]
		} else {
			// namespace/name: "library/alpine" -> docker.io/library/alpine
			namespace = parts[0]
			name = parts[1]
		}
	case 3:
		// registry/namespace/name: "ghcr.io/library/alpine"
		registry = parts[0]
		namespace = parts[1]
		name = parts[2]
	default:
		// For more than 3 parts, treat everything after registry as the image path
		if len(parts) > 3 {
			registry = parts[0]
			// Join the rest as namespace/name
			namespaceName := strings.Join(parts[1:], "/")
			lastSlash := strings.LastIndex(namespaceName, "/")
			if lastSlash > 0 {
				namespace = namespaceName[:lastSlash]
				name = namespaceName[lastSlash+1:]
			} else {
				namespace = "library"
				name = namespaceName
			}
		}
	}

	// Handle special registry aliases
	switch registry {
	case "docker.io":
		registry = "registry-1.docker.io"
	case "ghcr.io":
		// GitHub Container Registry - keep as is
	case "quay.io":
		// Quay.io - keep as is
	case "gcr.io":
		// Google Container Registry - keep as is
	default:
		// For unknown registries, assume they follow OCI v2 API
	}

	slog.Debug("parsed image reference",
		"original", imageName,
		"registry", registry,
		"namespace", namespace,
		"name", name)

	return registry, namespace, name
}

// GetSupportedRegistries returns a list of well-known supported registries
func GetSupportedRegistries() []string {
	registries := make([]string, 0, len(registryConfigs))
	for registry := range registryConfigs {
		registries = append(registries, registry)
	}
	return registries
}

// IsKnownRegistry checks if a registry is in the well-known list
func IsKnownRegistry(registry string) bool {
	_, exists := registryConfigs[registry]
	return exists
}

// AddRegistryConfig allows adding custom registry configurations
func AddRegistryConfig(registry string, config RegistryConfig) {
	registryConfigs[registry] = config
}

// GetRegistryConfig returns the configuration for a given registry
func GetRegistryConfig(registry string) (RegistryConfig, bool) {
	config, exists := registryConfigs[registry]
	return config, exists
}
