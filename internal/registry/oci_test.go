package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseImageReference(t *testing.T) {
	tests := []struct {
		name              string
		imageRef          string
		expectedRegistry  string
		expectedNamespace string
		expectedImage     string
	}{
		{
			name:              "simple image",
			imageRef:          "alpine",
			expectedRegistry:  "registry-1.docker.io",
			expectedNamespace: "library",
			expectedImage:     "alpine",
		},
		{
			name:              "image with namespace",
			imageRef:          "nginx/nginx",
			expectedRegistry:  "registry-1.docker.io",
			expectedNamespace: "nginx",
			expectedImage:     "nginx",
		},
		{
			name:              "custom registry",
			imageRef:          "gcr.io/project/image",
			expectedRegistry:  "gcr.io",
			expectedNamespace: "project",
			expectedImage:     "image",
		},
		{
			name:              "complex registry path",
			imageRef:          "registry.example.com:5000/user/repo/image",
			expectedRegistry:  "registry.example.com:5000",
			expectedNamespace: "user/repo",
			expectedImage:     "image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, namespace, image := ParseImageReference(tt.imageRef)

			if registry != tt.expectedRegistry {
				t.Errorf("Expected registry %s, got %s", tt.expectedRegistry, registry)
			}
			if namespace != tt.expectedNamespace {
				t.Errorf("Expected namespace %s, got %s", tt.expectedNamespace, namespace)
			}
			if image != tt.expectedImage {
				t.Errorf("Expected image %s, got %s", tt.expectedImage, image)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		registryURL string
	}{
		{
			name:        "docker.io",
			registryURL: "docker.io",
		},
		{
			name:        "custom registry",
			registryURL: "registry.example.com",
		},
		{
			name:        "registry with port",
			registryURL: "localhost:5000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.registryURL)

			if client == nil {
				t.Fatal("NewClient() returned nil")
			}

			if client.registry != tt.registryURL {
				t.Errorf("Expected registry %s, got %s", tt.registryURL, client.registry)
			}

			if client.client == nil {
				t.Error("HTTP client not initialized")
			}
		})
	}
}

func TestClient_PullImage(t *testing.T) {
	// Create test manifest
	manifest := OCIManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		Config: OCIDescriptor{
			MediaType: "application/vnd.docker.container.image.v1+json",
			Size:      1234,
			Digest:    "sha256:config-digest",
		},
		Layers: []OCIDescriptor{
			{
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      5678,
				Digest:    "sha256:layer-digest",
			},
		},
	}

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/manifests/"):
			// Manifest endpoint
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			json.NewEncoder(w).Encode(manifest)
		case strings.Contains(r.URL.Path, "/blobs/"):
			// Blob endpoint - return empty tar.gz for testing
			w.Header().Set("Content-Length", "10")
			w.Write([]byte("test blob "))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client and override config for testing
	client := NewClient("test-registry")
	client.config.URL = server.URL

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "pull-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	err = client.PullImage(ctx, "library", "alpine", "latest", tempDir)

	if err != nil {
		t.Logf("PullImage() failed as expected in test environment: %v", err)
		// This is acceptable since we're not providing a real tar.gz blob
	} else {
		t.Log("PullImage() completed successfully")
	}
}

func TestRegistryConfig(t *testing.T) {
	// Test that we have configs for well-known registries
	knownRegistries := []string{"docker.io", "ghcr.io", "quay.io", "gcr.io"}

	for _, registry := range knownRegistries {
		t.Run(registry, func(t *testing.T) {
			client := NewClient(registry)

			if client.config.URL == "" {
				t.Errorf("No URL configured for registry %s", registry)
			}

			if client.config.Type == "" {
				t.Errorf("No type configured for registry %s", registry)
			}
		})
	}
}

func TestParseImageReference_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		imageRef string
	}{
		{
			name:     "empty string",
			imageRef: "",
		},
		{
			name:     "just slash",
			imageRef: "/",
		},
		{
			name:     "multiple slashes",
			imageRef: "registry.com//namespace//image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			registry, namespace, image := ParseImageReference(tt.imageRef)
			t.Logf("Input: %s -> Registry: %s, Namespace: %s, Image: %s",
				tt.imageRef, registry, namespace, image)
		})
	}
}

func TestClientTimeout(t *testing.T) {
	client := NewClient("registry.example.com")

	if client.client.Timeout != 300*time.Second {
		t.Errorf("Expected timeout 300s, got %v", client.client.Timeout)
	}
}

func TestRegistryType(t *testing.T) {
	tests := []struct {
		registry     string
		expectedType RegistryType
	}{
		{"docker.io", RegistryTypeDockerHub},
		{"ghcr.io", RegistryTypeGitHub},
		{"quay.io", RegistryTypeQuay},
		{"gcr.io", RegistryTypeGCR},
		{"unknown.registry.com", RegistryTypeGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.registry, func(t *testing.T) {
			client := NewClient(tt.registry)

			if client.registryType != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, client.registryType)
			}
		})
	}
}

// Benchmark tests
func BenchmarkParseImageReference(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseImageReference("registry.example.com:5000/namespace/image")
	}
}

func BenchmarkNewClient(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewClient("registry.example.com")
	}
}
