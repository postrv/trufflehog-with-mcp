package tools

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	mcpInternal "github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
)

func TestListDetectorsTool(t *testing.T) {
	t.Run("has correct tool definition", func(t *testing.T) {
		tool := ListDetectorsTool()

		assert.Equal(t, "list_detectors", tool.Name)
		assert.NotEmpty(t, tool.Description)
		assert.Contains(t, tool.Description, "detector")
	})
}

func TestListDetectorsHandler(t *testing.T) {
	registry := mcpInternal.NewDetectorRegistry()
	handler := ListDetectorsHandler(registry)
	ctx := context.Background()

	t.Run("lists all detectors when no filter", func(t *testing.T) {
		req := createCallToolRequest("list_detectors", map[string]any{})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)

		// Parse the JSON response
		text := result.Content[0].(mcp.TextContent).Text
		var response struct {
			Total     int `json:"total"`
			Detectors []struct {
				Type string `json:"type"`
			} `json:"detectors"`
		}
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)
		assert.Greater(t, response.Total, 100)
	})

	t.Run("filters detectors by name", func(t *testing.T) {
		req := createCallToolRequest("list_detectors", map[string]any{
			"filter": "AWS",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		var response struct {
			Total     int `json:"total"`
			Detectors []struct {
				Type string `json:"type"`
			} `json:"detectors"`
		}
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		// All results should contain AWS
		for _, d := range response.Detectors {
			assert.Contains(t, d.Type, "AWS")
		}
	})
}

func TestGetDetectorInfoTool(t *testing.T) {
	t.Run("has correct tool definition", func(t *testing.T) {
		tool := GetDetectorInfoTool()

		assert.Equal(t, "get_detector_info", tool.Name)
		assert.NotEmpty(t, tool.Description)
	})
}

func TestGetDetectorInfoHandler(t *testing.T) {
	registry := mcpInternal.NewDetectorRegistry()
	handler := GetDetectorInfoHandler(registry)
	ctx := context.Background()

	t.Run("returns info for valid detector", func(t *testing.T) {
		req := createCallToolRequest("get_detector_info", map[string]any{
			"detector_type": "AWS",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)

		text := result.Content[0].(mcp.TextContent).Text
		var info struct {
			Type        string   `json:"type"`
			Description string   `json:"description"`
			Keywords    []string `json:"keywords"`
		}
		err = json.Unmarshal([]byte(text), &info)
		require.NoError(t, err)

		assert.Equal(t, "AWS", info.Type)
		assert.NotEmpty(t, info.Description)
		assert.NotEmpty(t, info.Keywords)
	})

	t.Run("returns error for missing detector_type", func(t *testing.T) {
		req := createCallToolRequest("get_detector_info", map[string]any{})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "detector_type")
	})

	t.Run("returns error for unknown detector", func(t *testing.T) {
		req := createCallToolRequest("get_detector_info", map[string]any{
			"detector_type": "NonExistentDetector12345",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "unknown detector type")
	})
}

func TestScanTextTool(t *testing.T) {
	t.Run("has correct tool definition", func(t *testing.T) {
		tool := ScanTextTool()

		assert.Equal(t, "scan_text", tool.Name)
		assert.NotEmpty(t, tool.Description)
		assert.Contains(t, tool.Description, "secret")
	})
}

func TestScanTextHandler(t *testing.T) {
	ctx := context.Background()
	cfg := mcpInternal.DefaultScannerConfig()
	cfg.Verify = false // Disable verification for faster tests

	scanner, err := mcpInternal.NewScanner(ctx, cfg)
	require.NoError(t, err)

	handler := ScanTextHandler(scanner)

	t.Run("scans text successfully", func(t *testing.T) {
		req := createCallToolRequest("scan_text", map[string]any{
			"text": "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)

		// Should have a valid JSON response
		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		// Should have results and summary
		_, hasResults := response["results"]
		_, hasSummary := response["summary"]
		assert.True(t, hasResults)
		assert.True(t, hasSummary)
	})

	t.Run("returns error for missing text parameter", func(t *testing.T) {
		req := createCallToolRequest("scan_text", map[string]any{})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "text")
	})

	t.Run("handles empty text", func(t *testing.T) {
		req := createCallToolRequest("scan_text", map[string]any{
			"text": "",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		results := response["results"].([]any)
		assert.Empty(t, results)
	})
}

// Helper function to create a CallToolRequest
func createCallToolRequest(name string, args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	}
}

func TestScanFileTool(t *testing.T) {
	t.Run("has correct tool definition", func(t *testing.T) {
		tool := ScanFileTool()

		assert.Equal(t, "scan_file", tool.Name)
		assert.NotEmpty(t, tool.Description)
		assert.Contains(t, tool.Description, "file")
	})
}

func TestScanFileHandler(t *testing.T) {
	ctx := context.Background()
	cfg := mcpInternal.DefaultScannerConfig()
	cfg.Verify = false // Disable verification for faster tests

	scanner, err := mcpInternal.NewScanner(ctx, cfg)
	require.NoError(t, err)

	handler := ScanFileHandler(scanner)

	t.Run("returns error for missing path parameter", func(t *testing.T) {
		req := createCallToolRequest("scan_file", map[string]any{})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "path")
	})

	t.Run("returns error for non-absolute path", func(t *testing.T) {
		req := createCallToolRequest("scan_file", map[string]any{
			"path": "relative/path/file.txt",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "absolute")
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		req := createCallToolRequest("scan_file", map[string]any{
			"path": "/nonexistent/path/to/file.txt",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "does not exist")
	})

	t.Run("scans file successfully", func(t *testing.T) {
		// Create a temporary file with test content
		tmpFile, err := os.CreateTemp("", "trufflehog-test-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		req := createCallToolRequest("scan_file", map[string]any{
			"path": tmpFile.Name(),
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)

		// Should have a valid JSON response
		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		// Should have results and summary
		_, hasResults := response["results"]
		_, hasSummary := response["summary"]
		assert.True(t, hasResults)
		assert.True(t, hasSummary)
	})

	t.Run("scans file with no secrets", func(t *testing.T) {
		// Create a temporary file with safe content
		tmpFile, err := os.CreateTemp("", "trufflehog-test-safe-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("This is just some normal text without secrets.\n")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		req := createCallToolRequest("scan_file", map[string]any{
			"path": tmpFile.Name(),
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		results := response["results"].([]any)
		assert.Empty(t, results)
	})
}

func TestScanDirectoryTool(t *testing.T) {
	t.Run("has correct tool definition", func(t *testing.T) {
		tool := ScanDirectoryTool()

		assert.Equal(t, "scan_directory", tool.Name)
		assert.NotEmpty(t, tool.Description)
		assert.Contains(t, tool.Description, "directory")
	})
}

func TestScanDirectoryHandler(t *testing.T) {
	ctx := context.Background()
	cfg := mcpInternal.DefaultScannerConfig()
	cfg.Verify = false // Disable verification for faster tests

	scanner, err := mcpInternal.NewScanner(ctx, cfg)
	require.NoError(t, err)

	handler := ScanDirectoryHandler(scanner)

	t.Run("returns error for missing path parameter", func(t *testing.T) {
		req := createCallToolRequest("scan_directory", map[string]any{})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "path")
	})

	t.Run("returns error for non-absolute path", func(t *testing.T) {
		req := createCallToolRequest("scan_directory", map[string]any{
			"path": "relative/path/dir",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "absolute")
	})

	t.Run("returns error for non-existent directory", func(t *testing.T) {
		req := createCallToolRequest("scan_directory", map[string]any{
			"path": "/nonexistent/path/to/directory",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "does not exist")
	})

	t.Run("returns error when path is a file not a directory", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "trufflehog-test-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		require.NoError(t, tmpFile.Close())

		req := createCallToolRequest("scan_directory", map[string]any{
			"path": tmpFile.Name(),
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "not a directory")
	})

	t.Run("scans directory successfully", func(t *testing.T) {
		// Create a temporary directory with a file containing a secret
		tmpDir, err := os.MkdirTemp("", "trufflehog-test-dir-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		// Create a file with a secret in the directory
		secretFile := filepath.Join(tmpDir, "config.txt")
		err = os.WriteFile(secretFile, []byte("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
		require.NoError(t, err)

		req := createCallToolRequest("scan_directory", map[string]any{
			"path": tmpDir,
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)

		// Should have a valid JSON response
		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		// Should have results and summary
		_, hasResults := response["results"]
		_, hasSummary := response["summary"]
		assert.True(t, hasResults)
		assert.True(t, hasSummary)
	})

	t.Run("scans directory with no secrets", func(t *testing.T) {
		// Create a temporary directory with safe content
		tmpDir, err := os.MkdirTemp("", "trufflehog-test-safe-dir-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		safeFile := filepath.Join(tmpDir, "readme.txt")
		err = os.WriteFile(safeFile, []byte("This is safe content.\n"), 0644)
		require.NoError(t, err)

		req := createCallToolRequest("scan_directory", map[string]any{
			"path": tmpDir,
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		results := response["results"].([]any)
		assert.Empty(t, results)
	})
}

func TestScanGitRepoTool(t *testing.T) {
	t.Run("has correct tool definition", func(t *testing.T) {
		tool := ScanGitRepoTool()

		assert.Equal(t, "scan_git_repo", tool.Name)
		assert.NotEmpty(t, tool.Description)
		assert.Contains(t, tool.Description, "git")
	})
}

func TestScanGitRepoHandler(t *testing.T) {
	ctx := context.Background()
	cfg := mcpInternal.DefaultScannerConfig()
	cfg.Verify = false // Disable verification for faster tests

	scanner, err := mcpInternal.NewScanner(ctx, cfg)
	require.NoError(t, err)

	handler := ScanGitRepoHandler(scanner)

	t.Run("returns error for missing uri parameter", func(t *testing.T) {
		req := createCallToolRequest("scan_git_repo", map[string]any{})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "uri")
	})

	t.Run("returns error for non-existent local repo", func(t *testing.T) {
		req := createCallToolRequest("scan_git_repo", map[string]any{
			"uri": "/nonexistent/path/to/repo",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.True(t, strings.Contains(text, "does not exist") || strings.Contains(text, "failed"))
	})

	t.Run("scans local git repo successfully", func(t *testing.T) {
		// Create a temporary git repository
		tmpDir, err := os.MkdirTemp("", "trufflehog-test-git-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		// Initialize git repo
		cmd := exec.Command("git", "init")
		cmd.Dir = tmpDir
		require.NoError(t, cmd.Run())

		// Configure git user
		cmd = exec.Command("git", "config", "user.email", "test@example.com")
		cmd.Dir = tmpDir
		require.NoError(t, cmd.Run())
		cmd = exec.Command("git", "config", "user.name", "Test User")
		cmd.Dir = tmpDir
		require.NoError(t, cmd.Run())

		// Create a file with a secret and commit it
		secretFile := filepath.Join(tmpDir, "config.txt")
		err = os.WriteFile(secretFile, []byte("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
		require.NoError(t, err)

		cmd = exec.Command("git", "add", ".")
		cmd.Dir = tmpDir
		require.NoError(t, cmd.Run())

		cmd = exec.Command("git", "commit", "-m", "initial commit")
		cmd.Dir = tmpDir
		require.NoError(t, cmd.Run())

		// Use file:// URI format for local repos
		req := createCallToolRequest("scan_git_repo", map[string]any{
			"uri": "file://" + tmpDir,
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)

		// Should have a valid JSON response
		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		// Should have results and summary
		_, hasResults := response["results"]
		_, hasSummary := response["summary"]
		assert.True(t, hasResults)
		assert.True(t, hasSummary)
	})
}

func TestVerifySecretTool(t *testing.T) {
	t.Run("has correct tool definition", func(t *testing.T) {
		tool := VerifySecretTool()

		assert.Equal(t, "verify_secret", tool.Name)
		assert.NotEmpty(t, tool.Description)
		assert.Contains(t, strings.ToLower(tool.Description), "verify")
	})
}

func TestVerifySecretHandler(t *testing.T) {
	ctx := context.Background()
	cfg := mcpInternal.DefaultScannerConfig()
	cfg.Verify = true // Verification is the point of this tool

	scanner, err := mcpInternal.NewScanner(ctx, cfg)
	require.NoError(t, err)

	registry := mcpInternal.NewDetectorRegistry()
	handler := VerifySecretHandler(scanner, registry)

	t.Run("returns error for missing detector_type parameter", func(t *testing.T) {
		req := createCallToolRequest("verify_secret", map[string]any{
			"secret": "test-secret",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "detector_type")
	})

	t.Run("returns error for missing secret parameter", func(t *testing.T) {
		req := createCallToolRequest("verify_secret", map[string]any{
			"detector_type": "AWS",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "secret")
	})

	t.Run("returns error for unknown detector type", func(t *testing.T) {
		req := createCallToolRequest("verify_secret", map[string]any{
			"detector_type": "NonExistentDetector12345",
			"secret":        "test-secret",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)

		text := result.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "unknown detector type")
	})

	t.Run("verifies secret with valid detector type", func(t *testing.T) {
		// Use a fake AWS key format - won't verify but will run through the detector
		req := createCallToolRequest("verify_secret", map[string]any{
			"detector_type": "AWS",
			"secret":        "AKIAIOSFODNN7EXAMPLE",
		})

		result, err := handler(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)

		// Should have a valid JSON response
		text := result.Content[0].(mcp.TextContent).Text
		var response map[string]any
		err = json.Unmarshal([]byte(text), &response)
		require.NoError(t, err)

		// Should have verification result
		_, hasResults := response["results"]
		_, hasSummary := response["summary"]
		assert.True(t, hasResults)
		assert.True(t, hasSummary)
	})
}
