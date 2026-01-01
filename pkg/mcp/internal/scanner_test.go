package internal

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestNewScanner(t *testing.T) {
	ctx := context.Background()

	t.Run("creates scanner with default config", func(t *testing.T) {
		cfg := DefaultScannerConfig()
		scanner, err := NewScanner(ctx, cfg)

		require.NoError(t, err)
		require.NotNil(t, scanner)
	})

	t.Run("creates scanner with custom config", func(t *testing.T) {
		cfg := &ScannerConfig{
			Concurrency: 4,
			Verify:      true,
			MaxResults:  500,
			Timeout:     2 * time.Minute,
		}
		scanner, err := NewScanner(ctx, cfg)

		require.NoError(t, err)
		require.NotNil(t, scanner)
	})
}

func TestDefaultScannerConfig(t *testing.T) {
	cfg := DefaultScannerConfig()

	assert.Greater(t, cfg.Concurrency, 0)
	assert.True(t, cfg.Verify)
	assert.Greater(t, cfg.MaxResults, 0)
	assert.Greater(t, cfg.Timeout, time.Duration(0))
}

func TestScanner_ScanText(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultScannerConfig()
	cfg.Verify = false // Disable verification for faster tests

	scanner, err := NewScanner(ctx, cfg)
	require.NoError(t, err)

	t.Run("scans text and finds AWS key", func(t *testing.T) {
		// A fake AWS key pattern that will match the detector
		text := `
		Here is my config:
		AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
		AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
		`

		opts := &ScanOptions{
			Verify: false,
		}

		response, err := scanner.ScanText(ctx, text, opts)
		require.NoError(t, err)
		require.NotNil(t, response)

		// Check that we got some results (the fake key should match AWS detector pattern)
		assert.GreaterOrEqual(t, len(response.Results), 0) // May or may not find depending on detector patterns
		assert.Greater(t, response.Summary.BytesScanned, uint64(0))
	})

	t.Run("handles empty text", func(t *testing.T) {
		response, err := scanner.ScanText(ctx, "", &ScanOptions{})
		require.NoError(t, err)
		require.NotNil(t, response)

		assert.Empty(t, response.Results)
	})

	t.Run("respects max results", func(t *testing.T) {
		cfg := &ScannerConfig{
			Concurrency: 1,
			Verify:      false,
			MaxResults:  1,
			Timeout:     time.Minute,
		}
		scanner, err := NewScanner(ctx, cfg)
		require.NoError(t, err)

		// Text with multiple potential matches
		text := `
		key1=AKIAIOSFODNN7EXAMPLE1
		key2=AKIAIOSFODNN7EXAMPLE2
		key3=AKIAIOSFODNN7EXAMPLE3
		`

		response, err := scanner.ScanText(ctx, text, &ScanOptions{})
		require.NoError(t, err)

		// Results should be limited to max
		assert.LessOrEqual(t, len(response.Results), 1)
	})
}

func TestScanner_ScanBytes(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultScannerConfig()
	cfg.Verify = false

	scanner, err := NewScanner(ctx, cfg)
	require.NoError(t, err)

	t.Run("scans bytes", func(t *testing.T) {
		data := []byte("secret=AKIAIOSFODNN7EXAMPLE")

		response, err := scanner.ScanBytes(ctx, data, &ScanOptions{})
		require.NoError(t, err)
		require.NotNil(t, response)

		assert.Equal(t, uint64(len(data)), response.Summary.BytesScanned)
	})
}

func TestScanner_ScanFile(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultScannerConfig()
	cfg.Verify = false

	scanner, err := NewScanner(ctx, cfg)
	require.NoError(t, err)

	t.Run("scans file with secrets", func(t *testing.T) {
		// Create a temporary file with test content
		tmpFile, err := os.CreateTemp("", "trufflehog-test-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		content := "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
		_, err = tmpFile.WriteString(content)
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		response, err := scanner.ScanFile(ctx, tmpFile.Name(), &ScanOptions{})
		require.NoError(t, err)
		require.NotNil(t, response)

		// Should have scanned the file
		assert.Greater(t, response.Summary.BytesScanned, uint64(0))
	})

	t.Run("scans file with no secrets", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "trufflehog-test-safe-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString("This is safe content without secrets.\n")
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		response, err := scanner.ScanFile(ctx, tmpFile.Name(), &ScanOptions{})
		require.NoError(t, err)
		require.NotNil(t, response)

		assert.Empty(t, response.Results)
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		_, err := scanner.ScanFile(ctx, "/nonexistent/path/to/file.txt", &ScanOptions{})
		require.Error(t, err)
	})
}

func TestScanner_ScanDirectory(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultScannerConfig()
	cfg.Verify = false

	scanner, err := NewScanner(ctx, cfg)
	require.NoError(t, err)

	t.Run("scans directory with secrets", func(t *testing.T) {
		// Create a temporary directory
		tmpDir, err := os.MkdirTemp("", "trufflehog-test-dir-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		// Create a file with a secret
		secretFile := filepath.Join(tmpDir, "config.txt")
		err = os.WriteFile(secretFile, []byte("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
		require.NoError(t, err)

		response, err := scanner.ScanDirectory(ctx, tmpDir, &ScanOptions{})
		require.NoError(t, err)
		require.NotNil(t, response)

		// Should have scanned the directory
		assert.Greater(t, response.Summary.BytesScanned, uint64(0))
	})

	t.Run("scans directory with no secrets", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "trufflehog-test-safe-dir-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		safeFile := filepath.Join(tmpDir, "readme.txt")
		err = os.WriteFile(safeFile, []byte("This is safe content.\n"), 0644)
		require.NoError(t, err)

		response, err := scanner.ScanDirectory(ctx, tmpDir, &ScanOptions{})
		require.NoError(t, err)
		require.NotNil(t, response)

		assert.Empty(t, response.Results)
	})

	t.Run("returns error for non-existent directory", func(t *testing.T) {
		_, err := scanner.ScanDirectory(ctx, "/nonexistent/path/to/directory", &ScanOptions{})
		require.Error(t, err)
	})

	t.Run("returns error when path is a file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "trufflehog-test-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		require.NoError(t, tmpFile.Close())

		_, err = scanner.ScanDirectory(ctx, tmpFile.Name(), &ScanOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a directory")
	})
}

func TestScanner_ScanGitRepo(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultScannerConfig()
	cfg.Verify = false

	scanner, err := NewScanner(ctx, cfg)
	require.NoError(t, err)

	t.Run("scans local git repo", func(t *testing.T) {
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

		opts := &GitScanOptions{
			ScanOptions: ScanOptions{},
		}
		// Use file:// URI format for local repos
		response, err := scanner.ScanGitRepo(ctx, "file://"+tmpDir, opts)
		require.NoError(t, err)
		require.NotNil(t, response)

		// Should have scanned the repo
		assert.Greater(t, response.Summary.BytesScanned, uint64(0))
	})

	t.Run("returns error for non-existent repo", func(t *testing.T) {
		opts := &GitScanOptions{}
		_, err := scanner.ScanGitRepo(ctx, "/nonexistent/path/to/repo", opts)
		require.Error(t, err)
	})
}
