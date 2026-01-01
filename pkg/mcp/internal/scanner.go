package internal

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/filesystem"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

// ScannerConfig holds configuration for the Scanner.
type ScannerConfig struct {
	// Concurrency is the number of concurrent workers.
	Concurrency int
	// Verify determines whether to verify found secrets.
	Verify bool
	// MaxResults is the maximum number of results to collect.
	MaxResults int
	// Timeout is the maximum time for a scan operation.
	Timeout time.Duration
	// IncludeDetectors is a comma-separated list of detector types to include.
	IncludeDetectors string
	// ExcludeDetectors is a comma-separated list of detector types to exclude.
	ExcludeDetectors string
}

// DefaultScannerConfig returns a ScannerConfig with sensible defaults.
func DefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		Concurrency: runtime.NumCPU(),
		Verify:      true,
		MaxResults:  1000,
		Timeout:     5 * time.Minute,
	}
}

// ScanOptions provides options for individual scan operations.
type ScanOptions struct {
	// Verify overrides the default verification setting.
	Verify bool
	// IncludeDetectors filters to only use these detector types.
	IncludeDetectors []string
	// ExcludeDetectors excludes these detector types.
	ExcludeDetectors []string
}

// GitScanOptions provides options for git repository scans.
type GitScanOptions struct {
	ScanOptions
	// Branch is the specific branch to scan.
	Branch string
	// SinceCommit limits scanning to commits after this hash.
	SinceCommit string
	// MaxDepth limits how many commits to scan (0 = unlimited).
	MaxDepth int64
}

// Scanner wraps the TruffleHog engine for MCP use.
type Scanner struct {
	config    *ScannerConfig
	detectors []detectors.Detector
}

// NewScanner creates a new Scanner with the given configuration.
func NewScanner(ctx context.Context, cfg *ScannerConfig) (*Scanner, error) {
	if cfg == nil {
		cfg = DefaultScannerConfig()
	}

	return &Scanner{
		config:    cfg,
		detectors: defaults.DefaultDetectors(),
	}, nil
}

// ScanText scans the provided text for secrets.
func (s *Scanner) ScanText(ctx context.Context, text string, opts *ScanOptions) (*ScanResponse, error) {
	return s.ScanBytes(ctx, []byte(text), opts)
}

// ScanBytes scans the provided bytes for secrets.
func (s *Scanner) ScanBytes(ctx context.Context, data []byte, opts *ScanOptions) (*ScanResponse, error) {
	if opts == nil {
		opts = &ScanOptions{Verify: s.config.Verify}
	}

	// Handle empty data
	if len(data) == 0 {
		return &ScanResponse{
			Results: []ScanResult{},
			Summary: ScanSummary{},
		}, nil
	}

	// Create result collector
	collector := NewResultCollector(s.config.MaxResults)

	// Create source manager
	sourceManager := sources.NewManager(
		sources.WithConcurrentSources(1),
		sources.WithConcurrentUnits(s.config.Concurrency),
		sources.WithBufferedOutput(64),
	)

	// Build engine config
	engConfig := engine.Config{
		Concurrency:      s.config.Concurrency,
		Detectors:        s.detectors,
		Verify:           opts.Verify,
		IncludeDetectors: s.buildDetectorFilter(opts.IncludeDetectors),
		ExcludeDetectors: s.buildDetectorFilter(opts.ExcludeDetectors),
		Dispatcher:       engine.NewPrinterDispatcher(collector),
		SourceManager:    sourceManager,
	}

	// Create engine
	eng, err := engine.NewEngine(ctx, &engConfig)
	if err != nil {
		return nil, err
	}

	// Start the engine
	eng.Start(ctx)

	// Create and initialize the bytes source
	bytesSource := NewBytesSource("mcp-scan", data, opts.Verify)

	// Use the source manager to enumerate and scan
	_, err = sourceManager.EnumerateAndScan(ctx, "mcp-scan", bytesSource)
	if err != nil {
		return nil, err
	}

	// Wait for completion
	if err := eng.Finish(ctx); err != nil {
		return nil, err
	}

	// Get metrics
	metrics := eng.GetMetrics()

	return &ScanResponse{
		Results: collector.Results(),
		Summary: ScanSummary{
			ChunksScanned:     metrics.ChunksScanned,
			BytesScanned:      metrics.BytesScanned,
			VerifiedSecrets:   metrics.VerifiedSecretsFound,
			UnverifiedSecrets: metrics.UnverifiedSecretsFound,
			Duration:          metrics.ScanDuration,
			TotalResults:      collector.Count(),
			Truncated:         collector.IsTruncated(),
		},
	}, nil
}

// ScanFile scans a file for secrets.
func (s *Scanner) ScanFile(ctx context.Context, path string, opts *ScanOptions) (*ScanResponse, error) {
	// Validate the file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", path)
	}

	return s.scanFilesystem(ctx, []string{path}, opts)
}

// ScanDirectory scans a directory for secrets.
func (s *Scanner) ScanDirectory(ctx context.Context, path string, opts *ScanOptions) (*ScanResponse, error) {
	// Validate the directory exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", path)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", path)
	}

	return s.scanFilesystem(ctx, []string{path}, opts)
}

// scanFilesystem performs a filesystem scan on the given paths.
func (s *Scanner) scanFilesystem(ctx context.Context, paths []string, opts *ScanOptions) (*ScanResponse, error) {
	if opts == nil {
		opts = &ScanOptions{Verify: s.config.Verify}
	}

	// Create result collector
	collector := NewResultCollector(s.config.MaxResults)

	// Create source manager
	sourceManager := sources.NewManager(
		sources.WithConcurrentSources(1),
		sources.WithConcurrentUnits(s.config.Concurrency),
		sources.WithBufferedOutput(64),
	)

	// Build engine config
	engConfig := engine.Config{
		Concurrency:      s.config.Concurrency,
		Detectors:        s.detectors,
		Verify:           opts.Verify,
		IncludeDetectors: s.buildDetectorFilter(opts.IncludeDetectors),
		ExcludeDetectors: s.buildDetectorFilter(opts.ExcludeDetectors),
		Dispatcher:       engine.NewPrinterDispatcher(collector),
		SourceManager:    sourceManager,
	}

	// Create engine
	eng, err := engine.NewEngine(ctx, &engConfig)
	if err != nil {
		return nil, err
	}

	// Start the engine
	eng.Start(ctx)

	// Create filesystem connection
	conn := &sourcespb.Filesystem{
		Paths: paths,
	}
	connAny, err := anypb.New(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}

	// Create and initialize the filesystem source
	fsSource := &filesystem.Source{}
	if err := fsSource.Init(ctx, "mcp-scan", 0, 0, opts.Verify, connAny, s.config.Concurrency); err != nil {
		return nil, fmt.Errorf("failed to initialize filesystem source: %w", err)
	}

	// Use the source manager to enumerate and scan
	_, err = sourceManager.EnumerateAndScan(ctx, "mcp-scan", fsSource)
	if err != nil {
		return nil, err
	}

	// Wait for completion
	if err := eng.Finish(ctx); err != nil {
		return nil, err
	}

	// Get metrics
	metrics := eng.GetMetrics()

	return &ScanResponse{
		Results: collector.Results(),
		Summary: ScanSummary{
			ChunksScanned:     metrics.ChunksScanned,
			BytesScanned:      metrics.BytesScanned,
			VerifiedSecrets:   metrics.VerifiedSecretsFound,
			UnverifiedSecrets: metrics.UnverifiedSecretsFound,
			Duration:          metrics.ScanDuration,
			TotalResults:      collector.Count(),
			Truncated:         collector.IsTruncated(),
		},
	}, nil
}

// buildDetectorFilter converts a slice of detector names to a comma-separated string.
func (s *Scanner) buildDetectorFilter(detectors []string) string {
	if len(detectors) == 0 {
		return ""
	}
	result := ""
	for i, d := range detectors {
		if i > 0 {
			result += ","
		}
		result += d
	}
	return result
}

// ScanGitRepo scans a git repository for secrets.
func (s *Scanner) ScanGitRepo(ctx context.Context, uri string, opts *GitScanOptions) (*ScanResponse, error) {
	if opts == nil {
		opts = &GitScanOptions{
			ScanOptions: ScanOptions{Verify: s.config.Verify},
		}
	}

	// For local file:// URIs, validate the path exists
	if strings.HasPrefix(uri, "file://") {
		localPath := strings.TrimPrefix(uri, "file://")
		if _, err := os.Stat(localPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("repository does not exist: %s", localPath)
		}
	} else if !strings.Contains(uri, "://") {
		// For bare local paths, validate existence
		if _, err := os.Stat(uri); os.IsNotExist(err) {
			return nil, fmt.Errorf("repository does not exist: %s", uri)
		}
	}

	// Create result collector
	collector := NewResultCollector(s.config.MaxResults)

	// Create source manager
	sourceManager := sources.NewManager(
		sources.WithConcurrentSources(1),
		sources.WithConcurrentUnits(s.config.Concurrency),
		sources.WithBufferedOutput(64),
	)

	// Build engine config
	engConfig := engine.Config{
		Concurrency:      s.config.Concurrency,
		Detectors:        s.detectors,
		Verify:           opts.Verify,
		IncludeDetectors: s.buildDetectorFilter(opts.IncludeDetectors),
		ExcludeDetectors: s.buildDetectorFilter(opts.ExcludeDetectors),
		Dispatcher:       engine.NewPrinterDispatcher(collector),
		SourceManager:    sourceManager,
	}

	// Create engine
	eng, err := engine.NewEngine(ctx, &engConfig)
	if err != nil {
		return nil, err
	}

	// Start the engine
	eng.Start(ctx)

	// Create git connection
	conn := &sourcespb.Git{
		Uri:      uri,
		Head:     opts.Branch,
		Base:     opts.SinceCommit,
		MaxDepth: opts.MaxDepth,
		Credential: &sourcespb.Git_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
	}
	connAny, err := anypb.New(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}

	// Create and initialize the git source
	gitSource := &git.Source{}
	if err := gitSource.Init(ctx, "mcp-scan", 0, 0, opts.Verify, connAny, s.config.Concurrency); err != nil {
		return nil, fmt.Errorf("failed to initialize git source: %w", err)
	}

	// Use the source manager to enumerate and scan
	_, err = sourceManager.EnumerateAndScan(ctx, "mcp-scan", gitSource)
	if err != nil {
		return nil, err
	}

	// Wait for completion
	if err := eng.Finish(ctx); err != nil {
		return nil, err
	}

	// Get metrics
	metrics := eng.GetMetrics()

	return &ScanResponse{
		Results: collector.Results(),
		Summary: ScanSummary{
			ChunksScanned:     metrics.ChunksScanned,
			BytesScanned:      metrics.BytesScanned,
			VerifiedSecrets:   metrics.VerifiedSecretsFound,
			UnverifiedSecrets: metrics.UnverifiedSecretsFound,
			Duration:          metrics.ScanDuration,
			TotalResults:      collector.Count(),
			Truncated:         collector.IsTruncated(),
		},
	}, nil
}
