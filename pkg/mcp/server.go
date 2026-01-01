package mcp

import (
	"github.com/mark3labs/mcp-go/server"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
	"github.com/trufflesecurity/trufflehog/v3/pkg/mcp/tools"
)

// Server represents the TruffleHog MCP server.
type Server struct {
	mcpServer *server.MCPServer
	scanner   *internal.Scanner
	registry  *internal.DetectorRegistry
	config    *Config
}

// NewServer creates a new TruffleHog MCP server.
func NewServer(ctx context.Context, cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Initialize detector registry
	registry := internal.NewDetectorRegistry()

	// Initialize scanner with config
	scannerCfg := &internal.ScannerConfig{
		Concurrency: cfg.Concurrency,
		Verify:      cfg.Verify,
		MaxResults:  cfg.MaxResults,
		Timeout:     cfg.ScanTimeout,
	}

	scanner, err := internal.NewScanner(ctx, scannerCfg)
	if err != nil {
		return nil, err
	}

	// Create MCP server
	mcpServer := server.NewMCPServer(
		cfg.ServerName,
		cfg.ServerVersion,
		server.WithToolCapabilities(true),
		server.WithRecovery(),
	)

	s := &Server{
		mcpServer: mcpServer,
		scanner:   scanner,
		registry:  registry,
		config:    cfg,
	}

	// Register tools
	s.registerTools()

	return s, nil
}

// registerTools adds all TruffleHog tools to the MCP server.
func (s *Server) registerTools() {
	// list_detectors - List all available detector types
	s.mcpServer.AddTool(tools.ListDetectorsTool(), tools.ListDetectorsHandler(s.registry))

	// get_detector_info - Get details about a specific detector
	s.mcpServer.AddTool(tools.GetDetectorInfoTool(), tools.GetDetectorInfoHandler(s.registry))

	// scan_text - Scan arbitrary text for secrets
	s.mcpServer.AddTool(tools.ScanTextTool(), tools.ScanTextHandler(s.scanner))

	// scan_file - Scan a local file for secrets
	s.mcpServer.AddTool(tools.ScanFileTool(), tools.ScanFileHandler(s.scanner))

	// scan_directory - Scan a directory for secrets
	s.mcpServer.AddTool(tools.ScanDirectoryTool(), tools.ScanDirectoryHandler(s.scanner))

	// scan_git_repo - Scan a git repository for secrets
	s.mcpServer.AddTool(tools.ScanGitRepoTool(), tools.ScanGitRepoHandler(s.scanner))

	// verify_secret - Verify a specific secret
	s.mcpServer.AddTool(tools.VerifySecretTool(), tools.VerifySecretHandler(s.scanner, s.registry))
}

// ServeStdio starts the MCP server on stdio.
func (s *Server) ServeStdio() error {
	return server.ServeStdio(s.mcpServer)
}
