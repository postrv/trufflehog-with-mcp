package tools

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	trufflehogContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	mcpInternal "github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
)

// ScanFileTool returns the MCP tool definition for scanning a file.
func ScanFileTool() mcp.Tool {
	return mcp.NewTool("scan_file",
		mcp.WithDescription("Scan a local file for secrets and credentials. "+
			"Use this to check source code files, configuration files, or any text file "+
			"for accidentally exposed secrets."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("The absolute path to the file to scan. Must be an absolute path."),
		),
		mcp.WithBoolean("verify",
			mcp.Description("Whether to verify found secrets by calling their respective APIs. "+
				"Verification confirms if secrets are still active. Default: true."),
		),
		mcp.WithArray("include_detectors",
			mcp.WithStringItems(),
			mcp.Description("List of detector types to include (e.g., ['AWS', 'GitHub']). "+
				"Default: all detectors. Use list_detectors to see available types."),
		),
		mcp.WithArray("exclude_detectors",
			mcp.WithStringItems(),
			mcp.Description("List of detector types to exclude from scanning."),
		),
	)
}

// ScanFileHandler creates the handler for the scan_file tool.
func ScanFileHandler(scanner *mcpInternal.Scanner) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		// Get required path parameter
		path, ok := args["path"].(string)
		if !ok || path == "" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "path parameter is required"}},
				IsError: true,
			}, nil
		}

		// Validate path is absolute
		if !filepath.IsAbs(path) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "path must be an absolute path"}},
				IsError: true,
			}, nil
		}

		// Build scan options
		opts := &mcpInternal.ScanOptions{
			Verify: true, // Default to verification
		}

		// Override verify if specified
		if v, ok := args["verify"].(bool); ok {
			opts.Verify = v
		}

		// Handle include_detectors
		if include, ok := args["include_detectors"].([]any); ok {
			opts.IncludeDetectors = toStringSlice(include)
		}

		// Handle exclude_detectors
		if exclude, ok := args["exclude_detectors"].([]any); ok {
			opts.ExcludeDetectors = toStringSlice(exclude)
		}

		// Create TruffleHog context for the scan
		thCtx := trufflehogContext.Background()

		// Perform the scan
		response, err := scanner.ScanFile(thCtx, path, opts)
		if err != nil {
			errMsg := err.Error()
			// Check for specific error cases
			if strings.Contains(errMsg, "does not exist") {
				return &mcp.CallToolResult{
					Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "file does not exist: " + path}},
					IsError: true,
				}, nil
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "scan failed: " + errMsg}},
				IsError: true,
			}, nil
		}

		// Format the response
		output, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "failed to format response: " + err.Error()}},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(output)}},
		}, nil
	}
}
