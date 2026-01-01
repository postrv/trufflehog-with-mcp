package tools

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	trufflehogContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	mcpInternal "github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
)

// ScanGitRepoTool returns the MCP tool definition for scanning a git repository.
func ScanGitRepoTool() mcp.Tool {
	return mcp.NewTool("scan_git_repo",
		mcp.WithDescription("Scan a git repository for secrets and credentials in commit history. "+
			"Use this to check repository history for accidentally committed secrets. "+
			"Supports local repositories and remote URLs."),
		mcp.WithString("uri",
			mcp.Required(),
			mcp.Description("The git repository URI. Can be a local path or remote URL (https://, git://, ssh://)."),
		),
		mcp.WithBoolean("verify",
			mcp.Description("Whether to verify found secrets by calling their respective APIs. "+
				"Verification confirms if secrets are still active. Default: true."),
		),
		mcp.WithString("branch",
			mcp.Description("Specific branch to scan. If not specified, scans the default branch."),
		),
		mcp.WithString("since_commit",
			mcp.Description("Only scan commits after this commit hash. Useful for incremental scanning."),
		),
		mcp.WithNumber("max_depth",
			mcp.Description("Maximum number of commits to scan. 0 means unlimited. Default: 0."),
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

// ScanGitRepoHandler creates the handler for the scan_git_repo tool.
func ScanGitRepoHandler(scanner *mcpInternal.Scanner) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		// Get required uri parameter
		uri, ok := args["uri"].(string)
		if !ok || uri == "" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "uri parameter is required"}},
				IsError: true,
			}, nil
		}

		// Build scan options
		opts := &mcpInternal.GitScanOptions{
			ScanOptions: mcpInternal.ScanOptions{
				Verify: true, // Default to verification
			},
		}

		// Override verify if specified
		if v, ok := args["verify"].(bool); ok {
			opts.Verify = v
		}

		// Handle branch
		if branch, ok := args["branch"].(string); ok {
			opts.Branch = branch
		}

		// Handle since_commit
		if sinceCommit, ok := args["since_commit"].(string); ok {
			opts.SinceCommit = sinceCommit
		}

		// Handle max_depth
		if maxDepth, ok := args["max_depth"].(float64); ok {
			opts.MaxDepth = int64(maxDepth)
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
		response, err := scanner.ScanGitRepo(thCtx, uri, opts)
		if err != nil {
			errMsg := err.Error()
			// Check for specific error cases
			if strings.Contains(errMsg, "does not exist") {
				return &mcp.CallToolResult{
					Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "repository does not exist: " + uri}},
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
