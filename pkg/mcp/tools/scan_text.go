package tools

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"

	trufflehogContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	mcpInternal "github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
)

// ScanTextTool returns the MCP tool definition for scanning text.
func ScanTextTool() mcp.Tool {
	return mcp.NewTool("scan_text",
		mcp.WithDescription("Scan arbitrary text content for secrets and credentials. "+
			"Use this to check code snippets, configuration files, environment variables, "+
			"or any text for accidentally exposed secrets."),
		mcp.WithString("text",
			mcp.Required(),
			mcp.Description("The text content to scan for secrets."),
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

// ScanTextHandler creates the handler for the scan_text tool.
func ScanTextHandler(scanner *mcpInternal.Scanner) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		// Get required text parameter
		text, ok := args["text"].(string)
		if !ok {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "text parameter is required"}},
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
		response, err := scanner.ScanText(thCtx, text, opts)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "scan failed: " + err.Error()}},
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

// toStringSlice converts a slice of any to a slice of strings.
func toStringSlice(input []any) []string {
	result := make([]string, 0, len(input))
	for _, v := range input {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
