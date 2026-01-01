// Package tools provides MCP tool definitions and handlers for TruffleHog.
package tools

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"

	mcpInternal "github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
)

// Helper type alias for clarity
type stdContext = context.Context

// ListDetectorsTool returns the MCP tool definition for listing detectors.
func ListDetectorsTool() mcp.Tool {
	return mcp.NewTool("list_detectors",
		mcp.WithDescription("List all available secret detector types. "+
			"TruffleHog has 900+ detectors for various services like AWS, GitHub, Stripe, etc. "+
			"Use the filter parameter to search for specific detectors."),
		mcp.WithString("filter",
			mcp.Description("Optional substring to filter detector names (case-insensitive). "+
				"Example: 'AWS' to find all AWS-related detectors."),
		),
	)
}

// ListDetectorsHandler creates the handler for the list_detectors tool.
func ListDetectorsHandler(registry *mcpInternal.DetectorRegistry) func(ctx stdContext, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx stdContext, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		filter := ""
		if f, ok := args["filter"].(string); ok {
			filter = f
		}

		detectors := registry.List(filter, false)

		response := map[string]any{
			"total":     len(detectors),
			"detectors": detectors,
		}

		output, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: err.Error()}},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(output)}},
		}, nil
	}
}
