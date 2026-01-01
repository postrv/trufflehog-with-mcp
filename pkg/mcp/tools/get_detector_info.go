package tools

import (
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"

	mcpInternal "github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
)

// GetDetectorInfoTool returns the MCP tool definition for getting detector info.
func GetDetectorInfoTool() mcp.Tool {
	return mcp.NewTool("get_detector_info",
		mcp.WithDescription("Get detailed information about a specific secret detector type. "+
			"Returns the detector's description, keywords used for matching, and version information."),
		mcp.WithString("detector_type",
			mcp.Required(),
			mcp.Description("The detector type name to get info for (e.g., 'AWS', 'Stripe', 'GitHubApp'). "+
				"Use list_detectors to see available types."),
		),
	)
}

// GetDetectorInfoHandler creates the handler for the get_detector_info tool.
func GetDetectorInfoHandler(registry *mcpInternal.DetectorRegistry) func(ctx stdContext, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx stdContext, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		detectorType, ok := args["detector_type"].(string)
		if !ok || detectorType == "" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "detector_type parameter is required"}},
				IsError: true,
			}, nil
		}

		info, err := registry.GetInfo(detectorType)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: err.Error()}},
				IsError: true,
			}, nil
		}

		output, err := json.MarshalIndent(info, "", "  ")
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
