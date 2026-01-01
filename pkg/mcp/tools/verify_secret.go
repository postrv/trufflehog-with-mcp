package tools

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"

	trufflehogContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	mcpInternal "github.com/trufflesecurity/trufflehog/v3/pkg/mcp/internal"
)

// VerifySecretTool returns the MCP tool definition for verifying a secret.
func VerifySecretTool() mcp.Tool {
	return mcp.NewTool("verify_secret",
		mcp.WithDescription("Verify if a specific secret is valid and active. "+
			"This tool scans the provided secret value using a specific detector and attempts verification. "+
			"Use this to check if a found secret is still active."),
		mcp.WithString("detector_type",
			mcp.Required(),
			mcp.Description("The detector type to use for verification (e.g., 'AWS', 'GitHub', 'Stripe'). "+
				"Use list_detectors to see available types."),
		),
		mcp.WithString("secret",
			mcp.Required(),
			mcp.Description("The secret value to verify."),
		),
		mcp.WithString("extra_data",
			mcp.Description("Additional data needed for verification (e.g., AWS key ID for AWS secrets). "+
				"Some detectors require additional context to verify secrets."),
		),
	)
}

// VerifySecretHandler creates the handler for the verify_secret tool.
func VerifySecretHandler(scanner *mcpInternal.Scanner, registry *mcpInternal.DetectorRegistry) func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		// Get required detector_type parameter
		detectorType, ok := args["detector_type"].(string)
		if !ok || detectorType == "" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "detector_type parameter is required"}},
				IsError: true,
			}, nil
		}

		// Validate detector type exists
		if !registry.Exists(detectorType) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "unknown detector type: " + detectorType}},
				IsError: true,
			}, nil
		}

		// Get required secret parameter
		secret, ok := args["secret"].(string)
		if !ok || secret == "" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "secret parameter is required"}},
				IsError: true,
			}, nil
		}

		// Build the text to scan - include extra_data if provided
		textToScan := secret
		if extraData, ok := args["extra_data"].(string); ok && extraData != "" {
			textToScan = extraData + " " + secret
		}

		// Build scan options - always verify and only use the specified detector
		opts := &mcpInternal.ScanOptions{
			Verify:           true,
			IncludeDetectors: []string{detectorType},
		}

		// Create TruffleHog context for the scan
		thCtx := trufflehogContext.Background()

		// Perform the scan with verification
		response, err := scanner.ScanText(thCtx, textToScan, opts)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "verification failed: " + err.Error()}},
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
