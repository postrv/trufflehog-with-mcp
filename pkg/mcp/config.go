// Package mcp provides an MCP (Model Context Protocol) server for TruffleHog,
// exposing secret scanning capabilities as tools for AI assistants.
package mcp

import (
	"runtime"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

// Config holds MCP server configuration.
type Config struct {
	// ServerName is the name reported to MCP clients.
	ServerName string
	// ServerVersion is the version reported to MCP clients.
	ServerVersion string

	// Concurrency is the number of concurrent workers for scanning.
	Concurrency int
	// Verify determines whether to verify found secrets by default.
	Verify bool
	// ScanTimeout is the maximum time for a single scan operation.
	ScanTimeout time.Duration

	// MaxResults is the maximum number of results to return per scan.
	MaxResults int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ServerName:    "trufflehog-mcp",
		ServerVersion: version.BuildVersion,
		Concurrency:   runtime.NumCPU(),
		Verify:        true,
		ScanTimeout:   5 * time.Minute,
		MaxResults:    1000,
	}
}
