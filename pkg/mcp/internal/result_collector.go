// Package internal contains internal implementation details for the MCP server.
package internal

import (
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
)

// ResultCollector implements the engine.Printer interface to collect results in-memory
// for MCP responses instead of printing to stdout.
type ResultCollector struct {
	mu         sync.Mutex
	results    []ScanResult
	maxResults int
	truncated  bool
}

// NewResultCollector creates a new ResultCollector with the specified maximum results limit.
func NewResultCollector(maxResults int) *ResultCollector {
	return &ResultCollector{
		results:    make([]ScanResult, 0),
		maxResults: maxResults,
		truncated:  false,
	}
}

// Print implements the engine.Printer interface.
// It converts the result to a ScanResult and stores it in memory.
func (c *ResultCollector) Print(_ context.Context, r *detectors.ResultWithMetadata) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxResults > 0 && len(c.results) >= c.maxResults {
		c.truncated = true
		return nil
	}

	result := ConvertResult(r)
	c.results = append(c.results, result)
	return nil
}

// Results returns a copy of the collected results.
func (c *ResultCollector) Results() []ScanResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return a copy to prevent external modification
	resultsCopy := make([]ScanResult, len(c.results))
	copy(resultsCopy, c.results)
	return resultsCopy
}

// IsTruncated returns true if results were truncated due to reaching the max limit.
func (c *ResultCollector) IsTruncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

// Count returns the number of results collected.
func (c *ResultCollector) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.results)
}

// ConvertResult converts a detectors.ResultWithMetadata to a ScanResult.
func ConvertResult(r *detectors.ResultWithMetadata) ScanResult {
	result := ScanResult{
		DetectorType: r.DetectorType.String(),
		DetectorName: r.DetectorName,
		Verified:     r.Verified,
		Redacted:     r.Redacted,
		ExtraData:    r.ExtraData,
		DecoderType:  r.DecoderType.String(),
	}

	// Include raw only if it's different from redacted (i.e., not sensitive)
	// For MCP, we typically want to include raw for verified secrets
	if r.Verified {
		result.Raw = string(r.Raw)
	}

	// Convert verification error
	if err := r.VerificationError(); err != nil {
		result.VerificationError = err.Error()
	}

	// Convert source metadata
	if r.SourceMetadata != nil {
		result.SourceMetadata = convertSourceMetadata(r.SourceMetadata)
	}

	return result
}

// convertSourceMetadata converts protocol buffer source metadata to a map.
func convertSourceMetadata(meta *source_metadatapb.MetaData) map[string]any {
	if meta == nil {
		return nil
	}

	result := make(map[string]any)

	switch data := meta.Data.(type) {
	case *source_metadatapb.MetaData_Filesystem:
		if data.Filesystem != nil {
			result["type"] = "filesystem"
			result["file"] = data.Filesystem.File
			if data.Filesystem.Line > 0 {
				result["line"] = data.Filesystem.Line
			}
		}
	case *source_metadatapb.MetaData_Git:
		if data.Git != nil {
			result["type"] = "git"
			result["repository"] = data.Git.Repository
			result["commit"] = data.Git.Commit
			result["file"] = data.Git.File
			if data.Git.Line > 0 {
				result["line"] = data.Git.Line
			}
		}
	case *source_metadatapb.MetaData_Github:
		if data.Github != nil {
			result["type"] = "github"
			result["repository"] = data.Github.Repository
			result["file"] = data.Github.File
			if data.Github.Line > 0 {
				result["line"] = data.Github.Line
			}
			if data.Github.Commit != "" {
				result["commit"] = data.Github.Commit
			}
		}
	case *source_metadatapb.MetaData_Gitlab:
		if data.Gitlab != nil {
			result["type"] = "gitlab"
			result["repository"] = data.Gitlab.Repository
			result["file"] = data.Gitlab.File
			if data.Gitlab.Line > 0 {
				result["line"] = data.Gitlab.Line
			}
		}
	case *source_metadatapb.MetaData_Stdin:
		result["type"] = "stdin"
	default:
		result["type"] = "unknown"
	}

	return result
}
