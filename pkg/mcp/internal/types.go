package internal

import (
	"time"
)

// ScanResult represents a single secret finding for MCP response.
type ScanResult struct {
	// DetectorType is the type of detector that found this secret.
	DetectorType string `json:"detector_type"`
	// DetectorName is the human-readable name of the detector.
	DetectorName string `json:"detector_name,omitempty"`
	// Verified indicates whether the secret was verified.
	Verified bool `json:"verified"`
	// VerificationError contains any error from verification.
	VerificationError string `json:"verification_error,omitempty"`
	// Raw contains the raw secret (only included if configured).
	Raw string `json:"raw,omitempty"`
	// Redacted contains a redacted version of the secret.
	Redacted string `json:"redacted"`
	// ExtraData contains detector-specific additional information.
	ExtraData map[string]string `json:"extra_data,omitempty"`
	// SourceMetadata contains information about where the secret was found.
	SourceMetadata map[string]any `json:"source_metadata,omitempty"`
	// DecoderType is the decoder that was used to find this secret.
	DecoderType string `json:"decoder_type"`
}

// ScanSummary provides aggregate information about a scan.
type ScanSummary struct {
	// ChunksScanned is the number of chunks scanned.
	ChunksScanned uint64 `json:"chunks_scanned"`
	// BytesScanned is the number of bytes scanned.
	BytesScanned uint64 `json:"bytes_scanned"`
	// VerifiedSecrets is the count of verified secrets found.
	VerifiedSecrets uint64 `json:"verified_secrets"`
	// UnverifiedSecrets is the count of unverified secrets found.
	UnverifiedSecrets uint64 `json:"unverified_secrets"`
	// Duration is the time taken for the scan.
	Duration time.Duration `json:"duration_ms"`
	// TotalResults is the total number of results returned.
	TotalResults int `json:"total_results"`
	// Truncated indicates whether results were truncated due to limits.
	Truncated bool `json:"truncated"`
}

// ScanResponse combines results and summary for a scan operation.
type ScanResponse struct {
	// Results contains the detected secrets.
	Results []ScanResult `json:"results"`
	// Summary contains aggregate scan information.
	Summary ScanSummary `json:"summary"`
}

// DetectorInfo contains metadata about a detector.
type DetectorInfo struct {
	// Type is the detector type identifier.
	Type string `json:"type"`
	// Name is the human-readable name.
	Name string `json:"name"`
	// Description describes what the detector finds.
	Description string `json:"description"`
	// Keywords are the keywords used for pre-filtering.
	Keywords []string `json:"keywords"`
	// Version is the detector version (if applicable).
	Version int `json:"version,omitempty"`
}
