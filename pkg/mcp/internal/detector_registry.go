package internal

import (
	"fmt"
	"strings"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// DetectorRegistry provides metadata about available detectors.
type DetectorRegistry struct {
	mu        sync.RWMutex
	detectors map[string]DetectorInfo
}

// NewDetectorRegistry creates a new DetectorRegistry populated with default detectors.
func NewDetectorRegistry() *DetectorRegistry {
	r := &DetectorRegistry{
		detectors: make(map[string]DetectorInfo),
	}
	r.loadDefaults()
	return r
}

// loadDefaults populates the registry with default TruffleHog detectors.
func (r *DetectorRegistry) loadDefaults() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, d := range defaults.DefaultDetectors() {
		info := DetectorInfo{
			Type:        d.Type().String(),
			Name:        d.Type().String(),
			Description: d.Description(),
			Keywords:    d.Keywords(),
		}

		// Check if detector implements Versioner interface
		if v, ok := d.(detectors.Versioner); ok {
			info.Version = v.Version()
		}

		// Store with lowercase key for case-insensitive lookup
		r.detectors[strings.ToLower(info.Type)] = info
	}
}

// List returns all detectors that match the optional filter.
// If filter is empty, all detectors are returned.
// The filter is applied case-insensitively to the detector type name.
func (r *DetectorRegistry) List(filter string, includeDeprecated bool) []DetectorInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	filter = strings.ToLower(filter)
	result := make([]DetectorInfo, 0, len(r.detectors))

	for _, info := range r.detectors {
		// Apply filter if provided
		if filter != "" && !strings.Contains(strings.ToLower(info.Type), filter) {
			continue
		}
		result = append(result, info)
	}

	return result
}

// GetInfo returns detailed information about a specific detector type.
func (r *DetectorRegistry) GetInfo(detectorType string) (*DetectorInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.detectors[strings.ToLower(detectorType)]
	if !ok {
		return nil, fmt.Errorf("unknown detector type: %s", detectorType)
	}

	// Return a copy to prevent external modification
	infoCopy := info
	return &infoCopy, nil
}

// GetCatalog returns a map containing all detector information.
func (r *DetectorRegistry) GetCatalog() map[string]any {
	detectors := r.List("", false)
	return map[string]any{
		"total":     len(detectors),
		"detectors": detectors,
	}
}

// Count returns the number of registered detectors.
func (r *DetectorRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.detectors)
}

// Exists returns true if a detector with the given type name exists.
func (r *DetectorRegistry) Exists(detectorType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.detectors[strings.ToLower(detectorType)]
	return ok
}
