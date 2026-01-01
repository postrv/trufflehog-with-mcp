package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDetectorRegistry(t *testing.T) {
	t.Run("creates registry with default detectors", func(t *testing.T) {
		registry := NewDetectorRegistry()
		require.NotNil(t, registry)

		// Should have loaded default detectors
		all := registry.List("", false)
		assert.NotEmpty(t, all)
	})
}

func TestDetectorRegistry_List(t *testing.T) {
	registry := NewDetectorRegistry()

	t.Run("returns all detectors with empty filter", func(t *testing.T) {
		detectors := registry.List("", false)
		assert.NotEmpty(t, detectors)
		// Should have many detectors (TruffleHog has 900+)
		assert.Greater(t, len(detectors), 100)
	})

	t.Run("filters detectors by name", func(t *testing.T) {
		detectors := registry.List("AWS", false)
		assert.NotEmpty(t, detectors)

		// All results should contain "AWS" (case-insensitive)
		for _, d := range detectors {
			assert.Contains(t, d.Type, "AWS")
		}
	})

	t.Run("filter is case-insensitive", func(t *testing.T) {
		upper := registry.List("AWS", false)
		lower := registry.List("aws", false)
		mixed := registry.List("AwS", false)

		assert.Equal(t, len(upper), len(lower))
		assert.Equal(t, len(upper), len(mixed))
	})

	t.Run("returns empty slice for non-matching filter", func(t *testing.T) {
		detectors := registry.List("NonExistentDetector12345", false)
		assert.Empty(t, detectors)
	})
}

func TestDetectorRegistry_GetInfo(t *testing.T) {
	registry := NewDetectorRegistry()

	t.Run("returns info for valid detector type", func(t *testing.T) {
		info, err := registry.GetInfo("AWS")
		require.NoError(t, err)
		require.NotNil(t, info)

		assert.Equal(t, "AWS", info.Type)
		assert.NotEmpty(t, info.Description)
		assert.NotEmpty(t, info.Keywords)
	})

	t.Run("is case-insensitive", func(t *testing.T) {
		info1, err1 := registry.GetInfo("AWS")
		info2, err2 := registry.GetInfo("aws")
		info3, err3 := registry.GetInfo("Aws")

		require.NoError(t, err1)
		require.NoError(t, err2)
		require.NoError(t, err3)

		assert.Equal(t, info1.Type, info2.Type)
		assert.Equal(t, info1.Type, info3.Type)
	})

	t.Run("returns error for unknown detector", func(t *testing.T) {
		info, err := registry.GetInfo("NonExistentDetector12345")
		assert.Error(t, err)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "unknown detector type")
	})
}

func TestDetectorRegistry_GetCatalog(t *testing.T) {
	registry := NewDetectorRegistry()

	t.Run("returns catalog with total and detectors", func(t *testing.T) {
		catalog := registry.GetCatalog()
		require.NotNil(t, catalog)

		total, ok := catalog["total"].(int)
		require.True(t, ok)
		assert.Greater(t, total, 100)

		detectors, ok := catalog["detectors"].([]DetectorInfo)
		require.True(t, ok)
		assert.Equal(t, total, len(detectors))
	})
}

func TestDetectorRegistry_Count(t *testing.T) {
	registry := NewDetectorRegistry()

	t.Run("returns non-zero count", func(t *testing.T) {
		count := registry.Count()
		assert.Greater(t, count, 100)
	})
}

func TestDetectorRegistry_Exists(t *testing.T) {
	registry := NewDetectorRegistry()

	t.Run("returns true for existing detector", func(t *testing.T) {
		assert.True(t, registry.Exists("AWS"))
		assert.True(t, registry.Exists("aws"))
		assert.True(t, registry.Exists("Stripe"))
	})

	t.Run("returns false for non-existing detector", func(t *testing.T) {
		assert.False(t, registry.Exists("NonExistentDetector12345"))
	})
}
