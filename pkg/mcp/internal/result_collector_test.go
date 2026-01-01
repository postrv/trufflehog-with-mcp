package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

func TestNewResultCollector(t *testing.T) {
	t.Run("creates collector with specified max results", func(t *testing.T) {
		collector := NewResultCollector(100)
		require.NotNil(t, collector)
		assert.Equal(t, 100, collector.maxResults)
		assert.Empty(t, collector.results)
		assert.False(t, collector.truncated)
	})

	t.Run("creates collector with zero max results", func(t *testing.T) {
		collector := NewResultCollector(0)
		require.NotNil(t, collector)
		assert.Equal(t, 0, collector.maxResults)
	})
}

func TestResultCollector_Print(t *testing.T) {
	ctx := context.Background()

	t.Run("collects single result", func(t *testing.T) {
		collector := NewResultCollector(10)

		result := createTestResult(detectorspb.DetectorType_AWS, true, "AKIAIOSFODNN7EXAMPLE", "AKIA****")
		err := collector.Print(ctx, result)

		require.NoError(t, err)
		results := collector.Results()
		assert.Len(t, results, 1)
		assert.Equal(t, "AWS", results[0].DetectorType)
		assert.True(t, results[0].Verified)
		assert.Equal(t, "AKIA****", results[0].Redacted)
	})

	t.Run("collects multiple results", func(t *testing.T) {
		collector := NewResultCollector(10)

		err := collector.Print(ctx, createTestResult(detectorspb.DetectorType_AWS, true, "secret1", "s***1"))
		require.NoError(t, err)
		err = collector.Print(ctx, createTestResult(detectorspb.DetectorType_Stripe, false, "secret2", "s***2"))
		require.NoError(t, err)

		results := collector.Results()
		assert.Len(t, results, 2)
		assert.Equal(t, "AWS", results[0].DetectorType)
		assert.Equal(t, "Stripe", results[1].DetectorType)
	})

	t.Run("truncates when max results reached", func(t *testing.T) {
		collector := NewResultCollector(2)

		err := collector.Print(ctx, createTestResult(detectorspb.DetectorType_AWS, true, "secret1", "s***1"))
		require.NoError(t, err)
		err = collector.Print(ctx, createTestResult(detectorspb.DetectorType_Stripe, true, "secret2", "s***2"))
		require.NoError(t, err)
		err = collector.Print(ctx, createTestResult(detectorspb.DetectorType_Azure, true, "secret3", "s***3"))
		require.NoError(t, err)

		results := collector.Results()
		assert.Len(t, results, 2)
		assert.True(t, collector.IsTruncated())
	})

	t.Run("handles verification error", func(t *testing.T) {
		collector := NewResultCollector(10)

		result := createTestResult(detectorspb.DetectorType_AWS, false, "secret", "s***")
		result.SetVerificationError(assert.AnError, "secret")
		err := collector.Print(ctx, result)

		require.NoError(t, err)
		results := collector.Results()
		assert.NotEmpty(t, results[0].VerificationError)
	})

	t.Run("handles extra data", func(t *testing.T) {
		collector := NewResultCollector(10)

		result := createTestResult(detectorspb.DetectorType_AWS, true, "secret", "s***")
		result.ExtraData = map[string]string{
			"account": "123456789",
			"region":  "us-east-1",
		}
		err := collector.Print(ctx, result)

		require.NoError(t, err)
		results := collector.Results()
		assert.Equal(t, "123456789", results[0].ExtraData["account"])
		assert.Equal(t, "us-east-1", results[0].ExtraData["region"])
	})
}

func TestResultCollector_Results(t *testing.T) {
	ctx := context.Background()

	t.Run("returns copy of results", func(t *testing.T) {
		collector := NewResultCollector(10)
		_ = collector.Print(ctx, createTestResult(detectorspb.DetectorType_AWS, true, "secret", "s***"))

		results1 := collector.Results()
		results2 := collector.Results()

		// Verify they are different slices
		assert.Equal(t, results1, results2)
		results1[0].DetectorType = "Modified"
		assert.NotEqual(t, results1[0].DetectorType, results2[0].DetectorType)
	})

	t.Run("returns empty slice when no results", func(t *testing.T) {
		collector := NewResultCollector(10)
		results := collector.Results()

		assert.NotNil(t, results)
		assert.Empty(t, results)
	})
}

func TestResultCollector_IsTruncated(t *testing.T) {
	ctx := context.Background()

	t.Run("returns false when not truncated", func(t *testing.T) {
		collector := NewResultCollector(10)
		_ = collector.Print(ctx, createTestResult(detectorspb.DetectorType_AWS, true, "secret", "s***"))

		assert.False(t, collector.IsTruncated())
	})

	t.Run("returns true when truncated", func(t *testing.T) {
		collector := NewResultCollector(1)
		_ = collector.Print(ctx, createTestResult(detectorspb.DetectorType_AWS, true, "secret1", "s***1"))
		_ = collector.Print(ctx, createTestResult(detectorspb.DetectorType_Stripe, true, "secret2", "s***2"))

		assert.True(t, collector.IsTruncated())
	})
}

func TestResultCollector_ThreadSafety(t *testing.T) {
	ctx := context.Background()
	collector := NewResultCollector(1000)

	// Run concurrent prints
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				_ = collector.Print(ctx, createTestResult(detectorspb.DetectorType_AWS, true, "secret", "s***"))
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	results := collector.Results()
	assert.Len(t, results, 100)
}

func TestConvertResult(t *testing.T) {
	t.Run("converts basic result", func(t *testing.T) {
		result := createTestResult(detectorspb.DetectorType_AWS, true, "AKIAIOSFODNN7EXAMPLE", "AKIA****")
		scanResult := ConvertResult(result)

		assert.Equal(t, "AWS", scanResult.DetectorType)
		assert.True(t, scanResult.Verified)
		assert.Equal(t, "AKIA****", scanResult.Redacted)
		assert.Equal(t, "PLAIN", scanResult.DecoderType)
	})

	t.Run("converts result with extra data", func(t *testing.T) {
		result := createTestResult(detectorspb.DetectorType_AWS, true, "secret", "s***")
		result.ExtraData = map[string]string{"key": "value"}
		scanResult := ConvertResult(result)

		assert.Equal(t, "value", scanResult.ExtraData["key"])
	})

	t.Run("converts result with source metadata", func(t *testing.T) {
		result := createTestResultWithMetadata(detectorspb.DetectorType_AWS, true, "secret", "s***", "test.go", 42)
		scanResult := ConvertResult(result)

		assert.NotNil(t, scanResult.SourceMetadata)
	})
}

// Helper function to create test results
func createTestResult(detectorType detectorspb.DetectorType, verified bool, raw, redacted string) *detectors.ResultWithMetadata {
	return &detectors.ResultWithMetadata{
		SourceType:  sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM,
		SourceName:  "test",
		DecoderType: detectorspb.DecoderType_PLAIN,
		Result: detectors.Result{
			DetectorType: detectorType,
			Verified:     verified,
			Raw:          []byte(raw),
			Redacted:     redacted,
		},
	}
}

func createTestResultWithMetadata(detectorType detectorspb.DetectorType, verified bool, raw, redacted, file string, line int64) *detectors.ResultWithMetadata {
	result := createTestResult(detectorType, verified, raw, redacted)
	result.SourceMetadata = &source_metadatapb.MetaData{
		Data: &source_metadatapb.MetaData_Filesystem{
			Filesystem: &source_metadatapb.Filesystem{
				File: file,
				Line: line,
			},
		},
	}
	return result
}
