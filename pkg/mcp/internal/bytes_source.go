package internal

import (
	"bytes"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// BytesSource is a simple source that scans in-memory bytes.
type BytesSource struct {
	name     string
	data     []byte
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure BytesSource implements the required interfaces.
var _ sources.Source = (*BytesSource)(nil)
var _ sources.SourceUnitEnumChunker = (*BytesSource)(nil)

// NewBytesSource creates a new BytesSource with the given data.
func NewBytesSource(name string, data []byte, verify bool) *BytesSource {
	return &BytesSource{
		name:   name,
		data:   data,
		verify: verify,
	}
}

// Type returns the source type.
func (s *BytesSource) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_STDIN
}

// SourceID returns the source ID.
func (s *BytesSource) SourceID() sources.SourceID {
	return s.sourceId
}

// JobID returns the job ID.
func (s *BytesSource) JobID() sources.JobID {
	return s.jobId
}

// Init initializes the source.
func (s *BytesSource) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, _ *anypb.Any, _ int) error {
	s.name = name
	s.jobId = jobId
	s.sourceId = sourceId
	s.verify = verify
	return nil
}

// Chunks emits the data as chunks.
func (s *BytesSource) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	chunkSkel := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Stdin{},
		},
		Verify: s.verify,
	}

	reader := bytes.NewReader(s.data)
	return handlers.HandleFile(ctx, reader, chunkSkel, sources.ChanReporter{Ch: chunksChan})
}

// Enumerate reports a single unit for this source.
func (s *BytesSource) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	unit := sources.CommonSourceUnit{ID: "<bytes>"}
	return reporter.UnitOk(ctx, unit)
}

// ChunkUnit chunks a single unit.
func (s *BytesSource) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	ch := make(chan *sources.Chunk)
	go func() {
		defer close(ch)
		_ = s.Chunks(ctx, ch)
	}()
	for chunk := range ch {
		if chunk != nil {
			if err := reporter.ChunkOk(ctx, *chunk); err != nil {
				return err
			}
		}
	}
	return nil
}
