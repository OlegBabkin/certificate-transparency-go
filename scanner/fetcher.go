// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scanner

import (
	"context"
	"net/http"
	"sync"
	"time"

	ct "github.com/OlegBabkin/certificate-transparency-go"
	"github.com/OlegBabkin/certificate-transparency-go/jsonclient"
	"github.com/google/trillian/client/backoff"
	"k8s.io/klog/v2"
)

// LogClient implements the subset of CT log API that the Fetcher uses.
type LogClient interface {
	BaseURI() string
	GetSTH(context.Context) (*ct.SignedTreeHead, error)
	GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error)
}

// FetcherOptions holds configuration options for the Fetcher.
type FetcherOptions struct {
	// Number of entries to request in one batch from the Log.
	BatchSize int

	// Number of concurrent fetcher workers to run.
	ParallelFetch int

	// [StartIndex, EndIndex) is a log entry range to fetch. If EndIndex == 0,
	// then it gets reassigned to sth.TreeSize.
	StartIndex int64
	EndIndex   int64

	// Continuous determines whether Fetcher should run indefinitely after
	// reaching EndIndex.
	Continuous bool
}

// DefaultFetcherOptions returns new FetcherOptions with sensible defaults.
func DefaultFetcherOptions() *FetcherOptions {
	return &FetcherOptions{
		BatchSize:     1000,
		ParallelFetch: 1,
		StartIndex:    0,
		EndIndex:      0,
		Continuous:    false,
	}
}

// Fetcher is a tool that fetches entries from a CT Log.
type Fetcher struct {
	// Base URI of the CT log, for diagnostics.
	uri string
	// Client used to talk to the CT log instance.
	client LogClient
	// Configuration options for this Fetcher instance.
	opts *FetcherOptions

	// Current STH of the Log this Fetcher sends queries to.
	sth *ct.SignedTreeHead
	// The STH retrieval backoff state. Used only in Continuous fetch mode.
	sthBackoff *backoff.Backoff

	// Stops range generator, which causes the Fetcher to terminate gracefully.
	mu     sync.Mutex
	cancel context.CancelFunc
}

// EntryBatch represents a contiguous range of entries of the Log.
type EntryBatch struct {
	Start   int64          // LeafIndex of the first entry in the range.
	Entries []ct.LeafEntry // Entries of the range.
}

// fetchRange represents a range of certs to fetch from a CT log.
type fetchRange struct {
	start int64 // inclusive
	end   int64 // inclusive
}

// NewFetcher creates a Fetcher instance using client to talk to the log,
// taking configuration options from opts.
func NewFetcher(client LogClient, opts *FetcherOptions) *Fetcher {
	cancel := func() {} // Protect against calling Stop before Run.
	return &Fetcher{
		uri:    client.BaseURI(),
		client: client,
		opts:   opts,
		cancel: cancel,
	}
}

// Prepare caches the latest Log's STH if not present and returns it. It also
// adjusts the entry range to fit the size of the tree.
func (f *Fetcher) Prepare(ctx context.Context) (*ct.SignedTreeHead, error) {
	if f.sth != nil {
		return f.sth, nil
	}

	sth, err := f.client.GetSTH(ctx)
	if err != nil {
		klog.Errorf("%s: GetSTH() failed: %v", f.uri, err)
		return nil, err
	}
	klog.V(1).Infof("%s: Got STH with %d certs", f.uri, sth.TreeSize)

	if size := int64(sth.TreeSize); f.opts.EndIndex == 0 || f.opts.EndIndex > size {
		klog.V(1).Infof("%s: Reset EndIndex from %d to %d", f.uri, f.opts.EndIndex, size)
		f.opts.EndIndex = size
	}
	f.sth = sth
	return sth, nil
}

// Run performs fetching of the Log. Blocks until scanning is complete, the
// passed in context is canceled, or Stop is called (and pending work is
// finished). For each successfully fetched batch, runs the fn callback.
func (f *Fetcher) Run(ctx context.Context, fn func(EntryBatch)) error {
	klog.V(1).Infof("%s: Starting up Fetcher...", f.uri)
	if _, err := f.Prepare(ctx); err != nil {
		return err
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	f.mu.Lock()
	f.cancel = cancel
	f.mu.Unlock()

	// Use a separately-cancelable context for the range generator, so we can
	// close it down (in Stop) but still let the fetchers below run to
	// completion.
	ranges := f.genRanges(cctx)

	// Run fetcher workers.
	var wg sync.WaitGroup
	for w, cnt := 0, f.opts.ParallelFetch; w < cnt; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			klog.V(1).Infof("%s: Fetcher worker %d starting...", f.uri, idx)
			f.runWorker(ctx, ranges, fn)
			klog.V(1).Infof("%s: Fetcher worker %d finished", f.uri, idx)
		}(w)
	}
	wg.Wait()

	klog.V(1).Infof("%s: Fetcher terminated", f.uri)
	return nil
}

// Stop causes the Fetcher to terminate gracefully. After this call Run will
// try to finish all the started fetches, and then return. Does nothing if
// there was no preceding Run invocation.
func (f *Fetcher) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancel()
}

// genRanges returns a channel of ranges to fetch, and starts a goroutine that
// sends things down this channel. The goroutine terminates when all ranges
// have been generated, or if context is cancelled.
func (f *Fetcher) genRanges(ctx context.Context) <-chan fetchRange {
	batch := int64(f.opts.BatchSize)
	ranges := make(chan fetchRange)

	go func() {
		klog.V(1).Infof("%s: Range generator starting", f.uri)
		defer klog.V(1).Infof("%s: Range generator finished", f.uri)
		defer close(ranges)
		start, end := f.opts.StartIndex, f.opts.EndIndex

		for start < end || f.opts.Continuous {
			// In continuous mode wait for bigger STH every time we reach the end,
			// including, possibly, the very first iteration.
			if start == end { // Implies f.opts.Continuous == true.
				if err := f.updateSTH(ctx); err != nil {
					klog.Warningf("%s: Failed to obtain bigger STH: %v", f.uri, err)
					return
				}
				end = f.opts.EndIndex
			}

			batchEnd := start + min(end-start, batch)
			next := fetchRange{start, batchEnd - 1}
			select {
			case <-ctx.Done():
				klog.Warningf("%s: Cancelling genRanges: %v", f.uri, ctx.Err())
				return
			case ranges <- next:
			}
			start = batchEnd
		}
	}()

	return ranges
}

// updateSTH waits until a bigger STH is discovered, and updates the Fetcher
// accordingly. It is optimized for both bulk-load (new STH is way bigger then
// the last one) and keep-up (STH grows slowly) modes of operation. Waits for
// some time until the STH grows enough to request a full batch, but falls back
// to *any* STH bigger than the old one if it takes too long.
// Returns error only if the context is cancelled.
func (f *Fetcher) updateSTH(ctx context.Context) error {
	// TODO(pavelkalinnikov): Make these parameters tunable.
	const quickDur = 45 * time.Second
	if f.sthBackoff == nil {
		f.sthBackoff = &backoff.Backoff{
			Min:    1 * time.Second,
			Max:    30 * time.Second,
			Factor: 2,
			Jitter: true,
		}
	}

	lastSize := uint64(f.opts.EndIndex)
	targetSize := lastSize + uint64(f.opts.BatchSize)
	quickDeadline := time.Now().Add(quickDur)

	return f.sthBackoff.Retry(ctx, func() error {
		sth, err := f.client.GetSTH(ctx)
		if err != nil {
			return backoff.RetriableErrorf("GetSTH: %v", err)
		}
		klog.V(2).Infof("%s: Got STH with %d certs", f.uri, sth.TreeSize)

		quick := time.Now().Before(quickDeadline)
		if sth.TreeSize <= lastSize || quick && sth.TreeSize < targetSize {
			return backoff.RetriableErrorf("wait for bigger STH than %d (last=%d, target=%d)", sth.TreeSize, lastSize, targetSize)
		}

		if quick {
			f.sthBackoff.Reset() // Growth is presumably fast, set next pause to Min.
		}
		f.sth = sth
		f.opts.EndIndex = int64(sth.TreeSize)
		return nil
	})
}

// runWorker is a worker function for handling fetcher ranges.
// Accepts cert ranges to fetch over the ranges channel, and if the fetch is
// successful sends the corresponding EntryBatch through the fn callback. Will
// retry failed attempts to retrieve ranges until the context is cancelled.
func (f *Fetcher) runWorker(ctx context.Context, ranges <-chan fetchRange, fn func(EntryBatch)) {
	for r := range ranges {
		// Logs MAY return fewer than the number of leaves requested. Only complete
		// if we actually got all the leaves we were expecting.
		for r.start <= r.end {
			if ctx.Err() != nil { // Prevent spinning when context is canceled.
				return
			}
			// TODO(pavelkalinnikov): Make these parameters tunable.
			// This backoff will only apply to a single request and be reset for the next one.
			// This precludes reaching some kind of stability in request rate, but means that
			// an intermittent problem won't harm long-term running of the worker.
			bo := &backoff.Backoff{
				Min:    1 * time.Second,
				Max:    30 * time.Second,
				Factor: 2,
				Jitter: true,
			}

			var resp *ct.GetEntriesResponse
			// TODO(pavelkalinnikov): Report errors in a LogClient decorator on failure.
			if err := bo.Retry(ctx, func() error {
				var err error
				resp, err = f.client.GetRawEntries(ctx, r.start, r.end)
				return err
			}); err != nil {
				if rspErr, isRspErr := err.(jsonclient.RspError); isRspErr && rspErr.StatusCode == http.StatusTooManyRequests {
					klog.V(2).Infof("%s: GetRawEntries() failed: %v", f.uri, err)
				} else {
					klog.Errorf("%s: GetRawEntries() failed: %v", f.uri, err)
				}
				// There is no error reporting yet for this worker, so just retry again.
				continue
			}
			fn(EntryBatch{Start: r.start, Entries: resp.Entries})
			r.start += int64(len(resp.Entries))
		}
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
