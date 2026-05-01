package payment

import (
	"context"
	"crypto/rsa"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bmailag/bmail/internal/crypto"
)

// SigningBatcher queues blind-signing requests and processes them in batches
// on a fixed interval. This breaks timing correlation between payment
// verification and token issuance — an observer cannot match a payment event
// to the exact moment a signature is produced.
type SigningBatcher struct {
	keys     map[string]*rsa.PrivateKey
	interval time.Duration
	maxBatch int
	queue    chan *signJob
	done     chan struct{}
	once     sync.Once
}

type signJob struct {
	ctx          context.Context
	blindedToken *big.Int
	tier         string
	result       chan signResult
}

type signResult struct {
	signature *big.Int
	err       error
}

// BatcherOption configures optional parameters on SigningBatcher.
type BatcherOption func(*SigningBatcher)

// WithMaxBatch sets the maximum number of requests processed per tick.
// Default is 100.
func WithMaxBatch(n int) BatcherOption {
	return func(b *SigningBatcher) {
		if n > 0 {
			b.maxBatch = n
		}
	}
}

// WithQueueSize sets the channel buffer size for pending sign requests.
// Default is 1000.
func WithQueueSize(n int) BatcherOption {
	return func(b *SigningBatcher) {
		if n > 0 {
			b.queue = make(chan *signJob, n)
		}
	}
}

// NewSigningBatcher creates a batcher that signs queued blinded tokens every
// interval using the provided per-tier RSA keys.
func NewSigningBatcher(keys map[string]*rsa.PrivateKey, interval time.Duration, opts ...BatcherOption) *SigningBatcher {
	b := &SigningBatcher{
		keys:     keys,
		interval: interval,
		maxBatch: 100,
		queue:    make(chan *signJob, 1000),
		done:     make(chan struct{}),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Start launches the background goroutine that processes batches.
func (b *SigningBatcher) Start() {
	go b.run()
}

// Stop signals the batcher goroutine to exit and waits for it to finish
// draining any remaining jobs.
func (b *SigningBatcher) Stop() {
	b.once.Do(func() {
		close(b.done)
	})
}

// Submit enqueues a blind-signing request and blocks until the batch
// containing it is processed. Returns the blind signature or an error.
// The caller's context is respected — if it is cancelled before the batch
// fires, Submit returns the context error.
func (b *SigningBatcher) Submit(ctx context.Context, blindedToken *big.Int, tier string) (*big.Int, error) {
	job := &signJob{
		ctx:          ctx,
		blindedToken: blindedToken,
		tier:         tier,
		result:       make(chan signResult, 1),
	}

	select {
	case b.queue <- job:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.done:
		return nil, fmt.Errorf("batcher stopped")
	}

	select {
	case res := <-job.result:
		return res.signature, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.done:
		return nil, fmt.Errorf("batcher stopped")
	}
}

func (b *SigningBatcher) run() {
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.processBatch()
		case <-b.done:
			// Drain any remaining jobs before exiting.
			b.processBatch()
			return
		}
	}
}

func (b *SigningBatcher) processBatch() {
	batch := b.drain()
	if len(batch) == 0 {
		return
	}

	for _, job := range batch {
		// Skip jobs whose caller has already cancelled.
		if job.ctx.Err() != nil {
			job.result <- signResult{err: job.ctx.Err()}
			continue
		}
		key, ok := b.keys[job.tier]
		if !ok {
			job.result <- signResult{err: fmt.Errorf("no signing key for tier %q", job.tier)}
			continue
		}
		sig, err := crypto.SignBlinded(job.blindedToken, key)
		job.result <- signResult{signature: sig, err: err}
	}
}

// drain pulls up to maxBatch jobs from the queue without blocking.
func (b *SigningBatcher) drain() []*signJob {
	var batch []*signJob
	for len(batch) < b.maxBatch {
		select {
		case job := <-b.queue:
			batch = append(batch, job)
		default:
			return batch
		}
	}
	return batch
}
