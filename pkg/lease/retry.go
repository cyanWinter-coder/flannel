// Copyright 2026 flannel authors
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

package lease

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// RetryConfig configures bounded exponential-backoff renewal retries.
type RetryConfig struct {
	// MaxAttempts is the total number of calls, including the first attempt.
	// A value <= 0 is replaced by DefaultMaxAttempts.
	MaxAttempts int
	// InitialBackoff is the delay after the first failure.
	InitialBackoff time.Duration
	// MaxBackoff caps exponential growth.
	MaxBackoff time.Duration
	// Multiplier defaults to 2.
	Multiplier float64
	// JitterFraction, when positive, adds deterministic-random jitter in
	// [-JitterFraction*delay, +JitterFraction*delay]. It avoids synchronized
	// renewal storms from thousands of nodes.
	JitterFraction float64

	// OnRetry, when non-nil, is called before waiting for the next attempt. It
	// can be used to log or persist the reason.
	OnRetry func(attempt int, delay time.Duration, err error)
}

// BackoffConfig is an alias for callers that prefer this name.
type BackoffConfig = RetryConfig

const (
	DefaultMaxAttempts    = 8
	DefaultInitialBackoff = time.Second
	DefaultMaxBackoff     = time.Minute
)

// DefaultRetryConfig returns a bounded exponential-backoff policy suitable for
// transient storage/API outages.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:    DefaultMaxAttempts,
		InitialBackoff: DefaultInitialBackoff,
		MaxBackoff:     DefaultMaxBackoff,
		Multiplier:     2,
		JitterFraction: 0.1,
	}
}

// Normalize fills defaults and clamps invalid values.
func (c RetryConfig) Normalize() RetryConfig {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.InitialBackoff <= 0 {
		c.InitialBackoff = DefaultInitialBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = DefaultMaxBackoff
	}
	if c.MaxBackoff < c.InitialBackoff {
		c.MaxBackoff = c.InitialBackoff
	}
	if c.Multiplier <= 1 {
		c.Multiplier = 2
	}
	if c.JitterFraction < 0 {
		c.JitterFraction = 0
	}
	if c.JitterFraction > 0.5 {
		c.JitterFraction = 0.5
	}
	return c
}

// BackoffForAttempt returns the delay before attempt nextAttempt (2 for the
// first retry). Attempt numbers start at one for the initial try.
func (c RetryConfig) BackoffForAttempt(nextAttempt int) time.Duration {
	c = c.Normalize()
	if nextAttempt < 2 {
		return 0
	}
	failures := nextAttempt - 2
	delay := float64(c.InitialBackoff) * math.Pow(c.Multiplier, float64(failures))
	if delay > float64(c.MaxBackoff) || math.IsInf(delay, 1) {
		delay = float64(c.MaxBackoff)
	}
	if c.JitterFraction > 0 {
		// rand.Float64 is concurrency-safe for the global source. Jitter is not
		// used for correctness, only fleet desynchronization.
		delta := (rand.Float64()*2 - 1) * c.JitterFraction * delay
		delay += delta
		if delay < 0 {
			delay = 0
		}
	}
	return time.Duration(delay)
}

// RetryExhaustedError records the threshold and final reason.
type RetryExhaustedError struct {
	Attempts  int
	LastError error
}

func (e *RetryExhaustedError) Error() string {
	if e.LastError == nil {
		return fmt.Sprintf("%s after %d attempts", ErrRetryExhausted.Error(), e.Attempts)
	}
	return fmt.Sprintf("%s after %d attempts: %v", ErrRetryExhausted.Error(), e.Attempts, e.LastError)
}

func (e *RetryExhaustedError) Unwrap() error { return e.LastError }
func (e *RetryExhaustedError) Is(target error) bool {
	return target == ErrRetryExhausted
}

// RenewWithRetry invokes renew until it succeeds, the attempt threshold is
// reached, or ctx is cancelled. The returned RetryExhaustedError preserves the
// last storage error as its cause.
func RenewWithRetry(ctx context.Context, cfg RetryConfig, renew func(context.Context) error) error {
	if renew == nil {
		return fmt.Errorf("%w: nil renewal function", ErrInvalidConfig)
	}
	cfg = cfg.Normalize()

	var lastErr error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = renew(ctx)
		if lastErr == nil {
			return nil
		}

		if attempt == cfg.MaxAttempts {
			break
		}

		delay := cfg.BackoffForAttempt(attempt + 1)
		if cfg.OnRetry != nil {
			cfg.OnRetry(attempt, delay, lastErr)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}

	return &RetryExhaustedError{Attempts: cfg.MaxAttempts, LastError: lastErr}
}

// RetryRenew is a convenience alias with the argument order used by some
// callers.
func RetryRenew(ctx context.Context, renew func(context.Context) error, cfg RetryConfig) error {
	return RenewWithRetry(ctx, cfg, renew)
}

// RenewWithBackoff is an alias for RenewWithRetry.
func RenewWithBackoff(ctx context.Context, cfg RetryConfig, renew func(context.Context) error) error {
	return RenewWithRetry(ctx, cfg, renew)
}
