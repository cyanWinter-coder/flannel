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

package lease_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/flannel-io/flannel/pkg/lease"
)

func robustTestConfig(t *testing.T, now *time.Time, store lease.Store) lease.Config {
	t.Helper()
	if now.IsZero() {
		*now = time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	}
	return lease.Config{
		Prefixes:    []string{"10.244.0.0/24", "10.244.1.0/24", "10.244.2.0/24"},
		LeaseTTL:    time.Hour,
		GracePeriod: 10 * time.Minute,
		Store:       store,
		Now:         func() time.Time { return *now },
	}
}

func TestRobustAllocatorBindsPrefixToNodeAndDoesNotDuplicate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	a, err := lease.NewAllocator(robustTestConfig(t, &now, nil))
	if err != nil {
		t.Fatal(err)
	}

	first, err := a.Acquire(ctx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Acquire(ctx, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	if first.Prefix == second.Prefix {
		t.Fatalf("two nodes received same prefix %s", first.Prefix)
	}

	_, err = a.AcquirePrefix(ctx, "node-c", first.Prefix)
	if !errors.Is(err, lease.ErrPrefixOccupied) {
		t.Fatalf("expected ErrPrefixOccupied, got %v", err)
	}
	var occupied *lease.PrefixOccupiedError
	if !errors.As(err, &occupied) || occupied.Owner != "node-a" {
		t.Fatalf("expected owner node-a in occupied error, got %v", err)
	}
}

func TestRobustAllocatorSameNodeRepeatReturnsOriginal(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	a, err := lease.NewAllocator(robustTestConfig(t, &now, lease.NewMemoryStore()))
	if err != nil {
		t.Fatal(err)
	}

	first, err := a.Acquire(ctx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		got, err := a.Acquire(ctx, "node-a")
		if err != nil {
			t.Fatal(err)
		}
		if got.Prefix != first.Prefix {
			t.Fatalf("repeat acquire changed prefix: first=%s repeat=%s", first.Prefix, got.Prefix)
		}
		if got.NodeID != "node-a" {
			t.Fatalf("node binding changed: %q", got.NodeID)
		}
	}
}

func TestRobustAllocatorGracePeriodBlocksReclamation(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	now := base
	a, err := lease.NewAllocator(robustTestConfig(t, &now, nil))
	if err != nil {
		t.Fatal(err)
	}

	old, err := a.Acquire(ctx, "old-node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Expire(ctx, "old-node"); err != nil {
		t.Fatal(err)
	}

	// Immediately after expiration and halfway through grace the prefix is held.
	now = base.Add(5 * time.Minute)
	other, err := a.Acquire(ctx, "other-node")
	if err != nil {
		t.Fatal(err)
	}
	if other.Prefix == old.Prefix {
		t.Fatalf("expired prefix %s reallocated before grace elapsed", old.Prefix)
	}
	_, err = a.AcquirePrefix(ctx, "intruder", old.Prefix)
	if !errors.Is(err, lease.ErrPrefixOccupied) {
		t.Fatalf("grace period did not protect prefix, err=%v", err)
	}

	// The original node still receives its old lease during grace.
	returned, err := a.Acquire(ctx, "old-node")
	if err != nil {
		t.Fatal(err)
	}
	if returned.Prefix != old.Prefix {
		t.Fatalf("original node lost prefix during grace: got %s want %s", returned.Prefix, old.Prefix)
	}

	// The idempotent acquire renewed the lease at t+5m, so its new expiration
	// is t+65m and the renewed grace deadline is t+75m.
	now = base.Add(76 * time.Minute)
	reclaimed, err := a.ReclaimExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var oldReclaimable bool
	for _, rec := range reclaimed {
		if rec.Prefix == old.Prefix {
			oldReclaimable = true
		}
	}
	if !oldReclaimable {
		t.Fatalf("expected %s to be reclaimable, got %+v", old.Prefix, reclaimed)
	}
	newOwner, err := a.AcquirePrefix(ctx, "new-node", old.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if newOwner.Prefix != old.Prefix || newOwner.NodeID != "new-node" {
		t.Fatalf("prefix was not reassigned after grace: %+v", newOwner)
	}
}

func TestRobustAllocatorFilePersistenceRecoversNodeBinding(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	path := filepath.Join(t.TempDir(), "nested", "leases.json")
	store := lease.NewFileStore(path)

	first, err := lease.NewRecoveredAllocator(ctx, robustTestConfig(t, &now, store))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := first.AcquirePrefix(ctx, "stable-node", "10.244.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Persist(ctx); err != nil {
		t.Fatal(err)
	}

	// A fresh allocator simulates flanneld restart. Recovery must make the local
	// record win before any random scan.
	restarted, err := lease.NewRecoveredAllocator(ctx, robustTestConfig(t, &now, lease.NewFileStore(path)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Acquire(ctx, "stable-node")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != rec.Prefix {
		t.Fatalf("restart changed prefix: got %s want %s", got.Prefix, rec.Prefix)
	}
}

func TestRobustAllocatorRecoveryPrefersLocalPreferredPrefix(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := lease.NewMemoryStore()
	cfg := robustTestConfig(t, &now, store)

	a, err := lease.NewRecoveredAllocator(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AcquirePrefix(ctx, "node-a", "10.244.2.0/24"); err != nil {
		t.Fatal(err)
	}

	b, err := lease.NewAllocator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := b.AcquirePrefix(ctx, "node-a", "10.244.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != "10.244.2.0/24" {
		t.Fatalf("did not prioritize recovered prefix: %s", got.Prefix)
	}
}

type robustFlakyRenewer struct {
	mu        sync.Mutex
	failures  int
	calls     int
	failUntil int
}

func (r *robustFlakyRenewer) renew(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls <= r.failUntil {
		r.failures++
		return fmt.Errorf("storage unavailable attempt %d", r.calls)
	}
	return nil
}

func TestRobustRenewRetriesWithBackoffThenSucceeds(t *testing.T) {
	r := &robustFlakyRenewer{failUntil: 2}
	var delays []time.Duration
	cfg := lease.RetryConfig{
		MaxAttempts:    5,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		Multiplier:     2,
		OnRetry: func(attempt int, delay time.Duration, err error) {
			if err == nil {
				t.Error("retry callback got nil error")
			}
			delays = append(delays, delay)
		},
	}

	start := time.Now()
	err := lease.RenewWithRetry(context.Background(), cfg, r.renew)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected renewal to recover, got %v", err)
	}
	if r.calls != 3 {
		t.Fatalf("expected 3 calls, got %d", r.calls)
	}
	if len(delays) != 2 {
		t.Fatalf("expected 2 retry callbacks, got %d", len(delays))
	}
	if delays[1] < delays[0] {
		t.Fatalf("expected non-decreasing backoff, got %v", delays)
	}
	if elapsed > time.Second {
		t.Fatalf("test backoff took too long: %v", elapsed)
	}
}

func TestRobustRenewGivesUpAfterThresholdAndPreservesReason(t *testing.T) {
	rootErr := errors.New("etcd quorum lost")
	calls := 0
	var loggedReasons []string
	cfg := lease.RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
		OnRetry: func(attempt int, _ time.Duration, err error) {
			loggedReasons = append(loggedReasons, fmt.Sprintf("attempt %d: %v", attempt, err))
		},
	}

	err := lease.RenewWithRetry(context.Background(), cfg, func(context.Context) error {
		calls++
		return rootErr
	})
	if calls != 3 {
		t.Fatalf("expected threshold of 3 attempts, got %d", calls)
	}
	if !errors.Is(err, lease.ErrRetryExhausted) {
		t.Fatalf("expected ErrRetryExhausted, got %v", err)
	}
	if !errors.Is(err, rootErr) {
		t.Fatalf("expected final cause to be preserved, got %v", err)
	}
	var exhausted *lease.RetryExhaustedError
	if !errors.As(err, &exhausted) || exhausted.Attempts != 3 {
		t.Fatalf("expected typed exhaustion after 3 attempts, got %#v", err)
	}
	if len(loggedReasons) != 2 {
		t.Fatalf("expected retry reasons to be recorded, got %v", loggedReasons)
	}
}

func TestRobustAllocatorEnumeratesParentPrefix(t *testing.T) {
	now := time.Now()
	a, err := lease.NewAllocator(lease.Config{
		Parent:                "10.10.0.0/22",
		PrefixLength:          24,
		SkipFirstParentSubnet: true,
		LeaseTTL:              time.Hour,
		Now:                   func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := a.Acquire(context.Background(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Prefix != "10.10.1.0/24" {
		t.Fatalf("unexpected first enumerated prefix: %s", rec.Prefix)
	}
}

func TestRobustAllocatorStateFileAutoRecovers(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	stateFile := filepath.Join(t.TempDir(), "auto", "state.json")
	cfg := lease.Config{
		Prefixes:  []string{"192.168.0.0/24", "192.168.1.0/24"},
		LeaseTTL:  time.Hour,
		StateFile: stateFile,
		Now:       func() time.Time { return now },
	}
	first, err := lease.NewAllocator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := first.Acquire(ctx, "auto-node")
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := lease.NewAllocator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Acquire(ctx, "auto-node")
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != rec.Prefix {
		t.Fatalf("auto state recovery changed prefix: got %s want %s", got.Prefix, rec.Prefix)
	}
}

func TestRobustMemoryStoreZeroValue(t *testing.T) {
	ctx := context.Background()
	var store lease.MemoryStore
	if err := store.Save(ctx, []lease.Record{{NodeID: "n", Prefix: "10.0.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("unexpected load result: %d, %v", len(got), err)
	}
}

func TestRobustAllocatorConcurrentAcquisitionsAreUnique(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cfg := robustTestConfig(t, &now, nil)
	cfg.Prefixes = []string{
		"10.0.0.0/30", "10.0.0.4/30", "10.0.0.8/30", "10.0.0.12/30",
	}
	a, err := lease.NewAllocator(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	results := make(chan string, len(cfg.Prefixes))
	for i := range cfg.Prefixes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, err := a.Acquire(ctx, fmt.Sprintf("node-%d", i))
			if err != nil {
				t.Errorf("acquire node-%d: %v", i, err)
				return
			}
			results <- rec.Prefix
		}(i)
	}
	wg.Wait()
	close(results)

	seen := map[string]bool{}
	for p := range results {
		if seen[p] {
			t.Fatalf("prefix %s allocated twice", p)
		}
		seen[p] = true
	}
}
