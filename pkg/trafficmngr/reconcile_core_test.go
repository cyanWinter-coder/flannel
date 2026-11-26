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

package trafficmngr_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tm "github.com/flannel-io/flannel/pkg/trafficmngr"
)

func h632Rule(table, chain string, spec ...string) tm.Rule {
	return tm.Rule{Family: tm.IPv4, Table: table, Chain: chain, Action: "-A", Rulespec: spec}
}

// h632FakeBackend is an in-memory rule store that applies Change plans exactly
// like a rule backend with duplicate copies would. It intentionally does not
// implement RuleSnapshotter so that the inverse-plan rollback path is tested.
type h632FakeBackend struct {
	mu     sync.Mutex
	rules  []tm.Rule
	failOn int // fail the nth ApplyChanges call (1-based); 0 = never
	calls  int
}

func (b *h632FakeBackend) ListRules(_ context.Context) ([]tm.Rule, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]tm.Rule, len(b.rules))
	copy(out, b.rules)
	return out, nil
}

func (b *h632FakeBackend) ApplyChanges(_ context.Context, changes []tm.Change) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	for _, c0 := range changes {
		c := c0
		if c.Count == 0 {
			c.Count = 1
		}
		switch c.Action {
		case tm.ActionAdd:
			for i := 0; i < c.Count; i++ {
				b.rules = append(b.rules, c.Rule)
			}
		case tm.ActionDelete:
			for n := 0; n < c.Count; n++ {
				idx := -1
				for i, r := range b.rules {
					if r.Key() == c.Rule.Key() {
						idx = i
						break
					}
				}
				if idx < 0 {
					return fmt.Errorf("delete of absent rule %s", c.Rule.Key())
				}
				b.rules = append(b.rules[:idx], b.rules[idx+1:]...)
			}
		case tm.ActionFlush:
			kept := b.rules[:0]
			for _, r := range b.rules {
				if r.Table != c.Rule.Table || r.Chain != c.Rule.Chain {
					kept = append(kept, r)
				}
			}
			b.rules = kept
		}
	}
	// Simulate a backend that applied (part of) the plan but reported failure.
	if b.failOn != 0 && b.failOn == b.calls {
		return errors.New("simulated apply failure")
	}
	return nil
}

// h632SnapBackend adds a real snapshot/restore implementation.
type h632SnapBackend struct {
	h632FakeBackend
	snapMu   sync.Mutex
	lastSnap []tm.Rule
}

func (b *h632SnapBackend) SnapshotRules(ctx context.Context) ([]byte, error) {
	b.snapMu.Lock()
	defer b.snapMu.Unlock()
	rules, _ := b.h632FakeBackend.ListRules(ctx)
	b.lastSnap = rules
	return []byte("snapshot"), nil
}

func (b *h632SnapBackend) RestoreRules(_ context.Context, _ []byte) error {
	b.snapMu.Lock()
	defer b.snapMu.Unlock()
	b.h632FakeBackend.mu.Lock()
	b.h632FakeBackend.rules = append([]tm.Rule(nil), b.lastSnap...)
	b.h632FakeBackend.mu.Unlock()
	return nil
}

func TestCompareMissingExtraAndUnchanged(t *testing.T) {
	want := []tm.Rule{
		h632Rule("nat", "POSTROUTING", "-j", "FLANNEL-POSTRTG"),
		h632Rule("nat", "FLANNEL-POSTRTG", "-j", "RETURN"),
	}
	actual := []tm.Rule{
		want[0],
		h632Rule("nat", "FLANNEL-POSTRTG", "-j", "OLD-RULE"),
	}
	d := tm.Compare(want, actual)
	if len(d.Missing) != 1 {
		t.Fatalf("expected 1 missing, got %d: %#v", len(d.Missing), d.Missing)
	}
	if d.Unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", d.Unchanged)
	}
	if len(d.Extra) != 1 || d.Extra[0].Count != 1 {
		t.Fatalf("expected 1 extra delete, got %#v", d.Extra)
	}
	if d.IsEmpty() {
		t.Fatal("diff should not be empty")
	}
}

func TestCompareFindsThousandsOfDuplicates(t *testing.T) {
	want := []tm.Rule{h632Rule("nat", "POSTROUTING", "-j", "FLANNEL-POSTRTG")}
	const copies = 5000
	actual := make([]tm.Rule, 0, copies)
	for i := 0; i < copies; i++ {
		actual = append(actual, want[0])
	}
	d := tm.Compare(want, actual)
	if d.Unchanged != 1 {
		t.Fatalf("one desired identity should be unchanged, got %d", d.Unchanged)
	}
	if d.DuplicateCount() != copies-1 {
		t.Fatalf("expected %d duplicate copies, got %d", copies-1, d.DuplicateCount())
	}
	if d.Deleted() != copies-1 {
		t.Fatalf("expected %d deletions, got %d", copies-1, d.Deleted())
	}
}

func TestReconcileIdempotentRemovesDuplicatesOnce(t *testing.T) {
	want := []tm.Rule{
		h632Rule("filter", "FORWARD", "-j", "FLANNEL-FWD"),
		h632Rule("filter", "FLANNEL-FWD", "-s", "10.0.0.0/16", "-j", "ACCEPT"),
	}
	// Node already has 1000 stacked copies of the parent jump.
	backend := &h632FakeBackend{}
	for i := 0; i < 1000; i++ {
		backend.rules = append(backend.rules, want[0])
	}

	cfg := tm.Config{RollbackOnFailure: true, VerifyAfterApply: true}
	res, err := tm.Reconcile(context.Background(), backend, want, cfg)
	if err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}
	if res.Deleted != 999 {
		t.Fatalf("first pass should delete 999 duplicate copies, got deleted=%d", res.Deleted)
	}
	if res.Added != 1 {
		t.Fatalf("first pass should add the missing in-chain rule, got added=%d", res.Added)
	}

	got, _ := backend.ListRules(context.Background())
	counts := map[string]int{}
	for _, r := range got {
		counts[r.Key()]++
	}
	for _, w := range want {
		if counts[w.Key()] != 1 {
			t.Fatalf("rule %s should exist exactly once, got %d", w.Key(), counts[w.Key()])
		}
	}

	// Repeated delivery must be a no-op with zero changes.
	res2, err := tm.Reconcile(context.Background(), backend, want, cfg)
	if err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}
	if res2.Changed() || res2.Added != 0 || res2.Deleted != 0 {
		t.Fatalf("second pass must be no-op, got added=%d deleted=%d changes=%v",
			res2.Added, res2.Deleted, res2.Changes)
	}
	if res2.Duration < 0 {
		t.Fatal("duration must not be negative")
	}
}

func TestReconcilerSerializesAndReportsMetrics(t *testing.T) {
	want := []tm.Rule{h632Rule("nat", "X", "-j", "Y")}
	backend := &h632FakeBackend{}
	r := tm.NewReconciler(backend, tm.Config{})
	r.Metrics = &tm.Metrics{}

	for i := 0; i < 5; i++ {
		if _, err := r.Reconcile(context.Background(), want); err != nil {
			t.Fatal(err)
		}
	}
	snap := r.Metrics.Snapshot()
	if snap.Reconciliations != 5 || snap.Successful != 5 {
		t.Fatalf("unexpected metrics: %+v", snap)
	}
	// First run adds one, next four are no-ops.
	if snap.RulesAdded != 1 {
		t.Fatalf("expected 1 total added, got %d", snap.RulesAdded)
	}
}

func TestDryRunDoesNotApplyButRendersDiff(t *testing.T) {
	want := []tm.Rule{h632Rule("nat", "POSTROUTING", "-j", "FLANNEL-POSTRTG")}
	backend := &h632FakeBackend{}
	res, err := tm.Reconcile(context.Background(), backend, want, tm.Config{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun {
		t.Fatal("result should be marked dry-run")
	}
	if res.Added != 1 {
		t.Fatalf("dry-run should report 1 would-be add, got %d", res.Added)
	}
	if res.Diff == "" || !strings.Contains(res.Diff, "+") {
		t.Fatalf("dry-run diff should contain an add line, got %q", res.Diff)
	}
	if backend.calls != 0 {
		t.Fatalf("dry-run must not call ApplyChanges, calls=%d", backend.calls)
	}
	got, _ := backend.ListRules(context.Background())
	if len(got) != 0 {
		t.Fatal("dry-run must not modify state")
	}

	// The dry-run report must clearly say dry-run in its summary.
	if !strings.Contains(res.Summary(), "dry-run") {
		t.Fatalf("summary should mention dry-run: %s", res.Summary())
	}
}

func TestApplyFailureRollsBackViaInversePlan(t *testing.T) {
	want := []tm.Rule{
		h632Rule("nat", "POSTROUTING", "-j", "FLANNEL-POSTRTG"),
		h632Rule("nat", "FLANNEL-POSTRTG", "-j", "RETURN"),
	}
	backend := &h632FakeBackend{failOn: 1}
	// pre-existing state: first desired rule present.
	backend.rules = []tm.Rule{want[0]}

	res, err := tm.Reconcile(context.Background(), backend, want, tm.Config{RollbackOnFailure: true})
	if err == nil {
		t.Fatal("expected apply error")
	}
	if res == nil {
		t.Fatal("result should be returned with error for observability")
	}
	if !res.RolledBack {
		t.Fatalf("expected successful inverse rollback, res=%s rollbackErr=%v", res, res.RollbackError)
	}
	got, _ := backend.ListRules(context.Background())
	if len(got) != 1 || got[0].Key() != want[0].Key() {
		t.Fatalf("state should be restored to the single pre-existing rule, got %#v", got)
	}
}

func TestApplyFailureRollsBackViaSnapshot(t *testing.T) {
	want := []tm.Rule{h632Rule("filter", "FLANNEL-FWD", "-j", "ACCEPT")}
	backend := &h632SnapBackend{}
	// Make the first ApplyChanges call fail after mutating.
	backend.failOn = 1
	original := []tm.Rule{h632Rule("filter", "FLANNEL-FWD", "-j", "ORIGINAL")}
	backend.rules = append([]tm.Rule(nil), original...)

	res, err := tm.Reconcile(context.Background(), backend, want, tm.Config{RollbackOnFailure: true})
	if err == nil {
		t.Fatal("expected apply error")
	}
	if !res.RolledBack || res.RollbackFailed {
		t.Fatalf("expected snapshot rollback, rolledBack=%v failed=%v err=%v",
			res.RolledBack, res.RollbackFailed, res.RollbackError)
	}
	got, _ := backend.ListRules(context.Background())
	if len(got) != 1 || got[0].Key() != original[0].Key() {
		t.Fatalf("snapshot state should be restored, got %#v", got)
	}
}

func TestRollbackDisabledReturnsErrorWithoutRestore(t *testing.T) {
	want := []tm.Rule{h632Rule("nat", "X", "-j", "Y")}
	backend := &h632FakeBackend{failOn: 1}
	res, err := tm.Reconcile(context.Background(), backend, want, tm.Config{RollbackOnFailure: false})
	if err == nil {
		t.Fatal("expected error")
	}
	if res.RolledBack {
		t.Fatal("must not roll back when disabled")
	}
}

func TestOrderedPlanFlushesScrambledChain(t *testing.T) {
	d1 := h632Rule("filter", "FLANNEL-FWD", "-s", "a", "-j", "ACCEPT")
	d2 := h632Rule("filter", "FLANNEL-FWD", "-d", "b", "-j", "ACCEPT")

	if plan := tm.OrderedPlan([]tm.Rule{d1, d2}, []tm.Rule{d1, d2}); plan != nil {
		t.Fatalf("identical ordered slices need no plan, got %#v", plan)
	}
	// Reversed order must trigger flush + both adds.
	plan := tm.OrderedPlan([]tm.Rule{d1, d2}, []tm.Rule{d2, d1})
	if len(plan) != 3 {
		t.Fatalf("expected flush + 2 adds, got %d changes: %#v", len(plan), plan)
	}
	if plan[0].Action != tm.ActionFlush {
		t.Fatalf("first change must be flush, got %s", plan[0].Action)
	}
	if plan[1].Action != tm.ActionAdd || plan[2].Action != tm.ActionAdd {
		t.Fatalf("then ordered adds, got %#v", plan[1:])
	}

	// Duplicates also make the ordered comparison fail.
	plan = tm.OrderedPlan([]tm.Rule{d1}, []tm.Rule{d1, d1, d1})
	if len(plan) != 2 || plan[0].Action != tm.ActionFlush {
		t.Fatalf("duplicates should trigger flush+add, got %#v", plan)
	}
}

func TestInverseReversesAddsAndDeletes(t *testing.T) {
	r := h632Rule("nat", "X", "-j", "Y")
	changes := []tm.Change{
		tm.NewDeleteChange(r, 3, "duplicate"),
		tm.NewAddChange(r),
	}
	inv := tm.Inverse(changes)
	// reverse order: add-of-original becomes delete first...
	if inv[0].Action != tm.ActionDelete {
		t.Fatalf("inverse[0] should delete the added rule, got %s", inv[0].Action)
	}
	if inv[1].Action != tm.ActionAdd || inv[1].Count != 3 {
		t.Fatalf("inverse[1] should re-add 3 copies, got %#v", inv[1])
	}
}

func TestExecuteRecordsWallClockDuration(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	backend := &h632FakeBackend{}
	plan := tm.Plan{
		Changes: []tm.Change{tm.NewAddChange(h632Rule("nat", "X", "-j", "Y"))},
		Added:   1,
	}
	res, err := tm.Execute(context.Background(), backend, plan, tm.Config{Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	if res.Duration != time.Second {
		t.Fatalf("expected 1s fake duration, got %s", res.Duration)
	}
	if res.Elapsed != res.Duration {
		t.Fatal("Elapsed alias must equal Duration")
	}
}

type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time {
	c.t = c.t.Add(time.Second)
	return c.t
}
