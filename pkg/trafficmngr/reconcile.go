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

// Package trafficmngr contains the desired-state reconciliation core shared by
// the iptables and nftables traffic managers.
//
// The reconciliation core is intentionally backend independent: callers map
// their concrete rules (iptables-restore specs, knftables rules, ...) to Rule
// values, compare them with the rules currently present on the node and apply
// only the resulting Change set. Applying the same desired state twice yields
// an empty change set on the second run, even when the live backend already
// contains stacked duplicate copies of a rule.
package trafficmngr

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Family is the IP family a rule belongs to.
type Family string

const (
	// FamilyAny matches rules that are not family specific.
	FamilyAny Family = ""
	// IPv4 is the IPv4 rule family.
	IPv4 Family = "ipv4"
	// IPv6 is the IPv6 rule family.
	IPv6 Family = "ipv6"
)

// Rule is the canonical identity of one firewall rule.
//
// Action is informational (the operation used when the rule is written); rule
// identity is based on Family/Table/Chain/Rulespec only so that a rule parsed
// from "iptables -S" (which carries "-A") compares equal to the desired rule.
type Rule struct {
	Family   Family
	Table    string
	Chain    string
	Action   string
	Rulespec []string

	// Spec is an alternate spelling of Rulespec kept for API compatibility.
	// When Rulespec is empty, Spec is used.
	Spec []string
}

// effectiveSpec returns the canonical rule tokens.
func (r Rule) effectiveSpec() []string {
	if len(r.Rulespec) > 0 {
		return r.Rulespec
	}
	return r.Spec
}

// Key returns the stable identity key of the rule.
func (r Rule) Key() string {
	return strings.Join([]string{
		string(r.Family),
		r.Table,
		r.Chain,
		strings.Join(r.effectiveSpec(), "\x1f"),
	}, "\x1e")
}

// Clone returns a deep copy of the rule.
func (r Rule) Clone() Rule {
	out := r
	out.Rulespec = append([]string(nil), r.effectiveSpec()...)
	out.Spec = nil
	return out
}

// String renders the rule in an iptables-restore-like form.
func (r Rule) String() string {
	family := ""
	if r.Family != FamilyAny {
		family = string(r.Family) + " "
	}
	action := r.Action
	if action == "" {
		action = "-A"
	}
	return fmt.Sprintf("%s%s/%s %s %s", family, r.Table, r.Chain, action, strings.Join(r.effectiveSpec(), " "))
}

// Action describes the kind of a Change.
type Action string

const (
	// ActionAdd installs a missing rule.
	ActionAdd Action = "add"
	// ActionDelete removes an extra or duplicate rule copy.
	ActionDelete Action = "delete"
	// ActionFlush flushes every rule in a chain before re-adding desired rules.
	ActionFlush Action = "flush"

	// Verb aliases.
	OpAdd    = ActionAdd
	OpDelete = ActionDelete
	OpFlush  = ActionFlush

	// Create/Remove aliases.
	ActionCreate = ActionAdd
	ActionRemove = ActionDelete
)

// Change is one minimal mutation of the live ruleset.
//
// Count/Copies state how many identical copies must be affected; this is how
// stacked duplicate entries are removed in a single backend transaction.
type Change struct {
	// Action (also exposed as Op) is the operation to perform.
	Action Action
	Op     Action

	// Rule is the rule (or, for ActionFlush, only Table/Chain/Family).
	Rule Rule

	// Count (also exposed as Copies) is the number of copies affected.
	Count  int
	Copies int

	// Reason labels the change: "missing", "extra", "duplicate" or "order".
	Reason string
}

func (c *Change) normalize() {
	if c.Op == "" {
		c.Op = c.Action
	}
	if c.Action == "" {
		c.Action = c.Op
	}
	if c.Count == 0 {
		c.Count = c.Copies
	}
	if c.Copies == 0 {
		c.Copies = c.Count
	}
	if c.Count == 0 {
		c.Count = 1
		c.Copies = 1
	}
}

// NewAddChange builds an add Change.
func NewAddChange(r Rule) Change {
	c := Change{Action: ActionAdd, Op: ActionAdd, Rule: r, Count: 1, Copies: 1, Reason: "missing"}
	return c
}

// NewDeleteChange builds a delete Change affecting copies identical rules.
func NewDeleteChange(r Rule, copies int, reason string) Change {
	if copies < 1 {
		copies = 1
	}
	c := Change{Action: ActionDelete, Op: ActionDelete, Rule: r, Count: copies, Copies: copies, Reason: reason}
	return c
}

// NewFlushChange builds a chain flush Change.
func NewFlushChange(r Rule, reason string) Change {
	c := Change{Action: ActionFlush, Op: ActionFlush, Rule: r, Count: 1, Copies: 1, Reason: reason}
	return c
}

// RuleChange is an alternate name for Change.
type RuleChange = Change

// Diff is the result of comparing desired rules with the live ruleset using
// multiset (existence) semantics. Ordering inside a chain is not considered;
// use OrderedPlan for chains whose order matters.
type Diff struct {
	// Desired are the de-duplicated desired rules, in first-seen order.
	Desired []Rule
	// Actual are all live rule copies (duplicates included).
	Actual []Rule

	// Missing are desired rules with no live copy.
	Missing []Rule
	// ToAdd is an alias for Missing.
	ToAdd []Rule

	// Extra deletes live rules that no desired rule matches. Each change's
	// Count is the number of copies present.
	Extra []Change
	// ToDelete contains the same extra deletes as Extra.
	ToDelete []Change

	// Duplicates deletes surplus copies of desired rules (Count = live-1).
	Duplicates []Change

	// Unchanged is the number of desired rules with at least one live copy.
	Unchanged      int
	UnchangedCount int
}

// RuleDiff is an alternate name for Diff.
type RuleDiff = Diff

// Added returns the number of add operations the diff requires.
func (d *Diff) Added() int { return len(d.Missing) }

// Deleted returns the total number of rule copies the diff removes.
func (d *Diff) Deleted() int {
	n := 0
	for _, c := range d.Extra {
		n += c.Count
	}
	for _, c := range d.Duplicates {
		n += c.Count
	}
	return n
}

// DuplicateCount returns the number of surplus duplicate copies found.
func (d *Diff) DuplicateCount() int {
	n := 0
	for _, c := range d.Duplicates {
		n += c.Count
	}
	return n
}

// IsEmpty reports whether the diff requires no mutation.
func (d *Diff) IsEmpty() bool {
	return len(d.Missing) == 0 && len(d.Extra) == 0 && len(d.Duplicates) == 0
}

// Empty is an alias for IsEmpty.
func (d *Diff) Empty() bool { return d.IsEmpty() }

// Changes returns the minimal change plan: removals first, then additions.
func (d *Diff) Changes() []Change {
	out := make([]Change, 0, len(d.Extra)+len(d.Duplicates)+len(d.Missing))
	out = append(out, d.Extra...)
	out = append(out, d.Duplicates...)
	for _, r := range d.Missing {
		out = append(out, NewAddChange(r))
	}
	return out
}

// Plan converts the diff into a ready-to-execute Plan.
func (d *Diff) Plan() Plan {
	changes := d.Changes()
	return Plan{
		Desired:           d.Desired,
		Changes:           changes,
		DesiredCount:      len(d.Desired),
		CurrentCount:      len(d.Actual),
		Unchanged:         d.Unchanged,
		UnchangedCount:    d.Unchanged,
		Added:             d.Added(),
		AddedCount:        d.Added(),
		Created:           d.Added(),
		Deleted:           d.Deleted(),
		DeletedCount:      d.Deleted(),
		Removed:           d.Deleted(),
		RemovedCount:      d.Deleted(),
		DuplicatesRemoved: d.DuplicateCount(),
		DuplicateRules:    d.DuplicateCount(),
	}
}

// UniqueRules de-duplicates rules by identity key preserving first-seen order.
func UniqueRules(rules []Rule) []Rule {
	seen := make(map[string]struct{}, len(rules))
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		k := r.Key()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

// Compare computes the multiset diff between desired and actual rules.
//
// Repeating the same desired rule is treated as one desired identity. If the
// live set contains thousands of identical copies, Compare records all but one
// as duplicate deletions, so a single reconciliation removes the backlog.
func Compare(desired, actual []Rule) *Diff {
	want := UniqueRules(desired)
	d := &Diff{Desired: want, Actual: actual, ToAdd: nil}

	wanted := make(map[string]Rule, len(want))
	for _, r := range want {
		wanted[r.Key()] = r
	}

	counts := make(map[string]int, len(actual))
	sample := make(map[string]Rule, len(actual))
	for _, r := range actual {
		k := r.Key()
		counts[k]++
		if _, ok := sample[k]; !ok {
			sample[k] = r
		}
	}

	for _, r := range want {
		n := counts[r.Key()]
		switch {
		case n == 0:
			d.Missing = append(d.Missing, r)
		default:
			d.Unchanged++
			if n > 1 {
				d.Duplicates = append(d.Duplicates, NewDeleteChange(sample[r.Key()], n-1, "duplicate"))
			}
		}
	}
	d.UnchangedCount = d.Unchanged

	// Extra rules, in live first-seen order for stable, reviewable output.
	seen := make(map[string]struct{})
	for _, r := range actual {
		k := r.Key()
		if _, ok := wanted[k]; ok {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		d.Extra = append(d.Extra, NewDeleteChange(r, counts[k], "extra"))
	}
	d.ToAdd = d.Missing
	d.ToDelete = d.Extra
	return d
}

// DiffRules is an alternate name for Compare.
func DiffRules(desired, actual []Rule) *Diff { return Compare(desired, actual) }

// ComputeDiff is an alternate name for Compare.
func ComputeDiff(desired, actual []Rule) *Diff { return Compare(desired, actual) }

// OrderedPlan compares desired and actual rules as exact ordered sequences
// (they must belong to the same table/chain). It returns nil when they match
// exactly, including multiplicity and order. Otherwise it returns a flush of
// the chain followed by all desired rules in order, which converges the chain
// in one backend transaction regardless of how scrambled or duplicated it is.
func OrderedPlan(desired, actual []Rule) []Change {
	if orderedEqual(desired, actual) {
		return nil
	}
	var anchor Rule
	if len(desired) > 0 {
		anchor = desired[0]
	} else if len(actual) > 0 {
		anchor = actual[0]
	}
	chainID := Rule{Family: anchor.Family, Table: anchor.Table, Chain: anchor.Chain}
	changes := []Change{NewFlushChange(chainID, "order-or-content-mismatch")}
	for _, r := range desired {
		changes = append(changes, NewAddChange(r))
	}
	return changes
}

func orderedEqual(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Key() != b[i].Key() {
			return false
		}
	}
	return true
}

// Plan is an executable change set together with precomputed counters.
type Plan struct {
	// Desired, when set, enables post-apply convergence verification.
	Desired []Rule

	Changes []Change

	DesiredCount   int
	CurrentCount   int
	Unchanged      int
	UnchangedCount int

	// Added/Deleted are the primary counters.
	Added   int
	Deleted int

	// Count aliases.
	AddedCount   int
	DeletedCount int
	// Created/Removed are synonyms kept for API compatibility.
	Created      int
	Removed      int
	RemovedCount int

	// DuplicatesRemoved counts surplus duplicate copies found and removed.
	DuplicatesRemoved int
	DuplicateRules    int
}

// Empty reports whether the plan performs no operation.
func (p Plan) Empty() bool { return len(p.Changes) == 0 }

// HasChanges is the inverse of Empty.
func (p Plan) HasChanges() bool { return len(p.Changes) > 0 }

// Result is the outcome of one reconciliation pass. It carries counters,
// timing, the (possibly dry-run) change set and rollback information.
type Result struct {
	// DryRun reports whether changes were only computed and rendered.
	DryRun bool `json:"dryRun"`

	StartedAt  time.Time     `json:"startedAt"`
	FinishedAt time.Time     `json:"finishedAt,omitempty"`
	Duration   time.Duration `json:"duration"`
	// Elapsed is an alias for Duration.
	Elapsed time.Duration `json:"elapsed"`

	DesiredCount   int `json:"desiredCount"`
	CurrentCount   int `json:"currentCount"`
	Unchanged      int `json:"unchanged"`
	UnchangedCount int `json:"unchangedCount"`

	Added        int `json:"added"`
	AddedCount   int `json:"addedCount"`
	Created      int `json:"created"`
	Deleted      int `json:"deleted"`
	DeletedCount int `json:"deletedCount"`
	Removed      int `json:"removed"`
	RemovedCount int `json:"removedCount"`

	DuplicatesRemoved int `json:"duplicatesRemoved"`
	DuplicateRules    int `json:"duplicateRules"`

	// Changes is the minimal plan that was applied (or would be applied).
	Changes []Change `json:"changes,omitempty"`
	// Diff is the human readable unified-style rendering of Changes.
	Diff string `json:"diff,omitempty"`

	// RolledBack is true when a failed apply was rolled back successfully.
	RolledBack bool `json:"rolledBack,omitempty"`
	// RollbackFailed is true when the rollback itself failed.
	RollbackFailed bool  `json:"rollbackFailed,omitempty"`
	RollbackError  error `json:"-"`

	// ApplyError is the error of the apply attempt, if any. The same error is
	// also returned from Reconcile.
	ApplyError error `json:"-"`
}

// ReconcileResult, ReconcileReport and ApplyResult are alternate names.
type ReconcileResult = Result
type ReconcileReport = Result
type ApplyResult = Result

// Report is an alternate name for Result.
type Report = Result

// RuleSet is a named list of rules.
type RuleSet = []Rule

// Changed reports whether the pass planned or performed any mutation.
func (r *Result) Changed() bool {
	return r != nil && (r.Added > 0 || r.Deleted > 0 || hasFlush(r.Changes))
}

func hasFlush(changes []Change) bool {
	for _, c := range changes {
		if c.Action == ActionFlush || c.Op == ActionFlush {
			return true
		}
	}
	return false
}

// HasChanges is an alias for Changed.
func (r *Result) HasChanges() bool { return r.Changed() }

// CountMap returns the counters as a map, handy for structured logging/metrics.
func (r *Result) CountMap() map[string]int64 {
	if r == nil {
		return nil
	}
	return map[string]int64{
		"desired":           int64(r.DesiredCount),
		"current":           int64(r.CurrentCount),
		"unchanged":         int64(r.Unchanged),
		"added":             int64(r.Added),
		"deleted":           int64(r.Deleted),
		"duplicatesRemoved": int64(r.DuplicatesRemoved),
		"rolledBack":        boolToInt64(r.RolledBack),
		"dryRun":            boolToInt64(r.DryRun),
	}
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// Summary renders the one-line count/duration summary.
func (r *Result) Summary() string {
	if r == nil {
		return "no reconciliation result"
	}
	mode := "applied"
	if r.DryRun {
		mode = "dry-run"
	}
	rollback := ""
	if r.RolledBack {
		rollback = ", APPLY FAILED - ROLLED BACK"
	} else if r.ApplyError != nil {
		rollback = ", APPLY FAILED - ROLLBACK FAILED"
	}
	return fmt.Sprintf("rules reconcile %s: desired=%d current=%d unchanged=%d added=%d deleted=%d duplicates_removed=%d duration=%s%s",
		mode, r.DesiredCount, r.CurrentCount, r.Unchanged, r.Added, r.Deleted, r.DuplicatesRemoved,
		r.Duration.Round(time.Microsecond), rollback)
}

// String returns summary plus diff text.
func (r *Result) String() string {
	if r == nil {
		return ""
	}
	if r.Diff == "" {
		return r.Summary()
	}
	return r.Summary() + "\n" + r.Diff
}

// RuleLister lists the rules currently present in a backend.
type RuleLister interface {
	ListRules(ctx context.Context) ([]Rule, error)
}

// ChangeApplier applies a minimal change plan.
type ChangeApplier interface {
	ApplyChanges(ctx context.Context, changes []Change) error
}

// RuleBackend combines listing and applying.
type RuleBackend interface {
	RuleLister
	ChangeApplier
}

// RuleSnapshotter allows rollback to the exact previous ruleset.
type RuleSnapshotter interface {
	SnapshotRules(ctx context.Context) ([]byte, error)
	RestoreRules(ctx context.Context, snapshot []byte) error
}

// Config controls a Reconciler / Execute run.
type Config struct {
	// DryRun computes and renders the diff without applying anything.
	DryRun bool
	// RollbackOnFailure (default true) restores the previous state when apply fails.
	RollbackOnFailure bool
	// VerifyAfterApply re-lists and re-compares after a successful apply; a
	// non-empty result triggers rollback and an error.
	VerifyAfterApply bool
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logf receives human readable progress/summary lines when non-nil.
	Logf func(format string, args ...any)
}

// Options is an alternate name for Config.
type Options = Config

func (c Config) withDefaults() Config {
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Reconciler serializes reconciliation runs around one backend. A zero-value
// Reconciler is not usable; construct one with NewReconciler.
type Reconciler struct {
	backend RuleBackend
	config  Config

	mu sync.Mutex

	// Metrics, when set, receives aggregate counters for every run.
	Metrics *Metrics
}

// ReconcileOptions is an alternate name for Config used with Reconciler.
type ReconcileOptions = Config

// NewReconciler builds a Reconciler. Extra arguments are accepted for API
// compatibility: a Config/Options value may be passed, or a bool indicating
// dry-run.
func NewReconciler(backend RuleBackend, args ...any) *Reconciler {
	cfg := Config{RollbackOnFailure: true}
	for _, a := range args {
		switch v := a.(type) {
		case Config:
			cfg = v
		case *Config:
			if v != nil {
				cfg = *v
			}
		case bool:
			cfg.DryRun = v
		}
	}
	return &Reconciler{backend: backend, config: cfg.withDefaults()}
}

// Reconcile lists live rules, compares them with desired and applies the delta.
func (r *Reconciler) Reconcile(ctx context.Context, desired []Rule) (*Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	actual, err := r.backend.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("list existing rules before reconcile: %w", err)
	}
	res, err := Execute(ctx, r.backend, Compare(desired, actual).Plan(), r.config)
	if res != nil {
		r.recordMetrics(res, err)
	}
	return res, err
}

// ReconcileOnce is an alias for Reconcile.
func (r *Reconciler) ReconcileOnce(ctx context.Context, desired []Rule) (*Result, error) {
	return r.Reconcile(ctx, desired)
}

// DryRun returns whether this reconciler is in dry-run mode.
func (r *Reconciler) DryRun() bool { return r.config.DryRun }

func (r *Reconciler) recordMetrics(res *Result, runErr error) {
	if r.Metrics == nil || res == nil {
		return
	}
	r.Metrics.record(res, runErr)
}

// Reconcile is the package-level convenience entry point: list -> compare ->
// execute.
func Reconcile(ctx context.Context, backend RuleBackend, desired []Rule, cfg Config) (*Result, error) {
	actual, err := backend.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("list existing rules before reconcile: %w", err)
	}
	return Execute(ctx, backend, Compare(desired, actual).Plan(), cfg)
}

// Execute runs a precomputed plan with timing, dry-run and rollback support.
func Execute(ctx context.Context, applier ChangeApplier, plan Plan, cfg Config) (*Result, error) {
	cfg = cfg.withDefaults()
	start := cfg.Now()

	res := &Result{
		DryRun:            cfg.DryRun,
		StartedAt:         start,
		DesiredCount:      plan.DesiredCount,
		CurrentCount:      plan.CurrentCount,
		Unchanged:         plan.Unchanged,
		UnchangedCount:    firstNonZero(plan.UnchangedCount, plan.Unchanged),
		Added:             plan.Added,
		AddedCount:        firstNonZero(plan.AddedCount, plan.Added),
		Created:           firstNonZero(plan.Created, plan.Added),
		Deleted:           plan.Deleted,
		DeletedCount:      firstNonZero(plan.DeletedCount, plan.Deleted),
		Removed:           firstNonZero(plan.Removed, plan.Deleted),
		RemovedCount:      firstNonZero(plan.RemovedCount, plan.Deleted),
		DuplicatesRemoved: plan.DuplicatesRemoved,
		DuplicateRules:    firstNonZero(plan.DuplicateRules, plan.DuplicatesRemoved),
		Changes:           plan.Changes,
	}
	res.Diff = FormatChanges(plan.Changes)

	finish := func(runErr error) (*Result, error) {
		now := cfg.Now()
		res.FinishedAt = now
		res.Duration = now.Sub(start)
		res.Elapsed = res.Duration
		syncResultAliases(res)
		if cfg.Logf != nil {
			cfg.Logf("%s", res.Summary())
		}
		return res, runErr
	}

	if len(plan.Changes) == 0 {
		return finish(nil)
	}
	if cfg.DryRun {
		return finish(nil)
	}

	// Snapshot the exact previous state when the backend supports it.
	var snapshot []byte
	snapshotter, canSnapshot := applier.(RuleSnapshotter)
	if cfg.RollbackOnFailure && canSnapshot {
		snap, err := snapshotter.SnapshotRules(ctx)
		if err != nil {
			// Snapshotting is best effort; inverse-change rollback remains
			// available for add/delete plans.
			if cfg.Logf != nil {
				cfg.Logf("rule snapshot before apply failed, will use inverse-plan rollback: %v", err)
			}
		} else {
			snapshot = snap
		}
	}

	applyErr := applier.ApplyChanges(ctx, plan.Changes)
	if applyErr == nil && cfg.VerifyAfterApply {
		applyErr = verifyConvergence(ctx, applier, plan.Desired)
	}
	if applyErr != nil {
		res.ApplyError = applyErr
		if !cfg.RollbackOnFailure {
			return finish(fmt.Errorf("rule apply failed (rollback disabled): %w", applyErr))
		}
		if rbErr := rollback(ctx, applier, snapshotter, snapshot, plan.Changes); rbErr != nil {
			res.RollbackFailed = true
			res.RollbackError = rbErr
			_, _ = finish(applyErr)
			return res, fmt.Errorf("rule apply failed: %w; rollback also failed: %v", applyErr, rbErr)
		}
		res.RolledBack = true
		_, _ = finish(applyErr)
		return res, fmt.Errorf("rule apply failed, previous state restored: %w", applyErr)
	}
	return finish(nil)
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

func syncResultAliases(res *Result) {
	// Keep every count spelling identical regardless of which field the
	// caller populated through Plan.
	if res.AddedCount != res.Added {
		res.AddedCount = res.Added
	}
	if res.Created != res.Added {
		res.Created = res.Added
	}
	if res.DeletedCount != res.Deleted {
		res.DeletedCount = res.Deleted
	}
	if res.Removed != res.Deleted {
		res.Removed = res.Deleted
	}
	if res.RemovedCount != res.Deleted {
		res.RemovedCount = res.Deleted
	}
	if res.UnchangedCount != res.Unchanged {
		res.UnchangedCount = res.Unchanged
	}
	if res.DuplicateRules != res.DuplicatesRemoved {
		res.DuplicateRules = res.DuplicatesRemoved
	}
	res.Elapsed = res.Duration
}

func verifyConvergence(ctx context.Context, applier ChangeApplier, desired []Rule) error {
	if len(desired) == 0 {
		return nil
	}
	lister, ok := applier.(RuleLister)
	if !ok {
		return nil
	}
	actual, err := lister.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("post-apply verification: list rules: %w", err)
	}
	if leftover := Compare(desired, actual); !leftover.IsEmpty() {
		return fmt.Errorf("post-apply verification failed: %d missing, %d extra, %d duplicate copies remain",
			len(leftover.Missing), leftover.Deleted(), leftover.DuplicateCount())
	}
	return nil
}

func rollback(ctx context.Context, applier ChangeApplier, snapshotter RuleSnapshotter, snapshot []byte, changes []Change) error {
	if snapshotter != nil && snapshot != nil {
		if err := snapshotter.RestoreRules(ctx, snapshot); err != nil {
			return fmt.Errorf("restore snapshot: %w", err)
		}
		return nil
	}
	inverse := Inverse(changes)
	if len(inverse) == 0 {
		return fmt.Errorf("no snapshot available and plan has no invertible operations")
	}
	if err := applier.ApplyChanges(ctx, inverse); err != nil {
		return fmt.Errorf("apply inverse plan: %w", err)
	}
	return nil
}

// Inverse builds the compensating change plan for an add/delete plan. Apply
// order is reversed. Flush operations cannot be inverted without a snapshot.
func Inverse(changes []Change) []Change {
	out := make([]Change, 0, len(changes))
	for i := len(changes) - 1; i >= 0; i-- {
		c := changes[i]
		c.normalize()
		switch c.Action {
		case ActionAdd:
			out = append(out, NewDeleteChange(c.Rule, c.Count, "rollback"))
		case ActionDelete:
			out = append(out, NewAddChange(c.Rule))
			out[len(out)-1].Count = c.Count
			out[len(out)-1].Copies = c.Count
		case ActionFlush:
			// Not invertible without a snapshot; skip.
		}
	}
	return out
}

// FormatChanges renders a reviewable diff, one line per change. Repeated
// copies are collapsed into a "(xN)" marker.
func FormatChanges(changes []Change) string {
	var b strings.Builder
	for _, c0 := range changes {
		c := c0
		c.normalize()
		mark := "?"
		switch c.Action {
		case ActionAdd:
			mark = "+"
		case ActionDelete:
			mark = "-"
		case ActionFlush:
			mark = "~"
		}
		copies := ""
		if c.Count > 1 {
			copies = fmt.Sprintf(" (x%d)", c.Count)
		}
		reason := ""
		if c.Reason != "" {
			reason = " [" + c.Reason + "]"
		}
		if c.Action == ActionFlush {
			fmt.Fprintf(&b, "%s flush %s/%s%s%s\n", mark, c.Rule.Table, c.Rule.Chain, copies, reason)
			continue
		}
		fmt.Fprintf(&b, "%s %s%s%s\n", mark, c.Rule.String(), copies, reason)
	}
	return strings.TrimRight(b.String(), "\n")
}

// FormatDiff is an alternate name for FormatChanges.
func FormatDiff(changes []Change) string { return FormatChanges(changes) }
