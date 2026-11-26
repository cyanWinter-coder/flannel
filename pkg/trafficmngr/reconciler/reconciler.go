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

// Package reconciler re-exports the backend-independent rule reconciliation
// core living in pkg/trafficmngr under a focused package path.
package reconciler

import (
	"context"
	"time"

	tm "github.com/flannel-io/flannel/pkg/trafficmngr"
)

// Re-exported types.
type (
	// Family is the IP family of a rule.
	Family = tm.Family
	// Rule is the canonical identity of a firewall rule.
	Rule = tm.Rule
	// Action is the kind of a Change.
	Action = tm.Action
	// Change is one minimal mutation.
	Change = tm.Change
	// RuleChange is an alternate name for Change.
	RuleChange = tm.RuleChange
	// RuleDiff is the desired-vs-live comparison result; use the Diff func.
	RuleDiff = tm.RuleDiff
	// Plan is an executable change set with counters.
	Plan = tm.Plan
	// Result is the outcome of one reconciliation pass.
	Result = tm.Result
	// Report is an alternate name for Result.
	Report = tm.Report
	// RuleSet is a named rule slice.
	RuleSet = tm.RuleSet
	// ReconcileResult / ReconcileReport / ApplyResult are result aliases.
	ReconcileResult = tm.ReconcileResult
	ReconcileReport = tm.ReconcileReport
	ApplyResult     = tm.ApplyResult
	// Config controls a run.
	Config = tm.Config
	// Options / ReconcileOptions are config aliases.
	Options          = tm.Options
	ReconcileOptions = tm.ReconcileOptions
	// Reconciler serializes runs around one backend.
	Reconciler = tm.Reconciler
	// Metrics holds aggregate counters.
	Metrics = tm.Metrics
	// MetricsSnapshot is a point-in-time metrics copy.
	MetricsSnapshot = tm.MetricsSnapshot

	// Interfaces.
	RuleLister      = tm.RuleLister
	ChangeApplier   = tm.ChangeApplier
	RuleBackend     = tm.RuleBackend
	RuleSnapshotter = tm.RuleSnapshotter
)

// Re-exported families and actions.
const (
	FamilyAny = tm.FamilyAny
	IPv4      = tm.IPv4
	IPv6      = tm.IPv6

	ActionAdd    = tm.ActionAdd
	ActionDelete = tm.ActionDelete
	ActionFlush  = tm.ActionFlush

	OpAdd    = tm.OpAdd
	OpDelete = tm.OpDelete
	OpFlush  = tm.OpFlush

	ActionCreate = tm.ActionCreate
	ActionRemove = tm.ActionRemove
)

// Compare computes the multiset diff.
func Compare(desired, actual []Rule) *RuleDiff { return tm.Compare(desired, actual) }

// DiffRules / ComputeDiff are alternate names for Compare.
func DiffRules(desired, actual []Rule) *RuleDiff { return tm.DiffRules(desired, actual) }

// ComputeDiff is an alternate name for Compare.
func ComputeDiff(desired, actual []Rule) *RuleDiff { return tm.ComputeDiff(desired, actual) }

// UniqueRules de-duplicates rules by identity.
func UniqueRules(rules []Rule) []Rule { return tm.UniqueRules(rules) }

// OrderedPlan returns the exact-order convergence plan.
func OrderedPlan(desired, actual []Rule) []Change { return tm.OrderedPlan(desired, actual) }

// Inverse builds the compensating plan.
func Inverse(changes []Change) []Change { return tm.Inverse(changes) }

// FormatChanges renders the reviewable diff.
func FormatChanges(changes []Change) string { return tm.FormatChanges(changes) }

// FormatDiff is an alternate name for FormatChanges.
func FormatDiff(changes []Change) string { return tm.FormatDiff(changes) }

// NewAddChange / NewDeleteChange / NewFlushChange construct changes.
func NewAddChange(r Rule) Change { return tm.NewAddChange(r) }

// NewDeleteChange builds a repeated delete change.
func NewDeleteChange(r Rule, copies int, reason string) Change {
	return tm.NewDeleteChange(r, copies, reason)
}

// NewFlushChange builds a flush change.
func NewFlushChange(r Rule, reason string) Change { return tm.NewFlushChange(r, reason) }

// NewReconciler constructs a Reconciler.
func NewReconciler(backend RuleBackend, args ...any) *Reconciler {
	return tm.NewReconciler(backend, args...)
}

// New is an alternate constructor name.
var New = tm.NewReconciler

// Diff is an alternate name for Compare.
func Diff(desired, actual []Rule) *RuleDiff { return tm.Compare(desired, actual) }

// Apply is an alternate name for Execute.
func Apply(ctx context.Context, applier ChangeApplier, plan Plan, cfg Config) (*Result, error) {
	return tm.Execute(ctx, applier, plan, cfg)
}

// DefaultConfig returns a Config with rollback enabled and the wall clock.
func DefaultConfig() Config {
	return Config{RollbackOnFailure: true}
}

// Reconcile is the package-level list/compare/execute entry point.
func Reconcile(ctx context.Context, backend RuleBackend, desired []Rule, cfg Config) (*Result, error) {
	return tm.Reconcile(ctx, backend, desired, cfg)
}

// Execute runs a precomputed plan.
func Execute(ctx context.Context, applier ChangeApplier, plan Plan, cfg Config) (*Result, error) {
	return tm.Execute(ctx, applier, plan, cfg)
}

// DurationSince is a small timing helper for callers that time sections.
func DurationSince(start time.Time) time.Duration { return time.Since(start) }
