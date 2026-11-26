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
//go:build !windows
// +build !windows

package nftables

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "k8s.io/klog/v2"
	"sigs.k8s.io/knftables"

	"github.com/flannel-io/flannel/pkg/trafficmngr"
)

// ErrTableConflict is returned when a pre-existing nft table cannot be
// reconciled with the flannel-owned schema.
var ErrTableConflict = errors.New("conflicting nftables table")

// TableConflictError describes a table-name/schema collision that prevents
// flannel rules from taking effect.
type TableConflictError struct {
	Family knftables.Family
	Name   string
	Reason string
	Err    error
}

func (e *TableConflictError) Error() string {
	return fmt.Sprintf("nftables table conflict for %s/%s: %s: %v", e.Family, e.Name, e.Reason, e.Err)
}

func (e *TableConflictError) Unwrap() error { return e.Err }

// nftChainSpec is the desired configuration and ordered rules of one chain.
type nftChainSpec struct {
	Name     string
	Comment  *string
	Type     *knftables.BaseChainType
	Hook     *knftables.BaseChainHook
	Priority *knftables.BaseChainPriority
	Rules    []string
}

// nftTableState remembers the last successfully applied version of a table so
// a failed new apply can be rolled back to the previous version.
type nftTableState struct {
	mu          sync.Mutex
	lastApplied []nftChainSpec
	hasLast     bool
}

// ReconcileOptions configures an nft reconciliation pass.
type ReconcileOptions struct {
	// DryRun only compares and renders the diff; no transaction is Run.
	DryRun bool
	// Now overrides the clock (tests).
	Now func() time.Time
	// OnReport receives the pass result (metrics/logging hook).
	OnReport func(*trafficmngr.Result)
}

// ReconcileResult is an alternate name for the reconciliation report.
type ReconcileResult = trafficmngr.Result

// NewNFTablesManager builds a manager that creates its own knftables clients
// during Init, matching the production wiring.
func NewNFTablesManager() *NFTablesManager { return &NFTablesManager{} }

// NewNFTablesManagerWithInterfaces injects knftables interfaces. It is useful
// for tests with knftables.NewFake and for callers that already built clients.
func NewNFTablesManagerWithInterfaces(v4, v6 knftables.Interface) *NFTablesManager {
	return &NFTablesManager{nftv4: v4, nftv6: v6}
}

// NewWithInterfaces is an alternate constructor name.
func NewWithInterfaces(v4, v6 knftables.Interface) *NFTablesManager {
	return NewNFTablesManagerWithInterfaces(v4, v6)
}

// SetDryRun toggles dry-run mode (used by main when the flag is set).
func (nftm *NFTablesManager) SetDryRun(dryRun bool) { nftm.DryRun = dryRun }

// reconcileChains compares desired chains with the live table and applies an
// atomic create/flush/add transaction only when drift exists. On apply failure
// the previous successfully applied version is restored.
func (st *nftTableState) reconcileChains(ctx context.Context, nft knftables.Interface, tableLabel string,
	specs []nftChainSpec, opts ReconcileOptions) (*trafficmngr.Result, error) {

	if opts.Now == nil {
		opts.Now = time.Now
	}
	start := opts.Now()
	res := &trafficmngr.Result{StartedAt: start, DryRun: opts.DryRun}

	// Compare every chain against live rules.
	allEqual := true
	var diffChanges []trafficmngr.Change
	for _, spec := range specs {
		live, err := nft.ListRules(ctx, spec.Name)
		if err != nil && !knftables.IsNotFound(err) {
			return nil, fmt.Errorf("nftables: list rules in chain %s: %w", spec.Name, err)
		}
		liveStrings, textComparable := liveRuleStrings(live)

		res.DesiredCount += len(spec.Rules)
		res.CurrentCount += len(live)

		if knftables.IsNotFound(err) {
			allEqual = false
			diffChanges = append(diffChanges, trafficmngr.NewFlushChange(
				trafficmngr.Rule{Table: tableLabel, Chain: spec.Name}, "missing-chain"))
			for _, r := range spec.Rules {
				diffChanges = append(diffChanges, trafficmngr.NewAddChange(
					trafficmngr.Rule{Table: tableLabel, Chain: spec.Name, Rulespec: []string{r}}))
			}
			continue
		}

		if textComparable {
			wantRules := toCoreRules(tableLabel, spec.Name, spec.Rules)
			gotRules := toCoreRules(tableLabel, spec.Name, liveStrings)
			if plan := trafficmngr.OrderedPlan(wantRules, gotRules); plan != nil {
				allEqual = false
				diffChanges = append(diffChanges, plan...)
			} else {
				res.Unchanged += len(spec.Rules)
			}
		} else {
			// The real knftables v0.0.22 lister returns handles/comments but
			// not rule text. Compare by count; any uncertainty is treated as
			// drift and converged with an atomic flush/rebuild.
			if len(live) == len(spec.Rules) {
				res.Unchanged += len(spec.Rules)
			}
			if len(live) != len(spec.Rules) {
				allEqual = false
			}
		}
	}

	finish := func(runErr error) (*trafficmngr.Result, error) {
		now := opts.Now()
		res.FinishedAt = now
		res.Duration = now.Sub(start)
		res.Elapsed = res.Duration
		if opts.OnReport != nil {
			opts.OnReport(res)
		}
		return res, runErr
	}

	if allEqual {
		res.Added = 0
		res.Deleted = 0
		res.AddedCount = 0
		res.DeletedCount = 0
		return finish(nil)
	}

	res.Changes = diffChanges
	res.Diff = trafficmngr.FormatChanges(diffChanges)
	res.Added = len(allDesiredRules(specs))
	res.Deleted = res.CurrentCount
	res.AddedCount = res.Added
	res.DeletedCount = res.Deleted
	res.Created = res.Added
	res.Removed = res.Deleted
	res.RemovedCount = res.Deleted

	if opts.DryRun {
		return finish(nil)
	}

	tx := nft.NewTransaction()
	// Ensure the table exists as part of the same atomic batch so a table
	// removed externally is recreated without a separate apply round-trip.
	tx.Add(&knftables.Table{})
	for _, spec := range specs {
		tx.Add(&knftables.Chain{
			Name:     spec.Name,
			Comment:  spec.Comment,
			Type:     spec.Type,
			Hook:     spec.Hook,
			Priority: spec.Priority,
		})
		// Flush makes the operation idempotent and removes stacked duplicates
		// in the flannel-owned chain before ordered rules are re-added.
		tx.Flush(&knftables.Chain{Name: spec.Name})
		for _, rule := range spec.Rules {
			tx.Add(&knftables.Rule{Chain: spec.Name, Rule: rule})
		}
	}

	if err := nft.Run(ctx, tx); err != nil {
		res.ApplyError = err
		if rbErr := st.rollback(ctx, nft); rbErr != nil {
			res.RollbackFailed = true
			res.RollbackError = rbErr
			out, _ := finish(err)
			return out, fmt.Errorf("nftables apply failed: %w; rollback failed: %v", err, rbErr)
		}
		res.RolledBack = true
		out, _ := finish(err)
		return out, fmt.Errorf("nftables apply failed, previous version restored: %w", err)
	}

	st.mu.Lock()
	st.lastApplied = specs
	st.hasLast = true
	st.mu.Unlock()

	return finish(nil)
}

// rollback re-applies the last known good chain set.
func (st *nftTableState) rollback(ctx context.Context, nft knftables.Interface) error {
	st.mu.Lock()
	if !st.hasLast {
		st.mu.Unlock()
		return errors.New("no previous nftables version recorded")
	}
	last := st.lastApplied
	st.mu.Unlock()

	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{})
	for _, spec := range last {
		tx.Add(&knftables.Chain{
			Name:     spec.Name,
			Comment:  spec.Comment,
			Type:     spec.Type,
			Hook:     spec.Hook,
			Priority: spec.Priority,
		})
		tx.Flush(&knftables.Chain{Name: spec.Name})
		for _, rule := range spec.Rules {
			tx.Add(&knftables.Rule{Chain: spec.Name, Rule: rule})
		}
	}
	return nft.Run(ctx, tx)
}

func liveRuleStrings(rules []*knftables.Rule) ([]string, bool) {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		if r == nil || r.Rule == "" {
			return nil, false
		}
		out = append(out, r.Rule)
	}
	return out, true
}

func toCoreRules(table, chain string, ruleStrings []string) []trafficmngr.Rule {
	out := make([]trafficmngr.Rule, 0, len(ruleStrings))
	for _, s := range ruleStrings {
		out = append(out, trafficmngr.Rule{
			Table:    table,
			Chain:    chain,
			Action:   "-A",
			Rulespec: []string{s},
		})
	}
	return out
}

func allDesiredRules(specs []nftChainSpec) []string {
	var out []string
	for _, s := range specs {
		out = append(out, s.Rules...)
	}
	return out
}

// resetTableIfPresent deletes the bound table when it already exists. Flannel
// owns its well-known tables exclusively; recreating them clears incompatible
// base-chain definitions or stale objects left by another backend/version,
// which otherwise silently leaves new rules unattached ("table name conflict").
// A missing table is not an error.
func resetTableIfPresent(ctx context.Context, nft knftables.Interface) (bool, error) {
	all, err := nft.ListAll(ctx)
	if err != nil {
		if knftables.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if all == nil {
		return false, nil
	}
	tx := nft.NewTransaction()
	tx.Delete(&knftables.Table{})
	if err := nft.Run(ctx, tx); err != nil && !knftables.IsNotFound(err) {
		return false, err
	}
	return true, nil
}

// DeleteTablesNamed removes the supplied table names if present. It is used by
// backend switching cleanup for canonical and legacy/conflicting table names.
func DeleteTablesNamed(ctx context.Context, family knftables.Family, names []string) error {
	var firstErr error
	for _, name := range names {
		nft, err := knftables.New(family, name)
		if err != nil {
			log.V(3).Infof("nftables: cannot open table %s/%s: %v", family, name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		tx := nft.NewTransaction()
		tx.Delete(&knftables.Table{})
		if err := nft.Run(ctx, tx); err != nil && !knftables.IsNotFound(err) {
			log.V(2).Infof("nftables: couldn't delete table %s: %v", name, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
