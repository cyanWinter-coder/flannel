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

package iptables

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	coreiptables "github.com/coreos/go-iptables/iptables"
	"github.com/flannel-io/flannel/pkg/trafficmngr"
	log "k8s.io/klog/v2"
)

// managerApplyMu serializes all reconcile passes of one flanneld process.
// iptables-restore already takes the xtables lock via --wait, but this also
// keeps our list -> snapshot -> apply sequence from interleaving across the
// forward/masquerade goroutines and address families.
var managerApplyMu sync.Mutex

// flannelChainPrefix marks chains owned exclusively by flannel. Rules in these
// chains are reconciled as exact ordered desired state; parent chains such as
// FORWARD/POSTROUTING are only scanned for flannel-owned jump rules.
const flannelChainPrefix = "FLANNEL-"

// ReconcileClient is the subset of the concrete go-iptables client used by the
// diff engine. *iptables.IPTables satisfies it.
type ReconcileClient interface {
	List(table, chain string) ([]string, error)
	ChainExists(table, chain string) (bool, error)
	NewChain(table, chain string) error
}

// ReconcileOptions configures one ReconcileRules pass.
type ReconcileOptions struct {
	// DryRun only computes and renders the diff.
	DryRun bool
	// RollbackOnFailure restores the previous ruleset when apply fails.
	// Defaults to true.
	RollbackOnFailure *bool
	// VerifyAfterApply re-lists and compares after applying.
	VerifyAfterApply bool
	// Snapshotter overrides the default iptables-save based snapshotter.
	Snapshotter trafficmngr.RuleSnapshotter
	// Now overrides the clock.
	Now func() time.Time
	// OnReport is invoked with the pass result (metrics/logging hook).
	OnReport func(*trafficmngr.Result)
	// Logf receives progress lines; klog.Infof style.
	Logf func(format string, args ...any)
}

// ReconcileResult is an alternate name for the reconciliation report.
type ReconcileResult = trafficmngr.Result

// chainRef identifies one table/chain pair.
type chainRef struct {
	table string
	chain string
}

func (c chainRef) key() string { return c.table + "\x00" + c.chain }

// ToCoreRules maps flannel IPTablesRule values to backend-neutral core Rules.
func ToCoreRules(rules []trafficmngr.IPTablesRule, family trafficmngr.Family) []trafficmngr.Rule {
	out := make([]trafficmngr.Rule, 0, len(rules))
	for _, r := range rules {
		spec := CanonicalizeSpec(append([]string(nil), r.Rulespec...))
		out = append(out, trafficmngr.Rule{
			Family:   family,
			Table:    r.Table,
			Chain:    r.Chain,
			Action:   r.Action,
			Rulespec: spec,
		})
	}
	return out
}

// CanonicalizeSpec normalizes known iptables output/input spelling differences
// so that desired and live rules compare equal:
//   - negation may be printed as "-s ! value" or passed as "! -s value";
//   - CIDRs are normalized through net.ParseCIDR.
func CanonicalizeSpec(spec []string) []string {
	out := make([]string, 0, len(spec))
	for i := 0; i < len(spec); i++ {
		tok := spec[i]
		if tok == "!" && len(out) > 0 && strings.HasPrefix(out[len(out)-1], "-") {
			// Transform "<opt> ! <value>" into "! <opt> <value>".
			opt := out[len(out)-1]
			out = out[:len(out)-1]
			out = append(out, "!", opt)
			continue
		}
		out = append(out, normalizeToken(tok))
	}
	return out
}

func normalizeToken(tok string) string {
	if strings.Contains(tok, "/") {
		if _, ipNet, err := net.ParseCIDR(tok); err == nil {
			return ipNet.String()
		}
	}
	return tok
}

// TokenizeLine splits one `iptables -S` line into tokens, stripping quotes
// around comments that contain spaces.
func TokenizeLine(line string) []string {
	var tokens []string
	var b strings.Builder
	inQuote := rune(0)
	flush := func() {
		if b.Len() > 0 {
			tokens = append(tokens, b.String())
			b.Reset()
		}
	}
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			} else {
				b.WriteRune(c)
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '\\' && i+1 < len(runes):
			b.WriteRune(runes[i+1])
			i++
		case c == ' ' || c == '\t':
			flush()
		default:
			b.WriteRune(c)
		}
	}
	flush()
	return tokens
}

// ParseSaveRuleLine parses an `iptables -S CHAIN` output line. Only "-A" rule
// lines are returned; policy (-P) and other lines yield ok=false. The returned
// spec is canonicalized and directly usable for comparison and -D operations.
func ParseSaveRuleLine(line string) (chain string, spec []string, ok bool) {
	tokens := TokenizeLine(strings.TrimSpace(line))
	if len(tokens) < 3 || tokens[0] != "-A" {
		return "", nil, false
	}
	return tokens[1], CanonicalizeSpec(tokens[2:]), true
}

// IsFlannelOwnedSpec reports whether a rule in an externally owned parent
// chain (FORWARD/POSTROUTING) belongs to flannel and may therefore be
// reconciled/deleted. We only claim rules jumping to a FLANNEL-* chain or
// carrying a "flanneld" comment.
func IsFlannelOwnedSpec(spec []string) bool {
	for i, tok := range spec {
		if tok == "-j" && i+1 < len(spec) && strings.HasPrefix(spec[i+1], flannelChainPrefix) {
			return true
		}
		if tok == "--comment" && i+1 < len(spec) && strings.Contains(spec[i+1], "flanneld") {
			return true
		}
	}
	return false
}

func ownedChain(chain string) bool {
	return strings.HasPrefix(chain, flannelChainPrefix)
}

// listLiveRules lists every referenced chain and returns its parsed rules.
// A missing chain is treated as empty rather than an error.
func listLiveRules(client ReconcileClient, refs []chainRef, family trafficmngr.Family) (map[chainRef][]trafficmngr.Rule, error) {
	live := make(map[chainRef][]trafficmngr.Rule, len(refs))
	for _, ref := range refs {
		lines, err := client.List(ref.table, ref.chain)
		if err != nil {
			if isClientNotExist(err) {
				live[ref] = nil
				continue
			}
			// Chain may simply not exist yet; probe ChainExists to distinguish.
			if exists, cerr := client.ChainExists(ref.table, ref.chain); cerr == nil && !exists {
				live[ref] = nil
				continue
			}
			return nil, fmt.Errorf("list rules in %s/%s: %w", ref.table, ref.chain, err)
		}
		for _, line := range lines {
			chain, spec, ok := ParseSaveRuleLine(line)
			if !ok {
				continue
			}
			// `-S CHAIN` should echo the requested chain; trust parsed chain but
			// fall back to the requested one if output differs.
			if chain == "" {
				chain = ref.chain
			}
			live[ref] = append(live[ref], trafficmngr.Rule{
				Family:   family,
				Table:    ref.table,
				Chain:    chain,
				Action:   "-A",
				Rulespec: spec,
			})
		}
	}
	return live, nil
}

func isClientNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no chain/target/match") ||
		strings.Contains(msg, "bad rule")
}

// ensureManagedChains creates missing flannel-owned chains without flushing
// them. Parent chains are expected to exist and are never created here.
func ensureManagedChains(client ReconcileClient, refs []chainRef) error {
	for _, ref := range refs {
		if !ownedChain(ref.chain) {
			continue
		}
		exists, err := client.ChainExists(ref.table, ref.chain)
		if err != nil {
			return fmt.Errorf("check chain %s/%s: %w", ref.table, ref.chain, err)
		}
		if !exists {
			if err := client.NewChain(ref.table, ref.chain); err != nil && !isClientNotExist(err) {
				// Another actor may have created it concurrently; re-check.
				if exists2, err2 := client.ChainExists(ref.table, ref.chain); err2 != nil || !exists2 {
					return fmt.Errorf("create chain %s/%s: %w", ref.table, ref.chain, err)
				}
			}
		}
	}
	return nil
}

// BuildPlan compares wanted rules with live rules and builds the minimal
// aggregated plan. Flannel-owned chains use exact ordered reconciliation;
// external parent chains only consider flannel-owned jump rules.
func BuildPlan(wanted []trafficmngr.Rule, live map[chainRef][]trafficmngr.Rule) trafficmngr.Plan {
	plan := trafficmngr.Plan{Desired: trafficmngr.UniqueRules(wanted)}

	groups := make(map[chainRef][]trafficmngr.Rule)
	var order []chainRef
	for _, r := range wanted {
		ref := chainRef{r.Table, r.Chain}
		if _, ok := groups[ref]; !ok {
			order = append(order, ref)
		}
		groups[ref] = append(groups[ref], r)
	}

	for _, ref := range order {
		wantGroup := groups[ref]
		actualAll := live[ref]

		if ownedChain(ref.chain) {
			plan.CurrentCount += len(actualAll)
			plan.DesiredCount += len(wantGroup)
			if trafficmngr.OrderedPlan(wantGroup, actualAll) == nil {
				plan.Unchanged += len(wantGroup)
				continue
			}
			changes := trafficmngr.OrderedPlan(wantGroup, actualAll)
			plan.Changes = append(plan.Changes, changes...)
			plan.Added += len(wantGroup)
			plan.Deleted += len(actualAll)
			plan.DuplicatesRemoved += duplicateCopies(actualAll)
			continue
		}

		// Parent chain: scope to flannel-owned rules only.
		scoped := make([]trafficmngr.Rule, 0, len(actualAll))
		for _, r := range actualAll {
			if IsFlannelOwnedSpec(r.Rulespec) {
				scoped = append(scoped, r)
			}
		}
		plan.CurrentCount += len(scoped)
		d := trafficmngr.Compare(wantGroup, scoped)
		gp := d.Plan()
		plan.Changes = append(plan.Changes, gp.Changes...)
		plan.DesiredCount += gp.DesiredCount
		plan.Unchanged += gp.Unchanged
		plan.Added += gp.Added
		plan.Deleted += gp.Deleted
		plan.DuplicatesRemoved += gp.DuplicatesRemoved
	}

	plan.UnchangedCount = plan.Unchanged
	plan.AddedCount = plan.Added
	plan.Created = plan.Added
	plan.DeletedCount = plan.Deleted
	plan.Removed = plan.Deleted
	plan.RemovedCount = plan.Deleted
	plan.DuplicateRules = plan.DuplicatesRemoved
	return plan
}

func duplicateCopies(rules []trafficmngr.Rule) int {
	seen := make(map[string]int)
	for _, r := range rules {
		seen[r.Key()]++
	}
	dups := 0
	for _, n := range seen {
		if n > 1 {
			dups += n - 1
		}
	}
	return dups
}

// restoreBackend applies core Changes through an IPTablesRestore applier and
// optionally provides full-table snapshots for exact rollback.
type restoreBackend struct {
	restore IPTablesRestore
	snap    trafficmngr.RuleSnapshotter
}

func (b *restoreBackend) ApplyChanges(_ context.Context, changes []trafficmngr.Change) error {
	if len(changes) == 0 {
		return nil
	}
	payload := BuildRestoreRules(changes)
	if len(payload) == 0 {
		return nil
	}
	return b.restore.ApplyWithoutFlush(payload)
}

func (b *restoreBackend) SnapshotRules(ctx context.Context) ([]byte, error) {
	if b.snap == nil {
		return nil, fmt.Errorf("no iptables snapshotter configured")
	}
	return b.snap.SnapshotRules(ctx)
}

func (b *restoreBackend) RestoreRules(ctx context.Context, snapshot []byte) error {
	if b.snap == nil {
		return fmt.Errorf("no iptables snapshotter configured")
	}
	return b.snap.RestoreRules(ctx, snapshot)
}

// BuildRestoreRules translates core Changes into the iptables-restore payload
// representation used by this package.
func BuildRestoreRules(changes []trafficmngr.Change) IPTablesRestoreRules {
	tables := IPTablesRestoreRules{}
	for _, c0 := range changes {
		op := c0.Op
		if op == "" {
			op = c0.Action
		}
		count := c0.Count
		if count == 0 {
			count = c0.Copies
		}
		if count == 0 {
			count = 1
		}
		specTokens := c0.Rule.Rulespec
		if len(specTokens) == 0 {
			specTokens = c0.Rule.Spec
		}
		table := c0.Rule.Table
		chain := c0.Rule.Chain

		switch op {
		case trafficmngr.ActionFlush:
			tables[table] = append(tables[table], IPTablesRestoreRuleSpec{"-F", chain})
		case trafficmngr.ActionDelete:
			for i := 0; i < count; i++ {
				line := IPTablesRestoreRuleSpec{"-D", chain}
				line = append(line, specTokens...)
				tables[table] = append(tables[table], line)
			}
		default: // add
			action := c0.Rule.Action
			if action != "-A" && action != "-I" {
				action = "-A"
			}
			for i := 0; i < count; i++ {
				line := append(IPTablesRestoreRuleSpec{action, chain}, specTokens...)
				tables[table] = append(tables[table], line)
			}
		}
	}
	return tables
}

// ReconcileRules compares the wanted flannel rules against the live iptables
// ruleset and applies only the delta. It removes stacked duplicate copies in a
// single iptables-restore transaction, supports dry-run and rolls back to the
// pre-apply snapshot on failure.
func ReconcileRules(ctx context.Context, client ReconcileClient, restore IPTablesRestore,
	rules []trafficmngr.IPTablesRule, family trafficmngr.Family, opts ReconcileOptions) (*trafficmngr.Result, error) {

	if opts.Now == nil {
		opts.Now = time.Now
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(format string, args ...any) { log.Infof(format, args...) }
	}

	wanted := ToCoreRules(rules, family)
	refs := uniqueRefs(wanted)

	// Dry-run must be read-only: a missing chain is simply reported as
	// requiring creation/adds below, never actually created.
	if !opts.DryRun {
		if err := ensureManagedChains(client, refs); err != nil {
			return nil, err
		}
	}
	live, err := listLiveRules(client, refs, family)
	if err != nil {
		return nil, err
	}
	plan := BuildPlan(wanted, live)

	rollback := true
	if opts.RollbackOnFailure != nil {
		rollback = *opts.RollbackOnFailure
	}
	backend := &restoreBackend{restore: restore, snap: opts.Snapshotter}
	cfg := trafficmngr.Config{
		DryRun:            opts.DryRun,
		RollbackOnFailure: rollback,
		VerifyAfterApply:  opts.VerifyAfterApply,
		Now:               opts.Now,
		Logf:              logf,
	}
	res, err := trafficmngr.Execute(ctx, backend, plan, cfg)
	if res != nil && opts.OnReport != nil {
		opts.OnReport(res)
	}
	if err != nil {
		logf("iptables rule reconcile failed: %v", err)
	}
	return res, err
}

func uniqueRefs(rules []trafficmngr.Rule) []chainRef {
	seen := map[string]struct{}{}
	var refs []chainRef
	for _, r := range rules {
		ref := chainRef{r.Table, r.Chain}
		if _, ok := seen[ref.key()]; ok {
			continue
		}
		seen[ref.key()] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

// reconcileRulesOnce runs one serialized compare -> diff -> apply -> verify
// pass for the manager. It never panics and only logs failures so the periodic
// goroutine keeps running; the next resync retries from the live state.
func (iptm *IPTablesManager) reconcileRulesOnce(ctx context.Context,
	client ReconcileClient, restore IPTablesRestore,
	rules []trafficmngr.IPTablesRule, family trafficmngr.Family, proto coreiptables.Protocol) {

	managerApplyMu.Lock()
	defer managerApplyMu.Unlock()

	var snapshotter trafficmngr.RuleSnapshotter
	if s, err := NewIPTablesSnapshotter(proto); err != nil {
		log.V(5).Infof("iptables state snapshot unavailable, inverse-plan rollback only: %v", err)
	} else {
		snapshotter = s
	}

	rollback := true
	res, err := ReconcileRules(ctx, client, restore, rules, family, ReconcileOptions{
		DryRun:            iptm.DryRun,
		RollbackOnFailure: &rollback,
		VerifyAfterApply:  iptm.VerifyAfterApply,
		Snapshotter:       snapshotter,
	})
	if res != nil {
		log.Infof("%s", res.Summary())
		if iptm.DryRun && res.Diff != "" {
			log.Infof("iptables dry-run diff for %s:\n%s", family, res.Diff)
		}
		if iptm.Metrics != nil {
			iptm.Metrics.Record(res, err)
		}
		if iptm.OnReport != nil {
			iptm.OnReport(res)
		}
	}
	if err != nil {
		log.Errorf("Failed to reconcile iptables rules: %v", err)
	}
}
