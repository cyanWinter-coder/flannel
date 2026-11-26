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
	"net"
	"testing"

	"sigs.k8s.io/knftables"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
)

func h632TestLease() *lease.Lease {
	_, v6net, _ := net.ParseCIDR("fd00::/64")
	return &lease.Lease{
		Subnet:     ip.IP4Net{IP: ip.MustParseIP4("10.244.1.0"), PrefixLen: 24},
		IPv6Subnet: ip.FromIP6Net(v6net),
	}
}

func h632ForwardSpec() nftChainSpec { return forwardV4Spec("10.244.0.0/16") }

func h632RuleCount(t *testing.T, fake *knftables.Fake, chain string) int {
	t.Helper()
	rules, err := fake.ListRules(context.Background(), chain)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	return len(rules)
}

func TestH632NFTApplyIdempotentNoDuplicates(t *testing.T) {
	fake := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	st := &nftTableState{}
	spec := h632ForwardSpec()
	ctx := context.Background()

	res, err := st.reconcileChains(ctx, fake, ipv4Table, []nftChainSpec{spec}, ReconcileOptions{})
	if err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if res.Added != 2 {
		t.Fatalf("expected 2 rules added, got %d", res.Added)
	}
	if got := h632RuleCount(t, fake, forwardChain); got != 2 {
		t.Fatalf("expected 2 rules after first apply, got %d", got)
	}

	// Repeated delivery must converge to the exact same state, no duplicates.
	res2, err := st.reconcileChains(ctx, fake, ipv4Table, []nftChainSpec{spec}, ReconcileOptions{})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if res2.Changed() {
		t.Fatalf("identical re-apply must be a no-op, added=%d deleted=%d diff=%s",
			res2.Added, res2.Deleted, res2.Diff)
	}
	if got := h632RuleCount(t, fake, forwardChain); got != 2 {
		t.Fatalf("duplicate rules accumulated: have %d rules, want 2", got)
	}
}

func TestH632NFTReconcileClearsStackedDuplicates(t *testing.T) {
	fake := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	st := &nftTableState{}
	ctx := context.Background()

	// First install a 5-rule version (simulates stacked/duplicate entries).
	bloated := h632ForwardSpec()
	bloated.Rules = []string{
		"ip saddr 10.244.0.0/16 accept",
		"ip saddr 10.244.0.0/16 accept",
		"ip daddr 10.244.0.0/16 accept",
		"ip daddr 10.244.0.0/16 accept",
		"ip daddr 10.244.0.0/16 accept",
	}
	if _, err := st.reconcileChains(ctx, fake, ipv4Table, []nftChainSpec{bloated}, ReconcileOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := h632RuleCount(t, fake, forwardChain); got != 5 {
		t.Fatalf("setup: expected 5 rules, got %d", got)
	}

	// Reconciling the canonical 2-rule spec flushes the surplus copies.
	res, err := st.reconcileChains(ctx, fake, ipv4Table, []nftChainSpec{h632ForwardSpec()}, ReconcileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed() {
		t.Fatal("bloated state should be detected as drift")
	}
	if got := h632RuleCount(t, fake, forwardChain); got != 2 {
		t.Fatalf("expected duplicates cleared to 2 rules, got %d", got)
	}
}

func TestH632NFTDryRunDoesNotApply(t *testing.T) {
	fake := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	st := &nftTableState{}
	res, err := st.reconcileChains(context.Background(), fake, ipv4Table,
		[]nftChainSpec{h632ForwardSpec()}, ReconcileOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Added != 2 {
		t.Fatalf("unexpected dry-run result: %+v", res)
	}
	if res.Diff == "" {
		t.Fatal("dry-run should render a diff")
	}
	if fake.Table != nil {
		t.Fatal("dry-run must not create the table or apply any transaction")
	}
	if res.Duration < 0 {
		t.Fatal("duration must be recorded")
	}
}

// h632FailRunFake fails the next failRuns Run calls, then delegates.
type h632FailRunFake struct {
	*knftables.Fake
	failRuns int
}

func (f *h632FailRunFake) Run(ctx context.Context, tx *knftables.Transaction) error {
	if f.failRuns > 0 {
		f.failRuns--
		return errors.New("simulated nft transaction failure")
	}
	return f.Fake.Run(ctx, tx)
}

func TestH632NFTFailedApplyRollsBackToPrevious(t *testing.T) {
	base := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	fake := &h632FailRunFake{Fake: base}
	st := &nftTableState{}
	ctx := context.Background()

	// Apply version 1 successfully.
	v1 := h632ForwardSpec()
	v1.Rules = []string{"ip saddr 10.244.0.0/16 accept"}
	if _, err := st.reconcileChains(ctx, fake, ipv4Table, []nftChainSpec{v1}, ReconcileOptions{}); err != nil {
		t.Fatalf("v1 apply: %v", err)
	}
	if got := h632RuleCount(t, base, forwardChain); got != 1 {
		t.Fatalf("v1 rule count = %d, want 1", got)
	}

	// Next Run (the v2 apply) fails; rollback Run must succeed and restore v1.
	fake.failRuns = 1
	v2 := h632ForwardSpec()
	_, err := st.reconcileChains(ctx, fake, ipv4Table, []nftChainSpec{v2}, ReconcileOptions{})
	if err == nil {
		t.Fatal("expected apply error")
	}

	// The failed fake Run never mutated state, and rollback re-applied v1.
	rules, lerr := base.ListRules(ctx, forwardChain)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(rules) != 1 || rules[0].Rule != v1.Rules[0] {
		t.Fatalf("expected previous version restored, got %#v", rules)
	}
}

func TestH632ResetTableIfPresent(t *testing.T) {
	fake := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	ctx := context.Background()

	replaced, err := resetTableIfPresent(ctx, fake)
	if err != nil || replaced {
		t.Fatalf("missing table should be (false,nil), got %v %v", replaced, err)
	}

	tx := fake.NewTransaction()
	tx.Add(&knftables.Table{Comment: knftables.PtrTo("pre-existing")})
	if err := fake.Run(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if fake.Table == nil {
		t.Fatal("table should exist after Add")
	}

	replaced, err = resetTableIfPresent(ctx, fake)
	if err != nil || !replaced {
		t.Fatalf("existing table should be reset, got replaced=%v err=%v", replaced, err)
	}
	if fake.Table != nil {
		t.Fatal("table should be deleted after reset")
	}
}

func TestH632AddMasqRulesCompat(t *testing.T) {
	v4 := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	mgr := NewNFTablesManagerWithInterfaces(v4, knftables.NewFake(knftables.IPv6Family, ipv6Table))
	ctx := context.Background()

	// Create the table/chain so running the transaction can attach rules.
	base := v4.NewTransaction()
	base.Add(&knftables.Table{})
	base.Add(&knftables.Chain{Name: postrtgChain})
	if err := v4.Run(ctx, base); err != nil {
		t.Fatal(err)
	}

	tx := v4.NewTransaction()
	if err := mgr.addMasqRules(ctx, tx, "10.244.0.0/16", "10.244.1.0/24", knftables.IPv4Family, true); err != nil {
		t.Fatalf("addMasqRules: %v", err)
	}
	if err := v4.Run(ctx, tx); err != nil {
		t.Fatalf("run tx: %v", err)
	}
	if got := h632RuleCount(t, v4, postrtgChain); got != 6 {
		t.Fatalf("addMasqRules should add 6 rules, got %d", got)
	}
}

func TestH632SetupForwardAndMasqIdempotentWithFake(t *testing.T) {
	v4 := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	v6 := knftables.NewFake(knftables.IPv6Family, ipv6Table)
	mgr := NewNFTablesManagerWithInterfaces(v4, v6)
	ctx := context.Background()
	lease := h632TestLease()

	v4net := ip.IP4Net{IP: ip.MustParseIP4("10.244.0.0"), PrefixLen: 16}
	_, v6cidr, _ := net.ParseCIDR("fd00::/48")
	v6net := ip.FromIP6Net(v6cidr)

	// resyncPeriod 0 -> no background goroutine in tests.
	mgr.SetupAndEnsureForwardRules(ctx, v4net, v6net, 0)
	mgr.SetupAndEnsureForwardRules(ctx, v4net, v6net, 0)
	if got := h632RuleCount(t, v4, forwardChain); got != 2 {
		t.Fatalf("v4 forward rules should stay 2, got %d", got)
	}
	if got := h632RuleCount(t, v6, forwardChain); got != 2 {
		t.Fatalf("v6 forward rules should stay 2, got %d", got)
	}

	if err := mgr.SetupAndEnsureMasqRules(ctx,
		v4net, ip.IP4Net{}, ip.IP4Net{},
		v6net, ip.IP6Net{}, ip.IP6Net{},
		lease, 0, false); err != nil {
		t.Fatalf("masq setup: %v", err)
	}
	if got := h632RuleCount(t, v4, postrtgChain); got != 6 {
		t.Fatalf("expected 6 v4 masq rules, got %d", got)
	}
	if got := h632RuleCount(t, v6, postrtgChain); got != 6 {
		t.Fatalf("expected 6 v6 masq rules, got %d", got)
	}
	// Re-apply must not stack duplicates.
	if err := mgr.SetupAndEnsureMasqRules(ctx,
		v4net, ip.IP4Net{}, ip.IP4Net{},
		v6net, ip.IP6Net{}, ip.IP6Net{},
		lease, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := h632RuleCount(t, v4, postrtgChain); got != 6 {
		t.Fatalf("masq re-apply produced duplicates: %d rules", got)
	}
}
