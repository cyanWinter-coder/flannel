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
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/trafficmngr"
)

func h632ParseNet(t *testing.T, cidr string) ip.IP4Net {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return ip.FromIPNet(ipNet)
}

// h632FakeClient serves canned `iptables -S` lines.
type h632FakeClient struct {
	lines       map[string][]string // key table\x00chain
	chainExists bool
	newChains   []string
}

func (f *h632FakeClient) key(table, chain string) string { return table + "\x00" + chain }

func (f *h632FakeClient) List(table, chain string) ([]string, error) {
	if lines, ok := f.lines[f.key(table, chain)]; ok {
		return lines, nil
	}
	// Mirror a missing chain error.
	return nil, errors.New("iptables: Bad rule (does a matching rule exist in that chain?).")
}

func (f *h632FakeClient) ChainExists(_, _ string) (bool, error) {
	return f.chainExists, nil
}

func (f *h632FakeClient) NewChain(table, chain string) error {
	f.newChains = append(f.newChains, table+"/"+chain)
	return nil
}

// h632FakeRestore records payloads and can be told to fail.
type h632FakeRestore struct {
	payloads []IPTablesRestoreRules
	fail     bool
}

func (m *h632FakeRestore) ApplyWithoutFlush(r IPTablesRestoreRules) error {
	m.payloads = append(m.payloads, r)
	if m.fail {
		return errors.New("simulated iptables-restore failure")
	}
	return nil
}

type h632FakeSnap struct {
	snap     []byte
	restored int
	fail     bool
}

func (s *h632FakeSnap) SnapshotRules(_ context.Context) ([]byte, error) {
	s.snap = []byte("fake-snapshot")
	return s.snap, nil
}

func (s *h632FakeSnap) RestoreRules(_ context.Context, data []byte) error {
	if s.fail {
		return errors.New("restore failed")
	}
	if string(data) != "fake-snapshot" {
		return errors.New("unexpected snapshot payload")
	}
	s.restored++
	return nil
}

func boolPtrH632(b bool) *bool { return &b }

func TestH632ParseSaveRuleLineQuotesAndNegation(t *testing.T) {
	line := `-A FLANNEL-POSTRTG ! -s 10.244.0.0/16 -d 10.244.0.0/16 -m comment --comment "flanneld masq" -j RETURN`
	chain, spec, ok := ParseSaveRuleLine(line)
	if !ok || chain != "FLANNEL-POSTRTG" {
		t.Fatalf("parse failed: ok=%v chain=%q", ok, chain)
	}
	joined := strings.Join(spec, " ")
	if !strings.Contains(joined, "! -s 10.244.0.0/16") {
		t.Fatalf("negation/cidr not canonicalized: %v", spec)
	}
	foundComment := false
	for i, tok := range spec {
		if tok == "--comment" && i+1 < len(spec) && spec[i+1] == "flanneld masq" {
			foundComment = true
		}
	}
	if !foundComment {
		t.Fatalf("quoted comment should be one token: %v", spec)
	}

	// Alternate post-option negation spelling canonicalizes to the same key.
	other := CanonicalizeSpec([]string{"-s", "!", "10.244.0.0/16"})
	want := CanonicalizeSpec([]string{"!", "-s", "10.244.0.0/16"})
	if strings.Join(other, "|") != strings.Join(want, "|") {
		t.Fatalf("negation forms differ: %v vs %v", other, want)
	}
}

func TestH632ReconcileDeletesThousandsOfDuplicateJumps(t *testing.T) {
	rules := []trafficmngr.IPTablesRule{
		{Table: "filter", Action: "-A", Chain: "FORWARD", Rulespec: []string{"-m", "comment", "--comment", "flanneld forward", "-j", "FLANNEL-FWD"}},
		{Table: "filter", Action: "-A", Chain: "FLANNEL-FWD", Rulespec: []string{"-s", "10.244.0.0/16", "-m", "comment", "--comment", "flanneld forward", "-j", "ACCEPT"}},
		{Table: "filter", Action: "-A", Chain: "FLANNEL-FWD", Rulespec: []string{"-d", "10.244.0.0/16", "-m", "comment", "--comment", "flanneld forward", "-j", "ACCEPT"}},
	}

	const dup = 3000
	forwardLines := []string{
		"-A FORWARD -j KUBE-FORWARD", // unrelated rule must be left alone
	}
	for i := 0; i < dup; i++ {
		forwardLines = append(forwardLines, `-A FORWARD -m comment --comment "flanneld forward" -j FLANNEL-FWD`)
	}
	client := &h632FakeClient{
		chainExists: true,
		lines: map[string][]string{
			"filter\x00FORWARD":     forwardLines,
			"filter\x00FLANNEL-FWD": {}, // empty owned chain
		},
	}
	restore := &h632FakeRestore{}

	res, err := ReconcileRules(context.Background(), client, restore, rules, trafficmngr.IPv4, ReconcileOptions{
		RollbackOnFailure: boolPtrH632(false),
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if res.Deleted != dup-1 {
		t.Fatalf("expected %d duplicate deletions, got %d", dup-1, res.Deleted)
	}
	// The empty ordered chain must be populated (2 adds).
	if res.Added != 2 {
		t.Fatalf("expected 2 adds for empty FLANNEL-FWD, got %d", res.Added)
	}
	if res.DuplicatesRemoved != dup-1 {
		t.Fatalf("expected duplicatesRemoved=%d got %d", dup-1, res.DuplicatesRemoved)
	}

	// All duplicate -D lines must be present in one restore payload.
	deleteJumps := 0
	for _, p := range restore.payloads {
		for table, specs := range p {
			if table != "filter" {
				continue
			}
			for _, s := range specs {
				if len(s) >= 2 && s[0] == "-D" && s[1] == "FORWARD" {
					deleteJumps++
				}
			}
		}
	}
	if deleteJumps != dup-1 {
		t.Fatalf("expected one -D per surplus jump (%d), got %d", dup-1, deleteJumps)
	}
}

func TestH632ReconcileConvergedStateIsNoop(t *testing.T) {
	rules := []trafficmngr.IPTablesRule{
		{Table: "filter", Action: "-A", Chain: "FORWARD", Rulespec: []string{"-m", "comment", "--comment", "flanneld forward", "-j", "FLANNEL-FWD"}},
		{Table: "filter", Action: "-A", Chain: "FLANNEL-FWD", Rulespec: []string{"-s", "10.244.0.0/16", "-m", "comment", "--comment", "flanneld forward", "-j", "ACCEPT"}},
		{Table: "filter", Action: "-A", Chain: "FLANNEL-FWD", Rulespec: []string{"-d", "10.244.0.0/16", "-m", "comment", "--comment", "flanneld forward", "-j", "ACCEPT"}},
	}
	client := &h632FakeClient{
		chainExists: true,
		lines: map[string][]string{
			"filter\x00FORWARD": {
				`-A FORWARD -m comment --comment "flanneld forward" -j FLANNEL-FWD`,
				"-A FORWARD -j KUBE-FORWARD",
			},
			"filter\x00FLANNEL-FWD": {
				`-A FLANNEL-FWD -s 10.244.0.0/16 -m comment --comment "flanneld forward" -j ACCEPT`,
				`-A FLANNEL-FWD -d 10.244.0.0/16 -m comment --comment "flanneld forward" -j ACCEPT`,
			},
		},
	}
	restore := &h632FakeRestore{}
	res, err := ReconcileRules(context.Background(), client, restore, rules, trafficmngr.IPv4, ReconcileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed() {
		t.Fatalf("converged state should require no changes, got added=%d deleted=%d changes=%q",
			res.Added, res.Deleted, res.Diff)
	}
	if len(restore.payloads) != 0 {
		t.Fatalf("no restore payload expected, got %d", len(restore.payloads))
	}
}

func TestH632DryRunReportsButDoesNotApply(t *testing.T) {
	rules := []trafficmngr.IPTablesRule{
		{Table: "nat", Action: "-A", Chain: "POSTROUTING", Rulespec: []string{"-j", "FLANNEL-POSTRTG"}},
	}
	client := &h632FakeClient{chainExists: true, lines: map[string][]string{}}
	restore := &h632FakeRestore{}
	res, err := ReconcileRules(context.Background(), client, restore, rules, trafficmngr.IPv4,
		ReconcileOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Added != 1 {
		t.Fatalf("unexpected dry-run result: %+v", res)
	}
	if len(restore.payloads) != 0 {
		t.Fatal("dry-run must not apply restore payloads")
	}
	if !strings.Contains(res.Diff, "+") {
		t.Fatalf("dry-run diff should show additions: %q", res.Diff)
	}
	if res.Duration < 0 {
		t.Fatal("duration missing")
	}
}

func TestH632ApplyFailureRollsBackSnapshot(t *testing.T) {
	rules := []trafficmngr.IPTablesRule{
		{Table: "nat", Action: "-A", Chain: "POSTROUTING", Rulespec: []string{"-j", "FLANNEL-POSTRTG"}},
	}
	client := &h632FakeClient{chainExists: true, lines: map[string][]string{}}
	restore := &h632FakeRestore{fail: true}
	snap := &h632FakeSnap{}
	res, err := ReconcileRules(context.Background(), client, restore, rules, trafficmngr.IPv4, ReconcileOptions{
		Snapshotter: snap,
	})
	if err == nil {
		t.Fatal("expected apply error")
	}
	if res == nil || !res.RolledBack {
		t.Fatalf("expected rolled back result, res=%+v", res)
	}
	if snap.restored != 1 {
		t.Fatalf("snapshot should be restored once, got %d", snap.restored)
	}
}

func TestH632MissingOwnedChainGetsCreated(t *testing.T) {
	rules := []trafficmngr.IPTablesRule{
		{Table: "filter", Action: "-A", Chain: "FLANNEL-FWD", Rulespec: []string{"-j", "ACCEPT"}},
	}
	client := &h632FakeClient{chainExists: false, lines: map[string][]string{}}
	restore := &h632FakeRestore{}
	if _, err := ReconcileRules(context.Background(), client, restore, rules, trafficmngr.IPv4, ReconcileOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(client.newChains) != 1 || client.newChains[0] != "filter/FLANNEL-FWD" {
		t.Fatalf("expected chain creation, got %v", client.newChains)
	}
}

func TestH632CleanupPayloadIncludesAllJumpCopies(t *testing.T) {
	const dup = 2500
	lines := []string{}
	for i := 0; i < dup; i++ {
		lines = append(lines, `-A POSTROUTING -m mark --mark 0x4000/0x4000 -m comment --comment "flanneld masq" -j FLANNEL-POSTRTG`)
	}
	lines = append(lines, "-A POSTROUTING -j KUBE-POSTROUTING")
	client := &h632FakeClient{
		lines: map[string][]string{
			"nat\x00POSTROUTING": lines,
			"filter\x00FORWARD":  {},
		},
	}
	payload := BuildParentJumpCleanupRules(client)
	natDeletes := 0
	for _, s := range payload["nat"] {
		if len(s) >= 2 && s[0] == "-D" && s[1] == "POSTROUTING" {
			natDeletes++
		}
	}
	if natDeletes != dup {
		t.Fatalf("cleanup should delete all %d jump copies, got %d", dup, natDeletes)
	}
	if _, ok := payload["filter"]; ok {
		t.Fatal("empty FORWARD chain should not produce filter payload")
	}
}

// TestH632GeneratedMasqRulesRoundTrip ensures the rules flannel generates
// compare equal to their parsed `iptables -S` rendering, so the hourly resync
// does not needlessly flush/rebuild chains.
func TestH632GeneratedMasqRulesRoundTrip(t *testing.T) {
	iptm := &IPTablesManager{}
	rules := iptm.masqRules(h632ParseNet(t, "10.244.0.0/16"), testingLease(), false)
	coreRules := ToCoreRules(rules, trafficmngr.IPv4)

	live := map[chainRef][]trafficmngr.Rule{}
	for _, r := range coreRules {
		line := h632RenderSLine(r.Chain, r.Rulespec)
		chain, spec, ok := ParseSaveRuleLine(line)
		if !ok {
			t.Fatalf("failed to parse rendered line: %s", line)
		}
		ref := chainRef{r.Table, chain}
		live[ref] = append(live[ref], trafficmngr.Rule{
			Family: trafficmngr.IPv4, Table: r.Table, Chain: chain, Action: "-A", Rulespec: spec,
		})
	}
	plan := BuildPlan(coreRules, live)
	if plan.HasChanges() {
		t.Fatalf("generated rules should round-trip as converged, got changes:\n%s",
			trafficmngr.FormatChanges(plan.Changes))
	}
}

func h632RenderSLine(chain string, spec []string) string {
	parts := []string{"-A", chain}
	for i := 0; i < len(spec); i++ {
		parts = append(parts, spec[i])
		if spec[i] == "--comment" && i+1 < len(spec) {
			parts = append(parts, `"`+spec[i+1]+`"`)
			i++
		}
	}
	return strings.Join(parts, " ")
}
