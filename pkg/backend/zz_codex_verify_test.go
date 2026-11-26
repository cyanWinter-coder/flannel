//go:build !windows
// +build !windows

// Copyright 2026 Flannel Authors
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

package backend

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func zzCodexIPNet(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func zzCodexIP(s string) net.IP { return net.ParseIP(s) }

func TestZZCodexDiffSafetyAndIdempotence(t *testing.T) {
	want := netlink.Route{Dst: zzCodexIPNet("10.42.0.0/24"), Gw: zzCodexIP("10.0.0.1"), LinkIndex: 7}
	same := want
	wrongGW := want
	wrongGW.Gw = zzCodexIP("10.0.0.9")
	extra := netlink.Route{Dst: zzCodexIPNet("10.42.1.0/24"), Gw: zzCodexIP("10.0.0.2"), LinkIndex: 7}
	def := netlink.Route{Dst: nil, Gw: zzCodexIP("10.0.0.254")}

	add, del := diffRoutes([]netlink.Route{want}, []netlink.Route{same, wrongGW, extra, def})
	if len(add) != 0 {
		t.Fatalf("exact desired route already exists, unexpected add: %+v", add)
	}
	if len(del) != 2 {
		t.Fatalf("expected wrong-gw and extra deletions, got %+v", del)
	}

	add, del = diffRoutes([]netlink.Route{want}, []netlink.Route{wrongGW, extra, def})
	if len(add) != 1 || !routeEqual(add[0], want) {
		t.Fatalf("unexpected replacement add: %+v", add)
	}
	if len(del) != 2 {
		t.Fatalf("expected wrong-gw and extra deletions, got %+v", del)
	}
	for _, r := range del {
		if isDefaultRoute(r) {
			t.Fatalf("default route proposed for deletion: %+v", r)
		}
	}

	add, del = diffRoutes([]netlink.Route{want}, []netlink.Route{same})
	if len(add) != 0 || len(del) != 0 {
		t.Fatalf("same state produced diff add=%v del=%v", add, del)
	}
}

func TestZZCodexReconcileFamilyAddDeleteAndNoop(t *testing.T) {
	oldList := netlinkRouteListFn
	oldAdd := netlinkRouteAddFn
	oldDel := netlinkRouteDelFn
	defer func() {
		netlinkRouteListFn = oldList
		netlinkRouteAddFn = oldAdd
		netlinkRouteDelFn = oldDel
	}()

	want := netlink.Route{Dst: zzCodexIPNet("10.42.0.0/24"), Gw: zzCodexIP("10.0.0.1"), LinkIndex: 7}
	extra := netlink.Route{Dst: zzCodexIPNet("10.42.9.0/24"), Gw: zzCodexIP("10.0.0.9"), LinkIndex: 7}
	current := []netlink.Route{extra}
	var adds, dels int
	netlinkRouteListFn = func(netlink.Link, int) ([]netlink.Route, error) { return current, nil }
	netlinkRouteAddFn = func(r *netlink.Route) error {
		adds++
		current = append(current, *r)
		return nil
	}
	netlinkRouteDelFn = func(r *netlink.Route) error {
		dels++
		next := current[:0]
		for _, x := range current {
			if routeEqual(x, *r) {
				continue
			}
			next = append(next, x)
		}
		current = next
		return nil
	}

	nw := &RouteNetwork{SyncConfig: RouteSyncConfig{Timeout: time.Second, MaxRetries: -1}}
	res := nw.ReconcileFamily(context.Background(), netlink.FAMILY_V4, []netlink.Route{want})
	if !res.Healthy() || res.Added != 1 || res.Deleted != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if adds != 1 || dels != 1 {
		t.Fatalf("calls add=%d del=%d", adds, dels)
	}

	adds, dels = 0, 0
	res = nw.ReconcileFamily(context.Background(), netlink.FAMILY_V4, []netlink.Route{want})
	if res.Changed() || adds != 0 || dels != 0 || res.Unchanged != 1 {
		t.Fatalf("second sync not idempotent: result=%+v add=%d del=%d", res, adds, dels)
	}
}

func TestZZCodexReconcileFamilyProtectsDefaultAndUnowned(t *testing.T) {
	oldList := netlinkRouteListFn
	oldDel := netlinkRouteDelFn
	defer func() { netlinkRouteListFn = oldList; netlinkRouteDelFn = oldDel }()

	def := netlink.Route{Dst: zzCodexIPNet("0.0.0.0/0"), Gw: zzCodexIP("192.168.0.1")}
	unowned := netlink.Route{Dst: zzCodexIPNet("192.168.50.0/24"), Gw: zzCodexIP("192.168.0.2")}
	owned := netlink.Route{Dst: zzCodexIPNet("10.42.7.0/24"), Gw: zzCodexIP("10.0.0.7")}
	netlinkRouteListFn = func(netlink.Link, int) ([]netlink.Route, error) {
		return []netlink.Route{def, unowned, owned}, nil
	}
	var deleted []string
	netlinkRouteDelFn = func(r *netlink.Route) error {
		deleted = append(deleted, r.Dst.String())
		return nil
	}

	nw := &RouteNetwork{ManagedCIDRs: []*net.IPNet{zzCodexIPNet("10.42.0.0/16")}}
	res := nw.ReconcileFamily(context.Background(), netlink.FAMILY_V4, nil)
	if res.SkippedDefault != 1 || res.SkippedUnowned != 1 || res.Deleted != 1 {
		t.Fatalf("unexpected safety result: %+v deleted=%v", res, deleted)
	}
	if len(deleted) != 1 || deleted[0] != "10.42.7.0/24" {
		t.Fatalf("wrong deletions: %v", deleted)
	}
}

func TestZZCodexReconcileFamilyTimeout(t *testing.T) {
	oldList := netlinkRouteListFn
	defer func() { netlinkRouteListFn = oldList }()
	release := make(chan struct{})
	defer close(release)
	netlinkRouteListFn = func(netlink.Link, int) ([]netlink.Route, error) {
		<-release
		return nil, nil
	}
	nw := &RouteNetwork{SyncConfig: RouteSyncConfig{Timeout: 5 * time.Millisecond}}
	res := nw.ReconcileFamily(context.Background(), netlink.FAMILY_V4, nil)
	if !res.TimedOut && !errors.Is(res.ListError, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %+v", res)
	}
}

func TestZZCodexFailureStatusPreservesSnapshot(t *testing.T) {
	nw := &RouteNetwork{}
	st := nw.getSyncStatus(netlink.FAMILY_V4)
	cfg := RouteSyncConfig{AlertThreshold: 2}
	res := RouteSyncResult{Family: netlink.FAMILY_V4}
	for i := 0; i < 2; i++ {
		nw.handleSyncFailure(st, res, errors.New("boom"), cfg,
			[]netlink.Route{{Dst: zzCodexIPNet("10.42.0.0/24")}},
			[]netlink.Route{{Dst: zzCodexIPNet("10.42.1.0/24")}})
	}
	got := nw.RouteSyncStatusFor(netlink.FAMILY_V4)
	if !got.Exhausted || got.Alerts != 1 || got.FailureSnapshot == nil {
		t.Fatalf("status not preserved: %+v", got)
	}
	if len(got.FailureSnapshot.Expected) != 1 || len(got.FailureSnapshot.Actual) != 1 {
		t.Fatalf("snapshot routes missing: %+v", got.FailureSnapshot)
	}
}
