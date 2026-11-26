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
	"net"
	"testing"

	"github.com/flannel-io/flannel/pkg/ns"
	"github.com/vishvananda/netlink"
)

func TestZZCodexNetnsReconcileAddsIdempotentlyAndProtectsDefault(t *testing.T) {
	teardown := ns.SetUpNetlinkTest(t)
	defer teardown()

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(lo, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)}}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}

	want := netlink.Route{
		Dst:       zzCodexIPNet("10.244.0.0/24"),
		Gw:        net.ParseIP("127.0.0.1"),
		LinkIndex: lo.Attrs().Index,
	}
	nw := &RouteNetwork{LinkIndex: lo.Attrs().Index}

	first := nw.ReconcileFamily(context.Background(), netlink.FAMILY_V4, []netlink.Route{want})
	if !first.Healthy() || first.Added != 1 {
		t.Fatalf("first reconcile failed: %+v", first)
	}
	second := nw.ReconcileFamily(context.Background(), netlink.FAMILY_V4, []netlink.Route{want})
	if second.Changed() || second.Unchanged != 1 {
		t.Fatalf("second reconcile was not idempotent: %+v", second)
	}

	extra := netlink.Route{
		Dst:       zzCodexIPNet("10.244.99.0/24"),
		Gw:        net.ParseIP("127.0.0.1"),
		LinkIndex: lo.Attrs().Index,
	}
	if err := netlink.RouteAdd(&extra); err != nil {
		t.Fatalf("add extra route: %v", err)
	}
	before, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("routes after extra add: %+v", before)
	third := nw.ReconcileFamily(context.Background(), netlink.FAMILY_V4, []netlink.Route{want})
	if !third.Healthy() || third.Deleted != 1 {
		t.Fatalf("third reconcile did not delete extra route: %+v", third)
	}
	remaining, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Dst: extra.Dst}, netlink.RT_FILTER_DST)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("extra route still present: %+v", remaining)
	}

	// A default route must never be proposed for deletion.
	def := netlink.Route{Dst: nil, Gw: net.ParseIP("127.0.0.1"), LinkIndex: lo.Attrs().Index}
	add, del := diffRoutes(nil, []netlink.Route{def})
	if len(add) != 0 || len(del) != 0 {
		t.Fatalf("default route entered diff: add=%+v del=%+v", add, del)
	}
}
