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

package vxlan

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/vishvananda/netlink"
)

// fakeNetlinkOps records the kernel calls the forwarding plane makes and can
// be configured to fail a chosen operation so rollback paths are testable
// without a real kernel.
type fakeNetlinkOps struct {
	mu sync.Mutex

	neighSets []netlink.Neigh
	neighDels []netlink.Neigh
	routeSet  []netlink.Route
	routeDel  []netlink.Route
	linkDels  []string

	// neighs/routes returned to the reconciler.
	neighs map[int][]netlink.Neigh // link index -> neighbors
	routes map[int][]netlink.Route

	// failNeighSet, when non-empty, makes the matching NeighSet fail once.
	failNeighSetIP string
	failCount      int
}

func newFakeNetlinkOps() *fakeNetlinkOps {
	return &fakeNetlinkOps{
		neighs: make(map[int][]netlink.Neigh),
		routes: make(map[int][]netlink.Route),
	}
}

func (f *fakeNetlinkOps) NeighSet(n *netlink.Neigh) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNeighSetIP != "" && f.failCount == 0 && n.IP.String() == f.failNeighSetIP {
		f.failCount++
		return errors.New("injected NeighSet failure")
	}
	f.neighSets = append(f.neighSets, *n)
	f.neighs[n.LinkIndex] = append(f.neighs[n.LinkIndex], *n)
	return nil
}

func (f *fakeNetlinkOps) NeighDel(n *netlink.Neigh) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.neighDels = append(f.neighDels, *n)
	// Match the kernel: AF_BRIDGE FDB records are keyed by (IP, MAC), so a
	// MAC-less delete is rejected; other neighbors are keyed by IP alone.
	if n.Family == syscall.AF_BRIDGE && n.HardwareAddr == nil {
		return syscall.EINVAL
	}
	list := f.neighs[n.LinkIndex]
	kept := list[:0]
	for _, existing := range list {
		if existing.IP.Equal(n.IP) {
			if n.Family == syscall.AF_BRIDGE && existing.HardwareAddr.String() != n.HardwareAddr.String() {
				kept = append(kept, existing) // different MAC: not this record
				continue
			}
			continue
		}
		kept = append(kept, existing)
	}
	f.neighs[n.LinkIndex] = kept
	return nil
}

func (f *fakeNetlinkOps) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netlink.Neigh(nil), f.neighs[linkIndex]...), nil
}

func (f *fakeNetlinkOps) RouteReplace(r *netlink.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routeSet = append(f.routeSet, *r)
	f.routes[r.LinkIndex] = append(f.routes[r.LinkIndex], *r)
	return nil
}

func (f *fakeNetlinkOps) RouteDel(r *netlink.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routeDel = append(f.routeDel, *r)
	list := f.routes[r.LinkIndex]
	kept := list[:0]
	for _, existing := range list {
		if existing.Dst != nil && r.Dst != nil && existing.Dst.String() == r.Dst.String() {
			continue
		}
		kept = append(kept, existing)
	}
	f.routes[r.LinkIndex] = kept
	return nil
}

func (f *fakeNetlinkOps) RouteList(_ netlink.Link, linkIndex int) ([]netlink.Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netlink.Route(nil), f.routes[linkIndex]...), nil
}

func (f *fakeNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 7}}, nil
}

func (f *fakeNetlinkOps) LinkDel(link netlink.Link) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.linkDels = append(f.linkDels, link.Attrs().Name)
	return nil
}

func (f *fakeNetlinkOps) countNeighSets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.neighSets)
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

// testDevice builds a vxlanDevice shell carrying just the link index the
// forwarding plane needs; no real device is created.
func testDevice(name string, index int) *vxlanDevice {
	return &vxlanDevice{
		link:    &netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}},
		created: true,
	}
}

func newTestPlane(dev, v6Dev *vxlanDevice) *forwardingPlane {
	fp := newForwardingPlane()
	fp.ops = newFakeNetlinkOps()
	fp.setDevices(dev, v6Dev)
	return fp
}

func tunnelEntry(t *testing.T, subnetCIDR, publicIP, macStr string) *forwardingEntry {
	t.Helper()
	_, n, _ := net.ParseCIDR(subnetCIDR)
	return &forwardingEntry{
		kind:      entryTunnel,
		podSubnet: ip.FromIPNet(n),
		publicIP:  ip.MustParseIP4(publicIP),
		vtepMAC:   mustMAC(t, macStr),
		gatewayIP: ip.MustParseIP4(n.IP.String()).ToIP(),
	}
}

// TestForwardingPlane_AddLease_InstallsARP_FDB_Route verifies the happy path:
// one tunneled lease results in exactly one ARP, one FDB and one route
// operation, and gets registered for later teardown and aging.
func TestForwardingPlane_AddLease_InstallsARP_FDB_Route(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)

	e := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(e); err != nil {
		t.Fatalf("addLease failed: %v", err)
	}

	ops := fp.ops.(*fakeNetlinkOps)
	if got := ops.countNeighSets(); got != 2 {
		t.Fatalf("expected 2 NeighSet calls (ARP+FDB), got %d", got)
	}
	if len(ops.routeSet) != 1 {
		t.Fatalf("expected 1 RouteReplace, got %d", len(ops.routeSet))
	}
	route := ops.routeSet[0]
	if route.Dst.String() != "10.2.0.0/24" {
		t.Fatalf("route dst = %s, want 10.2.0.0/24", route.Dst)
	}
	if route.LinkIndex != 3 {
		t.Fatalf("route link index = %d, want 3", route.LinkIndex)
	}

	keys := fp.snapshotKeys()
	if len(keys) != 1 || keys[0] != "v4:10.2.0.0/24" {
		t.Fatalf("registry keys = %v, want [v4:10.2.0.0/24]", keys)
	}
}

// TestForwardingPlane_Conflict_OverlappingSubnetRejected covers requirement
// 4: a lease whose subnet overlaps an already registered one is refused and
// must not touch the kernel.
func TestForwardingPlane_Conflict_OverlappingSubnetRejected(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)

	first := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(first); err != nil {
		t.Fatalf("first addLease failed: %v", err)
	}
	setsBefore := fp.ops.(*fakeNetlinkOps).countNeighSets()

	overlap := tunnelEntry(t, "10.2.0.128/25", "192.0.2.11", "02:00:00:00:00:0b")
	err := fp.addLease(overlap)
	if !errors.Is(err, ErrConflictSubnet) {
		t.Fatalf("expected ErrConflictSubnet, got %v", err)
	}
	if got := fp.ops.(*fakeNetlinkOps).countNeighSets(); got != setsBefore {
		t.Fatalf("conflicting add issued kernel calls: before=%d after=%d", setsBefore, got)
	}
	if keys := fp.snapshotKeys(); len(keys) != 1 {
		t.Fatalf("registry should keep only the original entry, got %v", keys)
	}
}

// TestForwardingPlane_Conflict_DuplicatePublicIPRejected covers the FDB
// endpoint side of requirement 4: two subnets must not share a VTEP public IP.
func TestForwardingPlane_Conflict_DuplicatePublicIPRejected(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)

	first := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(first); err != nil {
		t.Fatal(err)
	}
	// Different, non-overlapping subnet but the same VTEP public IP.
	second := tunnelEntry(t, "10.3.0.0/24", "192.0.2.10", "02:00:00:00:00:0b")
	if err := fp.addLease(second); !errors.Is(err, ErrConflictSubnet) {
		t.Fatalf("expected ErrConflictSubnet for duplicate public IP, got %v", err)
	}
}

// TestForwardingPlane_SameKey_MacChangeReplacesOldEntry reproduces the
// production incident: a node restarts with a new VTEP MAC. The replacement
// must delete the stale kernel record by IP only (so the old-MAC entry is
// actually matched) and then install the new one.
func TestForwardingPlane_SameKey_MacChangeReplacesOldEntry(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)

	old := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(old); err != nil {
		t.Fatal(err)
	}

	newMAC := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:ff")
	if err := fp.addLease(newMAC); err != nil {
		t.Fatalf("re-add with new MAC failed: %v", err)
	}

	ops := fp.ops.(*fakeNetlinkOps)
	// ARP deletions are IP-based with a nil MAC (ARP is keyed by IP); FDB
	// deletions must carry the MAC because the kernel keys static FDB records
	// by (VTEP IP, VTEP MAC) and rejects MAC-less deletes.
	var sawARP, sawFDB bool
	for _, d := range ops.neighDels {
		if d.Family == syscall.AF_BRIDGE {
			sawFDB = true
			if d.HardwareAddr == nil {
				t.Fatalf("FDB deletion must carry the MAC, got IP-only delete for %v", d.IP)
			}
		} else {
			sawARP = true
			if d.HardwareAddr != nil {
				t.Fatalf("ARP deletion must be IP-only, got MAC %v", d.HardwareAddr)
			}
		}
	}
	if !sawARP || !sawFDB {
		t.Fatalf("expected both an ARP and an FDB deletion, got arp=%v fdb=%v", sawARP, sawFDB)
	}
	if keys := fp.snapshotKeys(); len(keys) != 1 || keys[0] != "v4:10.2.0.0/24" {
		t.Fatalf("registry should hold exactly one replaced entry, got %v", keys)
	}
}

// TestForwardingPlane_InstallFailure_RollsBack covers requirement 3 at the
// entry level: when the FDB install fails after ARP was installed, the ARP
// entry must be rolled back and nothing stays registered.
func TestForwardingPlane_InstallFailure_RollsBack(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)
	ops := fp.ops.(*fakeNetlinkOps)
	// Fail the second neighbor install (the FDB, whose IP is the public IP).
	ops.failNeighSetIP = "192.0.2.10"

	e := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(e); err == nil {
		t.Fatal("expected addLease to fail when FDB install fails")
	}

	if len(ops.neighDels) == 0 {
		t.Fatal("expected rollback deletions after failed install, got none")
	}
	if keys := fp.snapshotKeys(); len(keys) != 0 {
		t.Fatalf("failed install must not leave a registered entry, got %v", keys)
	}
}

// TestForwardingPlane_RemoveLease_IdempotentAndIPOnly covers requirement 1's
// removal side and the stale-MAC scenario again from the event-removed path.
func TestForwardingPlane_RemoveLease_IdempotentAndIPOnly(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)
	e := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(e); err != nil {
		t.Fatal(err)
	}

	if err := fp.removeLease("v4:10.2.0.0/24"); err != nil {
		t.Fatalf("removeLease failed: %v", err)
	}
	// Second removal is a no-op, not an error.
	if err := fp.removeLease("v4:10.2.0.0/24"); err != nil {
		t.Fatalf("repeated removeLease must be idempotent, got %v", err)
	}

	ops := fp.ops.(*fakeNetlinkOps)
	for _, d := range ops.neighDels {
		if d.Family != syscall.AF_BRIDGE && d.HardwareAddr != nil {
			t.Fatalf("ARP removal must be IP-only (nil MAC), got %v", d.HardwareAddr)
		}
	}
	if keys := fp.snapshotKeys(); len(keys) != 0 {
		t.Fatalf("registry should be empty after removal, got %v", keys)
	}
}

// TestForwardingPlane_PurgeFDB_RemovesStaleMAC covers the reported stale-FDB
// incident at the state-machine level: multiple kernel records may exist for
// one VTEP IP (one per MAC), and (re)installing the current lease must purge
// every other-MAC record rather than just appending another.
func TestForwardingPlane_PurgeFDB_RemovesStaleMAC(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)
	ops := fp.ops.(*fakeNetlinkOps)

	old := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(old); err != nil {
		t.Fatal(err)
	}
	// Simulate the kernel accumulation the probe demonstrated: an extra
	// stale-MAC FDB record for the same VTEP IP.
	ops.mu.Lock()
	staleMAC := mustMAC(t, "de:ad:be:ef:00:01")
	ops.neighs[3] = append(ops.neighs[3], netlink.Neigh{
		LinkIndex: 3, Family: syscall.AF_BRIDGE, Flags: netlink.NTF_SELF,
		IP: net.ParseIP("192.0.2.10"), HardwareAddr: staleMAC,
	})
	ops.mu.Unlock()

	newEntry := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:ff")
	if err := fp.addLease(newEntry); err != nil {
		t.Fatalf("re-add with new MAC failed: %v", err)
	}

	ops.mu.Lock()
	defer ops.mu.Unlock()
	for _, n := range ops.neighs[3] {
		if n.Family == syscall.AF_BRIDGE && n.IP.String() == "192.0.2.10" &&
			n.HardwareAddr.String() == staleMAC.String() {
			t.Fatalf("stale FDB record %s was not purged", staleMAC)
		}
	}
}

// TestForwardingPlane_Reconcile_RelearnsStaleEntry covers requirement 2:
// once an entry ages out, a missing or drifted kernel object is rewritten
// from the lease data.
func TestForwardingPlane_Reconcile_RelearnsStaleEntry(t *testing.T) {
	oldAge := entryAge
	oldInterval := reconcileInterval
	entryAge = time.Millisecond
	reconcileInterval = time.Hour // keep the background ticker out of the way
	defer func() {
		entryAge = oldAge
		reconcileInterval = oldInterval
	}()

	fp := newTestPlane(testDevice("flannel.1", 3), nil)
	e := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(e); err != nil {
		t.Fatal(err)
	}
	ops := fp.ops.(*fakeNetlinkOps)
	setsBefore := ops.countNeighSets()

	// Simulate external drift: the kernel FDB/ARP records vanished.
	ops.neighs[3] = nil
	time.Sleep(2 * time.Millisecond)

	fp.reconcile()
	if got := ops.countNeighSets(); got <= setsBefore {
		t.Fatalf("reconcile should have re-added neighbors: before=%d after=%d", setsBefore, got)
	}
	// A fresh entry must not be rewritten on the next sweep.
	setsBefore = ops.countNeighSets()
	fp.reconcile()
	if got := ops.countNeighSets(); got != setsBefore {
		t.Fatalf("fresh entry was needlessly rewritten: before=%d after=%d", setsBefore, got)
	}
}

// TestForwardingPlane_Close_IdempotentAndOnlyOwnedDevices covers requirement
// 5: Close removes all registered entries and only the owned devices, and a
// second Close is a no-op.
func TestForwardingPlane_Close_IdempotentAndOnlyOwnedDevices(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), testDevice("flannel-v6.1", 4))
	fp.trackDevice("flannel.1")
	// flannel-v6.1 is adopted (not tracked): it must survive Close.

	e := tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")
	if err := fp.addLease(e); err != nil {
		t.Fatal(err)
	}

	if err := fp.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := fp.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}

	ops := fp.ops.(*fakeNetlinkOps)
	if len(ops.neighDels) == 0 {
		t.Fatal("Close did not remove registered neighbors")
	}
	if len(ops.linkDels) != 1 || ops.linkDels[0] != "flannel.1" {
		t.Fatalf("Close deleted devices %v, want only [flannel.1]", ops.linkDels)
	}
	if keys := fp.snapshotKeys(); len(keys) != 0 {
		t.Fatalf("registry should be empty after Close, got %v", keys)
	}

	// Operations after Close must be rejected rather than resurrecting state.
	if err := fp.addLease(e); err == nil {
		t.Fatal("addLease after Close must fail")
	}
}

// TestForwardingPlane_SetDevices_ClearsRegistry verifies a device recreation
// drops the stale registry so the lease replay repopulates it from scratch.
func TestForwardingPlane_SetDevices_ClearsRegistry(t *testing.T) {
	fp := newTestPlane(testDevice("flannel.1", 3), nil)
	if err := fp.addLease(tunnelEntry(t, "10.2.0.0/24", "192.0.2.10", "02:00:00:00:00:0a")); err != nil {
		t.Fatal(err)
	}

	fp.setDevices(testDevice("flannel.1", 9), nil)
	if keys := fp.snapshotKeys(); len(keys) != 0 {
		t.Fatalf("registry should be empty after device swap, got %v", keys)
	}
}

// TestIsNotExist checks the teardown tolerance for already-gone objects.
func TestIsNotExist(t *testing.T) {
	for _, err := range []error{syscall.ESRCH, syscall.ENOENT, syscall.ENODEV} {
		if !isNotExist(err) {
			t.Fatalf("%v must be treated as not-exist", err)
		}
	}
	if isNotExist(fmt.Errorf("some other failure")) {
		t.Fatal("generic error must not be treated as not-exist")
	}
}
