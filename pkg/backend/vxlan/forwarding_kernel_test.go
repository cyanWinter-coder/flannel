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
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/flannel-io/flannel/pkg/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/ns"
	"github.com/flannel-io/flannel/pkg/subnet"
	"github.com/vishvananda/netlink"
)

// neighByIP finds the neighbor for want in a dump, or nil. family is
// syscall.AF_BRIDGE for FDB records or netlink.FAMILY_V4 for ARP.
func neighByIP(t *testing.T, linkIndex, family int, want net.IP) *netlink.Neigh {
	t.Helper()
	neighs, err := netlink.NeighList(linkIndex, family)
	if err != nil {
		t.Fatalf("NeighList(family=%d) failed: %v", family, err)
	}
	for i := range neighs {
		if neighs[i].IP.Equal(want) {
			return &neighs[i]
		}
	}
	return nil
}

func vxlanLease(subnetCIDR, publicIP, macStr string) lease.Lease {
	_, remoteNet, _ := net.ParseCIDR(subnetCIDR)
	return lease.Lease{
		EnableIPv4: true,
		Subnet:     ip.FromIPNet(remoteNet),
		Attrs: lease.LeaseAttrs{
			PublicIP:    ip.MustParseIP4(publicIP),
			BackendType: "vxlan",
			BackendData: []byte(`{"VNI":1,"VtepMAC":"` + macStr + `"}`),
		},
	}
}

// newKernelNetwork builds a network backed by a real VXLAN device inside the
// test's network namespace, with a default (real netlink) forwarding plane.
func newKernelNetwork(t *testing.T, extName string) (*network, *vxlanDevice, *fakeSubnetManager) {
	t.Helper()
	extIface := addDummyLink(t, extName, "192.0.2.1/24")

	_, podNet, _ := net.ParseCIDR("198.18.0.0/16")
	_, ownNet, _ := net.ParseCIDR("198.18.1.0/24")
	sm := &fakeSubnetManager{config: &subnet.Config{
		EnableIPv4: true,
		Network:    ip.FromIPNet(podNet),
		Backend:    []byte(`{"Type":"vxlan","VNI":1}`),
	}}
	own := &lease.Lease{EnableIPv4: true, Subnet: ip.FromIPNet(ownNet)}

	cfg, err := parseVXLANConfig(sm.config.Backend, extIface.MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev, _, err := createVXLANDevice(t.Context(), sm.config, cfg, sm, extIface.Index, net.ParseIP("192.0.2.1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := configureDeviceIPv4IPv6(dev, nil, own, sm.config); err != nil {
		t.Fatal(err)
	}

	nw := &network{
		SimpleNetwork: backend.SimpleNetwork{SubnetLease: own, ExtIface: &backend.ExternalInterface{IfaceName: extName}},
		dev:           dev,
		subnetMgr:     sm,
	}
	nw.fp = newForwardingPlane() // real netlink ops
	nw.fp.setDevices(dev, nil)
	nw.fp.trackDevice(dev.link.Attrs().Name)
	nw.knownLeases.OwnLease = own
	return nw, dev, sm
}

// TestKernel_LeaseLifecycle_ARP_FDB_Route exercises requirement 1 against a
// real kernel: an added lease programs ARP, FDB and a route, and a removed
// lease tears all three down again.
func TestKernel_LeaseLifecycle_ARP_FDB_Route(t *testing.T) {
	teardown := ns.SetUpNetlinkTest(t)
	defer teardown()

	nw, dev, _ := newKernelNetwork(t, "ext0")
	index := dev.link.Index
	remote := vxlanLease("198.18.2.0/24", "192.0.2.2", "02:00:00:00:00:02")

	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventAdded, Lease: remote}})

	publicIP := net.ParseIP("192.0.2.2")
	gwIP := net.ParseIP("198.18.2.0")
	if n := neighByIP(t, index, syscall.AF_BRIDGE, publicIP); n == nil {
		t.Fatal("FDB entry for the VTEP public IP was not installed")
	}
	if n := neighByIP(t, index, netlink.FAMILY_V4, gwIP); n == nil {
		t.Fatal("ARP entry for the subnet gateway IP was not installed")
	}
	if !hasRoute(t, dev.link.Attrs().Name, remote.Subnet.ToIPNet()) {
		t.Fatal("route to the remote subnet was not installed")
	}

	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventRemoved, Lease: remote}})
	if n := neighByIP(t, index, syscall.AF_BRIDGE, publicIP); n != nil {
		t.Fatalf("FDB entry survived lease removal: %v", n)
	}
	if n := neighByIP(t, index, netlink.FAMILY_V4, gwIP); n != nil {
		t.Fatalf("ARP entry survived lease removal: %v", n)
	}
	if hasRoute(t, dev.link.Attrs().Name, remote.Subnet.ToIPNet()) {
		t.Fatal("route survived lease removal")
	}
}

// TestKernel_StaleFDB_MacChangeIsRepaired reproduces the reported incident:
// an FDB record pointing at a restarted node's old VTEP MAC must be replaced
// by the new MAC when the updated lease arrives, without anyone manually
// deleting the stale entry.
func TestKernel_StaleFDB_MacChangeIsRepaired(t *testing.T) {
	teardown := ns.SetUpNetlinkTest(t)
	defer teardown()

	nw, dev, _ := newKernelNetwork(t, "ext0")
	index := dev.link.Index
	publicIP := net.ParseIP("192.0.2.2")
	gwIP := net.ParseIP("198.18.2.0")

	first := vxlanLease("198.18.2.0/24", "192.0.2.2", "02:00:00:00:00:02")
	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventAdded, Lease: first}})

	// Simulate drift: the kernel FDB/ARP now point at a stale, old MAC that
	// no longer matches the lease flannel holds.
	staleMAC, _ := net.ParseMAC("de:ad:be:ef:00:01")
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: index, State: netlink.NUD_PERMANENT, Family: syscall.AF_BRIDGE,
		Flags: netlink.NTF_SELF, IP: publicIP, HardwareAddr: staleMAC,
	}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: index, State: netlink.NUD_PERMANENT, Type: syscall.RTN_UNICAST,
		IP: gwIP, HardwareAddr: staleMAC,
	}); err != nil {
		t.Fatal(err)
	}
	if got := neighByIP(t, index, syscall.AF_BRIDGE, publicIP); got.HardwareAddr.String() != staleMAC.String() {
		t.Fatalf("test setup: stale FDB not in place, got %v", got.HardwareAddr)
	}

	// The node comes back with a new VTEP MAC.
	newMAC := "02:00:00:00:00:ff"
	restarted := vxlanLease("198.18.2.0/24", "192.0.2.2", newMAC)
	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventAdded, Lease: restarted}})

	wantMAC, _ := net.ParseMAC(newMAC)
	if got := neighByIP(t, index, syscall.AF_BRIDGE, publicIP); got == nil || got.HardwareAddr.String() != wantMAC.String() {
		t.Fatalf("FDB not repaired to new MAC %s: %v", newMAC, got)
	}
	if got := neighByIP(t, index, netlink.FAMILY_V4, gwIP); got == nil || got.HardwareAddr.String() != wantMAC.String() {
		t.Fatalf("ARP not repaired to new MAC %s: %v", newMAC, got)
	}
}

// TestKernel_ConflictLease_RefusedAndExistingEntriesUntouched covers
// requirement 4 end to end: a conflicting lease is refused and the kernel
// objects of the original lease remain exactly as they were.
func TestKernel_ConflictLease_RefusedAndExistingEntriesUntouched(t *testing.T) {
	teardown := ns.SetUpNetlinkTest(t)
	defer teardown()

	nw, dev, _ := newKernelNetwork(t, "ext0")
	index := dev.link.Index
	first := vxlanLease("198.18.2.0/24", "192.0.2.2", "02:00:00:00:00:02")
	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventAdded, Lease: first}})

	fdbBefore := neighByIP(t, index, syscall.AF_BRIDGE, net.ParseIP("192.0.2.2"))
	keysBefore := nw.fp.snapshotKeys()

	// Overlapping subnet (same /24 range) must be rejected.
	conflict := vxlanLease("198.18.2.128/25", "192.0.2.3", "02:00:00:00:00:03")
	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventAdded, Lease: conflict}})

	fdbAfter := neighByIP(t, index, syscall.AF_BRIDGE, net.ParseIP("192.0.2.2"))
	if fdbAfter == nil || fdbAfter.HardwareAddr.String() != fdbBefore.HardwareAddr.String() {
		t.Fatalf("original FDB entry changed after conflict: before=%v after=%v", fdbBefore, fdbAfter)
	}
	if keys := nw.fp.snapshotKeys(); len(keys) != len(keysBefore) {
		t.Fatalf("registry changed after refused conflict: before=%v after=%v", keysBefore, keys)
	}
	if n := neighByIP(t, index, syscall.AF_BRIDGE, net.ParseIP("192.0.2.3")); n != nil {
		t.Fatalf("refused lease left an FDB entry behind: %v", n)
	}
}

// TestKernel_Reconcile_RelearnsAgedEntry covers requirement 2 against a real
// kernel: once the entry ages out, a drifted FDB record is detected and
// rewritten from the lease data.
func TestKernel_Reconcile_RelearnsAgedEntry(t *testing.T) {
	oldAge := entryAge
	entryAge = time.Millisecond
	defer func() { entryAge = oldAge }()

	teardown := ns.SetUpNetlinkTest(t)
	defer teardown()

	nw, dev, _ := newKernelNetwork(t, "ext0")
	index := dev.link.Index
	publicIP := net.ParseIP("192.0.2.2")

	l := vxlanLease("198.18.2.0/24", "192.0.2.2", "02:00:00:00:00:02")
	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventAdded, Lease: l}})

	// Corrupt the FDB to a stale MAC.
	staleMAC, _ := net.ParseMAC("de:ad:be:ef:00:02")
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: index, State: netlink.NUD_PERMANENT, Family: syscall.AF_BRIDGE,
		Flags: netlink.NTF_SELF, IP: publicIP, HardwareAddr: staleMAC,
	}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Millisecond)
	nw.fp.reconcile()

	wantMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	if got := neighByIP(t, index, syscall.AF_BRIDGE, publicIP); got == nil || got.HardwareAddr.String() != wantMAC.String() {
		t.Fatalf("aged reconcile did not restore FDB to lease MAC: %v", got)
	}
}

// TestKernel_Close_RemovesOwnedDeviceAndEntries covers requirement 5 against
// a real kernel: Close removes the entries and the device this process
// created, leaves an adopted device alone, and stays idempotent.
func TestKernel_Close_RemovesOwnedDeviceAndEntries(t *testing.T) {
	teardown := ns.SetUpNetlinkTest(t)
	defer teardown()

	nw, dev, _ := newKernelNetwork(t, "ext0")
	ownedName := dev.link.Attrs().Name

	l := vxlanLease("198.18.2.0/24", "192.0.2.2", "02:00:00:00:00:02")
	nw.handleSubnetEvents([]lease.Event{{Type: lease.EventAdded, Lease: l}})

	// A second VXLAN device that flannel merely adopted: it must survive.
	adopted, err := newVXLANDevice(&vxlanDeviceAttrs{
		vni: 2, name: "flannel.2", MTU: 1450,
		vtepIndex: dev.link.VtepDevIndex, vtepAddr: net.ParseIP("192.0.2.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	adopted.created = false // simulate adoption of a pre-existing device

	if err := nw.fp.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := nw.fp.Close(); err != nil {
		t.Fatalf("second Close must be idempotent, got %v", err)
	}

	if _, err := netlink.LinkByName(ownedName); err == nil {
		t.Fatalf("owned device %s was not deleted on Close", ownedName)
	}
	if _, err := netlink.LinkByName("flannel.2"); err != nil {
		t.Fatalf("adopted device was wrongly removed: %v", err)
	}
	if n := neighByIP(t, adopted.link.Index, syscall.AF_BRIDGE, net.ParseIP("192.0.2.2")); n != nil {
		t.Fatalf("entries were not cleaned up with the device")
	}
}

// TestKernel_RollbackCreatedDevices_DeletesOnlyCreated covers requirement 3
// at the device layer: newly created devices are deleted on rollback while
// adopted (created=false) devices are left in place.
func TestKernel_RollbackCreatedDevices_DeletesOnlyCreated(t *testing.T) {
	teardown := ns.SetUpNetlinkTest(t)
	defer teardown()

	extIface := addDummyLink(t, "ext0", "192.0.2.1/24")

	created, err := newVXLANDevice(&vxlanDeviceAttrs{
		vni: 1, name: "flannel.1", MTU: 1450,
		vtepIndex: extIface.Index, vtepAddr: net.ParseIP("192.0.2.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := newVXLANDevice(&vxlanDeviceAttrs{
		vni: 2, name: "flannel.2", MTU: 1450,
		vtepIndex: extIface.Index, vtepAddr: net.ParseIP("192.0.2.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	adopted.created = false

	rollbackCreatedDevices(created, adopted)

	if _, err := netlink.LinkByName("flannel.1"); err == nil {
		t.Fatal("rollback did not delete the newly created flannel.1")
	}
	if _, err := netlink.LinkByName("flannel.2"); err != nil {
		t.Fatalf("rollback deleted an adopted device: %v", err)
	}

	// Rolling back again must be a no-op without erroring.
	rollbackCreatedDevices(created, adopted)
}
