//go:build !windows
// +build !windows

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

package vxlan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/vishvananda/netlink"
	log "k8s.io/klog/v2"
)

// Tunables for the forwarding plane entry lifecycle. They are variables (not
// constants) so tests can shrink them; production code must not touch them.
var (
	// entryAge is how long an installed ARP/FDB/route entry is considered
	// fresh. Once it ages out the next reconciliation re-asserts it against
	// the kernel, which is how a stale entry (for example an FDB record left
	// behind by a restarted node whose VTEP MAC changed) gets relearned.
	entryAge = 5 * time.Minute
	// reconcileInterval is how often the background sweep runs. At a few
	// hundred nodes each sweep is a constant number of netlink dumps plus one
	// check per registered entry, so this stays cheap on 10G fabrics.
	reconcileInterval = 30 * time.Second
)

// ErrConflictSubnet is returned when a lease's subnet or VTEP address is
// already owned by a different registered entry. Such leases are refused and
// logged instead of silently overwriting the live forwarding state.
var ErrConflictSubnet = errors.New("conflicting subnet or VTEP address")

// entryKind distinguishes the two ways flannel steers traffic for a remote
// node: VXLAN tunneled entries (ARP + FDB + onlink route) and direct routes
// for neighbors on the same L2 underlay.
type entryKind int

const (
	entryTunnel entryKind = iota
	entryDirectRoute
)

func (k entryKind) String() string {
	switch k {
	case entryTunnel:
		return "vxlan-tunnel"
	case entryDirectRoute:
		return "direct-route"
	default:
		return "unknown"
	}
}

// forwardingEntry is everything flannel installed in the kernel for one
// remote node, on one address family. The same struct covers tunneled and
// direct-route entries.
type forwardingEntry struct {
	kind entryKind

	// podSubnet identifies the entry and backs its route. For v4 entries it
	// carries the remote pod subnet; v6 uses podSubnetV6 instead.
	podSubnet   ip.IP4Net
	podSubnetV6 ip.IP6Net
	v6          bool

	// Remote VTEP / public endpoint.
	publicIP   ip.IP4
	publicIPv6 *ip.IP6
	vtepMAC    net.HardwareAddr
	gatewayIP  net.IP // sn.IP (tunnel) or public IP (direct route)

	installedAt time.Time
}

// key returns the identity under which the entry is registered. The pod
// subnet is unique per node lease, so it doubles as the node key.
func (e *forwardingEntry) key() string {
	if e.v6 {
		return "v6:" + e.podSubnetV6.String()
	}
	return "v4:" + e.podSubnet.String()
}

// netlinkOps is the slice of the netlink API the forwarding plane uses.
// Production calls go through netlinkOpsDefault; tests inject a fake to run
// without a real kernel.
type netlinkOps interface {
	NeighSet(neigh *netlink.Neigh) error
	NeighDel(neigh *netlink.Neigh) error
	NeighList(linkIndex, family int) ([]netlink.Neigh, error)
	RouteReplace(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	LinkByName(name string) (netlink.Link, error)
	LinkDel(link netlink.Link) error
}

type netlinkOpsDefault struct{}

func (netlinkOpsDefault) NeighSet(neigh *netlink.Neigh) error { return netlink.NeighSet(neigh) }
func (netlinkOpsDefault) NeighDel(neigh *netlink.Neigh) error { return netlink.NeighDel(neigh) }
func (netlinkOpsDefault) NeighList(i, family int) ([]netlink.Neigh, error) {
	return netlink.NeighList(i, family)
}
func (netlinkOpsDefault) RouteReplace(route *netlink.Route) error { return netlink.RouteReplace(route) }
func (netlinkOpsDefault) RouteDel(route *netlink.Route) error     { return netlink.RouteDel(route) }
func (netlinkOpsDefault) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}
func (netlinkOpsDefault) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}
func (netlinkOpsDefault) LinkDel(link netlink.Link) error { return netlink.LinkDel(link) }

// forwardingPlane is the in-kernel forwarding state flannel owns: one entry
// per remote node per address family, plus the VXLAN devices this process
// created. All mutations go through it so the in-memory registry and the
// kernel stay in lockstep. It is safe for concurrent use: the lease event
// loop and the aging reconciler share it.
type forwardingPlane struct {
	mu      sync.Mutex
	ops     netlinkOps
	entries map[string]*forwardingEntry

	// Devices this process created and therefore owns at shutdown. A
	// pre-existing flannel.1 that flannel merely adopted is not tracked here
	// and must not be deleted on exit.
	ownedDevices map[string]bool
	vxlanDev     *vxlanDevice
	v6VxlanDev   *vxlanDevice
	closed       bool
}

func newForwardingPlane() *forwardingPlane {
	return &forwardingPlane{
		ops:          netlinkOpsDefault{},
		entries:      make(map[string]*forwardingEntry),
		ownedDevices: make(map[string]bool),
	}
}

// setDevices swaps the VXLAN devices, e.g. after watchVXLANDevice recreated
// them. The kernel drops every ARP/FDB/route entry together with the old
// device, so the registry is cleared and the caller replays the known
// leases to repopulate both the kernel and the registry.
func (fp *forwardingPlane) setDevices(dev, v6Dev *vxlanDevice) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.vxlanDev = dev
	fp.v6VxlanDev = v6Dev
	fp.entries = make(map[string]*forwardingEntry)
}

// addLease installs the forwarding entries for one remote lease (one entry
// per enabled family). It refuses conflicts: an entry whose subnet or VTEP
// endpoint is already owned by a different lease is rejected without
// touching the kernel. A re-add of the same lease refreshes it instead of
// conflicting. Any kernel failure rolls back the partial installation so a
// failed add never leaves half an entry behind.
func (fp *forwardingPlane) addLease(e *forwardingEntry) error {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	if fp.closed {
		return fmt.Errorf("forwarding plane is closed")
	}
	if err := fp.checkConflictLocked(e); err != nil {
		return err
	}

	// Same-key re-add (lease update, e.g. a node restart with a new VTEP
	// MAC) replaces the old entry. The FDB purge below enumerates and
	// deletes every record stored under the VTEP IP, including the one keyed
	// by the previous MAC, which an (IP, MAC)-keyed delete alone would miss.
	// This is what clears a stale FDB record after a VTEP MAC change.
	if old, ok := fp.entries[e.key()]; ok {
		log.Infof("replacing existing %s entry for %s", old.kind, e.key())
		if err := fp.removeEntryLocked(old); err != nil {
			log.Errorf("failed to remove stale entry for %s before replacement: %v", e.key(), err)
		}
		delete(fp.entries, old.key())
	}

	if err := fp.installEntryLocked(e); err != nil {
		// Roll back anything the partial installation already created.
		if rbErr := fp.removeEntryLocked(e); rbErr != nil {
			log.Errorf("rollback after failed install of %s also failed: %v", e.key(), rbErr)
		}
		return err
	}

	e.installedAt = time.Now()
	fp.entries[e.key()] = e
	return nil
}

// removeLease deletes the kernel entry for the given identity. It is
// idempotent: an unknown or already removed entry is not an error. ARP/ND
// records are deleted by IP while FDB records are deleted by (IP, MAC),
// matching how the kernel keys each table.
func (fp *forwardingPlane) removeLease(key string) error {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	e, ok := fp.entries[key]
	if !ok {
		log.V(2).Infof("no registered forwarding entry for %s, nothing to remove", key)
		return nil
	}
	err := fp.removeEntryLocked(e)
	delete(fp.entries, key)
	return err
}

// checkConflictLocked rejects an entry whose identity or L3 endpoint is
// already taken by a different entry. Overlapping pod subnets would make
// the kernel pick one route nondeterministically; duplicate FDB/ARP
// endpoints would point one VTEP IP at two MACs.
func (fp *forwardingPlane) checkConflictLocked(incoming *forwardingEntry) error {
	for _, existing := range fp.entries {
		if existing.key() == incoming.key() {
			continue // same identity: handled as a replacement
		}
		if existing.v6 != incoming.v6 {
			continue
		}

		if !incoming.v6 && existing.podSubnet.Overlaps(incoming.podSubnet) {
			return fmt.Errorf("%w: pod subnet %s overlaps registered %s", ErrConflictSubnet, incoming.podSubnet, existing.podSubnet)
		}
		if incoming.v6 && existing.podSubnetV6.Overlaps(incoming.podSubnetV6) {
			return fmt.Errorf("%w: pod subnet %s overlaps registered %s", ErrConflictSubnet, incoming.podSubnetV6, existing.podSubnetV6)
		}

		// The FDB/ARP endpoint must be unique per family as well.
		if !incoming.v6 && incoming.kind == entryTunnel && existing.kind == entryTunnel && existing.publicIP == incoming.publicIP {
			return fmt.Errorf("%w: VTEP public IP %s already registered for %s", ErrConflictSubnet, incoming.publicIP, existing.key())
		}
		if incoming.v6 && incoming.kind == entryTunnel && existing.kind == entryTunnel &&
			incoming.publicIPv6 != nil && existing.publicIPv6 != nil && existing.publicIPv6.Cmp(incoming.publicIPv6) == 0 {
			return fmt.Errorf("%w: VTEP public IPv6 %s already registered for %s", ErrConflictSubnet, incoming.publicIPv6, existing.key())
		}
	}
	return nil
}

// installEntryLocked programs the kernel objects for one entry. The
// operations are ordered so a failure can be undone: ARP first, then FDB,
// then the route, matching the kernel's resolution order.
func (fp *forwardingPlane) installEntryLocked(e *forwardingEntry) error {
	switch e.kind {
	case entryDirectRoute:
		route := fp.directRoute(e)
		if err := fp.ops.RouteReplace(route); err != nil {
			return fmt.Errorf("adding direct route to %s: %w", e.key(), err)
		}
		return nil
	case entryTunnel:
		// fall through below
	default:
		return fmt.Errorf("unknown entry kind %d", e.kind)
	}

	dev := fp.deviceFor(e.v6)
	if dev == nil {
		return fmt.Errorf("no vxlan device for family v6=%v, cannot install %s", e.v6, e.key())
	}

	// The kernel keys static FDB records by (VTEP IP, VTEP MAC) and a
	// replace appends a new record instead of replacing the one stored under
	// a stale MAC. A restarted node therefore leaves its old FDB record
	// behind, blackholing traffic - the exact incident reported here. Purge
	// every existing FDB record for this VTEP IP before installing the
	// current one.
	if err := fp.purgeFDBLocked(dev, e); err != nil {
		return fmt.Errorf("purging stale FDB entries for %s: %w", e.key(), err)
	}
	if err := fp.addNeighbor(dev, e, false /* fdb */); err != nil {
		return fmt.Errorf("adding ARP entry for %s: %w", e.key(), err)
	}
	if err := fp.addNeighbor(dev, e, true /* fdb */); err != nil {
		return fmt.Errorf("adding FDB entry for %s: %w", e.key(), err)
	}
	if err := fp.ops.RouteReplace(fp.tunnelRoute(e)); err != nil {
		return fmt.Errorf("adding tunnel route to %s: %w", e.key(), err)
	}
	return nil
}

// removeEntryLocked undoes everything installEntryLocked may have done. It
// keeps going on individual failures so one stuck object does not strand the
// others, and returns the joined error. Neighbors are deleted by IP with a
// nil MAC so a MAC-changed (stale) record is still matched.
func (fp *forwardingPlane) removeEntryLocked(e *forwardingEntry) error {
	var errs []error

	if e.kind == entryDirectRoute {
		if err := fp.ops.RouteDel(fp.directRoute(e)); err != nil && !isNotExist(err) {
			errs = append(errs, fmt.Errorf("deleting direct route to %s: %w", e.key(), err))
		}
		return errors.Join(errs...)
	}

	if dev := fp.deviceFor(e.v6); dev != nil {
		if err := fp.delNeighbor(dev, e, false /* fdb */); err != nil && !isNotExist(err) {
			errs = append(errs, fmt.Errorf("deleting ARP entry for %s: %w", e.key(), err))
		}
		// FDB deletion requires the MAC: the kernel keys static FDB records
		// by (VTEP IP, VTEP MAC) and rejects a MAC-less delete with EINVAL.
		// Use the MAC recorded in our registry, which is the one we installed.
		if err := fp.delFDBByMAC(dev, e); err != nil && !isNotExist(err) {
			errs = append(errs, fmt.Errorf("deleting FDB entry for %s: %w", e.key(), err))
		}
	} else {
		log.Warningf("vxlan device gone while removing %s; kernel already dropped its neighbors", e.key())
	}

	if err := fp.ops.RouteDel(fp.tunnelRoute(e)); err != nil && !isNotExist(err) {
		errs = append(errs, fmt.Errorf("deleting tunnel route to %s: %w", e.key(), err))
	}
	return errors.Join(errs...)
}

func (fp *forwardingPlane) addNeighbor(dev *vxlanDevice, e *forwardingEntry, fdb bool) error {
	family := syscall.AF_INET
	if e.v6 {
		family = syscall.AF_INET6
	}
	neigh := &netlink.Neigh{
		LinkIndex:    dev.link.Index,
		State:        netlink.NUD_PERMANENT,
		IP:           e.neighborIP(fdb),
		HardwareAddr: e.vtepMAC,
	}
	if fdb {
		neigh.Family = syscall.AF_BRIDGE
		neigh.Flags = netlink.NTF_SELF
	} else {
		neigh.Family = family
		neigh.Type = syscall.RTN_UNICAST
	}
	return fp.ops.NeighSet(neigh)
}

// delNeighbor deletes a non-FDB neighbor (ARP/ND) by IP with a nil
// HardwareAddr. ARP entries are keyed by IP only, so this also matches
// records whose MAC drifted.
func (fp *forwardingPlane) delNeighbor(dev *vxlanDevice, e *forwardingEntry, fdb bool) error {
	family := syscall.AF_INET
	if e.v6 {
		family = syscall.AF_INET6
	}
	neigh := &netlink.Neigh{
		LinkIndex: dev.link.Index,
		IP:        e.neighborIP(fdb),
	}
	if fdb {
		neigh.Family = syscall.AF_BRIDGE
		neigh.Flags = netlink.NTF_SELF
	} else {
		neigh.Family = family
		neigh.Type = syscall.RTN_UNICAST
	}
	return fp.ops.NeighDel(neigh)
}

// delFDBByMAC removes the static FDB record identified by the entry's VTEP IP
// and its registered MAC. The kernel requires the MAC for an AF_BRIDGE delete
// (a MAC-less delete fails with EINVAL).
func (fp *forwardingPlane) delFDBByMAC(dev *vxlanDevice, e *forwardingEntry) error {
	vtepIP := e.neighborIP(true)
	if vtepIP == nil {
		// No public VTEP endpoint (e.g. an IPv6 lease without PublicIPv6):
		// there is no FDB record to remove.
		return nil
	}
	return fp.ops.NeighDel(&netlink.Neigh{
		LinkIndex:    dev.link.Index,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           vtepIP,
		HardwareAddr: e.vtepMAC,
	})
}

// purgeFDBLocked removes every static FDB record that points at the entry's
// VTEP IP, regardless of its MAC. The kernel accumulates one FDB record per
// (VTEP IP, MAC) and treats replace as an append, so after a VTEP MAC change
// the stale record stays behind and attracts traffic. Enumerating the FDB and
// deleting by (IP, MAC) is the only way to guarantee a clean per-VTEP state.
func (fp *forwardingPlane) purgeFDBLocked(dev *vxlanDevice, e *forwardingEntry) error {
	vtepIP := e.neighborIP(true)
	if vtepIP == nil {
		return nil
	}
	fdbs, err := fp.ops.NeighList(dev.link.Index, syscall.AF_BRIDGE)
	if err != nil {
		return fmt.Errorf("listing FDB: %w", err)
	}
	for i := range fdbs {
		n := fdbs[i]
		if n.IP == nil || !n.IP.Equal(vtepIP) {
			continue
		}
		// Skip the record we are about to (re)install to avoid a pointless
		// delete/add when nothing drifted.
		if n.HardwareAddr.String() == e.vtepMAC.String() {
			continue
		}
		log.Warningf("purging stale FDB record %s -> %s for %s", vtepIP, n.HardwareAddr, e.key())
		if err := fp.ops.NeighDel(&netlink.Neigh{
			LinkIndex:    dev.link.Index,
			Family:       syscall.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			IP:           vtepIP,
			HardwareAddr: n.HardwareAddr,
		}); err != nil && !isNotExist(err) {
			return fmt.Errorf("deleting stale FDB record %s -> %s: %w", vtepIP, n.HardwareAddr, err)
		}
	}
	return nil
}

// neighborIP returns the endpoint IP addressed by a neighbor record: the
// public VTEP IP for an FDB record, the pod-subnet gateway IP for an ARP
// record.
func (e *forwardingEntry) neighborIP(fdb bool) net.IP {
	if fdb {
		if e.v6 {
			if e.publicIPv6 == nil {
				return nil
			}
			return e.publicIPv6.ToIP()
		}
		return e.publicIP.ToIP()
	}
	return e.gatewayIP
}

func (fp *forwardingPlane) tunnelRoute(e *forwardingEntry) *netlink.Route {
	dev := fp.deviceFor(e.v6)
	r := &netlink.Route{
		LinkIndex: dev.link.Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        e.gatewayIP,
	}
	if e.v6 {
		r.Dst = e.podSubnetV6.ToIPNet()
	} else {
		r.Dst = e.podSubnet.ToIPNet()
	}
	r.SetFlag(syscall.RTNH_F_ONLINK)
	return r
}

func (fp *forwardingPlane) directRoute(e *forwardingEntry) *netlink.Route {
	r := &netlink.Route{Gw: e.gatewayIP}
	if e.v6 {
		r.Dst = e.podSubnetV6.ToIPNet()
	} else {
		r.Dst = e.podSubnet.ToIPNet()
	}
	return r
}

func (fp *forwardingPlane) deviceFor(v6 bool) *vxlanDevice {
	if v6 {
		return fp.v6VxlanDev
	}
	return fp.vxlanDev
}

// reconcile re-asserts every aged entry against the kernel and reaps stale
// kernel neighbors that no longer correspond to a registered entry. This is
// the relearning path: an entry older than entryAge is rewritten from the
// lease data, repairing MAC drift or externally deleted records.
func (fp *forwardingPlane) reconcile() {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if fp.closed {
		return
	}

	now := time.Now()
	// Each device is dumped a constant number of times per sweep regardless
	// of how many entries it carries, so a few hundred nodes do not turn the
	// sweep into a few hundred netlink dumps.
	snap := fp.snapshotDumpsLocked()

	for key, e := range fp.entries {
		if now.Sub(e.installedAt) < entryAge {
			continue
		}
		log.V(2).Infof("reconciling aged forwarding entry %s", key)
		if err := fp.reconcileEntryLocked(e, snap); err != nil {
			log.Errorf("reconcile of %s failed: %v", key, err)
			continue
		}
		e.installedAt = now
	}
}

// deviceDump holds one sweep's kernel view of a VXLAN device.
type deviceDump struct {
	neighs []netlink.Neigh // ARP/ND entries (AF_INET or AF_INET6)
	fdbs   []netlink.Neigh // FDB entries (AF_BRIDGE)
	routes []netlink.Route
}

// snapshotDumpsLocked dumps the neighbor, FDB and route tables of every live
// VXLAN device once.
func (fp *forwardingPlane) snapshotDumpsLocked() map[int]*deviceDump {
	dumps := make(map[int]*deviceDump)
	dump := func(dev *vxlanDevice, family int) error {
		if dev == nil {
			return nil
		}
		idx := dev.link.Index
		if _, ok := dumps[idx]; ok {
			return nil
		}
		neighs, err := fp.ops.NeighList(idx, family)
		if err != nil {
			return err
		}
		fdbs, err := fp.ops.NeighList(idx, syscall.AF_BRIDGE)
		if err != nil {
			return err
		}
		routes, err := fp.ops.RouteList(dev.link, family)
		if err != nil {
			return err
		}
		dumps[idx] = &deviceDump{neighs: neighs, fdbs: fdbs, routes: routes}
		return nil
	}
	if err := dump(fp.vxlanDev, syscall.AF_INET); err != nil {
		log.Errorf("reconcile: dumping v4 vxlan device failed: %v", err)
	}
	if err := dump(fp.v6VxlanDev, syscall.AF_INET6); err != nil {
		log.Errorf("reconcile: dumping v6 vxlan device failed: %v", err)
	}
	return dumps
}

// reconcileEntryLocked verifies the kernel objects of one entry against the
// sweep's snapshot and rewrites any that are missing or drifted.
func (fp *forwardingPlane) reconcileEntryLocked(e *forwardingEntry, dumps map[int]*deviceDump) error {
	if e.kind == entryDirectRoute {
		ok, err := fp.routePresentInDumpsLocked(e, dumps)
		if err != nil {
			return err
		}
		if !ok {
			log.Warningf("direct route to %s missing, relearning", e.key())
			return fp.ops.RouteReplace(fp.directRoute(e))
		}
		return nil
	}

	dev := fp.deviceFor(e.v6)
	if dev == nil {
		return fmt.Errorf("vxlan device missing for %s", e.key())
	}
	snap, ok := dumps[dev.link.Index]
	if !ok {
		return fmt.Errorf("no kernel snapshot available for %s", e.key())
	}

	if !neighHas(snap.neighs, e.gatewayIP, e.vtepMAC) {
		log.Warningf("ARP entry for %s missing or stale, relearning", e.key())
		if err := fp.addNeighbor(dev, e, false); err != nil {
			return err
		}
	}
	// Always purge stale-MAC FDB records for this VTEP before re-asserting
	// the correct one: the kernel keeps one record per (IP, MAC), so a plain
	// existence check would leave an obsolete record in place.
	if err := fp.purgeFDBLocked(dev, e); err != nil {
		return err
	}
	if !neighHas(snap.fdbs, e.neighborIP(true), e.vtepMAC) {
		log.Warningf("FDB entry for %s missing or stale, relearning", e.key())
		if err := fp.addNeighbor(dev, e, true); err != nil {
			return err
		}
	}

	present, err := fp.routePresentInDumpsLocked(e, dumps)
	if err != nil {
		return err
	}
	if !present {
		log.Warningf("tunnel route to %s missing, relearning", e.key())
		if err := fp.ops.RouteReplace(fp.tunnelRoute(e)); err != nil {
			return err
		}
	}
	return nil
}

func (fp *forwardingPlane) routePresentInDumpsLocked(e *forwardingEntry, dumps map[int]*deviceDump) (bool, error) {
	dev := fp.deviceFor(e.v6)
	if dev == nil {
		return false, nil
	}
	snap, ok := dumps[dev.link.Index]
	if !ok {
		return false, fmt.Errorf("no kernel snapshot for device of %s", e.key())
	}
	dst := e.podSubnet.ToIPNet()
	if e.v6 {
		dst = e.podSubnetV6.ToIPNet()
	}
	for _, r := range snap.routes {
		if r.Dst != nil && r.Dst.String() == dst.String() {
			return true, nil
		}
	}
	return false, nil
}

// runReconciler sweeps on reconcileInterval until ctx is canceled. It is
// owned by the network Run loop.
func (fp *forwardingPlane) runReconciler(ctx context.Context) {
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fp.reconcile()
		}
	}
}

// trackDevice records a VXLAN device this process created, so Close can
// remove it. Adopted (pre-existing) devices are not tracked.
func (fp *forwardingPlane) trackDevice(name string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.ownedDevices[name] = true
}

// Close removes every entry this process installed and deletes the VXLAN
// devices it created. It is idempotent: a second call is a no-op, and
// individual removal failures are logged but do not stop the rest of the
// teardown.
func (fp *forwardingPlane) Close() error {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	if fp.closed {
		log.V(1).Info("forwarding plane already closed, skipping repeated shutdown")
		return nil
	}
	fp.closed = true

	var errs []error
	for key, e := range fp.entries {
		log.V(2).Infof("shutdown: removing forwarding entry %s", key)
		if err := fp.removeEntryLocked(e); err != nil {
			errs = append(errs, err)
		}
		delete(fp.entries, key)
	}

	for name := range fp.ownedDevices {
		link, err := fp.ops.LinkByName(name)
		if err != nil {
			if isNotExist(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("looking up device %s at shutdown: %w", name, err))
			continue
		}
		log.Infof("shutdown: deleting vxlan device %s", name)
		if err := fp.ops.LinkDel(link); err != nil && !isNotExist(err) {
			errs = append(errs, fmt.Errorf("deleting device %s at shutdown: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// snapshotKeys returns the registered entry identities. Tests and diagnostics
// only.
func (fp *forwardingPlane) snapshotKeys() []string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	keys := make([]string, 0, len(fp.entries))
	for k := range fp.entries {
		keys = append(keys, k)
	}
	return keys
}

// neighHas reports whether the dump contains a permanent neighbor for ip with
// the expected MAC. A record with a different MAC counts as absent, which is
// the stale-MAC condition the reconciler is meant to repair.
func neighHas(neighs []netlink.Neigh, ip net.IP, mac net.HardwareAddr) bool {
	for _, n := range neighs {
		if n.IP.Equal(ip) && n.HardwareAddr.String() == mac.String() {
			return true
		}
	}
	return false
}

// isNotExist reports whether a netlink error means the object was already
// gone, which is success during teardown.
func isNotExist(err error) bool {
	return errors.Is(err, syscall.ESRCH) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ENODEV)
}
