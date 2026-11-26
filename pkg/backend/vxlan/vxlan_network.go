// Copyright 2015 flannel authors
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/flannel-io/flannel/pkg/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	log "k8s.io/klog/v2"
)

type network struct {
	backend.SimpleNetwork
	dev       *vxlanDevice
	v6Dev     *vxlanDevice
	subnetMgr subnet.Manager
	mtu       int

	// fp is the authoritative in-memory registry of the ARP, FDB and route
	// entries this process installed, plus the VXLAN devices it created. All
	// kernel mutations go through it so the registry and the data plane stay
	// consistent, entries can age out and be relearned, and shutdown can
	// remove exactly what flannel owns.
	fp *forwardingPlane

	// knownLeases holds the remote leases that have been handed to
	// handleSubnetEvents, so that their ARP, FDB and route entries can be
	// written again after the VXLAN device is recreated. It is only used
	// from the Run loop.
	knownLeases lease.LeaseWatcher
}

// recreatedDevices carries the devices built by reCreateVxlan back to the
// Run loop, which owns nw.dev, nw.v6Dev and the lease handling.
type recreatedDevices struct {
	dev   *vxlanDevice
	v6Dev *vxlanDevice
}

const (
	encapOverhead = 50
)

func newNetwork(subnetMgr subnet.Manager, extIface *backend.ExternalInterface, dev *vxlanDevice, v6Dev *vxlanDevice, _ ip.IP4Net, lease *lease.Lease, mtu int) (*network, error) {
	fp := newForwardingPlane()
	fp.setDevices(dev, v6Dev)
	// The devices handed in here were created (or adopted) during
	// RegisterNetwork; only ones this process created are owned at Close.
	if dev != nil && dev.created {
		fp.trackDevice(dev.link.Attrs().Name)
	}
	if v6Dev != nil && v6Dev.created {
		fp.trackDevice(v6Dev.link.Attrs().Name)
	}

	nw := &network{
		SimpleNetwork: backend.SimpleNetwork{
			SubnetLease: lease,
			ExtIface:    extIface,
		},
		subnetMgr: subnetMgr,
		dev:       dev,
		v6Dev:     v6Dev,
		mtu:       mtu,
		fp:        fp,
	}

	return nw, nil
}

func (nw *network) Run(ctx context.Context) {
	var wg sync.WaitGroup

	log.V(0).Info("watching for new subnet leases")
	leaseEvents := make(chan []lease.Event)
	vxlanMissingChan := make(chan bool, 1) // buffered to avoid blocking
	vxlanRecreatedChan := make(chan recreatedDevices, 1)
	nw.knownLeases.OwnLease = nw.SubnetLease

	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, nw.subnetMgr, nw.SubnetLease, leaseEvents)
		log.V(1).Info("WatchLeases exited")
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		nw.watchVXLANDevice(ctx, vxlanMissingChan)
		log.V(1).Info("WatchVXLANDevice exited")
		wg.Done()
	}()

	// Periodically re-assert aged entries so stale ARP/FDB/route state
	// (e.g. an FDB record pointing at a restarted node's old VTEP MAC) is
	// relearned from the authoritative leases.
	go nw.fp.runReconciler(ctx)

	defer func() {
		wg.Wait()
		// Every exit path runs the idempotent teardown: remove the entries
		// and devices this process created. Close itself guards against
		// being invoked more than once.
		if err := nw.fp.Close(); err != nil {
			log.Errorf("error during vxlan forwarding plane shutdown: %v", err)
		}
	}()

	for {
		select {
		case evtBatch, ok := <-leaseEvents:
			if !ok {
				log.Infof("leaseEvents chan closed")
				return
			}
			nw.knownLeases.Update(evtBatch)
			nw.handleSubnetEvents(evtBatch)

		case _, ok := <-vxlanMissingChan:
			if !ok {
				log.Infof("vxlanMissingChan closed")
				return
			}
			log.Info("vxlan device missing, attempting to recreate...")

			// Offload recreate so this loop doesn’t block handleSubnetEvents.
			// The new devices are handed back through vxlanRecreatedChan so
			// that this loop installs them and re-applies the known leases.
			go func() {
				dev, v6Dev, err := nw.reCreateVxlan(ctx)
				if err != nil {
					log.Errorf("failed to recreate vxlan: %v", err)
					return
				}
				select {
				case vxlanRecreatedChan <- recreatedDevices{dev: dev, v6Dev: v6Dev}:
				case <-ctx.Done():
				}
			}()

		case recreated := <-vxlanRecreatedChan:
			nw.useRecreatedDevices(recreated)

		case <-ctx.Done():
			log.Info("vxlan network context canceled, exiting Run loop")
			return
		}
	}
}

// Close tears down the forwarding plane. It is safe to call more than once
// and safe to call while Run is also exiting: forwardingPlane.Close is
// synchronized and idempotent.
func (nw *network) Close() error {
	if nw.fp == nil {
		return nil
	}
	return nw.fp.Close()
}

// useRecreatedDevices installs the devices built by reCreateVxlan and writes
// the ARP, FDB and route entries of every known remote lease again. The kernel
// removes those entries together with the old device, and lease events are
// only delivered when a lease changes, so without this replay the node stays
// cut off from the other nodes' pod subnets until flannel restarts.
func (nw *network) useRecreatedDevices(recreated recreatedDevices) {
	nw.dev = recreated.dev
	nw.v6Dev = recreated.v6Dev
	if nw.dev != nil {
		nw.mtu = nw.dev.link.Attrs().MTU
	} else if nw.v6Dev != nil {
		nw.mtu = nw.v6Dev.link.Attrs().MTU
	}

	// The old device took every kernel entry with it and the recreated
	// devices are freshly created, so the registry starts empty and any
	// newly created devices become owned by this process.
	nw.fp.setDevices(recreated.dev, recreated.v6Dev)
	if recreated.dev != nil && recreated.dev.created {
		nw.fp.trackDevice(recreated.dev.link.Attrs().Name)
	}
	if recreated.v6Dev != nil && recreated.v6Dev.created {
		nw.fp.trackDevice(recreated.v6Dev.link.Attrs().Name)
	}

	batch := nw.knownLeaseEvents()
	if len(batch) == 0 {
		return
	}
	log.Infof("re-applying %d known subnet lease(s) to the recreated vxlan device", len(batch))
	nw.handleSubnetEvents(batch)
}

// knownLeaseEvents returns an EventAdded for every known remote lease.
func (nw *network) knownLeaseEvents() []lease.Event {
	batch := make([]lease.Event, 0, len(nw.knownLeases.Leases))
	for _, l := range nw.knownLeases.Leases {
		batch = append(batch, lease.Event{Type: lease.EventAdded, Lease: l})
	}
	return batch
}

// linkSubscribeFunc matches the signature of netlink.LinkSubscribe. It exists
// so tests can substitute a fake subscription instead of a real netlink socket.
type linkSubscribeFunc func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error

func (nw *network) watchVXLANDevice(ctx context.Context, vxlanMissingChan chan<- bool) {
	nw.watchVXLANDeviceWithSubscriber(ctx, vxlanMissingChan, netlink.LinkSubscribe, time.Second)
}

// watchVXLANDeviceWithSubscriber does the work for watchVXLANDevice. subscribe
// and retryDelay are parameterized so tests can run this without a real
// netlink socket and without waiting on production-sized delays.
func (nw *network) watchVXLANDeviceWithSubscriber(ctx context.Context, vxlanMissingChan chan<- bool, subscribe linkSubscribeFunc, retryDelay time.Duration) {
	log.Info("starting vxlan device watcher")
	if nw.dev == nil {
		log.Error("vxlan device is nil, cannot watch for events")
		return
	}

	updates := make(chan netlink.LinkUpdate)
	done := make(chan struct{})

	// The initial subscription must succeed for the watcher to be of any use,
	// so - as before - a failure here is fatal.
	if err := subscribe(updates, done); err != nil {
		log.Fatalf("failed to subscribe to netlink: %v", err)
	}

	name := nw.dev.link.Attrs().Name
	defer close(vxlanMissingChan)
	for {
		select {
		case <-ctx.Done():
			close(done)
			log.Info("stopping vxlan device watcher")
			return

		case update, ok := <-updates:
			if !ok {
				// The subscription's netlink socket died (e.g. ENOBUFS caused
				// the kernel to drop messages and the receive loop to exit).
				// Release this attempt's done-goroutine/socket and
				// re-establish the subscription; a dead subscription must not
				// silently stop the watcher or close vxlanMissingChan.
				close(done)
				log.Warning("vxlan device watcher: netlink subscription closed, resubscribing")
				updates, done = linkResubscribe(ctx, subscribe, retryDelay)
				if updates == nil {
					log.Info("stopping vxlan device watcher")
					return
				}
				continue
			}

			if update.Link == nil || update.Attrs() == nil {
				continue
			}
			// Detect deletion
			if update.Attrs().Name == name && update.Header.Type == unix.RTM_DELLINK {
				log.Infof("Interface %s deleted", name)
				select {
				case vxlanMissingChan <- true:
				default:
					// Skip if signal already queued
				}
			}
		}
	}
}

// waitForRetry waits for retryDelay, interruptible by ctx cancellation. It
// returns false if ctx was canceled during the wait, true if the delay
// elapsed normally.
func waitForRetry(ctx context.Context, retryDelay time.Duration) bool {
	timer := time.NewTimer(retryDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// linkResubscribe waits retryDelay and then calls subscribe, repeating
// (wait, attempt) until an attempt succeeds or ctx is canceled. It returns
// (nil, nil) if ctx is canceled before a subscription could be established.
//
// Waiting before every attempt - including the first, which follows an
// established subscription's updates channel closing - matters: without it,
// a subscribe() call that succeeds but whose Receive() goroutine fails again
// immediately (e.g. a persistent ENOBUFS condition) would tear its updates
// channel down right away too, and the caller would loop back into
// linkResubscribe with no delay at all, spinning.
func linkResubscribe(ctx context.Context, subscribe linkSubscribeFunc, retryDelay time.Duration) (chan netlink.LinkUpdate, chan struct{}) {
	for {
		if !waitForRetry(ctx, retryDelay) {
			return nil, nil
		}

		updates := make(chan netlink.LinkUpdate)
		done := make(chan struct{})
		if err := subscribe(updates, done); err != nil {
			close(done)
			log.Errorf("failed to resubscribe to netlink: %v, retrying in %s", err, retryDelay)
			continue
		}
		return updates, done
	}
}

// reCreateVxlan builds new VXLAN devices once the external interface is back.
// It does not modify nw.dev or nw.v6Dev; the caller installs the returned
// devices from the Run loop.
func (nw *network) reCreateVxlan(ctx context.Context) (*vxlanDevice, *vxlanDevice, error) {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("context canceled, stopping vxlan recreate")
		default:
		}

		extIface, _ := net.InterfaceByName(nw.ExtIface.IfaceName)
		if extIface == nil {
			log.Infof("external interface %s not found, retrying in %s", nw.ExtIface.IfaceName, backoff)
			retryAfterBackoff(&backoff, maxBackoff)
			continue
		}

		config, err := nw.subnetMgr.GetNetworkConfig(ctx)
		if err != nil {
			log.Errorf("failed to get network config: %v", err)
			retryAfterBackoff(&backoff, maxBackoff)
			continue
		}

		cfg, err := parseVXLANConfig(config.Backend, extIface.MTU)
		if err != nil {
			log.Errorf("failed to parse vxlan config: %v", err)
			retryAfterBackoff(&backoff, maxBackoff)
			continue
		}

		var ifaceAddr, ifaceAddrV6 net.IP

		if config.EnableIPv4 {
			addrs, err := ip.GetInterfaceIP4Addrs(extIface)
			if err != nil {
				log.Errorf("error getting IPv4 addresses for %s: %v", extIface.Name, err)
				retryAfterBackoff(&backoff, maxBackoff)
				continue
			}
			if len(addrs) == 0 {
				log.Warningf("no IPv4 addresses found for interface %s, retrying", extIface.Name)
				retryAfterBackoff(&backoff, maxBackoff)
				continue
			}
			ifaceAddr = addrs[0]
		}

		if config.EnableIPv6 {
			addrs, err := ip.GetInterfaceIP6Addrs(extIface)
			if err != nil {
				log.Errorf("error getting IPv6 addresses for %s: %v", extIface.Name, err)
				retryAfterBackoff(&backoff, maxBackoff)
				continue
			}
			if len(addrs) == 0 {
				log.Warningf("no IPv6 addresses found for interface %s, retrying", extIface.Name)
				retryAfterBackoff(&backoff, maxBackoff)
				continue
			}
			ifaceAddrV6 = addrs[0]
		}

		// Create the VXLAN device. ifaceAddr / ifaceAddrV6 stay nil
		// when their family is disabled, so the v4-only and v6-only
		// paths see the same shape: createVXLANDevice already gates
		// the v4 / v6 code paths on config.EnableIPv4 / EnableIPv6.
		dev, v6Dev, err := createVXLANDevice(ctx, config, cfg, nw.subnetMgr, extIface.Index, ifaceAddr, ifaceAddrV6)
		if err != nil {
			log.Errorf("failed to create vxlan device: %v", err)
			retryAfterBackoff(&backoff, maxBackoff)
			continue
		}

		if err := configureDeviceIPv4IPv6(dev, v6Dev, nw.SubnetLease, config); err != nil {
			log.Errorf("failed to configure vxlan device: %v", err)
			// configureDeviceIPv4IPv6 does not roll back on failure; remove
			// the devices this attempt created before retrying so repeated
			// recreate cycles do not accumulate half-configured devices.
			rollbackCreatedDevices(dev, v6Dev)
			retryAfterBackoff(&backoff, maxBackoff)
			continue
		}

		if dev != nil {
			log.Infof("VXLAN device %s recreated successfully", dev.link.Attrs().Name)
		}
		if v6Dev != nil {
			log.Infof("VXLAN device %s recreated successfully", v6Dev.link.Attrs().Name)
		}
		return dev, v6Dev, nil
	}
}

func retryAfterBackoff(backoff *time.Duration, maxBackoff time.Duration) {
	time.Sleep(*backoff)
	*backoff = minDuration(*backoff*2, maxBackoff)
}

// helper to cap exponential backoff
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (nw *network) MTU() int {
	return nw.mtu - encapOverhead
}

type vxlanLeaseAttrs struct {
	VNI     uint32
	VtepMAC hardwareAddr
}

func (nw *network) handleSubnetEvents(batch []lease.Event) {
	for _, event := range batch {
		sn := event.Lease.Subnet
		v6Sn := event.Lease.IPv6Subnet
		attrs := event.Lease.Attrs
		log.Infof("Received Subnet Event with VxLan: %s", attrs.String())
		if attrs.BackendType != "vxlan" {
			log.Warningf("ignoring non-vxlan v4Subnet(%s) v6Subnet(%s): type=%v", sn, v6Sn, attrs.BackendType)
			continue
		}

		switch event.Type {
		case lease.EventAdded:
			nw.handleLeaseAdded(event)
		case lease.EventRemoved:
			nw.handleLeaseRemoved(event)
		default:
			log.Error("internal error: unknown event type: ", int(event.Type))
		}
	}
}

// handleLeaseAdded builds one forwarding entry per enabled family and hands
// them to the forwarding plane, which rejects conflicts, installs the kernel
// objects transactionally and keeps the registry in sync.
func (nw *network) handleLeaseAdded(event lease.Event) {
	entries, err := nw.buildEntries(event)
	if err != nil {
		log.Error(err)
		return
	}
	for _, e := range entries {
		if err := nw.fp.addLease(e); err != nil {
			if errors.Is(err, ErrConflictSubnet) {
				// Requirement: refuse and log, never overwrite the live entry.
				log.Errorf("refusing subnet lease %s: %v", e.key(), err)
			} else {
				log.Errorf("failed to install forwarding entry %s: %v", e.key(), err)
			}
		} else {
			log.V(2).Infof("installed %s forwarding entry %s", e.kind, e.key())
		}
	}
}

// handleLeaseRemoved deletes the entries for both enabled families. The
// forwarding plane makes removal idempotent and matches by IP so stale MACs
// do not prevent deletion.
func (nw *network) handleLeaseRemoved(event lease.Event) {
	if event.Lease.EnableIPv4 {
		key := "v4:" + event.Lease.Subnet.String()
		if err := nw.fp.removeLease(key); err != nil {
			log.Errorf("failed to remove forwarding entry %s: %v", key, err)
		}
	}
	if event.Lease.EnableIPv6 {
		key := "v6:" + event.Lease.IPv6Subnet.String()
		if err := nw.fp.removeLease(key); err != nil {
			log.Errorf("failed to remove forwarding entry %s: %v", key, err)
		}
	}
}

// buildEntries translates a lease into the concrete forwarding entries for
// each enabled family, deciding between a VXLAN tunnel (ARP + FDB + onlink
// route) and a direct route when the remote VTEP is on the local L2.
func (nw *network) buildEntries(event lease.Event) ([]*forwardingEntry, error) {
	var (
		entries                            []*forwardingEntry
		vxlanAttrs, v6VxlanAttrs           vxlanLeaseAttrs
		directRoutingOK, v6DirectRoutingOK bool
	)
	l := event.Lease

	if l.EnableIPv4 && nw.dev != nil {
		if err := json.Unmarshal(l.Attrs.BackendData, &vxlanAttrs); err != nil {
			return nil, fmt.Errorf("error decoding subnet lease JSON: %w", err)
		}
		if nw.dev.directRouting {
			dr, err := ip.DirectRouting(l.Attrs.PublicIP.ToIP())
			if err != nil {
				log.Error(err)
			} else {
				directRoutingOK = dr
			}
		}

		e := &forwardingEntry{
			podSubnet: l.Subnet,
			publicIP:  l.Attrs.PublicIP,
			vtepMAC:   net.HardwareAddr(vxlanAttrs.VtepMAC),
		}
		if directRoutingOK {
			e.kind = entryDirectRoute
			e.gatewayIP = l.Attrs.PublicIP.ToIP()
			log.V(2).Infof("adding direct route to subnet: %s PublicIP: %s", l.Subnet, l.Attrs.PublicIP)
		} else {
			e.kind = entryTunnel
			e.gatewayIP = l.Subnet.IP.ToIP()
			log.V(2).Infof("adding subnet: %s PublicIP: %s VtepMAC: %s", l.Subnet, l.Attrs.PublicIP, e.vtepMAC)
		}
		entries = append(entries, e)
	}

	if l.EnableIPv6 && nw.v6Dev != nil {
		if err := json.Unmarshal(l.Attrs.BackendV6Data, &v6VxlanAttrs); err != nil {
			return nil, fmt.Errorf("error decoding v6 subnet lease JSON: %w", err)
		}
		if l.IPv6Subnet.IP != nil {
			if nw.v6Dev.directRouting {
				dr, err := ip.DirectRouting(l.Attrs.PublicIPv6.ToIP())
				if err != nil {
					log.Error(err)
				} else {
					v6DirectRoutingOK = dr
				}
			}

			e := &forwardingEntry{
				v6:          true,
				podSubnetV6: l.IPv6Subnet,
				publicIPv6:  l.Attrs.PublicIPv6,
				vtepMAC:     net.HardwareAddr(v6VxlanAttrs.VtepMAC),
			}
			if v6DirectRoutingOK {
				e.kind = entryDirectRoute
				e.gatewayIP = l.Attrs.PublicIPv6.ToIP()
				log.V(2).Infof("adding v6 direct route to v6 subnet: %s PublicIPv6: %s", l.IPv6Subnet, l.Attrs.PublicIPv6)
			} else {
				e.kind = entryTunnel
				e.gatewayIP = l.IPv6Subnet.IP.ToIP()
				log.V(2).Infof("adding v6 subnet: %s PublicIPv6: %s VtepMAC: %s", l.IPv6Subnet, l.Attrs.PublicIPv6, e.vtepMAC)
			}
			entries = append(entries, e)
		}
	}

	return entries, nil
}
