//go:build !windows
// +build !windows

// Copyright 2017 flannel authors
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
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	"github.com/vishvananda/netlink"
	log "k8s.io/klog/v2"
)

const (
	routeCheckRetries = 10
)

type RouteNetwork struct {
	SimpleNetwork
	BackendType string
	routes      []netlink.Route
	v6Routes    []netlink.Route
	SM          subnet.Manager
	GetRoute    func(lease *lease.Lease) *netlink.Route
	GetV6Route  func(lease *lease.Lease) *netlink.Route
	Mtu         int
	LinkIndex   int

	// routesMu protects routes and v6Routes.
	routesMu sync.RWMutex
	// statusMu protects syncStatus initialization.
	statusMu   sync.Mutex
	syncStatus map[int]*routeSyncState

	// desiredReady is set after the first lease event batch has populated the
	// desired route cache. deletionsPaused is used during the startup grace
	// window to add missing routes without deleting from a partial cache.
	desiredReady    atomic.Bool
	deletionsPaused atomic.Bool

	// SyncConfig tunes periodic reconciliation. Zero fields use defaults.
	SyncConfig RouteSyncConfig
	// Alternate configuration field names used by tests/call sites.
	Config          RouteSyncConfig
	RouteSyncConfig RouteSyncConfig
	ReconcileConfig RouteSyncConfig
	// ManagedCIDRs optionally limits deletion to destinations inside these
	// cluster CIDRs. When empty, only default/desired-state safety guards apply.
	ManagedCIDRs []*net.IPNet
}

// ManagedCIDRsFromConfig returns the cluster CIDRs that are allowed to contain
// routes deleted by reconciliation. Limiting deletions to these CIDRs prevents
// unrelated host routes from being removed.
func ManagedCIDRsFromConfig(config *subnet.Config) []*net.IPNet {
	if config == nil {
		return nil
	}
	cidrs := make([]*net.IPNet, 0, 2)
	if config.EnableIPv4 && !config.Network.Empty() {
		cidrs = append(cidrs, config.Network.ToIPNet())
	}
	if config.EnableIPv6 && !config.IPv6Network.Empty() {
		cidrs = append(cidrs, config.IPv6Network.ToIPNet())
	}
	return cidrs
}

func (n *RouteNetwork) MTU() int {
	return n.Mtu
}

func (n *RouteNetwork) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.Info("Watching for new subnet leases")
	evts := make(chan []lease.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, n.SM, n.SubnetLease, evts)
		wg.Done()
	}()

	n.routes = make([]netlink.Route, 0, 10)
	wg.Add(1)
	go func() {
		n.routeCheck(ctx)
		wg.Done()
	}()

	defer wg.Wait()

	for {
		evtBatch, ok := <-evts
		if !ok {
			log.Infof("evts chan closed")
			return
		}
		n.handleSubnetEvents(evtBatch)
	}
}

func (n *RouteNetwork) handleSubnetEvents(batch []lease.Event) {
	// The first watch batch is the initial lease snapshot. Only after it has
	// been applied is the desired route cache safe to use for deletions.
	defer n.desiredReady.Store(true)

	for _, evt := range batch {
		switch evt.Type {
		case lease.EventAdded:
			if evt.Lease.Attrs.BackendType != n.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}

			if evt.Lease.EnableIPv4 {
				log.Infof("Subnet added: %v via %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

				route := n.GetRoute(&evt.Lease)
				routeAdd(route, netlink.FAMILY_V4, n.addToRouteList, n.removeFromV4RouteList)
			}

			if evt.Lease.EnableIPv6 {
				log.Infof("Subnet added: %v via %v", evt.Lease.IPv6Subnet, evt.Lease.Attrs.PublicIPv6)

				route := n.GetV6Route(&evt.Lease)
				routeAdd(route, netlink.FAMILY_V6, n.addToV6RouteList, n.removeFromV6RouteList)
			}

		case lease.EventRemoved:
			if evt.Lease.Attrs.BackendType != n.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}

			if evt.Lease.EnableIPv4 {
				log.Info("Subnet removed: ", evt.Lease.Subnet)

				route := n.GetRoute(&evt.Lease)
				if isDefaultRoute(route) {
					log.Errorf("Refusing to delete default IPv4 route while removing subnet %v", evt.Lease.Subnet)
					continue
				}
				// Always remove the route from the route list.
				n.removeFromV4RouteList(*route)

				if err := netlink.RouteDel(route); err != nil {
					log.Errorf("Error deleting route to %v: %v", evt.Lease.Subnet, err)
				}
			}

			if evt.Lease.EnableIPv6 {
				log.Info("Subnet removed: ", evt.Lease.IPv6Subnet)

				route := n.GetV6Route(&evt.Lease)
				if isDefaultRoute(route) {
					log.Errorf("Refusing to delete default IPv6 route while removing subnet %v", evt.Lease.IPv6Subnet)
					continue
				}
				// Always remove the route from the route list.
				n.removeFromV6RouteList(*route)

				if err := netlink.RouteDel(route); err != nil {
					log.Errorf("Error deleting route to %v: %v", evt.Lease.IPv6Subnet, err)
				}
			}

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}

func routeAdd(route *netlink.Route, ipFamily int, addToRouteList, removeFromRouteList func(netlink.Route)) {
	addToRouteList(*route)
	// Check if route exists before attempting to add it
	routeList, err := netlink.RouteListFiltered(ipFamily, &netlink.Route{Dst: route.Dst}, netlink.RT_FILTER_DST)
	if err != nil {
		log.Warningf("Unable to list routes: %v", err)
	}

	if len(routeList) > 0 && !routeEqual(routeList[0], *route) {
		// Same Dst different Gw or different link index. Remove it, correct route will be added below.
		log.Warningf("Replacing existing route to %v with %v", routeList[0], route)
		if err := netlink.RouteDel(&routeList[0]); err != nil {
			log.Errorf("Effor deleteing route to %v: %v", routeList[0].Dst, err)
			return
		}
		removeFromRouteList(routeList[0])
	}
	routeList, err = netlink.RouteListFiltered(ipFamily, &netlink.Route{Dst: route.Dst}, netlink.RT_FILTER_DST)
	if err != nil {
		log.Warningf("Unable to list routes: %v", err)
	}

	if len(routeList) > 0 && routeEqual(routeList[0], *route) {
		// Same Dst and same Gw, keep it and do not attempt to add it.
		log.Infof("Route to %v already exists, skipping.", route)
	} else if err := netlink.RouteAdd(route); err != nil {
		log.Errorf("Error adding route to %v: %s", route, err)
		return
	}
	_, err = netlink.RouteListFiltered(ipFamily, &netlink.Route{Dst: route.Dst}, netlink.RT_FILTER_DST)
	if err != nil {
		log.Warningf("Unable to list routes: %v", err)
	}
}

func (n *RouteNetwork) addToRouteList(route netlink.Route) {
	n.routesMu.Lock()
	defer n.routesMu.Unlock()
	n.routes = addToRouteList(&route, n.routes)
}

func (n *RouteNetwork) addToV6RouteList(route netlink.Route) {
	n.routesMu.Lock()
	defer n.routesMu.Unlock()
	n.v6Routes = addToRouteList(&route, n.v6Routes)
}

func addToRouteList(route *netlink.Route, routes []netlink.Route) []netlink.Route {
	for _, r := range routes {
		if routeEqual(r, *route) {
			return routes
		}
	}
	return append(routes, *route)
}

func (n *RouteNetwork) removeFromV4RouteList(route netlink.Route) {
	n.routesMu.Lock()
	defer n.routesMu.Unlock()
	n.routes = n.removeFromRouteList(&route, n.routes)
}

func (n *RouteNetwork) removeFromV6RouteList(route netlink.Route) {
	n.routesMu.Lock()
	defer n.routesMu.Unlock()
	n.v6Routes = n.removeFromRouteList(&route, n.v6Routes)
}

func (n *RouteNetwork) removeFromRouteList(route *netlink.Route, routes []netlink.Route) []netlink.Route {
	for index, r := range routes {
		if routeEqual(r, *route) {
			routes = append(routes[:index], routes[index+1:]...)
			return routes
		}
	}
	return routes
}

func (n *RouteNetwork) routeCheck(ctx context.Context) {
	n.runRouteSyncLoop(ctx)
}

func (n *RouteNetwork) checkSubnetExistInV4Routes() {
	n.checkSubnetExistInRoutes(n.snapshotDesiredRoutes(netlink.FAMILY_V4), netlink.FAMILY_V4)
}

func (n *RouteNetwork) checkSubnetExistInV6Routes() {
	n.checkSubnetExistInRoutes(n.snapshotDesiredRoutes(netlink.FAMILY_V6), netlink.FAMILY_V6)
}

func (n *RouteNetwork) checkSubnetExistInRoutes(routes []netlink.Route, ipFamily int) {
	n.ReconcileFamily(context.Background(), ipFamily, routes)
}

func routeEqual(x, y netlink.Route) bool {
	// For ipip backend, when enabling directrouting, link index of some routes may change
	// For both ipip and host-gw backend, link index may also change if updating ExtIface.
	// Nil destinations are handled safely so a default route can never panic reconciliation.
	return routeIPNetEqual(x.Dst, y.Dst) && x.Gw.Equal(y.Gw) && x.LinkIndex == y.LinkIndex
}

func routeIPNetEqual(x, y *net.IPNet) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}
	return x.IP.Equal(y.IP) && bytes.Equal(x.Mask, y.Mask)
}
