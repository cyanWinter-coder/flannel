//go:build linux
// +build linux

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

package routing

import (
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

// RouterLinux manages Linux routes through rtnetlink. It is the Linux
// counterpart of RouterWindows and is safe for zero-value use.
type RouterLinux struct {
	// SocketTimeout optionally bounds individual netlink operations. Zero
	// leaves the netlink default unchanged.
	SocketTimeout time.Duration
}

// NewLinuxRouter returns a Linux route router.
func NewLinuxRouter(socketTimeout time.Duration) RouterLinux {
	return RouterLinux{SocketTimeout: socketTimeout}
}

var _ Router = RouterLinux{}

// GetAllRoutes returns IPv4 and IPv6 routes from the main route table.
func (r RouterLinux) GetAllRoutes() ([]Route, error) {
	if r.SocketTimeout > 0 {
		if err := netlink.SetSocketTimeout(r.SocketTimeout); err != nil {
			return nil, err
		}
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	out := make([]Route, 0, len(routes))
	for _, route := range routes {
		out = append(out, fromNetlinkRoute(route))
	}
	return out, nil
}

// GetRoutesFromInterfaceToSubnet returns routes on interfaceIndex to subnet.
func (r RouterLinux) GetRoutesFromInterfaceToSubnet(interfaceIndex int, destinationSubnet *net.IPNet) ([]Route, error) {
	if r.SocketTimeout > 0 {
		if err := netlink.SetSocketTimeout(r.SocketTimeout); err != nil {
			return nil, err
		}
	}
	filter := &netlink.Route{
		LinkIndex: interfaceIndex,
		Dst:       destinationSubnet,
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter,
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST)
	if err != nil {
		return nil, err
	}
	out := make([]Route, 0, len(routes))
	for _, route := range routes {
		out = append(out, fromNetlinkRoute(route))
	}
	return out, nil
}

// CreateRoute creates the requested route.
func (r RouterLinux) CreateRoute(interfaceIndex int, destinationSubnet *net.IPNet, gatewayAddress net.IP) error {
	if r.SocketTimeout > 0 {
		if err := netlink.SetSocketTimeout(r.SocketTimeout); err != nil {
			return err
		}
	}
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: interfaceIndex,
		Dst:       destinationSubnet,
		Gw:        gatewayAddress,
	})
}

// DeleteRoute deletes the requested route.
func (r RouterLinux) DeleteRoute(interfaceIndex int, destinationSubnet *net.IPNet, gatewayAddress net.IP) error {
	if r.SocketTimeout > 0 {
		if err := netlink.SetSocketTimeout(r.SocketTimeout); err != nil {
			return err
		}
	}
	return netlink.RouteDel(&netlink.Route{
		LinkIndex: interfaceIndex,
		Dst:       destinationSubnet,
		Gw:        gatewayAddress,
	})
}

func fromNetlinkRoute(route netlink.Route) Route {
	dst := route.Dst
	if dst == nil {
		// rtnetlink represents default routes with a nil destination; give
		// them an explicit value so safety checks and diffs can see them.
		if route.Family == netlink.FAMILY_V6 {
			_, dst, _ = net.ParseCIDR("::/0")
		} else {
			_, dst, _ = net.ParseCIDR("0.0.0.0/0")
		}
	}
	return Route{
		InterfaceIndex:    route.LinkIndex,
		DestinationSubnet: dst,
		GatewayAddress:    route.Gw,
	}
}
