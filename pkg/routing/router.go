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

package routing

import (
	"bytes"
	"net"
)

// Router manages network routes
type Router interface {
	// GetAllRoutes returns all existing routes
	GetAllRoutes() ([]Route, error)

	// GetRoutesFromInterfaceToSubnet returns all routes from the given Interface to the given subnet
	GetRoutesFromInterfaceToSubnet(interfaceIndex int, destinationSubnet *net.IPNet) ([]Route, error)

	// CreateRoute creates a new route
	CreateRoute(interfaceIndex int, destinationSubnet *net.IPNet, gatewayAddress net.IP) error

	// DeleteRoute removes an existing route
	DeleteRoute(interfaceIndex int, destinationSubnet *net.IPNet, gatewayAddress net.IP) error
}

// Route present a specific route
type Route struct {
	InterfaceIndex    int
	DestinationSubnet *net.IPNet
	GatewayAddress    net.IP
}

// Equal reports whether two routes describe the same destination and gateway.
// Interface index is intentionally not part of this historical identity; use
// EqualOnInterface when the interface must also match.
func (r Route) Equal(other Route) bool {
	return ipNetEqual(r.DestinationSubnet, other.DestinationSubnet) &&
		ipEqual(r.GatewayAddress, other.GatewayAddress)
}

// EqualOnInterface additionally compares the route interface index.
func (r Route) EqualOnInterface(other Route) bool {
	return r.InterfaceIndex == other.InterfaceIndex && r.Equal(other)
}

func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}
