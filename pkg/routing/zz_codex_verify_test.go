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
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type zzCodexFakeRouter struct {
	mu          sync.Mutex
	routes      []Route
	getAllErr   error
	createErr   error
	deleteErr   error
	createCalls int
	deleteCalls int
}

func (f *zzCodexFakeRouter) GetAllRoutes() ([]Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getAllErr != nil {
		return nil, f.getAllErr
	}
	return append([]Route(nil), f.routes...), nil
}

func (f *zzCodexFakeRouter) GetRoutesFromInterfaceToSubnet(int, *net.IPNet) ([]Route, error) {
	return nil, nil
}

func (f *zzCodexFakeRouter) CreateRoute(_ int, dst *net.IPNet, gw net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	if f.createErr != nil {
		return f.createErr
	}
	f.routes = append(f.routes, Route{DestinationSubnet: dst, GatewayAddress: gw})
	return nil
}

func (f *zzCodexFakeRouter) DeleteRoute(_ int, dst *net.IPNet, gw net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	out := f.routes[:0]
	for _, r := range f.routes {
		if !ipNetEqual(r.DestinationSubnet, dst) || !ipEqual(r.GatewayAddress, gw) {
			out = append(out, r)
		}
	}
	f.routes = out
	return nil
}

func zzCodexCIDR(s string) *net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return n
}

func TestZZCodexReconcilerIdempotentAndSafe(t *testing.T) {
	desired := []Route{{DestinationSubnet: zzCodexCIDR("10.42.0.0/24"), GatewayAddress: net.ParseIP("10.0.0.1")}}
	extra := Route{DestinationSubnet: zzCodexCIDR("10.42.1.0/24"), GatewayAddress: net.ParseIP("10.0.0.2")}
	def := Route{DestinationSubnet: zzCodexCIDR("0.0.0.0/0"), GatewayAddress: net.ParseIP("10.0.0.254")}
	r := &zzCodexFakeRouter{routes: []Route{desired[0], extra, def}}
	rec := NewReconciler(r, WithPolicy(Policy{SyncTimeout: time.Second, MaxRetries: -1}))

	res, err := rec.ReconcileOnce(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deleted) != 1 || r.deleteCalls != 1 {
		t.Fatalf("expected one extra deletion, result=%+v calls=%d", res, r.deleteCalls)
	}
	if IsDefaultRoute(res.Deleted[0]) {
		t.Fatal("deleted extra was default")
	}

	beforeCreates, beforeDeletes := r.createCalls, r.deleteCalls
	res, err = rec.ReconcileOnce(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed() || r.createCalls != beforeCreates || r.deleteCalls != beforeDeletes {
		t.Fatalf("second sync changed state: result=%+v create=%d delete=%d", res, r.createCalls, r.deleteCalls)
	}
}

func TestZZCodexReconcilerRetryCapSnapshotAlert(t *testing.T) {
	r := &zzCodexFakeRouter{getAllErr: errors.New("netlink down")}
	var alerts int
	rec := NewReconciler(r,
		WithPolicy(Policy{MaxRetries: 2, InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, SyncTimeout: time.Second}),
		WithAlerter(AlerterFunc(func(*Snapshot) { alerts++ })),
	)
	rec.Sleep = func(context.Context, time.Duration) error { return nil }
	_, err := rec.ReconcileWithRetry(context.Background(), nil)
	if !errors.Is(err, ErrRetriesExceeded) {
		t.Fatalf("expected retry cap, got %v", err)
	}
	if alerts != 1 || !rec.Exhausted() || rec.LastSnapshot() == nil {
		t.Fatalf("alert=%d exhausted=%v snapshot=%v", alerts, rec.Exhausted(), rec.LastSnapshot())
	}
}

func TestZZCodexReconcilerTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	router := zzCodexBlockingRouter{release: release}
	rec := NewReconciler(router, WithPolicy(Policy{SyncTimeout: 5 * time.Millisecond, MaxRetries: -1}))
	_, err := rec.ReconcileOnce(context.Background(), nil)
	if !errors.Is(err, ErrSyncTimeout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
}

type zzCodexBlockingRouter struct{ release chan struct{} }

func (z zzCodexBlockingRouter) GetAllRoutes() ([]Route, error) {
	<-z.release
	return nil, nil
}
func (z zzCodexBlockingRouter) GetRoutesFromInterfaceToSubnet(int, *net.IPNet) ([]Route, error) {
	<-z.release
	return nil, nil
}
func (z zzCodexBlockingRouter) CreateRoute(int, *net.IPNet, net.IP) error {
	<-z.release
	return nil
}
func (z zzCodexBlockingRouter) DeleteRoute(int, *net.IPNet, net.IP) error {
	<-z.release
	return nil
}
