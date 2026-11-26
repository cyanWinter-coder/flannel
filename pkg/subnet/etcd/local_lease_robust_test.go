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

package etcd

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
)

func TestRobustEtcdLeaseStableNodeID(t *testing.T) {
	msr := newDummyRegistry()
	sm := newLocalManager(msr, ip.IP4Net{}, ip.IP6Net{}, 60)
	ctx := context.Background()

	firstAttrs := &lease.LeaseAttrs{
		NodeID:   "stable-node",
		PublicIP: ip.MustParseIP4("1.2.3.4"),
	}
	first, err := sm.AcquireLease(ctx, firstAttrs)
	if err != nil {
		t.Fatalf("first AcquireLease failed: %v", err)
	}

	// Node IP can change after reprovisioning; NodeID must keep the subnet stable.
	secondAttrs := &lease.LeaseAttrs{
		NodeID:   "stable-node",
		PublicIP: ip.MustParseIP4("5.6.7.8"),
	}
	second, err := sm.AcquireLease(ctx, secondAttrs)
	if err != nil {
		t.Fatalf("second AcquireLease failed: %v", err)
	}
	if !first.Subnet.Equal(second.Subnet) {
		t.Fatalf("node subnet changed: first=%s second=%s", first.Subnet, second.Subnet)
	}
	if second.NodeID != "stable-node" {
		t.Fatalf("NodeID not returned on lease: %q", second.NodeID)
	}
}

func TestRobustEtcdLocalStateRecoversSubnet(t *testing.T) {
	ctx := context.Background()
	statePath := filepath.Join(t.TempDir(), "nested", "lease-state.json")

	firstRegistry := newDummyRegistry()
	first := newLocalManager(firstRegistry, ip.IP4Net{}, ip.IP6Net{}, 60)
	first.stateFile = statePath
	attrs := &lease.LeaseAttrs{NodeID: "restart-node", PublicIP: ip.MustParseIP4("1.2.3.4")}

	l, err := first.AcquireLease(ctx, attrs)
	if err != nil {
		t.Fatalf("AcquireLease failed: %v", err)
	}

	loaded, err := LoadLocalLeaseState(statePath)
	if err != nil {
		t.Fatalf("LoadLocalLeaseState failed: %v", err)
	}
	if loaded == nil || loaded.Subnet != l.Subnet.String() || loaded.NodeID != "restart-node" {
		t.Fatalf("unexpected persisted state: %+v", loaded)
	}

	// A new manager/process with no subnet-file input must recover from the
	// durable local state and request the same prefix.
	restarted := newLocalManager(newDummyRegistry(), ip.IP4Net{}, ip.IP6Net{}, 60)
	restarted.stateFile = statePath
	if err := restarted.loadLocalState(); err != nil {
		t.Fatalf("loadLocalState failed: %v", err)
	}
	if !restarted.previousSubnet.Equal(l.Subnet) {
		t.Fatalf("previous subnet not recovered: got %s want %s", restarted.previousSubnet, l.Subnet)
	}

	got, err := restarted.AcquireLease(ctx, &lease.LeaseAttrs{
		NodeID:   "restart-node",
		PublicIP: ip.MustParseIP4("9.9.9.9"),
	})
	if err != nil {
		t.Fatalf("restarted AcquireLease failed: %v", err)
	}
	if !got.Subnet.Equal(l.Subnet) {
		t.Fatalf("restart did not reuse subnet: got %s want %s", got.Subnet, l.Subnet)
	}
}

type robustFailUpdateRegistry struct {
	Registry
	calls     int
	failUntil int
}

func (r *robustFailUpdateRegistry) updateSubnet(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net, attrs *lease.LeaseAttrs, ttl time.Duration, asof int64) (time.Time, error) {
	r.calls++
	if r.calls <= r.failUntil {
		return time.Time{}, errors.New("temporary storage unavailable")
	}
	return r.Registry.updateSubnet(ctx, sn, sn6, attrs, ttl, asof)
}

func fastRobustRetryPolicy(attempts int) lease.RetryConfig {
	return lease.RetryConfig{
		MaxAttempts:    attempts,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
		Multiplier:     2,
	}
}

func TestRobustEtcdRenewRetriesUntilSuccess(t *testing.T) {
	ctx := context.Background()
	registry := &robustFailUpdateRegistry{Registry: newDummyRegistry(), failUntil: 2}
	sm := newLocalManager(registry, ip.IP4Net{}, ip.IP6Net{}, 60)
	sm.renewBackoff = fastRobustRetryPolicy(5)

	l, err := sm.AcquireLease(ctx, &lease.LeaseAttrs{NodeID: "retry-node", PublicIP: ip.MustParseIP4("1.2.3.4")})
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.RenewLeaseWithRetry(ctx, l); err != nil {
		t.Fatalf("renewal should recover: %v", err)
	}
	if registry.calls != 3 {
		t.Fatalf("expected 3 update calls, got %d", registry.calls)
	}
}

func TestRobustEtcdRenewThresholdWrapsReason(t *testing.T) {
	ctx := context.Background()
	rootErr := errors.New("storage gone")
	registry := &robustAlwaysFailUpdateRegistry{err: rootErr}
	sm := newLocalManager(registry, ip.IP4Net{}, ip.IP6Net{}, 60)
	sm.renewBackoff = fastRobustRetryPolicy(2)

	l := &lease.Lease{
		NodeID: "retry-node",
		Subnet: ip.IP4Net{IP: ip.MustParseIP4("10.3.9.0"), PrefixLen: 24},
		Attrs:  lease.LeaseAttrs{NodeID: "retry-node"},
	}
	err := sm.RenewLeaseWithRetry(ctx, l)
	if !errors.Is(err, lease.ErrRetryExhausted) {
		t.Fatalf("expected ErrRetryExhausted, got %v", err)
	}
	if !errors.Is(err, rootErr) {
		t.Fatalf("expected root reason %v, got %v", rootErr, err)
	}
	if registry.calls != 2 {
		t.Fatalf("expected threshold 2 calls, got %d", registry.calls)
	}
}

type robustAlwaysFailUpdateRegistry struct {
	*MockSubnetRegistry
	calls int
	err   error
}

func (r *robustAlwaysFailUpdateRegistry) updateSubnet(context.Context, ip.IP4Net, ip.IP6Net, *lease.LeaseAttrs, time.Duration, int64) (time.Time, error) {
	r.calls++
	return time.Time{}, r.err
}

type robustCompleteFailRegistry struct {
	*MockSubnetRegistry
	err   error
	calls int
}

func (r *robustCompleteFailRegistry) getSubnet(context.Context, ip.IP4Net, ip.IP6Net) (*lease.Lease, int64, error) {
	return &lease.Lease{
		Subnet:     ip.IP4Net{IP: ip.MustParseIP4("10.3.9.0"), PrefixLen: 24},
		Expiration: time.Now().Add(-time.Minute),
	}, 1, nil
}

func (r *robustCompleteFailRegistry) updateSubnet(context.Context, ip.IP4Net, ip.IP6Net, *lease.LeaseAttrs, time.Duration, int64) (time.Time, error) {
	r.calls++
	return time.Time{}, r.err
}

func TestRobustCompleteLeaseThresholdReturnsDetectableExhaustion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rootErr := errors.New("storage unavailable")
	registry := &robustCompleteFailRegistry{MockSubnetRegistry: newDummyRegistry(), err: rootErr}
	sm := newLocalManager(registry, ip.IP4Net{}, ip.IP6Net{}, 0)
	sm.renewBackoff = fastRobustRetryPolicy(1)

	myLease := &lease.Lease{
		NodeID:     "complete-node",
		Subnet:     ip.IP4Net{IP: ip.MustParseIP4("10.3.9.0"), PrefixLen: 24},
		Expiration: time.Now().Add(-time.Minute),
		Attrs:      lease.LeaseAttrs{NodeID: "complete-node"},
	}

	var wg sync.WaitGroup
	done := make(chan error, 1)
	go func() {
		done <- sm.CompleteLease(ctx, myLease, &wg)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, lease.ErrRetryExhausted) {
			t.Fatalf("expected ErrRetryExhausted, got %v", err)
		}
		if !errors.Is(err, rootErr) {
			t.Fatalf("expected root storage error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CompleteLease did not give up after the configured threshold")
	}

	cancel()
	waitDone := make(chan struct{})
	go func() { wg.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("lease watcher did not stop after context cancellation")
	}
}
