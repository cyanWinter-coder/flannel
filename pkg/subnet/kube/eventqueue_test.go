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

package kube

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
)

func orderingEvent(lastOctet byte, et lease.EventType) lease.Event {
	return lease.Event{
		Type: et,
		Lease: lease.Lease{
			Subnet:     ip.IP4Net{IP: ip.IP4(0x0a000000 | uint32(lastOctet)), PrefixLen: 24},
			EnableIPv4: true,
		},
	}
}

// drain reads n events from ch or fails the test on timeout.
func drain(t *testing.T, ch chan lease.Event, n int) []lease.Event {
	t.Helper()
	out := make([]lease.Event, 0, n)
	deadline := time.After(5 * time.Second)
	for len(out) < n {
		select {
		case evt := <-ch:
			out = append(out, evt)
		case <-deadline:
			t.Fatalf("timed out: got %d of %d events", len(out), n)
		}
	}
	return out
}

// TestNodeEventQueuePerNodeOrdering interleaves two nodes' events and asserts
// each node's own stream stays FIFO. This is the property that stops a stale
// add from overwriting a newer delete (and therefore a subnet that never gets
// released), while distinct nodes still flow concurrently.
func TestNodeEventQueuePerNodeOrdering(t *testing.T) {
	const count = 50
	events := make(chan lease.Event, count*2)
	q := newNodeEventQueue(events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < count; i++ {
		// node-a: last octet 0..49; node-b: last octet 100..149
		q.enqueue(ctx, "node-a", orderingEvent(byte(i), lease.EventAdded))
		q.enqueue(ctx, "node-b", orderingEvent(byte(100+i), lease.EventAdded))
	}

	got := drain(t, events, count*2)
	seenA, seenB := make([]byte, 0, count), make([]byte, 0, count)
	for _, evt := range got {
		_, _, _, last := evt.Lease.Subnet.IP.Octets()
		switch {
		case last < 100:
			seenA = append(seenA, last)
		default:
			seenB = append(seenB, last)
		}
	}

	if len(seenA) != count || len(seenB) != count {
		t.Fatalf("expected %d events per node, got a=%d b=%d", count, len(seenA), len(seenB))
	}
	for i, last := range seenA {
		if last != byte(i) {
			t.Fatalf("node-a event %d reordered: got last octet %d", i, last)
		}
	}
	for i, last := range seenB {
		if last != byte(100+i) {
			t.Fatalf("node-b event %d reordered: got last octet %d, want %d", i, last, 100+i)
		}
	}
}

// TestNodeEventQueueAddDeleteOrdering is the concrete subnet-leak scenario:
// add then delete for the same node must be delivered in that order, so the
// delete always wins and the route is removed.
func TestNodeEventQueueAddDeleteOrdering(t *testing.T) {
	events := make(chan lease.Event, 4)
	q := newNodeEventQueue(events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q.enqueue(ctx, "node-a", orderingEvent(1, lease.EventAdded))
	q.enqueue(ctx, "node-a", orderingEvent(1, lease.EventRemoved))
	q.enqueue(ctx, "node-a", orderingEvent(1, lease.EventAdded))
	q.enqueue(ctx, "node-a", orderingEvent(1, lease.EventRemoved))

	want := []lease.EventType{lease.EventAdded, lease.EventRemoved, lease.EventAdded, lease.EventRemoved}
	got := drain(t, events, len(want))
	for i, evt := range got {
		if evt.Type != want[i] {
			t.Fatalf("event %d: expected %v, got %v", i, want[i], evt.Type)
		}
	}
}

// TestNodeEventQueueConcurrentEnqueue hammers enqueue from many goroutines to
// catch map/queue races; run with -race.
func TestNodeEventQueueConcurrentEnqueue(t *testing.T) {
	const goroutines, perGoroutine = 20, 100
	events := make(chan lease.Event, goroutines*perGoroutine)
	q := newNodeEventQueue(events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				q.enqueue(ctx, "shared-node", orderingEvent(byte(i), lease.EventAdded))
			}
		}()
	}
	wg.Wait()

	drain(t, events, goroutines*perGoroutine)
}

// TestNodeEventQueueCancelDrains verifies that after cancellation the queue
// shuts its goroutine down and removes the node bookkeeping, so node churn
// cannot leak goroutines or map entries. It polls the internal map directly
// because the in-flight event may be delivered either before or after the
// cancellation is observed.
func TestNodeEventQueueCancel(t *testing.T) {
	events := make(chan lease.Event, 16)
	q := newNodeEventQueue(events)
	ctx, cancel := context.WithCancel(context.Background())

	for i := 0; i < 5; i++ {
		q.enqueue(ctx, "node-a", orderingEvent(byte(i), lease.EventAdded))
	}
	drain(t, events, 5)

	// fresh enqueue spawns a new drain goroutine which is either blocked
	// forwarding or parked on the select when cancellation arrives.
	q.enqueue(ctx, "node-a", orderingEvent(9, lease.EventRemoved))
	cancel()

	deadline := time.After(2 * time.Second)
	for {
		q.mu.Lock()
		_, exists := q.nodes["node-a"]
		q.mu.Unlock()
		if !exists {
			return
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatal("node entry leaked after context cancellation")
		}
	}
}

// TestNodeEventQueueEntryReaped verifies the map entry disappears once a
// node's events have all drained and is recreated cleanly by a later enqueue,
// keeping memory bounded on clusters where nodes come and go.
func TestNodeEventQueueEntryReaped(t *testing.T) {
	events := make(chan lease.Event, 8)
	q := newNodeEventQueue(events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q.enqueue(ctx, "ephemeral", orderingEvent(1, lease.EventAdded))
	drain(t, events, 1)

	deadline := time.After(2 * time.Second)
	for {
		q.mu.Lock()
		_, exists := q.nodes["ephemeral"]
		q.mu.Unlock()
		if !exists {
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatal("idle node entry was not reaped")
		}
	}

	// a later event still works after the entry was removed
	q.enqueue(ctx, "ephemeral", orderingEvent(2, lease.EventRemoved))
	got := drain(t, events, 1)
	if got[0].Type != lease.EventRemoved {
		t.Fatalf("expected removal after re-enqueue, got %v", got[0].Type)
	}
}
