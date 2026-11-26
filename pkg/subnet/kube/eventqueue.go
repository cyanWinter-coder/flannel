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

	"github.com/flannel-io/flannel/pkg/lease"
	log "k8s.io/klog/v2"
)

// perNodeEventBuffer bounds how many informer events for a single node can be
// buffered ahead of its drain goroutine. Each node gets its own queue and
// goroutine, so in practice only update bursts (e.g. resync) fill it; the
// global downstream channel remains the main backpressure point.
const perNodeEventBuffer = 32

// nodeEventQueue serializes lease events on a per-node basis while letting
// distinct nodes be processed concurrently. Every node owns a small, ordered
// queue and a single drain goroutine, so events of the same node are always
// forwarded to the downstream events channel in the order the informer
// delivered them. A slow or stuck node can never reorder or block events of
// other nodes.
type nodeEventQueue struct {
	events chan lease.Event

	mu    sync.Mutex
	nodes map[string]*nodeQueue
}

// nodeQueue is the per-node FIFO plus the bookkeeping of its drain goroutine.
type nodeQueue struct {
	name     string
	events   chan lease.Event
	queued   int // events accepted into the per-node channel, not yet drained
	draining bool
}

func newNodeEventQueue(downstream chan lease.Event) *nodeEventQueue {
	return &nodeEventQueue{
		events: downstream,
		nodes:  make(map[string]*nodeQueue),
	}
}

// enqueue appends an event to the node's ordered queue. It blocks when that
// node's queue is full, applying backpressure to the informer goroutine
// instead of spawning unbounded helper goroutines or dropping the event, which
// preserves in-order delivery per node.
func (q *nodeEventQueue) enqueue(ctx context.Context, nodeName string, evt lease.Event) {
	q.mu.Lock()
	nq, ok := q.nodes[nodeName]
	if !ok {
		nq = &nodeQueue{
			name:   nodeName,
			events: make(chan lease.Event, perNodeEventBuffer),
		}
		q.nodes[nodeName] = nq
	}
	nq.queued++
	startDrain := !nq.draining
	if startDrain {
		nq.draining = true
	}
	q.mu.Unlock()

	if startDrain {
		go q.drain(ctx, nq)
	}

	select {
	case nq.events <- evt:
	case <-ctx.Done():
		log.Warningf("Context cancelled while enqueuing lease event for node %q, event dropped", nodeName)
	}
}

// drain forwards a node's events in order. After each event it atomically
// checks under the lock whether the queue is empty; if so it marks the node as
// no longer draining and removes its entry before exiting. A concurrent
// enqueue that arrives in that window observes draining==false and starts a
// fresh drain goroutine, so no event can ever be left without a drainer. The
// same cleanup runs on shutdown after a best-effort flush.
func (q *nodeEventQueue) drain(ctx context.Context, nq *nodeQueue) {
	for {
		select {
		case evt := <-nq.events:
			// Forward outside the lock: a blocked downstream consumer must not
			// hold up enqueue() bookkeeping for the other nodes.
			select {
			case q.events <- evt:
			case <-ctx.Done():
				log.Warningf("Context cancelled while forwarding lease event for node %q, event dropped", nq.name)
			}

			if q.consumeAndMaybeStop(nq) {
				return
			}
		case <-ctx.Done():
			// On shutdown, flush events already accepted so in-flight delete
			// events still get a chance to release subnets, then clean up.
			for {
				select {
				case evt := <-nq.events:
					select {
					case q.events <- evt:
					default:
						log.Warningf("Shutdown: lease event for node %q could not be delivered", nq.name)
					}
				default:
					q.stopAndRemove(nq)
					return
				}
			}
		}
	}
}

// consumeAndMaybeStop accounts for one drained event and, when the node has no
// more buffered events, stops draining and removes its map entry. It reports
// whether the caller's drain goroutine should exit.
func (q *nodeEventQueue) consumeAndMaybeStop(nq *nodeQueue) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	nq.queued--
	if nq.queued > 0 {
		return false
	}
	nq.draining = false
	delete(q.nodes, nq.name)
	return true
}

// stopAndRemove unconditionally tears down a node entry during shutdown.
func (q *nodeEventQueue) stopAndRemove(nq *nodeQueue) {
	q.mu.Lock()
	defer q.mu.Unlock()
	nq.queued = 0
	nq.draining = false
	delete(q.nodes, nq.name)
}
