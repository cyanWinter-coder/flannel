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

package trafficmngr

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds aggregate rule-delivery counters and timings for one manager.
// All fields are safe for concurrent use.
type Metrics struct {
	Reconciliations atomic.Int64
	Successful      atomic.Int64
	Failed          atomic.Int64
	DryRuns         atomic.Int64
	Rollbacks       atomic.Int64

	RulesAdded            atomic.Int64
	RulesDeleted          atomic.Int64
	DuplicatesRemoved     atomic.Int64
	UnchangedObservations atomic.Int64

	// TotalApplyDuration accumulates the duration of every finished pass.
	TotalApplyDuration time.Duration

	mu sync.Mutex

	LastDuration time.Duration
	LastRunAt    time.Time
}

// MetricsSnapshot is a point-in-time copy of Metrics.
type MetricsSnapshot struct {
	Reconciliations       int64
	Successful            int64
	Failed                int64
	DryRuns               int64
	Rollbacks             int64
	RulesAdded            int64
	RulesDeleted          int64
	DuplicatesRemoved     int64
	UnchangedObservations int64
	TotalApplyDuration    time.Duration
	LastDuration          time.Duration
	LastRunAt             time.Time
}

// Record updates the aggregate metrics from one reconcile result. It is safe
// for concurrent use.
func (m *Metrics) Record(res *Result, runErr error) {
	m.record(res, runErr)
}

func (m *Metrics) record(res *Result, runErr error) {
	m.Reconciliations.Add(1)
	if res.DryRun {
		m.DryRuns.Add(1)
	}
	if runErr != nil {
		m.Failed.Add(1)
	} else {
		m.Successful.Add(1)
	}
	if res.RolledBack {
		m.Rollbacks.Add(1)
	}
	m.RulesAdded.Add(int64(res.Added))
	m.RulesDeleted.Add(int64(res.Deleted))
	m.DuplicatesRemoved.Add(int64(res.DuplicatesRemoved))
	m.UnchangedObservations.Add(int64(res.Unchanged))

	m.mu.Lock()
	m.TotalApplyDuration += res.Duration
	m.LastDuration = res.Duration
	m.LastRunAt = res.StartedAt
	m.mu.Unlock()
}

// Snapshot returns a consistent point-in-time copy of the metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	m.mu.Lock()
	total := m.TotalApplyDuration
	last := m.LastDuration
	lastAt := m.LastRunAt
	m.mu.Unlock()
	return MetricsSnapshot{
		Reconciliations:       m.Reconciliations.Load(),
		Successful:            m.Successful.Load(),
		Failed:                m.Failed.Load(),
		DryRuns:               m.DryRuns.Load(),
		Rollbacks:             m.Rollbacks.Load(),
		RulesAdded:            m.RulesAdded.Load(),
		RulesDeleted:          m.RulesDeleted.Load(),
		DuplicatesRemoved:     m.DuplicatesRemoved.Load(),
		UnchangedObservations: m.UnchangedObservations.Load(),
		TotalApplyDuration:    total,
		LastDuration:          last,
		LastRunAt:             lastAt,
	}
}
