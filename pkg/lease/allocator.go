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

package lease

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
)

// State is the lifecycle state of an allocated lease.
type State string

const (
	// StateActive means the lease is within its lifetime.
	StateActive State = "active"
	// StateGrace means the lease has logically expired but its prefix is still
	// reserved for the owner until the grace period elapses.
	StateGrace State = "grace"
	// StateReclaimable means the grace period has elapsed and the prefix may be
	// assigned to another node. The previous owner still gets the record back if
	// it asks before another node claims the prefix.
	StateReclaimable State = "reclaimable"
	// StateReleased means the owner explicitly released the prefix.
	StateReleased State = "released"
)

// Compatibility aliases for callers/tests that describe a grace-held lease as
// expired.
const (
	StateAllocated   = StateActive
	StateExpired     = StateGrace
	LeaseActive      = StateActive
	LeaseExpired     = StateGrace
	LeaseGrace       = StateGrace
	LeaseReclaimable = StateReclaimable
)

var (
	ErrNodeIDRequired = errors.New("node id is required")
	ErrPrefixRequired = errors.New("prefix is required")
	ErrPrefixOccupied = errors.New("prefix is occupied by another node")
	ErrNoPrefix       = errors.New("no allocatable prefix")
	ErrLeaseNotFound  = errors.New("lease not found")
	ErrStoreRequired  = errors.New("lease store is required")
	ErrInvalidConfig  = errors.New("invalid lease allocator config")
	ErrRetryExhausted = errors.New("lease renewal retry limit reached")
)

// Record is the durable allocation state for one node/prefix binding.
type Record struct {
	// NodeID is the stable node identity. It is the idempotency key for Acquire.
	NodeID string `json:"node_id"`
	// Prefix is the canonical allocated subnet prefix.
	Prefix string `json:"prefix"`
	// State is the current lifecycle state.
	State State `json:"state"`
	// Generation is incremented every time a record is allocated or reactivated.
	Generation int64 `json:"generation"`

	AcquiredAt  time.Time `json:"acquired_at"`
	RenewedAt   time.Time `json:"renewed_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	GraceEndsAt time.Time `json:"grace_ends_at,omitempty"`

	// RenewFailures is the number of consecutive failed renewal attempts. A
	// successful renewal resets it to zero.
	RenewFailures int `json:"renew_failures,omitempty"`
	// LastFailureReason preserves the reason giving up or entering backoff.
	LastFailureReason string `json:"last_failure_reason,omitempty"`
}

// Expired reports whether the logical lease lifetime has ended at now.
func (r Record) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// InGrace reports whether now is after logical expiration but before the
// reclamation deadline.
func (r Record) InGrace(now time.Time) bool {
	return r.State == StateGrace ||
		(r.Expired(now) && !r.GraceEndsAt.IsZero() && now.Before(r.GraceEndsAt))
}

// Reclaimable reports whether the prefix can be assigned to another node.
func (r Record) Reclaimable(now time.Time) bool {
	if r.State == StateReclaimable || r.State == StateReleased {
		return true
	}
	return !r.GraceEndsAt.IsZero() && !now.Before(r.GraceEndsAt)
}

// Held reports whether the prefix must not be allocated to another node.
func (r Record) Held(now time.Time) bool {
	return r.State == StateActive || r.State == StateGrace || (!r.Reclaimable(now) && r.Expired(now))
}

func (r *Record) reconcile(now time.Time, grace time.Duration) {
	if r.State == StateReleased || r.State == StateReclaimable {
		return
	}
	if !r.Expired(now) {
		r.State = StateActive
		return
	}
	if r.GraceEndsAt.IsZero() {
		r.GraceEndsAt = r.ExpiresAt.Add(grace)
	}
	if now.Before(r.GraceEndsAt) {
		r.State = StateGrace
	} else {
		r.State = StateReclaimable
	}
}

// Clone returns a value copy safe to return outside the allocator lock.
func (r Record) Clone() Record { return r }

// Store persists the complete set of allocation records.
type Store interface {
	Load(ctx context.Context) ([]Record, error)
	Save(ctx context.Context, records []Record) error
}

// Config configures an Allocator.
type Config struct {
	// Prefixes is the explicit candidate pool. Either Prefixes or Parent plus
	// PrefixLength must be configured.
	Prefixes []string
	// Parent is an aggregate prefix such as 10.244.0.0/16.
	Parent string
	// PrefixLength is the per-node subnet length used with Parent.
	PrefixLength int
	// SkipFirstParentSubnet mirrors Flannel's historical allocation behavior by
	// skipping the zero subnet of Parent.
	SkipFirstParentSubnet bool

	// LeaseTTL is the logical lease lifetime.
	LeaseTTL time.Duration
	// GracePeriod keeps an expired prefix reserved for its previous owner.
	GracePeriod time.Duration

	// Store is optional for purely in-memory use.
	Store Store
	// StateFile is an optional convenience for a JSON FileStore. It is ignored
	// when Store is set. When non-empty, NewAllocator also recovers any existing
	// state from the file.
	StateFile string
	// Clock is useful in tests. Defaults to the real clock.
	Clock clockwork.Clock

	// Now is retained as a convenient injection point for callers that do not
	// want to construct a clockwork.Clock. When set it takes precedence over
	// Clock.
	Now func() time.Time
}

// Allocator is a concurrency-safe node-id/prefix allocator with idempotent
// acquisition, expiration grace and durable recovery.
type Allocator struct {
	mu     sync.Mutex
	config Config
	clock  clockwork.Clock

	prefixes []netip.Prefix
	records  map[string]*Record
	byNode   map[string]string
}

// LeaseAllocator is a descriptive alias for callers/tests.
type LeaseAllocator = Allocator

// NewLeaseAllocator is an alias for NewAllocator.
func NewLeaseAllocator(cfg Config) (*Allocator, error) { return NewAllocator(cfg) }

// NewAllocator constructs an allocator. It does not read Store; call Recover
// (or NewRecoveredAllocator) after construction to restore persisted records.
func NewAllocator(cfg Config) (*Allocator, error) {
	if cfg.LeaseTTL <= 0 {
		return nil, fmt.Errorf("%w: LeaseTTL must be positive", ErrInvalidConfig)
	}
	if cfg.GracePeriod < 0 {
		return nil, fmt.Errorf("%w: GracePeriod must not be negative", ErrInvalidConfig)
	}

	clock := cfg.Clock
	if clock == nil {
		clock = clockwork.NewRealClock()
	}

	prefixes, err := normalizePrefixes(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Store == nil && cfg.StateFile != "" {
		cfg.Store = NewFileStore(cfg.StateFile)
	}

	a := &Allocator{
		config:   cfg,
		clock:    clock,
		prefixes: prefixes,
		records:  make(map[string]*Record),
		byNode:   make(map[string]string),
	}
	if cfg.StateFile != "" && cfg.Store != nil {
		if err := a.Recover(context.Background()); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// NewRecoveredAllocator constructs an allocator and loads its persisted state.
func NewRecoveredAllocator(ctx context.Context, cfg Config) (*Allocator, error) {
	a, err := NewAllocator(cfg)
	if err != nil {
		return nil, err
	}
	if err := a.Recover(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Allocator) now() time.Time {
	if a.config.Now != nil {
		return a.config.Now()
	}
	return a.clock.Now()
}

func normalizePrefixes(cfg Config) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := make(map[string]struct{})

	add := func(p netip.Prefix) error {
		if !p.IsValid() {
			return fmt.Errorf("%w: invalid prefix", ErrInvalidConfig)
		}
		p = p.Masked()
		key := p.String()
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		out = append(out, p)
		return nil
	}

	for _, raw := range cfg.Prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: parse prefix %q: %v", ErrInvalidConfig, raw, err)
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}

	if cfg.Parent != "" {
		parent, err := netip.ParsePrefix(cfg.Parent)
		if err != nil {
			return nil, fmt.Errorf("%w: parse parent %q: %v", ErrInvalidConfig, cfg.Parent, err)
		}
		if cfg.PrefixLength <= parent.Bits() || cfg.PrefixLength > parent.Addr().BitLen() {
			return nil, fmt.Errorf("%w: PrefixLength %d invalid for %s", ErrInvalidConfig, cfg.PrefixLength, cfg.Parent)
		}

		generated, err := enumerateChildPrefixes(parent.Masked(), cfg.PrefixLength, cfg.SkipFirstParentSubnet)
		if err != nil {
			return nil, err
		}
		for _, p := range generated {
			if err := add(p); err != nil {
				return nil, err
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: at least one prefix is required", ErrInvalidConfig)
	}

	// Explicit prefixes may arrive in arbitrary order. Sorting makes allocation
	// deterministic while still allowing occupied prefixes to be skipped.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

func enumerateChildPrefixes(parent netip.Prefix, newBits int, skipFirst bool) ([]netip.Prefix, error) {
	addr := parent.Addr()
	bitLen := addr.BitLen()
	parentBits := parent.Bits()

	count := new(big.Int).Lsh(big.NewInt(1), uint(newBits-parentBits))
	step := new(big.Int).Lsh(big.NewInt(1), uint(bitLen-newBits))
	base := new(big.Int).SetBytes(addr.AsSlice())

	// Limit accidental enormous pools (for example IPv6 /32 to /64) while still
	// comfortably supporting the stated thousand-node scale.
	const maxGenerated = 65536
	if !count.IsInt64() || count.Int64() > maxGenerated {
		count = big.NewInt(maxGenerated)
	}

	out := make([]netip.Prefix, 0, int(count.Int64()))
	start := int64(0)
	if skipFirst {
		start = 1
	}
	for i := big.NewInt(start); i.Cmp(count) < 0; i.Add(i, big.NewInt(1)) {
		value := new(big.Int).Add(base, new(big.Int).Mul(i, step))
		b := value.Bytes()
		if len(b) < bitLen/8 {
			padded := make([]byte, bitLen/8)
			copy(padded[len(padded)-len(b):], b)
			b = padded
		}

		var childAddr netip.Addr
		var ok bool
		if bitLen == 32 {
			var arr [4]byte
			copy(arr[:], b)
			childAddr, ok = netip.AddrFromSlice(arr[:])
		} else {
			var arr [16]byte
			copy(arr[:], b)
			childAddr, ok = netip.AddrFromSlice(arr[:])
		}
		if !ok {
			return nil, fmt.Errorf("%w: generated invalid address", ErrInvalidConfig)
		}
		out = append(out, netip.PrefixFrom(childAddr, newBits).Masked())
	}
	return out, nil
}

// Recover loads records from the configured Store and rebuilds node/prefix
// indexes. Records from disk take precedence over empty in-memory state, but
// existing in-memory records are not silently overwritten.
func (a *Allocator) Recover(ctx context.Context) error {
	if a.config.Store == nil {
		return ErrStoreRequired
	}
	loaded, err := a.config.Store.Load(ctx)
	if err != nil {
		return fmt.Errorf("load lease state: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	for i := range loaded {
		r := loaded[i]
		if r.NodeID == "" || r.Prefix == "" {
			continue
		}
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue
		}
		r.Prefix = p.Masked().String()
		r.reconcile(now, a.config.GracePeriod)
		if _, exists := a.records[r.Prefix]; exists {
			continue
		}
		cp := r
		a.records[r.Prefix] = &cp
		// A prefix claimed by another node wins over a stale node index.
		if _, nodeBound := a.byNode[r.NodeID]; !nodeBound {
			a.byNode[r.NodeID] = r.Prefix
		}
	}
	return nil
}

// Persist writes the current records to the configured Store.
func (a *Allocator) Persist(ctx context.Context) error {
	if a.config.Store == nil {
		return ErrStoreRequired
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.config.Store.Save(ctx, a.snapshotRecordsLocked())
}

func (a *Allocator) snapshotRecordsLocked() []Record {
	out := make([]Record, 0, len(a.records))
	for _, r := range a.records {
		out = append(out, r.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// Acquire returns the existing lease for nodeID or allocates a free prefix.
// Repeated calls for the same node never move it to a different prefix while
// its record is retained.
func (a *Allocator) Acquire(ctx context.Context, nodeID string) (*Record, error) {
	return a.AcquirePrefix(ctx, nodeID, "")
}

// Allocate is an alias for Acquire.
func (a *Allocator) Allocate(ctx context.Context, nodeID string) (*Record, error) {
	return a.Acquire(ctx, nodeID)
}

// AllocateSubnet is an alias for AcquirePrefix. An empty preferredPrefix lets
// the allocator choose a free prefix from its pool.
func (a *Allocator) AllocateSubnet(ctx context.Context, nodeID, preferredPrefix string) (*Record, error) {
	return a.AcquirePrefix(ctx, nodeID, preferredPrefix)
}

// AcquirePrefix is the idempotent allocation entry point. When preferredPrefix
// is empty the pool is scanned. A non-empty preferredPrefix can recreate a
// node's persisted lease or explicitly claim a chosen free prefix.
func (a *Allocator) AcquirePrefix(ctx context.Context, nodeID, preferredPrefix string) (*Record, error) {
	if nodeID == "" {
		return nil, ErrNodeIDRequired
	}
	if preferredPrefix != "" {
		p, err := netip.ParsePrefix(preferredPrefix)
		if err != nil {
			return nil, fmt.Errorf("%w: parse preferred prefix %q: %v", ErrInvalidConfig, preferredPrefix, err)
		}
		preferredPrefix = p.Masked().String()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	a.reconcileAllLocked(now)

	// Idempotency by stable node identity has highest priority.
	if key, ok := a.byNode[nodeID]; ok {
		if r := a.records[key]; r != nil {
			r.reconcile(now, a.config.GracePeriod)
			r.State = StateActive
			r.ExpiresAt = now.Add(a.config.LeaseTTL)
			r.GraceEndsAt = time.Time{}
			if r.RenewedAt.IsZero() {
				r.RenewedAt = now
			}
			r.LastFailureReason = ""
			if err := a.commitLocked(ctx); err != nil {
				return nil, err
			}
			return ptrClone(r), nil
		}
		// Index is stale; rebuild it below.
		delete(a.byNode, nodeID)
	}

	// Restart recovery often has a local prefix before the node index is known.
	// If that prefix record carries the same node id, adopt it.
	if preferredPrefix != "" {
		if r, ok := a.records[preferredPrefix]; ok {
			if r.NodeID != "" && r.NodeID != nodeID && r.Held(now) {
				return nil, &PrefixOccupiedError{Prefix: preferredPrefix, Owner: r.NodeID}
			}
			if r.NodeID == nodeID || !r.Held(now) {
				return a.claimLocked(ctx, nodeID, preferredPrefix, r, now)
			}
		}
	}

	// Try the locally preferred prefix even if it is not currently in records.
	if preferredPrefix != "" && a.prefixInPoolLocked(preferredPrefix) {
		if r := a.records[preferredPrefix]; r == nil || !r.Held(now) {
			return a.claimLocked(ctx, nodeID, preferredPrefix, r, now)
		}
	}

	for _, p := range a.prefixes {
		key := p.String()
		r := a.records[key]
		if r != nil && r.Held(now) {
			continue
		}
		return a.claimLocked(ctx, nodeID, key, r, now)
	}

	return nil, ErrNoPrefix
}

// PrefixOccupiedError identifies the owner of a conflicting prefix.
type PrefixOccupiedError struct {
	Prefix string
	Owner  string
}

func (e *PrefixOccupiedError) Error() string {
	return fmt.Sprintf("%s %q is bound to node %q", ErrPrefixOccupied.Error(), e.Prefix, e.Owner)
}

func (e *PrefixOccupiedError) Is(target error) bool { return target == ErrPrefixOccupied }

func (a *Allocator) prefixInPoolLocked(key string) bool {
	for _, p := range a.prefixes {
		if p.String() == key {
			return true
		}
	}
	return false
}

func (a *Allocator) claimLocked(ctx context.Context, nodeID, prefix string, previous *Record, now time.Time) (*Record, error) {
	// If this prefix was reclaimable and belonged to another node, remove that
	// node's reverse index only while it still points at this prefix.
	if previous != nil && previous.NodeID != "" && previous.NodeID != nodeID {
		if current, ok := a.byNode[previous.NodeID]; ok && current == prefix {
			delete(a.byNode, previous.NodeID)
		}
	}

	generation := int64(1)
	acquiredAt := now
	if previous != nil {
		generation = previous.Generation + 1
		if !previous.AcquiredAt.IsZero() {
			acquiredAt = previous.AcquiredAt
		}
	}

	r := &Record{
		NodeID:     nodeID,
		Prefix:     prefix,
		State:      StateActive,
		Generation: generation,
		AcquiredAt: acquiredAt,
		RenewedAt:  now,
		ExpiresAt:  now.Add(a.config.LeaseTTL),
	}

	oldRecord := a.records[prefix]
	oldNodeKey, hadNodeIndex := a.byNode[nodeID]
	a.records[prefix] = r
	a.byNode[nodeID] = prefix

	if err := a.saveLocked(ctx); err != nil {
		// Roll back in-memory state so a failed durable commit does not hand out
		// a lease that cannot be recovered.
		if oldRecord != nil {
			a.records[prefix] = oldRecord
		} else {
			delete(a.records, prefix)
		}
		if hadNodeIndex {
			a.byNode[nodeID] = oldNodeKey
		} else {
			delete(a.byNode, nodeID)
		}
		return nil, fmt.Errorf("persist lease allocation: %w", err)
	}
	return ptrClone(r), nil
}

func ptrClone(r *Record) *Record {
	if r == nil {
		return nil
	}
	c := r.Clone()
	return &c
}

func (a *Allocator) commitLocked(ctx context.Context) error {
	if err := a.saveLocked(ctx); err != nil {
		return fmt.Errorf("persist lease update: %w", err)
	}
	return nil
}

func (a *Allocator) saveLocked(ctx context.Context) error {
	if a.config.Store == nil {
		return nil
	}
	// Store implementations are expected to be safe; callers hold the allocator
	// lock so Save must not call back into Allocator.
	return a.config.Store.Save(ctx, a.snapshotRecordsLocked())
}

func (a *Allocator) reconcileAllLocked(now time.Time) {
	for _, r := range a.records {
		r.reconcile(now, a.config.GracePeriod)
	}
}

// GetByNode returns a copy of the record bound to nodeID.
func (a *Allocator) GetByNode(nodeID string) (*Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key, ok := a.byNode[nodeID]
	if !ok {
		return nil, fmt.Errorf("%w: node %q", ErrLeaseNotFound, nodeID)
	}
	r, ok := a.records[key]
	if !ok {
		return nil, fmt.Errorf("%w: prefix index %q", ErrLeaseNotFound, key)
	}
	r.reconcile(a.now(), a.config.GracePeriod)
	return ptrClone(r), nil
}

// GetByPrefix returns a copy of the record bound to prefix.
func (a *Allocator) GetByPrefix(prefix string) (*Record, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	key := p.Masked().String()

	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.records[key]
	if !ok {
		return nil, fmt.Errorf("%w: prefix %q", ErrLeaseNotFound, key)
	}
	r.reconcile(a.now(), a.config.GracePeriod)
	return ptrClone(r), nil
}

// Renew extends the local lifetime and persists the result. Storage-backend
// renewal with retry/backoff is provided by RenewWithRetry.
func (a *Allocator) Renew(ctx context.Context, nodeID string) (*Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key, ok := a.byNode[nodeID]
	if !ok {
		return nil, fmt.Errorf("%w: node %q", ErrLeaseNotFound, nodeID)
	}
	r := a.records[key]
	if r == nil {
		return nil, fmt.Errorf("%w: prefix %q", ErrLeaseNotFound, key)
	}
	now := a.now()
	r.State = StateActive
	r.RenewedAt = now
	r.ExpiresAt = now.Add(a.config.LeaseTTL)
	r.GraceEndsAt = time.Time{}
	r.RenewFailures = 0
	r.LastFailureReason = ""
	if err := a.commitLocked(ctx); err != nil {
		return nil, err
	}
	return ptrClone(r), nil
}

// RecordRenewalFailure records the most recent renewal failure without changing
// the prefix binding.
func (a *Allocator) RecordRenewalFailure(ctx context.Context, nodeID string, cause error) (*Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key, ok := a.byNode[nodeID]
	if !ok {
		return nil, fmt.Errorf("%w: node %q", ErrLeaseNotFound, nodeID)
	}
	r := a.records[key]
	if r == nil {
		return nil, fmt.Errorf("%w: prefix %q", ErrLeaseNotFound, key)
	}
	r.RenewFailures++
	if cause != nil {
		r.LastFailureReason = cause.Error()
	}
	if err := a.commitLocked(ctx); err != nil {
		return nil, err
	}
	return ptrClone(r), nil
}

// Expire marks a lease logically expired. Reconciliation will place it in the
// grace state and eventually make it reclaimable.
func (a *Allocator) Expire(ctx context.Context, nodeID string) (*Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key, ok := a.byNode[nodeID]
	if !ok {
		return nil, fmt.Errorf("%w: node %q", ErrLeaseNotFound, nodeID)
	}
	r := a.records[key]
	if r == nil {
		return nil, fmt.Errorf("%w: prefix %q", ErrLeaseNotFound, key)
	}
	now := a.now()
	r.ExpiresAt = now
	r.GraceEndsAt = now.Add(a.config.GracePeriod)
	r.reconcile(now, a.config.GracePeriod)
	if err := a.commitLocked(ctx); err != nil {
		return nil, err
	}
	return ptrClone(r), nil
}

// ReclaimExpired advances expiration/grace state and returns prefixes that are
// now reclaimable. It does not delete records so the previous node can still
// idempotently recover its prefix before another node claims it.
func (a *Allocator) ReclaimExpired(ctx context.Context) ([]Record, error) {
	a.mu.Lock()
	now := a.now()
	a.reconcileAllLocked(now)
	var reclaimed []Record
	for _, r := range a.records {
		if r.State == StateReclaimable {
			reclaimed = append(reclaimed, r.Clone())
		}
	}
	var err error
	if a.config.Store != nil {
		err = a.saveLocked(ctx)
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	sort.Slice(reclaimed, func(i, j int) bool { return reclaimed[i].Prefix < reclaimed[j].Prefix })
	return reclaimed, nil
}

// Release removes an active binding. The prefix becomes immediately available.
func (a *Allocator) Release(ctx context.Context, nodeID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	key, ok := a.byNode[nodeID]
	if !ok {
		return nil
	}
	r := a.records[key]
	delete(a.byNode, nodeID)
	delete(a.records, key)
	if r != nil {
		r.State = StateReleased
	}
	return a.saveLocked(ctx)
}

// Records returns a sorted copy of all records.
func (a *Allocator) Records() []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snapshotRecordsLocked()
}
