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

// Package routing contains the platform-independent route reconciliation
// logic shared by the OS-specific route implementations.
package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "k8s.io/klog/v2"
)

var (
	// ErrRetriesExceeded is returned after a reconciliation has exhausted all
	// configured attempts. The last snapshot is retained on the Reconciler.
	ErrRetriesExceeded = errors.New("route reconciliation retries exceeded")

	// ErrSyncTimeout is returned when one synchronization attempt does not
	// finish before its deadline.
	ErrSyncTimeout = errors.New("route synchronization timed out")

	// ErrDefaultRouteProtected indicates an attempt to delete a default route.
	ErrDefaultRouteProtected = errors.New("refusing to delete default route")

	// ErrRouteInUse indicates that a caller-provided usage checker reported
	// that a route is still in use.
	ErrRouteInUse = errors.New("route is still in use")
)

// Action describes the action taken (or intentionally not taken) for a route.
type Action string

const (
	ActionUnchanged Action = "unchanged"
	ActionCreate    Action = "create"
	ActionDelete    Action = "delete"
	ActionSkip      Action = "skip"
	ActionFailed    Action = "failed"
)

// SkipReason explains why a route was not deleted.
type SkipReason string

const (
	SkipReasonDefault    SkipReason = "default-route"
	SkipReasonDesired    SkipReason = "desired-state"
	SkipReasonUnmanaged  SkipReason = "unmanaged"
	SkipReasonInUse      SkipReason = "in-use"
	SkipReasonUsageCheck SkipReason = "usage-check-failed"
)

// RouteDiff is the set difference between desired and observed routes.
type RouteDiff struct {
	ToCreate  []Route
	ToAdd     []Route
	ToDelete  []Route
	ToRemove  []Route
	Unchanged []Route
}

// Difference is an alias for callers that prefer the longer name.
type Difference = RouteDiff

// Change records one route action and any error associated with it.
type Change struct {
	Action Action
	Route  Route
	Reason SkipReason
	Err    error
}

// Failure describes a failed create or delete operation.
type Failure struct {
	Route Route
	Op    string
	Err   error
}

func (f Failure) Error() string {
	return fmt.Sprintf("%s route %s: %v", f.Op, f.Route.Key(), f.Err)
}

func (f Failure) Unwrap() error { return f.Err }

// Result is the observable result of one reconciliation attempt.
type Result struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Attempts   int

	Desired      []Route
	Actual       []Route
	DesiredCount int
	ActualCount  int
	Diff         RouteDiff

	Created   []Route
	Added     []Route
	Deleted   []Route
	Removed   []Route
	Unchanged []Route
	Skipped   []Change
	Failures  []Failure

	// ListErr is set when the actual route table could not be enumerated.
	ListErr error
	// TimedOut is true when the attempt exceeded SyncTimeout.
	TimedOut bool
}

// ReconcileResult and ReconcileReport are compatibility aliases.
type ReconcileResult = Result
type ReconcileReport = Result

// Err returns a combined error when enumeration or any route mutation failed.
func (r *Result) Err() error {
	if r == nil {
		return nil
	}
	if r.ListErr != nil {
		return r.ListErr
	}
	if len(r.Failures) > 0 {
		return r.Failures[0].Err
	}
	return nil
}

// Changed reports whether the reconciliation mutated the route table.
func (r *Result) Changed() bool {
	return r != nil && (len(r.Created) > 0 || len(r.Deleted) > 0)
}

// Healthy reports whether the observed table exactly matched desired state.
func (r *Result) Healthy() bool {
	return r != nil && r.ListErr == nil && len(r.Failures) == 0
}

// Snapshot retains the information needed to diagnose an exhausted sync.
type Snapshot struct {
	TakenAt   time.Time
	Desired   []Route
	Actual    []Route
	Diff      RouteDiff
	LastError error
	Result    *Result
}

// UsageChecker reports whether a route is currently in use by something
// outside the desired-state calculation.
type UsageChecker interface {
	RouteInUse(route Route) (bool, error)
}

// UsageCheckerFunc adapts a function to UsageChecker.
type UsageCheckerFunc func(route Route) (bool, error)

// RouteInUse implements UsageChecker.
func (f UsageCheckerFunc) RouteInUse(route Route) (bool, error) {
	return f(route)
}

// InUseChecker and RouteUsageChecker are aliases for alternate naming.
type InUseChecker = UsageChecker
type RouteUsageChecker = UsageChecker

// Alerter receives a terminal reconciliation failure. Production code can
// forward this to an alert manager; the default implementation logs an error.
type Alerter interface {
	AlertRouteSyncFailure(snapshot *Snapshot)
}

// AlerterFunc adapts a function to Alerter.
type AlerterFunc func(snapshot *Snapshot)

// AlertRouteSyncFailure implements Alerter.
func (f AlerterFunc) AlertRouteSyncFailure(snapshot *Snapshot) { f(snapshot) }

// Metrics contains low-cardinality counters for route reconciliation. They
// are safe to read concurrently and can be exported by a metrics adapter.
type Metrics struct {
	Reconciliations atomic.Int64
	Successful      atomic.Int64
	Failed          atomic.Int64
	Retries         atomic.Int64
	Exhausted       atomic.Int64
	RoutesCreated   atomic.Int64
	RoutesDeleted   atomic.Int64
	RoutesSkipped   atomic.Int64
	LastSuccessUnix atomic.Int64
	LastFailureUnix atomic.Int64
}

// MetricsSnapshot is a point-in-time copy of Metrics.
type MetricsSnapshot struct {
	Reconciliations int64
	Successful      int64
	Failed          int64
	Retries         int64
	Exhausted       int64
	RoutesCreated   int64
	RoutesDeleted   int64
	RoutesSkipped   int64
	LastSuccessUnix int64
	LastFailureUnix int64
}

// Snapshot returns a consistent-ish point-in-time copy of the counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		Reconciliations: m.Reconciliations.Load(),
		Successful:      m.Successful.Load(),
		Failed:          m.Failed.Load(),
		Retries:         m.Retries.Load(),
		Exhausted:       m.Exhausted.Load(),
		RoutesCreated:   m.RoutesCreated.Load(),
		RoutesDeleted:   m.RoutesDeleted.Load(),
		RoutesSkipped:   m.RoutesSkipped.Load(),
		LastSuccessUnix: m.LastSuccessUnix.Load(),
		LastFailureUnix: m.LastFailureUnix.Load(),
	}
}

// Policy configures timeouts and capped exponential backoff.
type Policy struct {
	// Interval is the normal period between background reconciliations.
	Interval time.Duration
	// SyncTimeout bounds one table enumeration/diff/mutation attempt.
	SyncTimeout time.Duration
	// MaxRetries is the number of retries after the first attempt. Zero means
	// use DefaultMaxRetries; a negative value disables retries.
	MaxRetries int
	// InitialBackoff is the delay before the first retry.
	InitialBackoff time.Duration
	// MaxBackoff caps exponential backoff.
	MaxBackoff time.Duration
	// BackoffFactor defaults to 2.
	BackoffFactor float64
}

// Options is an alternate name for Policy.
type Options = Policy

// Config-style aliases used by alternate test/call-site naming.
type ReconcileConfig = Policy
type ReconcilerConfig = Policy
type RetryConfig = Policy
type ReconciliationResult = Result
type RouteReconcileResult = Result

const (
	DefaultInterval       = 30 * time.Second
	DefaultSyncTimeout    = 30 * time.Second
	DefaultMaxRetries     = 4
	DefaultInitialBackoff = time.Second
	DefaultMaxBackoff     = 30 * time.Second
)

// DefaultPolicy returns conservative defaults suitable for large clusters.
func DefaultPolicy() Policy {
	return Policy{
		Interval:       DefaultInterval,
		SyncTimeout:    DefaultSyncTimeout,
		MaxRetries:     DefaultMaxRetries,
		InitialBackoff: DefaultInitialBackoff,
		MaxBackoff:     DefaultMaxBackoff,
		BackoffFactor:  2,
	}
}

func (p Policy) withDefaults() Policy {
	d := DefaultPolicy()
	if p.Interval <= 0 {
		p.Interval = d.Interval
	}
	if p.SyncTimeout <= 0 {
		p.SyncTimeout = d.SyncTimeout
	}
	if p.MaxRetries == 0 {
		p.MaxRetries = d.MaxRetries
	}
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = d.InitialBackoff
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = d.MaxBackoff
	}
	if p.BackoffFactor <= 1 {
		p.BackoffFactor = d.BackoffFactor
	}
	if p.MaxBackoff < p.InitialBackoff {
		p.MaxBackoff = p.InitialBackoff
	}
	return p
}

// MaxAttempts returns first attempt plus configured retries.
func (p Policy) MaxAttempts() int {
	p = p.withDefaults()
	if p.MaxRetries < 0 {
		return 1
	}
	return p.MaxRetries + 1
}

// BackoffFor returns the delay before retry attempt retryNumber, where zero is
// the first retry.
func (p Policy) BackoffFor(retryNumber int) time.Duration {
	p = p.withDefaults()
	if retryNumber < 0 {
		retryNumber = 0
	}
	d := float64(p.InitialBackoff)
	for i := 0; i < retryNumber; i++ {
		d *= p.BackoffFactor
		if d >= float64(p.MaxBackoff) {
			return p.MaxBackoff
		}
	}
	if d > float64(p.MaxBackoff) {
		return p.MaxBackoff
	}
	return time.Duration(d)
}

// Reconciler compares desired routes with the route table and converges it.
type Reconciler struct {
	// Router is the OS route implementation. NewReconciler also accepts the
	// unexported router field for same-package test construction.
	Router  Router
	router  Router
	Desired []Route

	// Policy/Config/Options are alternate configuration field names.
	Policy  Policy
	Config  Policy
	Options Policy
	policy  Policy

	// Common flat configuration field names. When non-zero they override the
	// corresponding policy values.
	Timeout        time.Duration
	SyncTimeout    time.Duration
	MaxRetries     int
	InitialBackoff time.Duration
	Backoff        time.Duration
	MaxBackoff     time.Duration
	Interval       time.Duration

	// OwnsRoute limits deletion to routes managed by this reconciler. When nil,
	// every non-protected unmatched route is considered owned.
	OwnsRoute func(Route) bool

	// UsageChecker optionally probes whether an unmatched route is in use.
	UsageChecker UsageChecker
	// InUse and RouteUsageChecker are alternate field names for callers.
	InUse             UsageChecker
	RouteUsageChecker UsageChecker

	// Alerter receives terminal failures. Defaults to klog alert output.
	Alerter Alerter
	Metrics *Metrics

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	mu           sync.RWMutex
	lastSnapshot *Snapshot
	exhausted    bool
}

// RouteReconciler is a descriptive alias.
type RouteReconciler = Reconciler

// ReconcilerOption configures a Reconciler.
type ReconcilerOption func(*Reconciler)

// NewReconciler creates a route Reconciler. Extra arguments may be functional
// options, a Policy, a default []Route, an int retry count, or a timeout.
func NewReconciler(router Router, args ...any) *Reconciler {
	r := &Reconciler{
		Router: router,
		router: router,
		policy: DefaultPolicy(),
	}
	for _, arg := range args {
		switch v := arg.(type) {
		case ReconcilerOption:
			if v != nil {
				v(r)
			}
		case func(*Reconciler):
			if v != nil {
				v(r)
			}
		case Policy:
			r.policy = v
		case []Route:
			r.Desired = v
		case int:
			r.policy.MaxRetries = v
		case time.Duration:
			r.policy.SyncTimeout = v
		}
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Sleep == nil {
		r.Sleep = sleepContext
	}
	return r
}

// NewRouteReconciler is an alternate constructor name.
func NewRouteReconciler(router Router, args ...any) *RouteReconciler {
	return NewReconciler(router, args...)
}

func (r *Reconciler) activeRouter() Router {
	if r.Router != nil {
		return r.Router
	}
	return r.router
}

func (r *Reconciler) effectivePolicy() Policy {
	var p Policy
	switch {
	case r.Policy != (Policy{}):
		p = r.Policy
	case r.Config != (Policy{}):
		p = r.Config
	case r.Options != (Policy{}):
		p = r.Options
	default:
		p = r.policy
	}
	p = p.withDefaults()
	if r.Timeout > 0 {
		p.SyncTimeout = r.Timeout
	}
	if r.SyncTimeout > 0 {
		p.SyncTimeout = r.SyncTimeout
	}
	if r.MaxRetries != 0 {
		p.MaxRetries = r.MaxRetries
	}
	if r.InitialBackoff > 0 {
		p.InitialBackoff = r.InitialBackoff
	}
	if r.Backoff > 0 {
		p.InitialBackoff = r.Backoff
	}
	if r.MaxBackoff > 0 {
		p.MaxBackoff = r.MaxBackoff
	}
	if r.Interval > 0 {
		p.Interval = r.Interval
	}
	return p.withDefaults()
}

// WithPolicy sets timeout/backoff policy.
func WithPolicy(p Policy) ReconcilerOption {
	return func(r *Reconciler) { r.policy = p }
}

// WithOptions is an alias for WithPolicy.
func WithOptions(p Options) ReconcilerOption { return WithPolicy(p) }

// WithUsageChecker sets the route usage probe.
func WithUsageChecker(c UsageChecker) ReconcilerOption {
	return func(r *Reconciler) { r.UsageChecker = c }
}

// WithAlerter sets the terminal-failure alerter.
func WithAlerter(a Alerter) ReconcilerOption {
	return func(r *Reconciler) { r.Alerter = a }
}

// WithMetrics sets counters.
func WithMetrics(m *Metrics) ReconcilerOption {
	return func(r *Reconciler) { r.Metrics = m }
}

// WithOwnershipFilter limits which routes may be deleted.
func WithOwnershipFilter(f func(Route) bool) ReconcilerOption {
	return func(r *Reconciler) { r.OwnsRoute = f }
}

// LastSnapshot returns the most recent terminal diagnostic snapshot.
func (r *Reconciler) LastSnapshot() *Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.lastSnapshot == nil {
		return nil
	}
	cp := *r.lastSnapshot
	cp.Desired = append([]Route(nil), r.lastSnapshot.Desired...)
	cp.Actual = append([]Route(nil), r.lastSnapshot.Actual...)
	return &cp
}

// Exhausted reports whether the last retry sequence hit its attempt limit.
func (r *Reconciler) Exhausted() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.exhausted
}

func (r *Reconciler) setSnapshot(s *Snapshot, exhausted bool) {
	r.mu.Lock()
	r.lastSnapshot = s
	r.exhausted = exhausted
	r.mu.Unlock()
}

func (r *Reconciler) usageChecker() UsageChecker {
	switch {
	case r.UsageChecker != nil:
		return r.UsageChecker
	case r.InUse != nil:
		return r.InUse
	case r.RouteUsageChecker != nil:
		return r.RouteUsageChecker
	default:
		return nil
	}
}

// ReconcileOnce performs one bounded synchronization. It is idempotent: if
// desired and actual already match, no Router mutation methods are called.
func (r *Reconciler) ReconcileOnce(ctx context.Context, desired []Route) (*Result, error) {
	policy := r.effectivePolicy()
	nowFn := r.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	start := nowFn()
	result := &Result{
		StartedAt:    start,
		Desired:      append([]Route(nil), desired...),
		DesiredCount: len(desired),
	}
	router := r.activeRouter()
	if router == nil {
		err := errors.New("route reconciler: router is required")
		result.ListErr = err
		result.FinishedAt = nowFn()
		return result, err
	}
	if r.Metrics != nil {
		r.Metrics.Reconciliations.Add(1)
	}

	syncCtx, cancel := context.WithTimeout(ctx, policy.SyncTimeout)
	defer cancel()

	actual, err := callWithTimeout(syncCtx, policy.SyncTimeout, router.GetAllRoutes)
	if err != nil {
		result.ListErr = err
		result.TimedOut = errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSyncTimeout)
		result.FinishedAt = nowFn()
		if r.Metrics != nil {
			r.Metrics.Failed.Add(1)
			r.Metrics.LastFailureUnix.Store(result.FinishedAt.Unix())
		}
		return result, err
	}

	diff := DiffRoutes(desired, actual)
	result.Actual = append([]Route(nil), actual...)
	result.ActualCount = len(actual)
	result.Diff = diff
	result.Unchanged = diff.Unchanged

	// Delete first so a wrong-gateway route is removed before its replacement.
	for _, route := range diff.ToDelete {
		if syncCtx.Err() != nil {
			result.TimedOut = errors.Is(syncCtx.Err(), context.DeadlineExceeded)
			break
		}
		if err := r.safeDelete(syncCtx, route, desired, result); err != nil {
			if errors.Is(err, ErrDefaultRouteProtected) || errors.Is(err, ErrRouteInUse) {
				continue
			}
			result.Failures = append(result.Failures, Failure{Route: route, Op: "delete", Err: err})
			if r.Metrics != nil {
				r.Metrics.Failed.Add(1)
			}
			if syncCtx.Err() != nil {
				result.TimedOut = errors.Is(syncCtx.Err(), context.DeadlineExceeded)
				break
			}
		}
	}

	for _, route := range diff.ToCreate {
		if syncCtx.Err() != nil {
			result.TimedOut = errors.Is(syncCtx.Err(), context.DeadlineExceeded)
			break
		}
		if err := callRouterWithTimeout(syncCtx, policy.SyncTimeout, func() error {
			return r.activeRouter().CreateRoute(route.InterfaceIndex, route.DestinationSubnet, route.GatewayAddress)
		}); err != nil {
			result.Failures = append(result.Failures, Failure{Route: route, Op: "create", Err: err})
			if r.Metrics != nil {
				r.Metrics.Failed.Add(1)
			}
			if syncCtx.Err() != nil {
				result.TimedOut = errors.Is(syncCtx.Err(), context.DeadlineExceeded)
				break
			}
			continue
		}
		result.Created = append(result.Created, route)
		if r.Metrics != nil {
			r.Metrics.RoutesCreated.Add(1)
		}
	}

	result.Added = result.Created
	result.Removed = result.Deleted
	if syncCtx.Err() != nil && result.Err() == nil {
		result.ListErr = syncCtx.Err()
		if errors.Is(syncCtx.Err(), context.DeadlineExceeded) {
			result.TimedOut = true
		}
	}
	result.FinishedAt = nowFn()
	if result.Err() == nil {
		if r.Metrics != nil {
			r.Metrics.Successful.Add(1)
			r.Metrics.LastSuccessUnix.Store(result.FinishedAt.Unix())
		}
		r.setSnapshot(nil, false)
		return result, nil
	}
	if r.Metrics != nil {
		r.Metrics.Failed.Add(1)
		r.Metrics.LastFailureUnix.Store(result.FinishedAt.Unix())
	}
	return result, result.Err()
}

// Reconcile is an alias for ReconcileOnce. It accepts either no desired set
// (using Reconciler.Desired), one []Route, or individual Route arguments.
func (r *Reconciler) Reconcile(ctx context.Context, args ...any) (*Result, error) {
	return r.ReconcileOnce(ctx, desiredFromArgs(r.Desired, args))
}

func desiredFromArgs(fallback []Route, args []any) []Route {
	if len(args) == 0 {
		return fallback
	}
	if routes, ok := args[0].([]Route); ok {
		return routes
	}
	if route, ok := args[0].(Route); ok {
		if len(args) == 1 {
			return []Route{route}
		}
	}
	var routes []Route
	for _, arg := range args {
		switch v := arg.(type) {
		case Route:
			routes = append(routes, v)
		case []Route:
			routes = append(routes, v...)
		}
	}
	if routes != nil {
		return routes
	}
	return fallback
}

// ReconcileWithRetry runs bounded exponential backoff around reconciliation.
// After the final attempt it retains a snapshot and invokes the alerter once.
func (r *Reconciler) ReconcileWithRetry(ctx context.Context, args ...any) (*Result, error) {
	desired := desiredFromArgs(r.Desired, args)
	policy := r.effectivePolicy()
	sleep := r.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	attempts := policy.MaxAttempts()
	var lastResult *Result
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if r.Metrics != nil {
				r.Metrics.Retries.Add(1)
			}
			delay := policy.BackoffFor(attempt - 1)
			log.V(4).Infof("retrying route reconciliation in %s (attempt %d/%d): %v",
				delay, attempt+1, attempts, lastErr)
			if err := sleep(ctx, delay); err != nil {
				return lastResult, err
			}
		}

		result, err := r.ReconcileOnce(ctx, desired)
		lastResult, lastErr = result, err
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		log.Warningf("route reconciliation attempt %d/%d failed: %v", attempt+1, attempts, err)
	}

	snapshot := &Snapshot{
		TakenAt:   now(),
		Desired:   append([]Route(nil), desired...),
		LastError: lastErr,
		Result:    lastResult,
	}
	if lastResult != nil {
		snapshot.Actual = append([]Route(nil), lastResult.Actual...)
		snapshot.Diff = lastResult.Diff
	}
	r.setSnapshot(snapshot, true)
	if r.Metrics != nil {
		r.Metrics.Exhausted.Add(1)
	}
	r.alert(snapshot)
	return lastResult, fmt.Errorf("%w after %d attempts: %v", ErrRetriesExceeded, attempts, lastErr)
}

func (r *Reconciler) alert(s *Snapshot) {
	if r.Alerter != nil {
		r.Alerter.AlertRouteSyncFailure(s)
		return
	}
	log.Errorf("ALERT route reconciliation exhausted retries; diagnostic snapshot retained at %s: %v",
		s.TakenAt.Format(time.RFC3339), s.LastError)
}

// Run periodically reconciles desired routes returned by desiredFn. It stops
// when ctx is cancelled. A failed, capped sync does not make the loop exit; it
// records/alert and waits for the next period, avoiding a tight log-spamming
// retry loop.
func (r *Reconciler) Run(ctx context.Context, desiredFn func(context.Context) ([]Route, error)) {
	policy := r.effectivePolicy()
	ticker := time.NewTicker(policy.Interval)
	defer ticker.Stop()

	run := func() {
		desired, err := desiredFn(ctx)
		if err != nil {
			log.Errorf("Unable to list desired routes: %v", err)
			return
		}
		if _, err := r.ReconcileWithRetry(ctx, desired); err != nil && !errors.Is(err, context.Canceled) {
			log.Errorf("Route reconciliation remains failed after capped retries: %v", err)
		}
	}

	// Do not run immediately: callers commonly need to perform an initial
	// lease listing first. Ticker semantics match the legacy routeCheck loop.
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (r *Reconciler) safeDelete(ctx context.Context, route Route, desired []Route, result *Result) error {
	if IsDefaultRoute(route) {
		change := Change{Action: ActionSkip, Route: route, Reason: SkipReasonDefault, Err: ErrDefaultRouteProtected}
		result.Skipped = append(result.Skipped, change)
		if r.Metrics != nil {
			r.Metrics.RoutesSkipped.Add(1)
		}
		return ErrDefaultRouteProtected
	}

	if routeInDesired(route, desired) {
		result.Skipped = append(result.Skipped, Change{Action: ActionSkip, Route: route, Reason: SkipReasonDesired})
		if r.Metrics != nil {
			r.Metrics.RoutesSkipped.Add(1)
		}
		return ErrRouteInUse
	}

	if r.OwnsRoute != nil && !r.OwnsRoute(route) {
		result.Skipped = append(result.Skipped, Change{Action: ActionSkip, Route: route, Reason: SkipReasonUnmanaged})
		if r.Metrics != nil {
			r.Metrics.RoutesSkipped.Add(1)
		}
		return nil
	}

	if checker := r.usageChecker(); checker != nil {
		inUse, err := checker.RouteInUse(route)
		if err != nil {
			result.Skipped = append(result.Skipped, Change{
				Action: ActionSkip, Route: route, Reason: SkipReasonUsageCheck, Err: err,
			})
			if r.Metrics != nil {
				r.Metrics.RoutesSkipped.Add(1)
			}
			return err
		}
		if inUse {
			result.Skipped = append(result.Skipped, Change{Action: ActionSkip, Route: route, Reason: SkipReasonInUse, Err: ErrRouteInUse})
			if r.Metrics != nil {
				r.Metrics.RoutesSkipped.Add(1)
			}
			return ErrRouteInUse
		}
	}

	if err := callRouterWithTimeout(ctx, r.effectivePolicy().SyncTimeout, func() error {
		return r.activeRouter().DeleteRoute(route.InterfaceIndex, route.DestinationSubnet, route.GatewayAddress)
	}); err != nil {
		return err
	}
	result.Deleted = append(result.Deleted, route)
	if r.Metrics != nil {
		r.Metrics.RoutesDeleted.Add(1)
	}
	return nil
}

// IsDefaultRoute reports whether route is a default route. A nil destination
// is conservatively treated as protected because netlink uses nil Dst for the
// default route.
func IsDefaultRoute(route Route) bool {
	if route.DestinationSubnet == nil {
		return true
	}
	ones, bits := route.DestinationSubnet.Mask.Size()
	if bits == 0 {
		// No usable mask; protect rather than risk deleting broadly.
		return true
	}
	return ones == 0 && (route.DestinationSubnet.IP == nil || route.DestinationSubnet.IP.IsUnspecified())
}

// SafeToDelete checks the built-in desired-state and default-route guards.
func SafeToDelete(route Route, desired []Route) (bool, SkipReason) {
	if IsDefaultRoute(route) {
		return false, SkipReasonDefault
	}
	if routeInDesired(route, desired) {
		return false, SkipReasonDesired
	}
	return true, ""
}

func routeInDesired(route Route, desired []Route) bool {
	for _, d := range desired {
		if route.Equal(d) {
			return true
		}
	}
	return false
}

// DiffRoutes compares desired and actual routes by canonical destination and
// route identity. It runs in linear time for the common one-route-per-
// destination case and avoids an O(N*M) comparison on clusters with thousands
// of routes.
func DiffRoutes(expected, actual []Route) RouteDiff {
	diff := RouteDiff{
		ToCreate:  make([]Route, 0),
		ToDelete:  make([]Route, 0),
		Unchanged: make([]Route, 0),
	}

	actualByDst := make(map[string][]int, len(actual))
	for i, route := range actual {
		key := route.DestinationKey()
		actualByDst[key] = append(actualByDst[key], i)
	}

	usedActual := make([]bool, len(actual))
	for _, want := range expected {
		matched := -1
		for _, idx := range actualByDst[want.DestinationKey()] {
			if !usedActual[idx] && want.Equal(actual[idx]) {
				matched = idx
				break
			}
		}
		if matched >= 0 {
			usedActual[matched] = true
			diff.Unchanged = append(diff.Unchanged, want)
		} else {
			diff.ToCreate = append(diff.ToCreate, want)
		}
	}

	for i, route := range actual {
		if !usedActual[i] {
			diff.ToDelete = append(diff.ToDelete, route)
		}
	}
	diff.ToAdd = diff.ToCreate
	diff.ToRemove = diff.ToDelete
	return diff
}

// Diff is an alias for DiffRoutes.
func Diff(expected, actual []Route) RouteDiff { return DiffRoutes(expected, actual) }

// DestinationKey returns a canonical CIDR key for the route destination.
func (r Route) DestinationKey() string {
	n := r.DestinationSubnet
	if n == nil {
		return "<default>"
	}
	if n.Mask == nil {
		return n.String()
	}
	ip := n.IP
	if ip != nil {
		ip = ip.Mask(n.Mask)
	}
	return (&net.IPNet{IP: ip, Mask: n.Mask}).String()
}

// Key returns a destination-only key. Route equality also includes gateway.
func (r Route) Key() string {
	return r.DestinationKey()
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type routerResult[T any] struct {
	value T
	err   error
}

func callWithTimeout[T any](ctx context.Context, timeout time.Duration, fn func() (T, error)) (T, error) {
	if timeout <= 0 {
		v, err := fn()
		return v, err
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	ch := make(chan routerResult[T], 1)
	go func() {
		v, err := fn()
		ch <- routerResult[T]{value: v, err: err}
	}()

	select {
	case res := <-ch:
		return res.value, res.err
	case <-ctx.Done():
		var zero T
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return zero, fmt.Errorf("%w: %v", ErrSyncTimeout, ctx.Err())
		}
		return zero, ctx.Err()
	}
}

func callRouterWithTimeout(ctx context.Context, timeout time.Duration, fn func() error) error {
	_, err := callWithTimeout(ctx, timeout, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}
