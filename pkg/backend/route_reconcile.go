//go:build !windows
// +build !windows

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

package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	log "k8s.io/klog/v2"
)

const (
	defaultRouteSyncTimeout     = 30 * time.Second
	defaultRouteSyncMaxRetries  = 4
	defaultRouteSyncBaseBackoff = time.Second
	defaultRouteSyncMaxBackoff  = 30 * time.Second

	// defaultRouteSyncAlertThreshold means a capped retry sequence immediately
	// preserves its snapshot and raises an alert.
	defaultRouteSyncAlertThreshold = 1
)

// Netlink hooks are variables so unit tests can simulate large tables and
// failures without CAP_NET_ADMIN/CAP_SYS_ADMIN.
var (
	netlinkRouteListFn = netlink.RouteList
	netlinkRouteAddFn  = netlink.RouteAdd
	netlinkRouteDelFn  = netlink.RouteDel
)

// RouteSyncFailure describes one failed route mutation.
type RouteSyncFailure struct {
	Op      string
	Family  int
	Dst     string
	Gateway string
	Err     error
}

func (f RouteSyncFailure) Error() string {
	return fmt.Sprintf("%s route %s via %s: %v", f.Op, f.Dst, f.Gateway, f.Err)
}

func (f RouteSyncFailure) Unwrap() error { return f.Err }

// RouteSyncResult is the observable outcome of reconciling one address family.
type RouteSyncResult struct {
	Family     int
	StartedAt  time.Time
	FinishedAt time.Time
	TimedOut   bool

	ExpectedRoutes  int
	ActualRoutes    int
	Expected        []netlink.Route
	Actual          []netlink.Route
	Unchanged       int
	Added           int
	Deleted         int
	Replaced        int
	SkippedDefault  int
	SkippedUnowned  int
	SkippedUnsafe   int
	SkippedNotReady int
	InUse           int

	ListError error
	Failures  []RouteSyncFailure
}

// ReconcileResult is a descriptive alias.
type ReconcileResult = RouteSyncResult

// Changed reports whether any route was added or deleted.
func (r RouteSyncResult) Changed() bool {
	return r.Added > 0 || r.Deleted > 0 || r.Replaced > 0
}

// Healthy reports whether enumeration and all mutations succeeded.
func (r RouteSyncResult) Healthy() bool {
	return r.ListError == nil && len(r.Failures) == 0 && !r.TimedOut
}

// Err returns the first reconciliation error.
func (r RouteSyncResult) Err() error {
	if r.ListError != nil {
		return r.ListError
	}
	if len(r.Failures) > 0 {
		return r.Failures[0].Err
	}
	return nil
}

// RouteSyncSnapshot retains the diagnostic "scene" after capped retries fail.
type RouteSyncSnapshot struct {
	At       time.Time
	Family   int
	Expected []netlink.Route
	Actual   []netlink.Route
	Result   RouteSyncResult
	LastErr  error
}

// RouteSyncStatus is the concurrency-safe observable status for one family.
type RouteSyncStatus struct {
	Family              int
	ConsecutiveFailures int
	TotalAttempts       int64
	TotalFailures       int64
	TotalAdded          int64
	TotalDeleted        int64
	LastAttempt         time.Time
	LastSuccess         time.Time
	LastError           string
	Exhausted           bool
	Alerts              int
	FailureSnapshot     *RouteSyncSnapshot
}

type routeSyncState struct {
	mu     sync.RWMutex
	status RouteSyncStatus
}

// Snapshot returns a value copy safe for callers to inspect.
func (s *routeSyncState) Snapshot() RouteSyncStatus {
	if s == nil {
		return RouteSyncStatus{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.status
	if s.status.FailureSnapshot != nil {
		snap := *s.status.FailureSnapshot
		snap.Expected = append([]netlink.Route(nil), s.status.FailureSnapshot.Expected...)
		snap.Actual = append([]netlink.Route(nil), s.status.FailureSnapshot.Actual...)
		cp.FailureSnapshot = &snap
	}
	return cp
}

func (s *routeSyncState) recordAttempt(now time.Time) {
	s.mu.Lock()
	s.status.TotalAttempts++
	s.status.LastAttempt = now
	s.mu.Unlock()
}

func (s *routeSyncState) recordSuccess(now time.Time, result RouteSyncResult) {
	s.mu.Lock()
	s.status.ConsecutiveFailures = 0
	s.status.Exhausted = false
	s.status.LastSuccess = now
	s.status.LastError = ""
	s.status.TotalAdded += int64(result.Added)
	s.status.TotalDeleted += int64(result.Deleted)
	s.status.FailureSnapshot = nil
	s.mu.Unlock()
}

func (s *routeSyncState) recordAttemptFailure(now time.Time, err error) {
	s.mu.Lock()
	s.status.TotalFailures++
	s.status.LastError = err.Error()
	s.mu.Unlock()
}

func (s *routeSyncState) recordFailure(now time.Time, result RouteSyncResult, err error, threshold int) *RouteSyncSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.ConsecutiveFailures++
	s.status.TotalFailures++
	s.status.LastError = err.Error()
	exhausted := threshold > 0 && s.status.ConsecutiveFailures >= threshold
	if exhausted && !s.status.Exhausted {
		s.status.Exhausted = true
		s.status.Alerts++
		snapshot := &RouteSyncSnapshot{
			At:       now,
			Family:   s.status.Family,
			Expected: nil, // filled by caller after unlocking
			Actual:   nil,
			Result:   result,
			LastErr:  err,
		}
		s.status.FailureSnapshot = snapshot
		return snapshot
	}
	if exhausted {
		s.status.Exhausted = true
	}
	return nil
}

// RouteSyncConfig tunes periodic route reconciliation. Zero fields are replaced
// by safe defaults.
type RouteSyncConfig struct {
	Interval       time.Duration
	StartupGrace   time.Duration
	Timeout        time.Duration
	MaxRetries     int
	BaseBackoff    time.Duration
	MaxBackoff     time.Duration
	AlertThreshold int
}

func (c RouteSyncConfig) withDefaults() RouteSyncConfig {
	if c.Interval <= 0 {
		c.Interval = routeCheckRetries * time.Second
	}
	if c.StartupGrace <= 0 {
		c.StartupGrace = 3 * c.Interval
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultRouteSyncTimeout
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = defaultRouteSyncMaxRetries
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = defaultRouteSyncBaseBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = defaultRouteSyncMaxBackoff
	}
	if c.MaxBackoff < c.BaseBackoff {
		c.MaxBackoff = c.BaseBackoff
	}
	if c.AlertThreshold <= 0 {
		c.AlertThreshold = defaultRouteSyncAlertThreshold
	}
	return c
}

// routeSyncBackoff returns capped exponential backoff for zero-based retry.
func routeSyncBackoff(retry int, cfg RouteSyncConfig) time.Duration {
	cfg = cfg.withDefaults()
	if retry < 0 {
		retry = 0
	}
	d := cfg.BaseBackoff
	for i := 0; i < retry; i++ {
		d *= 2
		if d >= cfg.MaxBackoff {
			return cfg.MaxBackoff
		}
	}
	if d > cfg.MaxBackoff {
		return cfg.MaxBackoff
	}
	return d
}

// RouteSyncBackoff is the exported helper for observability/tests.
func RouteSyncBackoff(retry int) time.Duration {
	return routeSyncBackoff(retry, RouteSyncConfig{})
}

var (
	// ErrUnsafeRouteDeletion is returned by safeDeleteRoute for default,
	// in-use, or otherwise protected routes.
	ErrUnsafeRouteDeletion = errors.New("unsafe route deletion")
)

// canDeleteRoute is a small compatibility/safety helper. It accepts either a
// netlink.Route or *netlink.Route and optional guards:
//   - []netlink.Route / netlink.Route: desired-state routes
//   - bool: when true, an external usage check reports the route is in use
func canDeleteRoute(route any, guards ...any) bool {
	r, ok := asNetlinkRoute(route)
	if !ok || isDefaultRoute(r) || !isOrdinaryUnicastRoute(r) {
		return false
	}
	for _, guard := range guards {
		switch g := guard.(type) {
		case bool:
			if g {
				return false
			}
		case netlink.Route:
			if routeEqual(r, g) {
				return false
			}
		case *netlink.Route:
			if g != nil && routeEqual(r, *g) {
				return false
			}
		case []netlink.Route:
			if containsNetlinkRoute(g, r) {
				return false
			}
		}
	}
	return true
}

// safeDeleteRoute deletes a route only after the built-in safety checks pass.
// See canDeleteRoute for accepted optional guards.
func safeDeleteRoute(route any, guards ...any) error {
	r, ok := asNetlinkRoute(route)
	if !ok {
		return fmt.Errorf("%w: unsupported route %T", ErrUnsafeRouteDeletion, route)
	}
	if !canDeleteRoute(r, guards...) {
		return fmt.Errorf("%w: %s", ErrUnsafeRouteDeletion, routeDestinationKey(r))
	}
	return netlinkRouteDelFn(&r)
}

func asNetlinkRoute(route any) (netlink.Route, bool) {
	switch r := route.(type) {
	case netlink.Route:
		return r, true
	case *netlink.Route:
		if r == nil {
			return netlink.Route{}, false
		}
		return *r, true
	default:
		return netlink.Route{}, false
	}
}

// isDefaultRoute reports whether route is a default route. It accepts either
// netlink.Route or *netlink.Route so callers can use it with range values or
// pointers. A nil destination is the kernel representation of default and is
// always protected.
func isDefaultRoute(route any) bool {
	if route == nil {
		return true
	}
	var r netlink.Route
	switch v := route.(type) {
	case netlink.Route:
		r = v
	case *netlink.Route:
		if v == nil || v.Dst == nil {
			return true
		}
		r = *v
	default:
		return false
	}
	if r.Dst == nil {
		return true
	}
	ones, bits := r.Dst.Mask.Size()
	if bits == 0 {
		return true
	}
	return ones == 0 && (r.Dst.IP == nil || r.Dst.IP.IsUnspecified())
}

// IsDefaultNetlinkRoute is an exported wrapper.
func IsDefaultNetlinkRoute(route netlink.Route) bool { return isDefaultRoute(route) }

// routeDestinationKey returns a linear-time map key for a route destination.
func routeDestinationKey(route netlink.Route) string {
	if route.Dst == nil {
		return "default"
	}
	ones, bits := route.Dst.Mask.Size()
	if bits == 0 {
		return route.Dst.String()
	}
	ip := route.Dst.IP
	if ip != nil {
		ip = ip.Mask(route.Dst.Mask)
	}
	return fmt.Sprintf("%s/%d/%d", ip.String(), ones, bits)
}

// diffRoutes compares desired and actual netlink routes. It returns routes
// that should be added and actual routes that should be removed. Same-
// destination routes with the wrong gateway/link are returned for deletion;
// the desired route appears in toAdd.
func diffRoutes(expected, actual []netlink.Route) (toAdd []netlink.Route, toDelete []netlink.Route) {
	diff := diffNetlinkRoutesDetailed(expected, actual)
	return diff.ToAdd, diff.ToDelete
}

// RouteDiffDetailed contains categorized route differences.
type RouteDiffDetailed struct {
	ToAdd     []netlink.Route
	ToDelete  []netlink.Route
	Unchanged []netlink.Route
}

// DiffRoutesDetailed returns add/delete/unchanged sets in O(N+M).
func DiffRoutesDetailed(expected, actual []netlink.Route) RouteDiffDetailed {
	return diffNetlinkRoutesDetailed(expected, actual)
}

func diffNetlinkRoutesDetailed(expected, actual []netlink.Route) RouteDiffDetailed {
	diff := RouteDiffDetailed{
		ToAdd:     make([]netlink.Route, 0),
		ToDelete:  make([]netlink.Route, 0),
		Unchanged: make([]netlink.Route, 0),
	}

	actualByDst := make(map[string][]int, len(actual))
	for i := range actual {
		key := routeDestinationKey(actual[i])
		actualByDst[key] = append(actualByDst[key], i)
	}

	used := make([]bool, len(actual))
	for _, want := range expected {
		key := routeDestinationKey(want)
		matched := -1
		for _, idx := range actualByDst[key] {
			if !used[idx] && routeEqual(actual[idx], want) {
				matched = idx
				break
			}
		}
		if matched >= 0 {
			used[matched] = true
			diff.Unchanged = append(diff.Unchanged, want)
			continue
		}
		diff.ToAdd = append(diff.ToAdd, want)
	}

	for i, got := range actual {
		if used[i] {
			continue
		}
		if isDefaultRoute(got) {
			// Safety guard. ReconcileRoutes also counts/skips this, but the
			// pure diff must never propose deleting a default route.
			continue
		}
		diff.ToDelete = append(diff.ToDelete, got)
	}
	return diff
}

func isOrdinaryUnicastRoute(route netlink.Route) bool {
	// Zero values are accepted for compact unit-test routes. rtnetlink normally
	// reports main-table unicast routes as table 254 and type 1.
	if route.Table != 0 && route.Table != rtTableMain {
		return false
	}
	if route.Type != 0 && route.Type != rtNUnicast {
		return false
	}
	return route.Dst != nil && !isDefaultRoute(route)
}

const (
	rtTableMain = 254
	rtNUnicast  = 1
)

// routeOwnedByCIDRs reports whether dst belongs to one of cidrs. An empty
// cidr list means ownership filtering is disabled; callers then rely on the
// default-route and desired-state guards.
func routeOwnedByCIDRs(route netlink.Route, cidrs []*net.IPNet) bool {
	if len(cidrs) == 0 || route.Dst == nil {
		return len(cidrs) == 0
	}
	for _, cidr := range cidrs {
		if cidr != nil && cidr.Contains(route.Dst.IP) {
			return true
		}
	}
	return false
}

// waitWithContext runs fn in a goroutine and abandons waiting when ctx ends.
// Netlink calls do not all accept contexts, so this supplies the observable
// per-sync timeout. The buffered goroutine cannot block forever on result
// delivery.
func waitWithContext(ctx context.Context, timeout time.Duration, fn func() error) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Tests (and some Flannel internals) can enter a network namespace on a
	// locked OS thread. The worker goroutine is not that thread, so explicitly
	// return to the caller's namespace for the blocking netlink operation.
	targetNS, nsErr := netns.Get()

	done := make(chan error, 1)
	go func() {
		if nsErr == nil && targetNS >= 0 {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			originNS, err := netns.Get()
			if err == nil && originNS >= 0 {
				defer func() {
					_ = netns.Set(originNS)
					_ = originNS.Close()
				}()
			}
			if err := netns.Set(targetNS); err != nil {
				_ = targetNS.Close()
				// If we lack permission to switch, the worker is normally in
				// the same namespace already. Run the operation there rather
				// than making unit fakes require CAP_SYS_ADMIN.
				log.V(5).Infof("could not enter caller network namespace for route operation: %v", err)
				done <- fn()
				return
			}
			_ = targetNS.Close()
		}
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%w: route sync exceeded %s", context.DeadlineExceeded, timeout)
		}
		return ctx.Err()
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isNetlinkAlreadyExists(err error) bool {
	return errors.Is(err, syscall.EEXIST) || (err != nil && strings.Contains(strings.ToLower(err.Error()), "file exists"))
}

func isNetlinkNoSuchRoute(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) ||
		(err != nil && strings.Contains(strings.ToLower(err.Error()), "no such process"))
}

// ReconcileFamily compares desired routes for one IP family with the kernel
// table and converges differences. It never deletes default routes or routes
// outside ManagedCIDRs when those are configured.
func (n *RouteNetwork) ReconcileFamily(ctx context.Context, family int, desired []netlink.Route) RouteSyncResult {
	cfg := n.routeSyncConfig()
	listRoutes := netlinkRouteListFn
	addRoute := netlinkRouteAddFn
	deleteRoute := netlinkRouteDelFn
	now := time.Now()
	result := RouteSyncResult{
		Family:         family,
		StartedAt:      now,
		ExpectedRoutes: len(desired),
		Expected:       append([]netlink.Route(nil), desired...),
	}
	status := n.getSyncStatus(family)
	status.recordAttempt(now)

	syncCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	var actual []netlink.Route
	listErr := waitWithContext(syncCtx, cfg.Timeout, func() error {
		routes, err := listRoutes(nil, family)
		if err != nil {
			return err
		}
		actual = routes
		return nil
	})
	if listErr != nil {
		result.ListError = listErr
		result.TimedOut = errors.Is(listErr, context.DeadlineExceeded) || syncCtx.Err() == context.DeadlineExceeded
		result.FinishedAt = time.Now()
		status.recordAttemptFailure(result.FinishedAt, listErr)
		log.Warningf("Route sync family %d attempt failed: %v", family, listErr)
		return result
	}

	result.ActualRoutes = len(actual)
	result.Actual = append([]netlink.Route(nil), actual...)
	for _, route := range actual {
		if isDefaultRoute(route) {
			result.SkippedDefault++
		}
	}
	diff := diffNetlinkRoutesDetailed(desired, actual)
	toAdd, toDelete := diff.ToAdd, diff.ToDelete
	result.Unchanged = len(diff.Unchanged)

	// Build an O(1) identity set from the current cache. The diff input is a
	// snapshot, while lease events may have updated the cache concurrently.
	n.routesMu.RLock()
	var latestDesired []netlink.Route
	if family == netlink.FAMILY_V6 {
		latestDesired = append([]netlink.Route(nil), n.v6Routes...)
	} else {
		latestDesired = append([]netlink.Route(nil), n.routes...)
	}
	n.routesMu.RUnlock()
	desiredIdentities := make(map[string]struct{}, len(latestDesired))
	for _, route := range latestDesired {
		desiredIdentities[netlinkRouteIdentityKey(route)] = struct{}{}
	}

	// Delete unexpected/stale routes first.
	deletionsPaused := n.deletionsPaused.Load()
	for _, route := range toDelete {
		if syncCtx.Err() != nil {
			result.TimedOut = errors.Is(syncCtx.Err(), context.DeadlineExceeded)
			break
		}
		if deletionsPaused {
			result.SkippedNotReady++
			continue
		}
		route := route
		if isDefaultRoute(route) {
			result.SkippedDefault++
			continue
		}
		if !isOrdinaryUnicastRoute(route) {
			// Never remove local/broadcast/multicast or non-main-table routes.
			result.SkippedUnsafe++
			continue
		}
		if !routeOwnedByCIDRs(route, n.ManagedCIDRs) {
			result.SkippedUnowned++
			continue
		}

		if _, stillDesired := desiredIdentities[netlinkRouteIdentityKey(route)]; stillDesired {
			result.InUse++
			continue
		}

		err := waitWithContext(syncCtx, cfg.Timeout, func() error {
			return deleteRoute(&route)
		})
		if err != nil && !isNetlinkNoSuchRoute(err) {
			result.Failures = append(result.Failures, RouteSyncFailure{
				Op: "delete", Family: family, Dst: route.Dst.String(),
				Gateway: route.Gw.String(), Err: err,
			})
			if errors.Is(err, context.DeadlineExceeded) || syncCtx.Err() != nil {
				result.TimedOut = true
				break
			}
			continue
		}
		result.Deleted++
	}

	// Add missing/replacement routes.
	for _, route := range toAdd {
		if syncCtx.Err() != nil {
			result.TimedOut = errors.Is(syncCtx.Err(), context.DeadlineExceeded)
			break
		}
		route := route
		if isDefaultRoute(route) {
			// Desired state should never contain a default route managed here.
			result.SkippedDefault++
			continue
		}
		err := waitWithContext(syncCtx, cfg.Timeout, func() error {
			return addRoute(&route)
		})
		if err != nil && !isNetlinkAlreadyExists(err) {
			result.Failures = append(result.Failures, RouteSyncFailure{
				Op: "add", Family: family, Dst: route.Dst.String(),
				Gateway: route.Gw.String(), Err: err,
			})
			if errors.Is(err, context.DeadlineExceeded) || syncCtx.Err() != nil {
				result.TimedOut = true
				break
			}
			continue
		}
		result.Added++
	}

	// Same-destination mismatch is observable as both delete and add. Count
	// replacements conservatively from overlapping destination keys.
	result.Replaced = countReplacements(toAdd, toDelete)
	result.FinishedAt = time.Now()

	if result.Healthy() {
		previous := status.Snapshot()
		status.recordSuccess(result.FinishedAt, result)
		if previous.Exhausted {
			log.Infof("Route sync family %d recovered after %d consecutive failures", family, previous.ConsecutiveFailures)
		}
		n.logSyncResult(family, result)
	} else {
		err := result.Err()
		if err == nil {
			err = errors.New("route reconciliation failed")
		}
		status.recordAttemptFailure(result.FinishedAt, err)
	}
	return result
}

// ReconcileFamilyWithRetry runs capped exponential backoff around one family
// synchronization. After the final attempt it retains a diagnostic snapshot
// and emits an alert via the status/log.
func (n *RouteNetwork) ReconcileFamilyWithRetry(ctx context.Context, family int, desired []netlink.Route) RouteSyncResult {
	cfg := n.routeSyncConfig()
	status := n.getSyncStatus(family)
	attempts := cfg.MaxRetries + 1
	if cfg.MaxRetries < 0 {
		attempts = 1
	}

	var result RouteSyncResult
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			delay := routeSyncBackoff(attempt-1, cfg)
			log.V(4).Infof("Retrying route sync family %d in %s (attempt %d/%d)", family, delay, attempt+1, attempts)
			if err := sleepWithContext(ctx, delay); err != nil {
				result.FinishedAt = time.Now()
				result.ListError = err
				return result
			}
		}

		result = n.ReconcileFamily(ctx, family, desired)
		if result.Healthy() {
			return result
		}
		if ctx.Err() != nil {
			return result
		}
		log.Warningf("Route sync family %d attempt %d/%d failed", family, attempt+1, attempts)
	}

	err := result.Err()
	if err == nil {
		err = errors.New("route reconciliation failed after retries")
	}
	n.handleSyncFailure(status, result, err, cfg, result.Expected, result.Actual)
	return result
}

// ReconcileRoutesWithRetry reconciles both families using capped backoff.
func (n *RouteNetwork) ReconcileRoutesWithRetry(ctx context.Context) map[int]RouteSyncResult {
	v4 := n.snapshotDesiredRoutes(netlink.FAMILY_V4)
	v6 := n.snapshotDesiredRoutes(netlink.FAMILY_V6)
	out := map[int]RouteSyncResult{}
	if n.routeSyncEnabled(netlink.FAMILY_V4, v4) {
		out[netlink.FAMILY_V4] = n.ReconcileFamilyWithRetry(ctx, netlink.FAMILY_V4, v4)
	}
	if n.routeSyncEnabled(netlink.FAMILY_V6, v6) {
		out[netlink.FAMILY_V6] = n.ReconcileFamilyWithRetry(ctx, netlink.FAMILY_V6, v6)
	}
	return out
}

// ReconcileRoutes reconciles both IPv4 and IPv6 desired route sets.
func (n *RouteNetwork) ReconcileRoutes(ctx context.Context) map[int]RouteSyncResult {
	v4 := n.snapshotDesiredRoutes(netlink.FAMILY_V4)
	v6 := n.snapshotDesiredRoutes(netlink.FAMILY_V6)
	out := map[int]RouteSyncResult{}
	if n.routeSyncEnabled(netlink.FAMILY_V4, v4) {
		out[netlink.FAMILY_V4] = n.ReconcileFamily(ctx, netlink.FAMILY_V4, v4)
	}
	if n.routeSyncEnabled(netlink.FAMILY_V6, v6) {
		out[netlink.FAMILY_V6] = n.ReconcileFamily(ctx, netlink.FAMILY_V6, v6)
	}
	return out
}

// reconcileRoutes is an unexported alias for internal callers/tests.
func (n *RouteNetwork) reconcileRoutes(ctx context.Context) map[int]RouteSyncResult {
	return n.ReconcileRoutes(ctx)
}

func (n *RouteNetwork) routeSyncEnabled(family int, routes []netlink.Route) bool {
	if family == netlink.FAMILY_V6 && !n.hasIPv6Lease() && len(routes) == 0 {
		// Existing installations may not have an IPv6 lease; avoid noisy v6
		// dumps when IPv6 is disabled.
		return n.GetV6Route != nil
	}
	return true
}

func (n *RouteNetwork) hasIPv6Lease() bool {
	return n.SubnetLease != nil && n.SubnetLease.EnableIPv6
}

func (n *RouteNetwork) snapshotDesiredRoutes(family int) []netlink.Route {
	n.routesMu.RLock()
	defer n.routesMu.RUnlock()
	var src []netlink.Route
	if family == netlink.FAMILY_V6 {
		src = n.v6Routes
	} else {
		src = n.routes
	}
	return append([]netlink.Route(nil), src...)
}

func (n *RouteNetwork) routeSyncConfig() RouteSyncConfig {
	cfg := RouteSyncConfig{}
	if n != nil {
		for _, candidate := range []RouteSyncConfig{n.SyncConfig, n.Config, n.RouteSyncConfig, n.ReconcileConfig} {
			if candidate != (RouteSyncConfig{}) {
				cfg = candidate
				break
			}
		}
	}
	return cfg.withDefaults()
}

func (n *RouteNetwork) getSyncStatus(family int) *routeSyncState {
	n.statusMu.Lock()
	defer n.statusMu.Unlock()
	if n.syncStatus == nil {
		n.syncStatus = make(map[int]*routeSyncState)
	}
	st, ok := n.syncStatus[family]
	if !ok {
		st = &routeSyncState{status: RouteSyncStatus{Family: family}}
		n.syncStatus[family] = st
	}
	return st
}

// RouteSyncStatusFor returns a copy of the status for family.
func (n *RouteNetwork) RouteSyncStatusFor(family int) RouteSyncStatus {
	return n.getSyncStatus(family).Snapshot()
}

func (n *RouteNetwork) handleSyncFailure(status *routeSyncState, result RouteSyncResult, err error, cfg RouteSyncConfig, expected, actual []netlink.Route) {
	now := time.Now()
	snapshot := status.recordFailure(now, result, err, cfg.AlertThreshold)
	if snapshot == nil {
		current := status.Snapshot()
		if current.Exhausted {
			// The terminal alert and full snapshot were already emitted. Stay
			// quiet at default verbosity to avoid reflooding logs.
			log.V(4).Infof("Route sync family %d still exhausted after %d failures: %v",
				result.Family, current.ConsecutiveFailures, err)
			return
		}
		// Log at warning with backoff; do not print full tables on every retry.
		backoff := routeSyncBackoff(current.ConsecutiveFailures-1, cfg)
		log.Warningf("Route sync family %d failed (consecutive=%d, next backoff=%s): %v",
			result.Family, current.ConsecutiveFailures, backoff, err)
		return
	}

	// Terminal failure: retain the full scene once and emit an alert-level log.
	snapshot.Expected = append([]netlink.Route(nil), expected...)
	snapshot.Actual = append([]netlink.Route(nil), actual...)
	status.mu.Lock()
	if status.status.FailureSnapshot != nil {
		status.status.FailureSnapshot.Expected = snapshot.Expected
		status.status.FailureSnapshot.Actual = snapshot.Actual
	}
	status.mu.Unlock()

	log.Errorf("ALERT route sync family %d exhausted %d consecutive failures; snapshot retained: expected=%d actual=%d added=%d deleted=%d failures=%d last_error=%q",
		result.Family, status.Snapshot().ConsecutiveFailures, len(expected), len(actual),
		result.Added, result.Deleted, len(result.Failures), err)
	for _, f := range result.Failures {
		log.Errorf("ALERT route sync failure detail family=%d op=%s dst=%s gw=%s err=%v",
			f.Family, f.Op, f.Dst, f.Gateway, f.Err)
	}
}

func (n *RouteNetwork) logSyncResult(family int, result RouteSyncResult) {
	if !result.Changed() {
		log.V(4).Infof("Route sync family %d no changes: desired=%d actual=%d unchanged=%d",
			family, result.ExpectedRoutes, result.ActualRoutes, result.Unchanged)
		return
	}
	log.Infof("Route sync family %d converged: added=%d deleted=%d replaced=%d unchanged=%d skipped_default=%d skipped_unowned=%d",
		family, result.Added, result.Deleted, result.Replaced, result.Unchanged,
		result.SkippedDefault, result.SkippedUnowned)
}

func netlinkRouteIdentityKey(route netlink.Route) string {
	gateway := ""
	if route.Gw != nil {
		gateway = route.Gw.String()
	}
	return fmt.Sprintf("%s|gw=%s|if=%d", routeDestinationKey(route), gateway, route.LinkIndex)
}

func containsNetlinkRoute(routes []netlink.Route, target netlink.Route) bool {
	for _, r := range routes {
		if routeEqual(r, target) {
			return true
		}
	}
	return false
}

func countReplacements(toAdd, toDelete []netlink.Route) int {
	addKeys := make(map[string]int)
	for _, r := range toAdd {
		addKeys[routeDestinationKey(r)]++
	}
	seen := 0
	for _, r := range toDelete {
		key := routeDestinationKey(r)
		if addKeys[key] > 0 {
			seen++
		}
	}
	return seen
}

// linkIndexByName looks up a link by name. host-gw routes are pinned to the
// external interface's ifindex, which changes when that interface is recreated.
func linkIndexByName(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}
	return link.Attrs().Index, nil
}

// syncHostGWLinkIndex points cached host-gw routes at the external interface's
// current ifindex. Other backends (for example ipip) use a different link for
// some or all routes and therefore must not be retargeted here.
func (n *RouteNetwork) syncHostGWLinkIndex(lookup func(name string) (int, error)) {
	if n.BackendType != "host-gw" || n.ExtIface == nil || n.ExtIface.Iface == nil || lookup == nil {
		return
	}
	name := n.ExtIface.Iface.Name
	if name == "" {
		name = n.ExtIface.IfaceName
	}
	if name == "" {
		return
	}
	idx, err := lookup(name)
	if err != nil {
		log.V(4).Infof("host-gw: could not look up %s: %v", name, err)
		return
	}
	if idx == 0 || idx == n.LinkIndex {
		return
	}
	log.Infof("host-gw: external interface %s index changed from %d to %d", name, n.LinkIndex, idx)
	n.LinkIndex = idx
	n.ExtIface.Iface.Index = idx

	n.routesMu.Lock()
	for i := range n.routes {
		n.routes[i].LinkIndex = idx
	}
	for i := range n.v6Routes {
		n.v6Routes[i].LinkIndex = idx
	}
	n.routesMu.Unlock()
}

// runRouteSyncLoop owns the periodic timer and applies outer backoff between
// capped reconciliation attempts.
func (n *RouteNetwork) runRouteSyncLoop(ctx context.Context) {
	cfg := n.routeSyncConfig()
	failures := 0
	startedAt := time.Now()
	timer := time.NewTimer(cfg.Interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		// Do not delete routes until the initial snapshot has been applied or
		// the startup grace has elapsed. Adding missing routes is always safe.
		if !n.desiredReady.Load() && time.Since(startedAt) < cfg.StartupGrace {
			n.deletionsPaused.Store(true)
			log.V(2).Info("Route reconciliation startup grace is active; adding missing routes but not deleting extras")
		} else {
			n.desiredReady.Store(true)
			n.deletionsPaused.Store(false)
		}

		n.syncHostGWLinkIndex(linkIndexByName)
		results := n.ReconcileRoutesWithRetry(ctx)
		healthy := true
		for _, res := range results {
			if !res.Healthy() {
				healthy = false
			}
		}

		delay := cfg.Interval
		if healthy {
			failures = 0
		} else {
			failures++
			delay = routeSyncBackoff(failures-1, cfg)
			if failures >= cfg.AlertThreshold {
				// Once the scene has been preserved and alert emitted, drop
				// back to the maximum interval instead of spamming retries.
				delay = cfg.MaxBackoff
			}
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
	}
}
