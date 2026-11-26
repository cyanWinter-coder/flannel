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

package etcd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	log "k8s.io/klog/v2"
)

const (
	raceRetries = 10
	subnetTTL   = 24 * time.Hour
)

var (
	errInterrupted   = errors.New("interrupted")
	errCanceled      = errors.New("canceled")
	errUnimplemented = errors.New("unimplemented")
)

type LocalManager struct {
	registry               Registry
	previousSubnet         ip.IP4Net
	previousIPv6Subnet     ip.IP6Net
	subnetLeaseRenewMargin int

	nodeID       string
	stateFile    string
	gracePeriod  time.Duration
	renewBackoff lease.RetryConfig
}

// LocalManagerOption configures optional stable-lease behavior.
type LocalManagerOption func(*LocalManager)

// WithNodeID sets the stable node identity stored in lease attributes.
func WithNodeID(nodeID string) LocalManagerOption {
	return func(m *LocalManager) {
		if nodeID != "" {
			m.nodeID = nodeID
		}
	}
}

// WithLeaseStateFile enables durable local allocation records used to recover
// the same subnet after a process or node restart.
func WithLeaseStateFile(path string) LocalManagerOption {
	return func(m *LocalManager) { m.stateFile = path }
}

// WithGracePeriod keeps an expired etcd lease physically present for an extra
// grace interval so a storage blip or node restart cannot immediately allow
// another node to allocate the same prefix.
func WithGracePeriod(grace time.Duration) LocalManagerOption {
	return func(m *LocalManager) {
		if grace > 0 {
			m.gracePeriod = grace
		}
	}
}

// WithRenewBackoff overrides the bounded renewal retry policy.
func WithRenewBackoff(cfg lease.RetryConfig) LocalManagerOption {
	return func(m *LocalManager) { m.renewBackoff = cfg }
}

type watchCursor struct {
	index int64
}

func isErrEtcdNodeExist(e error) bool {
	if e == nil {
		return false
	}
	return e == rpctypes.ErrDuplicateKey
}

func (c watchCursor) String() string {
	return strconv.FormatInt(c.index, 10)
}

func NewLocalManager(ctx context.Context, config *EtcdConfig, prevSubnet ip.IP4Net, prevIPv6Subnet ip.IP6Net, subnetLeaseRenewMargin int, opts ...LocalManagerOption) (subnet.Manager, error) {
	r, err := newEtcdSubnetRegistry(ctx, config, nil)
	if err != nil {
		return nil, err
	}
	m := newLocalManager(r, prevSubnet, prevIPv6Subnet, subnetLeaseRenewMargin)
	for _, opt := range opts {
		opt(m)
	}
	if err := m.loadLocalState(); err != nil {
		log.Warningf("Failed to recover local lease state, continuing with subnet file/registry: %v", err)
	}
	m.ensureNodeID()
	return m, nil
}

func newLocalManager(r Registry, prevSubnet ip.IP4Net, prevIPv6Subnet ip.IP6Net, subnetLeaseRenewMargin int) *LocalManager {
	return &LocalManager{
		registry:               r,
		previousSubnet:         prevSubnet,
		previousIPv6Subnet:     prevIPv6Subnet,
		subnetLeaseRenewMargin: subnetLeaseRenewMargin,
		renewBackoff: lease.RetryConfig{
			// The cap keeps retries spaced by at most one minute. Sixty attempts
			// cover the default one-hour renewal margin without hot-looping.
			MaxAttempts:    60,
			InitialBackoff: time.Second,
			MaxBackoff:     time.Minute,
			Multiplier:     2,
			JitterFraction: 0.1,
		},
	}
}

func (m *LocalManager) GetStoredMacAddresses(ctx context.Context) (string, string) {
	return "", ""
}

func (m *LocalManager) GetStoredPublicIP(ctx context.Context) (string, string) {
	return "", ""
}

func (m *LocalManager) GetNetworkConfig(ctx context.Context) (*subnet.Config, error) {
	cfg, err := m.registry.getNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	config, err := subnet.ParseConfig(cfg)
	if err != nil {
		return nil, err
	}
	err = subnet.CheckNetworkConfig(config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (m *LocalManager) physicalLeaseTTL() time.Duration {
	return subnetTTL + m.gracePeriod
}

// logicalExpiration removes the reclamation grace extension from an etcd TTL
// expiration so renewal timing remains anchored to subnetTTL.
func (m *LocalManager) logicalExpiration(physical time.Time) time.Time {
	if m.gracePeriod > 0 && !physical.IsZero() {
		return physical.Add(-m.gracePeriod)
	}
	return physical
}

func (m *LocalManager) AcquireLease(ctx context.Context, attrs *lease.LeaseAttrs) (*lease.Lease, error) {
	config, err := m.GetNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	if attrs.NodeID == "" {
		attrs.NodeID = m.nodeID
	}

	var l *lease.Lease
	for i := 0; i < raceRetries; i++ {
		l, err = m.tryAcquireLease(ctx, config, attrs.PublicIP, attrs)
		switch err {
		case nil:
			l.NodeID = attrs.NodeID
			l.Expiration = m.logicalExpiration(l.Expiration)
			if saveErr := m.saveLocalState(l); saveErr != nil {
				return nil, fmt.Errorf("lease %s allocated in storage but local state was not persisted: %w", l.Subnet, saveErr)
			}
			return l, nil
		case errTryAgain:
			continue
		default:
			return nil, err
		}
	}

	return nil, errors.New("max retries reached trying to acquire a subnet")
}

func findLeaseByNodeID(leases []lease.Lease, nodeID string) *lease.Lease {
	if nodeID == "" {
		return nil
	}
	for i := range leases {
		l := &leases[i]
		if l.Attrs.NodeID == nodeID || l.NodeID == nodeID {
			return l
		}
	}
	return nil
}

func findLeaseByIP(leases []lease.Lease, pubIP ip.IP4) *lease.Lease {
	for _, l := range leases {
		if pubIP == l.Attrs.PublicIP {
			return &l
		}
	}

	return nil
}

func findLeaseBySubnet(leases []lease.Lease, subnet ip.IP4Net) *lease.Lease {
	for _, l := range leases {
		if subnet.Equal(l.Subnet) {
			return &l
		}
	}

	return nil
}

func (m *LocalManager) tryAcquireLease(ctx context.Context, config *subnet.Config, extIaddr ip.IP4, attrs *lease.LeaseAttrs) (*lease.Lease, error) {
	leases, _, err := m.registry.getSubnets(ctx)
	if err != nil {
		return nil, err
	}

	// Stable node identity is the strongest idempotency key. Fall back to the
	// historical public-IP binding for leases written by older flanneld.
	nodeID := attrs.NodeID
	if l := findLeaseByNodeID(leases, nodeID); l != nil {
		if isSubnetConfigCompat(config, l.Subnet) && isIPv6SubnetConfigCompat(config, l.IPv6Subnet) {
			log.Infof("Found lease (ip: %v ipv6: %v) for current node %q, reusing", l.Subnet, l.IPv6Subnet, nodeID)

			ttl := time.Duration(0)
			if !l.Expiration.IsZero() {
				ttl = m.physicalLeaseTTL()
			}
			exp, err := m.registry.updateSubnet(ctx, l.Subnet, l.IPv6Subnet, attrs, ttl, 0)
			if err != nil {
				return nil, err
			}

			l.NodeID = nodeID
			l.Attrs = *attrs
			l.Expiration = exp
			return l, nil
		}
		log.Infof("Found node-bound lease (%+v) for node %q but it is incompatible with current config, deleting", l, nodeID)
		if err := m.registry.deleteSubnet(ctx, l.Subnet, l.IPv6Subnet); err != nil {
			return nil, err
		}
	}

	// Try to reuse a subnet if there's one that matches our IP
	if l := findLeaseByIP(leases, extIaddr); l != nil {
		// Make sure the existing subnet is still within the configured network
		if isSubnetConfigCompat(config, l.Subnet) && isIPv6SubnetConfigCompat(config, l.IPv6Subnet) {
			log.Infof("Found lease (ip: %v ipv6: %v) for current IP (%v), reusing", l.Subnet, l.IPv6Subnet, extIaddr)

			ttl := time.Duration(0)
			if !l.Expiration.IsZero() {
				// Not a reservation
				ttl = m.physicalLeaseTTL()
			}
			exp, err := m.registry.updateSubnet(ctx, l.Subnet, l.IPv6Subnet, attrs, ttl, 0)
			if err != nil {
				return nil, err
			}

			l.NodeID = attrs.NodeID
			l.Attrs = *attrs
			l.Expiration = exp
			return l, nil
		} else {
			log.Infof("Found lease (%+v) for current IP (%v) but not compatible with current config, deleting", l, extIaddr)
			if err := m.registry.deleteSubnet(ctx, l.Subnet, l.IPv6Subnet); err != nil {
				return nil, err
			}
		}
	}

	// no existing match, check if there was a previous subnet to use
	var sn ip.IP4Net
	var sn6 ip.IP6Net
	if !m.previousSubnet.Empty() {
		// use previous subnet
		if l := findLeaseBySubnet(leases, m.previousSubnet); l == nil {
			// Check if the previous subnet is a part of the network and of the right subnet length
			if isSubnetConfigCompat(config, m.previousSubnet) && isIPv6SubnetConfigCompat(config, m.previousIPv6Subnet) {
				log.Infof("Found previously leased subnet (%v), reusing", m.previousSubnet)
				sn = m.previousSubnet
				sn6 = m.previousIPv6Subnet
			} else {
				log.Errorf("Found previously leased subnet (%v) that is not compatible with the Etcd network config, ignoring", m.previousSubnet)
			}
		}
	}

	if sn.Empty() {
		// no existing match, grab a new one
		sn, sn6, err = m.allocateSubnet(config, leases)
		if err != nil {
			return nil, err
		}
	}

	exp, err := m.registry.createSubnet(ctx, sn, sn6, attrs, m.physicalLeaseTTL())
	switch {
	case err == nil:
		log.Infof("Allocated lease (ip: %v ipv6: %v) to current node (%v) ", sn, sn6, extIaddr)
		return &lease.Lease{
			EnableIPv4: true,
			NodeID:     attrs.NodeID,
			Subnet:     sn,
			EnableIPv6: !sn6.Empty(),
			IPv6Subnet: sn6,
			Attrs:      *attrs,
			Expiration: exp,
		}, nil
	case isErrEtcdNodeExist(err):
		return nil, errTryAgain
	default:
		return nil, err
	}
}

func (m *LocalManager) allocateSubnet(config *subnet.Config, leases []lease.Lease) (ip.IP4Net, ip.IP6Net, error) {
	log.Infof("Picking subnet in range %s ... %s", config.SubnetMin, config.SubnetMax)
	if config.EnableIPv6 {
		log.Infof("Picking ipv6 subnet in range %s ... %s", config.IPv6SubnetMin, config.IPv6SubnetMax)
	}

	var availableIPs []ip.IP4
	var availableIPv6s []*ip.IP6

	sn := ip.IP4Net{IP: config.SubnetMin, PrefixLen: config.SubnetLen}
	var sn6 ip.IP6Net
	if config.EnableIPv6 {
		sn6 = ip.IP6Net{IP: config.IPv6SubnetMin, PrefixLen: config.IPv6SubnetLen}
	}

OuterLoop:
	for ; sn.IP <= config.SubnetMax && len(availableIPs) < 100; sn = sn.Next() {
		for _, l := range leases {
			if sn.Overlaps(l.Subnet) {
				continue OuterLoop
			}
		}
		availableIPs = append(availableIPs, sn.IP)
	}

	if !sn6.Empty() {
	OuterLoopv6:
		for ; sn6.IP.Cmp(config.IPv6SubnetMax) <= 0 && len(availableIPv6s) < 100; sn6 = sn6.Next() {
			for _, l := range leases {
				if sn6.Overlaps(l.IPv6Subnet) {
					continue OuterLoopv6
				}
			}
			availableIPv6s = append(availableIPv6s, sn6.IP)
		}
	}

	if len(availableIPs) == 0 || (!sn6.Empty() && len(availableIPv6s) == 0) {
		return ip.IP4Net{}, ip.IP6Net{}, errors.New("out of subnets")
	} else {
		i := randInt(0, len(availableIPs))
		ipnet := ip.IP4Net{IP: availableIPs[i], PrefixLen: config.SubnetLen}

		if sn6.Empty() {
			return ipnet, ip.IP6Net{}, nil
		}
		i = randInt(0, len(availableIPv6s))
		return ipnet, ip.IP6Net{IP: availableIPv6s[i], PrefixLen: config.IPv6SubnetLen}, nil
	}
}

func (m *LocalManager) RenewLease(ctx context.Context, lease *lease.Lease) error {
	exp, err := m.registry.updateSubnet(ctx, lease.Subnet, lease.IPv6Subnet, &lease.Attrs, m.physicalLeaseTTL(), 0)
	if err != nil {
		return err
	}

	lease.Expiration = m.logicalExpiration(exp)
	if lease.NodeID == "" {
		lease.NodeID = lease.Attrs.NodeID
	}
	return m.saveLocalState(lease)
}

// RenewLeaseWithRetry renews the storage lease using bounded exponential
// backoff. The final error wraps the last storage failure and marks retry
// exhaustion so callers can record/give up according to policy.
func (m *LocalManager) RenewLeaseWithRetry(ctx context.Context, l *lease.Lease) error {
	cfg := m.renewBackoff.Normalize()
	if cfg.OnRetry == nil {
		cfg.OnRetry = func(attempt int, delay time.Duration, err error) {
			log.Errorf("Error renewing lease (attempt %d/%d, next retry in %s): %v",
				attempt, cfg.MaxAttempts, delay, err)
		}
	}
	return lease.RenewWithRetry(ctx, cfg, func(ctx context.Context) error {
		return m.RenewLease(ctx, l)
	})
}

func getNextIndex(cursor interface{}) (int64, error) {
	nextIndex := int64(0)

	if wc, ok := cursor.(watchCursor); ok {
		nextIndex = wc.index
	} else if s, ok := cursor.(string); ok {
		var err error
		nextIndex, err = strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse cursor: %v", err)
		}
	} else {
		return 0, fmt.Errorf("internal error: watch cursor is of unknown type")
	}

	return nextIndex + 1, nil
}

func (m *LocalManager) leaseWatchReset(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net) (lease.LeaseWatchResult, error) {
	l, index, err := m.registry.getSubnet(ctx, sn, sn6)
	if err != nil {
		return lease.LeaseWatchResult{}, err
	}

	return lease.LeaseWatchResult{
		Snapshot: []lease.Lease{*l},
		Cursor:   watchCursor{index},
	}, nil
}

func (m *LocalManager) WatchLease(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net, receiver chan []lease.LeaseWatchResult) error {
	wr, err := m.leaseWatchReset(ctx, sn, sn6)
	if err != nil {
		return err
	}

	log.Info("manager.WatchLease: sending reset results...")
	//send the result of leaseWatchResult to allow the listener
	//to catch-up to the current state
	receiver <- []lease.LeaseWatchResult{wr}

	nextIndex, err := getNextIndex(wr.Cursor)
	if err != nil {
		return err
	}

	err = m.registry.watchSubnet(ctx, nextIndex, sn, sn6, receiver)
	if err != nil {
		return err
	}
	return nil
}

func (m *LocalManager) WatchLeases(ctx context.Context, receiver chan []lease.LeaseWatchResult) error {
	wr, err := m.registry.leasesWatchReset(ctx)
	if err != nil {
		return err
	}

	// send the result of leasesWatchReset to the listener
	// to catch-up on the state if the registry
	// before starting to watch changes
	receiver <- []lease.LeaseWatchResult{wr}

	nextIndex, err := getNextIndex(wr.Cursor)
	if err != nil {
		return err
	}

	err = m.registry.watchSubnets(ctx, nextIndex, receiver)
	if err != nil {
		return err
	}
	return nil
}

// CompleteLease monitor lease
func (m *LocalManager) CompleteLease(ctx context.Context, myLease *lease.Lease, wg *sync.WaitGroup) error {
	// Use the subnet manager to start watching leases.
	evts := make(chan lease.Event)

	wg.Add(1)
	go func() {
		l := myLease
		subnet.WatchLease(ctx, m, l.Subnet, l.IPv6Subnet, evts)
		wg.Done()
	}()

	renewMargin := time.Duration(m.subnetLeaseRenewMargin) * time.Minute
	dur := time.Until(myLease.Expiration) - renewMargin
	renewFailures := 0
	policy := m.renewBackoff.Normalize()

	for {
		select {
		case <-time.After(dur):
			err := m.RenewLease(ctx, myLease)
			if err != nil {
				renewFailures++
				// The etcd key lives until logical expiration plus the grace
				// extension. Never schedule another blind update after that
				// point: the prefix may already have been reallocated.
				reclamationDeadline := myLease.Expiration.Add(m.gracePeriod)
				if renewFailures >= policy.MaxAttempts || !time.Now().Before(reclamationDeadline) {
					exhausted := &lease.RetryExhaustedError{Attempts: renewFailures, LastError: err}
					log.Errorf("Giving up renewing lease %s after %d attempts: %v", myLease.Subnet, renewFailures, err)
					return exhausted
				}

				dur = policy.BackoffForAttempt(renewFailures + 1)
				if remaining := time.Until(reclamationDeadline); dur > remaining {
					dur = remaining
				}
				log.Errorf("Error renewing lease (attempt %d/%d, retrying in %s): %v",
					renewFailures, policy.MaxAttempts, dur, err)
				continue
			}

			renewFailures = 0
			log.Info("Lease renewed, new expiration: ", myLease.Expiration)
			dur = time.Until(myLease.Expiration) - renewMargin

		case e, ok := <-evts:
			if !ok {
				log.Infof("Stopped monitoring lease")
				return errCanceled
			}
			switch e.Type {
			case lease.EventAdded:
				myLease.Expiration = m.logicalExpiration(e.Lease.Expiration)
				dur = time.Until(myLease.Expiration) - renewMargin
				log.Infof("Waiting for %s to renew lease", dur)

			case lease.EventRemoved:
				log.Error("Lease has been revoked. Shutting down daemon.")
				return errInterrupted
			}
		}
	}
}

func isSubnetConfigCompat(config *subnet.Config, sn ip.IP4Net) bool {
	if sn.IP < config.SubnetMin || sn.IP > config.SubnetMax {
		return false
	}

	return sn.PrefixLen == config.SubnetLen
}

func isIPv6SubnetConfigCompat(config *subnet.Config, sn6 ip.IP6Net) bool {
	if !config.EnableIPv6 {
		return sn6.Empty()
	}
	if sn6.Empty() || sn6.IP.Cmp(config.IPv6SubnetMin) < 0 || sn6.IP.Cmp(config.IPv6SubnetMax) > 0 {
		return false
	}

	return sn6.PrefixLen == config.IPv6SubnetLen
}

func (m *LocalManager) Name() string {
	previousSubnet := m.previousSubnet.String()
	if m.previousSubnet.Empty() {
		previousSubnet = "None"
	}
	return fmt.Sprintf("Etcd Local Manager with Previous Subnet: %s", previousSubnet)
}

// For etcd subnet manager, the file never changes so we just write it once at startup
func (m *LocalManager) HandleSubnetFile(path string, config *subnet.Config, ipMasq bool, sn ip.IP4Net, ipv6sn ip.IP6Net, mtu int) error {
	return subnet.WriteSubnetFile(path, config, ipMasq, sn, ipv6sn, mtu)
}
