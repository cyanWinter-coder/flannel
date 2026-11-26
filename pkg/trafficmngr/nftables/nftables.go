// Copyright 2024 flannel authors
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
//go:build !windows
// +build !windows

package nftables

import (
	"context"
	"fmt"
	"time"

	log "k8s.io/klog/v2"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/trafficmngr"
	"sigs.k8s.io/knftables"
)

const (
	ipv4Table    = "flannel-ipv4"
	ipv6Table    = "flannel-ipv6"
	forwardChain = "forward"
	postrtgChain = "postrtg"
)

type NFTablesManager struct {
	nftv4 knftables.Interface
	nftv6 knftables.Interface

	// DryRun makes reconciliation compare/render diffs without applying.
	DryRun bool
	// Metrics receives aggregate delivery counters when set.
	Metrics *trafficmngr.Metrics
	// OnReport is called after every reconcile pass with its result.
	OnReport func(*trafficmngr.Result)

	v4State nftTableState
	v6State nftTableState
}

func (nftm *NFTablesManager) Init(ctx context.Context) error {
	log.Info("Starting flannel in nftables mode...")
	var err error
	nftm.nftv4, err = initTable(ctx, knftables.IPv4Family, ipv4Table)
	if err != nil {
		return err
	}
	nftm.nftv6, err = initTable(ctx, knftables.IPv6Family, ipv6Table)
	if err != nil {
		return err
	}

	return nil
}

// create a new table and returns the interface to interact with it
func initTable(ctx context.Context, ipFamily knftables.Family, name string) (knftables.Interface, error) {
	nft, err := knftables.New(ipFamily, name)
	if err != nil {
		return nil, fmt.Errorf("no nftables support: %v", err)
	}
	// A pre-existing flannel table may contain incompatible base-chain
	// definitions or stale objects (e.g. left by another traffic backend);
	// recreating our exclusively-owned table prevents name/schema conflicts
	// from silently detaching the rules installed below.
	if replaced, err := resetTableIfPresent(ctx, nft); err != nil {
		log.Warningf("nftables: could not reset pre-existing table %s, continuing: %v", name, err)
	} else if replaced {
		log.Infof("nftables: recreated pre-existing table %s to clear conflicting objects", name)
	}
	tx := nft.NewTransaction()

	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + name),
	})
	err = nft.Run(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("nftables: couldn't initialise table %s: %v", name, err)
	}
	return nft, nil
}

// It is needed when using nftables? accept seems to be the default
// warning: never add a default 'drop' policy on the forwardChain as it breaks connectivity to the node
func (nftm *NFTablesManager) SetupAndEnsureForwardRules(ctx context.Context,
	flannelIPv4Network ip.IP4Net, flannelIPv6Network ip.IP6Net, resyncPeriod int) {
	if !flannelIPv4Network.Empty() && nftm.nftv4 != nil {
		log.Infof("Changing default FORWARD chain policy to ACCEPT")
		spec := forwardV4Spec(flannelIPv4Network.String())
		nftm.reconcileForwardOnce(ctx, nftm.nftv4, ipv4Table, &nftm.v4State, spec)
		if resyncPeriod > 0 {
			go nftm.resyncLoop(ctx, resyncPeriod, func() {
				nftm.reconcileForwardOnce(ctx, nftm.nftv4, ipv4Table, &nftm.v4State, spec)
			})
		}
	}
	if !flannelIPv6Network.Empty() && nftm.nftv6 != nil {
		log.Infof("Changing default FORWARD chain policy to ACCEPT (ipv6)")
		spec := forwardV6Spec(flannelIPv6Network.String())
		nftm.reconcileForwardOnce(ctx, nftm.nftv6, ipv6Table, &nftm.v6State, spec)
		if resyncPeriod > 0 {
			go nftm.resyncLoop(ctx, resyncPeriod, func() {
				nftm.reconcileForwardOnce(ctx, nftm.nftv6, ipv6Table, &nftm.v6State, spec)
			})
		}
	}
}

func (nftm *NFTablesManager) reconcileForwardOnce(ctx context.Context, nft knftables.Interface,
	table string, state *nftTableState, spec nftChainSpec) {

	res, err := state.reconcileChains(ctx, nft, table, []nftChainSpec{spec}, ReconcileOptions{DryRun: nftm.DryRun})
	nftm.report(res, err)
	if err != nil {
		log.Errorf("nftables: couldn't reconcile forward rules: %v", err)
	}
}

func (nftm *NFTablesManager) report(res *trafficmngr.Result, err error) {
	if res == nil {
		return
	}
	log.Infof("%s", res.Summary())
	if nftm.DryRun && res.Diff != "" {
		log.Infof("nftables dry-run diff:\n%s", res.Diff)
	}
	if nftm.Metrics != nil {
		nftm.Metrics.Record(res, err)
	}
	if nftm.OnReport != nil {
		nftm.OnReport(res)
	}
}

func (nftm *NFTablesManager) resyncLoop(ctx context.Context, resyncPeriod int, fn func()) {
	ticker := time.NewTicker(time.Duration(resyncPeriod) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

func forwardV4Spec(network string) nftChainSpec {
	return nftChainSpec{
		Name:     forwardChain,
		Comment:  knftables.PtrTo("chain to accept flannel traffic"),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.ForwardHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
		Rules: []string{
			knftables.Concat("ip saddr", network, "accept"),
			knftables.Concat("ip daddr", network, "accept"),
		},
	}
}

func forwardV6Spec(network string) nftChainSpec {
	return nftChainSpec{
		Name:     forwardChain,
		Comment:  knftables.PtrTo("chain to accept flannel traffic"),
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.ForwardHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
		Rules: []string{
			knftables.Concat("ip6 saddr", network, "accept"),
			knftables.Concat("ip6 daddr", network, "accept"),
		},
	}
}

func (nftm *NFTablesManager) SetupAndEnsureMasqRules(ctx context.Context, flannelIPv4Net, prevSubnet, prevNetwork ip.IP4Net,
	flannelIPv6Net, prevIPv6Subnet, prevIPv6Network ip.IP6Net,
	currentlease *lease.Lease,
	resyncPeriod int,
	ipMasqRandomFullyDisable bool) error {

	masquerade := "masquerade fully-random"
	if !nftm.checkRandomfully(ctx) || ipMasqRandomFullyDisable {
		masquerade = "masquerade"
	}

	if !flannelIPv4Net.Empty() && nftm.nftv4 != nil {
		log.Infof("nftables: setting up masking rules (ipv4)")
		spec := masqSpec(knftables.IPv4Family, flannelIPv4Net.String(), currentlease.Subnet.String(), masquerade)
		if err := nftm.reconcileMasqOnce(ctx, nftm.nftv4, ipv4Table, &nftm.v4State, spec); err != nil {
			return err
		}
		if resyncPeriod > 0 {
			go nftm.resyncLoop(ctx, resyncPeriod, func() {
				if err := nftm.reconcileMasqOnce(ctx, nftm.nftv4, ipv4Table, &nftm.v4State, spec); err != nil {
					log.Errorf("nftables: masq resync failed (ipv4): %v", err)
				}
			})
		}
	}
	if !flannelIPv6Net.Empty() && nftm.nftv6 != nil {
		log.Infof("nftables: setting up masking rules (ipv6)")
		spec := masqSpec(knftables.IPv6Family, flannelIPv6Net.String(), currentlease.IPv6Subnet.String(), masquerade)
		if err := nftm.reconcileMasqOnce(ctx, nftm.nftv6, ipv6Table, &nftm.v6State, spec); err != nil {
			return err
		}
		if resyncPeriod > 0 {
			go nftm.resyncLoop(ctx, resyncPeriod, func() {
				if err := nftm.reconcileMasqOnce(ctx, nftm.nftv6, ipv6Table, &nftm.v6State, spec); err != nil {
					log.Errorf("nftables: masq resync failed (ipv6): %v", err)
				}
			})
		}
	}
	return nil
}

func (nftm *NFTablesManager) reconcileMasqOnce(ctx context.Context, nft knftables.Interface,
	table string, state *nftTableState, spec nftChainSpec) error {

	res, err := state.reconcileChains(ctx, nft, table, []nftChainSpec{spec}, ReconcileOptions{DryRun: nftm.DryRun})
	nftm.report(res, err)
	if err != nil {
		return fmt.Errorf("nftables: couldn't setup masq rules: %v", err)
	}
	return nil
}

// masqSpec builds the ordered postrouting chain specification. The rule
// strings are identical to the ones historically added via addMasqRules.
func masqSpec(family knftables.Family, clusterCidr, podCidr, masquerade string) nftChainSpec {
	multicastCidr := "224.0.0.0/4"
	if family == knftables.IPv6Family {
		multicastCidr = "ff00::/8"
	}
	f := string(family)
	return nftChainSpec{
		Name:     postrtgChain,
		Comment:  knftables.PtrTo("chain to manage traffic masquerading by flannel"),
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.PostroutingHook),
		Priority: knftables.PtrTo(knftables.SNATPriority),
		Rules: []string{
			// Avoid double NAT for kube-proxy marked traffic.
			knftables.Concat("meta mark", "0x4000", "return"),
			knftables.Concat(f, "saddr", podCidr, f, "daddr", clusterCidr, "return"),
			knftables.Concat(f, "saddr", clusterCidr, f, "daddr", podCidr, "return"),
			knftables.Concat(f, "saddr", "!=", podCidr, f, "daddr", clusterCidr, "return"),
			knftables.Concat(f, "saddr", clusterCidr, f, "daddr", "!=", multicastCidr, masquerade),
			knftables.Concat(f, "saddr", "!=", clusterCidr, f, "daddr", clusterCidr, masquerade),
		},
	}
}

// add required masking rules to transaction tx
func (nftm *NFTablesManager) addMasqRules(ctx context.Context,
	tx *knftables.Transaction,
	clusterCidr, podCidr string,
	family knftables.Family,
	ipMasqRandomFullyDisable bool) error {
	masquerade := "masquerade fully-random"
	if !nftm.checkRandomfully(ctx) || ipMasqRandomFullyDisable {
		masquerade = "masquerade"
	}

	multicastCidr := "224.0.0.0/4"
	if family == knftables.IPv6Family {
		multicastCidr = "ff00::/8"
	}
	// This rule will not masquerade traffic marked
	// by the kube-proxy to avoid double NAT bug on some kernel version
	tx.Add(&knftables.Rule{
		Chain: postrtgChain,
		Rule: knftables.Concat(
			"meta mark", "0x4000", //TODO_TF: check the correct value when deploying kube-proxy
			"return",
		),
	})
	// don't NAT traffic within overlay network
	tx.Add(&knftables.Rule{
		Chain: postrtgChain,
		Rule: knftables.Concat(
			family, "saddr", podCidr,
			family, "daddr", clusterCidr,
			"return",
		),
	})
	tx.Add(&knftables.Rule{
		Chain: postrtgChain,
		Rule: knftables.Concat(
			family, "saddr", clusterCidr,
			family, "daddr", podCidr,
			"return",
		),
	})
	// Prevent performing Masquerade on external traffic which arrives from a Node that owns the container/pod IP address
	tx.Add(&knftables.Rule{
		Chain: postrtgChain,
		Rule: knftables.Concat(
			family, "saddr", "!=", podCidr,
			family, "daddr", clusterCidr,
			"return",
		),
	})
	// NAT if it's not multicast traffic
	tx.Add(&knftables.Rule{
		Chain: postrtgChain,
		Rule: knftables.Concat(
			family, "saddr", clusterCidr,
			family, "daddr", "!=", multicastCidr,
			masquerade,
		),
	})
	// Masquerade anything headed towards flannel from the host
	tx.Add(&knftables.Rule{
		Chain: postrtgChain,
		Rule: knftables.Concat(
			family, "saddr", "!=", clusterCidr,
			family, "daddr", clusterCidr,
			masquerade,
		),
	})
	return nil
}

// legacyTableNames lists table names used by older or alternative flannel
// deployments that may collide with the canonical tables after a backend
// switch. CleanUp removes them when present.
var legacyTableNames = []string{"flannel"}

// clean-up all nftables states created by flannel by deleting all related tables
func (nftm *NFTablesManager) CleanUp(ctx context.Context) error {
	log.Info("Cleaning-up nftables rules...")

	v4names := append([]string{ipv4Table}, legacyTableNames...)
	if err := DeleteTablesNamed(ctx, knftables.IPv4Family, v4names); err != nil {
		log.V(2).Infof("nftables (ipv4): cleanup error: %v", err)
	}

	v6names := append([]string{ipv6Table}, legacyTableNames...)
	if err := DeleteTablesNamed(ctx, knftables.IPv6Family, v6names); err != nil {
		log.V(2).Infof("nftables (ipv6): cleanup error: %v", err)
	}

	return nil
}
