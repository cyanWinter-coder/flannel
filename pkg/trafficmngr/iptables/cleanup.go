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
//go:build !windows
// +build !windows

package iptables

import (
	coreiptables "github.com/coreos/go-iptables/iptables"
	log "k8s.io/klog/v2"
)

// cleanupJob pairs one flannel chain with the parent chain that jumps to it.
type cleanupJob struct {
	table        string
	parentChain  string
	flannelChain string
}

var cleanupJobs = []cleanupJob{
	{table: "nat", parentChain: "POSTROUTING", flannelChain: "FLANNEL-POSTRTG"},
	// FLANNEL-FWD lives in the filter table (older cleanup mistakenly tried nat).
	{table: "filter", parentChain: "FORWARD", flannelChain: "FLANNEL-FWD"},
}

// ruleLister is the List-only capability needed to build cleanup payloads.
type ruleLister interface {
	List(table, chain string) ([]string, error)
}

// BuildParentJumpCleanupRules lists parent chains and builds -D operations for
// every flannel-owned jump rule, including stacked duplicate copies.
func BuildParentJumpCleanupRules(client ruleLister) IPTablesRestoreRules {
	payload := IPTablesRestoreRules{}
	for _, job := range cleanupJobs {
		lines, err := client.List(job.table, job.parentChain)
		if err != nil {
			log.V(3).Infof("cleanup: cannot list %s/%s: %v", job.table, job.parentChain, err)
			continue
		}
		for _, line := range lines {
			chain, spec, ok := ParseSaveRuleLine(line)
			if !ok {
				continue
			}
			if chain != job.parentChain {
				continue
			}
			if !IsFlannelOwnedSpec(spec) {
				continue
			}
			payload[job.table] = append(payload[job.table],
				append(IPTablesRestoreRuleSpec{"-D", job.parentChain}, spec...))
		}
	}
	return payload
}

// cleanupIPTablesFamily removes all flannel iptables state for one IP family:
// every (possibly duplicated) parent-chain jump, then the flannel chains
// themselves. Errors on individual objects are logged but do not stop cleanup
// of the remaining objects.
func cleanupIPTablesFamily(ipt *coreiptables.IPTables, proto coreiptables.Protocol) error {
	restore, err := NewIPTablesRestoreWithProtocol(proto)
	if err != nil {
		// Without iptables-restore we can still clear/delete chains below.
		log.V(2).Infof("cleanup: iptables-restore unavailable, jumps will be removed with the chain: %v", err)
	} else {
		payload := BuildParentJumpCleanupRules(ipt)
		if len(payload) > 0 {
			if err := restore.ApplyWithoutFlush(payload); err != nil {
				log.V(2).Infof("cleanup: failed to delete parent jump rules: %v", err)
			}
		}
	}

	var firstErr error
	for _, job := range cleanupJobs {
		if err := ipt.ClearAndDeleteChain(job.table, job.flannelChain); err != nil {
			log.V(2).Infof("could not clean-up %s (%s): %v", job.flannelChain, job.table, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
