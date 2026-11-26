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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/google/renameio/v2"
	log "k8s.io/klog/v2"
)

const localLeaseStateVersion = 1

// LocalLeaseState is the durable, node-local copy of the allocated lease. It is
// intentionally small and stable so a restart can recover the same subnet even
// before etcd is reachable.
type LocalLeaseState struct {
	Version    int       `json:"version"`
	NodeID     string    `json:"node_id,omitempty"`
	Subnet     string    `json:"subnet,omitempty"`
	IPv6Subnet string    `json:"ipv6_subnet,omitempty"`
	Expiration time.Time `json:"expiration,omitempty"`
	SavedAt    time.Time `json:"saved_at"`
}

func newLocalLeaseState(l *lease.Lease) LocalLeaseState {
	nodeID := l.NodeID
	if nodeID == "" {
		nodeID = l.Attrs.NodeID
	}
	state := LocalLeaseState{
		Version:    localLeaseStateVersion,
		NodeID:     nodeID,
		Expiration: l.Expiration,
		SavedAt:    time.Now().UTC(),
	}
	if !l.Subnet.Empty() {
		state.Subnet = l.Subnet.String()
	}
	if !l.IPv6Subnet.Empty() {
		state.IPv6Subnet = l.IPv6Subnet.String()
	}
	return state
}

// LoadLocalLeaseState reads a durable local lease record. A missing file is not
// an error.
func LoadLocalLeaseState(path string) (*LocalLeaseState, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	var state LocalLeaseState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse local lease state %s: %w", path, err)
	}
	return &state, nil
}

func (m *LocalManager) saveLocalState(l *lease.Lease) error {
	if m == nil || m.stateFile == "" || l == nil {
		return nil
	}

	state := newLocalLeaseState(l)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.stateFile), 0o755); err != nil {
		return fmt.Errorf("create local lease state directory: %w", err)
	}
	if err := renameio.WriteFile(m.stateFile, data, 0o600); err != nil {
		return fmt.Errorf("write local lease state %s: %w", m.stateFile, err)
	}
	return nil
}

func defaultNodeID() string {
	if nodeName := os.Getenv("NODE_NAME"); nodeName != "" {
		return nodeName
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return ""
}

func (m *LocalManager) ensureNodeID() {
	if m.nodeID == "" {
		m.nodeID = defaultNodeID()
	}
}

func (m *LocalManager) loadLocalState() error {
	if m.stateFile == "" {
		return nil
	}

	state, err := LoadLocalLeaseState(m.stateFile)
	if err != nil {
		// A corrupt state file must not prevent recovery from etcd/subnet.env.
		// Preserve it for diagnosis instead of silently deleting evidence.
		backup := fmt.Sprintf("%s.corrupt.%d", m.stateFile, time.Now().UnixNano())
		if renameErr := os.Rename(m.stateFile, backup); renameErr == nil {
			log.Warningf("Moved corrupt lease state file to %s: %v", backup, err)
			return nil
		}
		return err
	}
	if state == nil {
		return nil
	}

	if m.nodeID == "" && state.NodeID != "" {
		m.nodeID = state.NodeID
	}
	if m.previousSubnet.Empty() && state.Subnet != "" {
		if _, cidr, err := net.ParseCIDR(state.Subnet); err == nil && cidr.IP.To4() != nil {
			m.previousSubnet = ip.FromIPNet(cidr)
		} else if err != nil {
			log.Warningf("Ignoring invalid IPv4 subnet %q in local lease state: %v", state.Subnet, err)
		}
	}
	if m.previousIPv6Subnet.Empty() && state.IPv6Subnet != "" {
		if _, cidr, err := net.ParseCIDR(state.IPv6Subnet); err == nil && cidr.IP.To4() == nil {
			m.previousIPv6Subnet = ip.FromIP6Net(cidr)
		} else if err != nil {
			log.Warningf("Ignoring invalid IPv6 subnet %q in local lease state: %v", state.IPv6Subnet, err)
		}
	}
	return nil
}
