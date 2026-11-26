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
	"bytes"
	"context"
	"fmt"
	"os/exec"

	coreiptables "github.com/coreos/go-iptables/iptables"
	tm "github.com/flannel-io/flannel/pkg/trafficmngr"
)

// iptablesSnapshotter captures the full ruleset with iptables-save and
// restores it with a full (flush-capable) iptables-restore. It provides exact
// rollback to the state immediately before a reconcile apply.
type iptablesSnapshotter struct {
	savePath    string
	restorePath string
	proto       coreiptables.Protocol
	hasWait     bool
}

// NewIPTablesSnapshotter builds a snapshotter for the given IP protocol. It
// returns an error when the save/restore binaries cannot be located; callers
// may log and continue with inverse-plan rollback instead.
func NewIPTablesSnapshotter(proto coreiptables.Protocol) (tm.RuleSnapshotter, error) {
	saveCmd := ipTablesSaveCommand(proto)
	restoreCmd := getIptablesRestoreCommand(proto)
	savePath, err := exec.LookPath(saveCmd)
	if err != nil {
		return nil, fmt.Errorf("locate %s: %w", saveCmd, err)
	}
	restorePath, err := exec.LookPath(restoreCmd)
	if err != nil {
		return nil, fmt.Errorf("locate %s: %w", restoreCmd, err)
	}
	cmdIptables := getIptablesCommand(proto)
	pathIptables, err := exec.LookPath(cmdIptables)
	if err != nil {
		return nil, fmt.Errorf("locate %s: %w", cmdIptables, err)
	}
	hasWait, err := getIptablesRestoreSupport(pathIptables)
	if err != nil {
		return nil, err
	}
	return &iptablesSnapshotter{
		savePath:    savePath,
		restorePath: restorePath,
		proto:       proto,
		hasWait:     hasWait,
	}, nil
}

func ipTablesSaveCommand(proto coreiptables.Protocol) string {
	if proto == coreiptables.ProtocolIPv6 {
		return "ip6tables-save"
	}
	return "iptables-save"
}

// SnapshotRules runs iptables-save and returns the complete ruleset payload.
func (s *iptablesSnapshotter) SnapshotRules(ctx context.Context) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.savePath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("iptables-save failed (%s): %w", stringsTrim(stderr.String()), err)
	}
	return stdout.Bytes(), nil
}

// RestoreRules replays a snapshot through iptables-restore (without
// --noflush), restoring every table present in the snapshot exactly.
func (s *iptablesSnapshotter) RestoreRules(ctx context.Context, snapshot []byte) error {
	var stderr bytes.Buffer
	args := []string{}
	if s.hasWait {
		args = append(args, "--wait")
	}
	cmd := exec.CommandContext(ctx, s.restorePath, args...)
	cmd.Stdin = bytes.NewReader(snapshot)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables-restore rollback failed (%s): %w", stringsTrim(stderr.String()), err)
	}
	return nil
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
