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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newPatchTestManager(t *testing.T) *kubeSubnetManager {
	t.Helper()
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-self", ResourceVersion: "1"}}
	client := fake.NewSimpleClientset(node)
	sm, err := newKubeSubnetManagerWithListerWatcher(
		context.Background(), client, testSubnetConfig(), "node-self", testAnnotationPrefix, nil)
	if err != nil {
		t.Fatalf("newKubeSubnetManager: %v", err)
	}
	// shrink the retry delays so the retry-loop tests stay fast
	sm.patchBackoff = wait.Backoff{
		Duration: time.Millisecond,
		Factor:   2.0,
		Steps:    patchMaxAttempts,
	}
	sm.patchTimeout = 5 * time.Second
	return sm
}

// TestPatchNodeWithRetrySucceedsAfterTransientFailures drives two failures
// followed by success and asserts the per-node stats record the attempts and
// retain the last failure reason, satisfying the "count and reason
// observable" requirement.
func TestPatchNodeWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	sm := newPatchTestManager(t)
	var calls int32
	sm.client.(*fake.Clientset).PrependReactor("patch", "nodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			n := atomic.AddInt32(&calls, 1)
			if n < 3 {
				return true, nil, errors.New("api server unavailable")
			}
			return false, nil, nil // fall through to the default tracker
		})

	// keep the test fast: the helper shrinks backoff to millisecond delays.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sm.patchNodeWithRetry(ctx, []byte(`{"metadata":{"annotations":{"x":"y"}}}`)); err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 patch attempts, got %d", got)
	}

	stats := sm.NodePatchStats()
	s, ok := stats["node-self"]
	if !ok {
		t.Fatal("no patch stats recorded for node-self")
	}
	if s.Attempts != 3 {
		t.Errorf("attempts: want 3, got %d", s.Attempts)
	}
	if s.Failures != 2 {
		t.Errorf("failures: want 2, got %d", s.Failures)
	}
	if s.LastError != "" {
		t.Errorf("LastError should be cleared on success, got %q", s.LastError)
	}
	if s.LastAttempt.IsZero() {
		t.Error("LastAttempt was not recorded")
	}
}

// TestPatchNodeWithRetryConflictSucceeds verifies a 409 conflict is retried
// rather than surfaced immediately.
func TestPatchNodeWithRetryConflictSucceeds(t *testing.T) {
	sm := newPatchTestManager(t)
	var calls int32
	conflict := apierrors.NewConflict(
		schema.GroupResource{Resource: "nodes"}, "node-self", errors.New("the object has been modified"))
	sm.client.(*fake.Clientset).PrependReactor("patch", "nodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				return true, nil, conflict
			}
			return false, nil, nil
		})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sm.patchNodeWithRetry(ctx, []byte(`{}`)); err != nil {
		t.Fatalf("expected conflict to be retried, got %v", err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 attempts after conflict, got %d", calls)
	}
}

// TestPatchNodeWithRetryExhaustsAttempts forces every attempt to fail and
// asserts the returned error carries the last reason and stats keep it.
func TestPatchNodeWithRetryExhaustsAttempts(t *testing.T) {
	sm := newPatchTestManager(t)
	sm.client.(*fake.Clientset).PrependReactor("patch", "nodes",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("persistent failure")
		})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := sm.patchNodeWithRetry(ctx, []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}

	stats := sm.NodePatchStats()["node-self"]
	if stats.Failures != patchMaxAttempts {
		t.Errorf("failures: want %d, got %d", patchMaxAttempts, stats.Failures)
	}
	if stats.Attempts != patchMaxAttempts {
		t.Errorf("attempts: want %d, got %d", patchMaxAttempts, stats.Attempts)
	}
	if stats.LastError != "persistent failure" {
		t.Errorf("last error not retained: %q", stats.LastError)
	}
}

// TestRecordPatchAttemptIndependentNodes ensures stats are kept per node and
// do not overwrite each other.
func TestRecordPatchAttemptIndependentNodes(t *testing.T) {
	sm := newPatchTestManager(t)
	sm.recordPatchAttempt("node-a", 1, errors.New("boom"))
	sm.recordPatchAttempt("node-a", 2, nil)
	sm.recordPatchAttempt("node-b", 1, errors.New("nope"))

	stats := sm.NodePatchStats()
	if stats["node-a"].Failures != 1 || stats["node-a"].Attempts != 2 {
		t.Errorf("node-a stats wrong: %+v", stats["node-a"])
	}
	if stats["node-b"].Failures != 1 || stats["node-b"].LastError != "nope" {
		t.Errorf("node-b stats wrong: %+v", stats["node-b"])
	}
}
