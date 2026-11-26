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
	"net"
	"testing"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

const testAnnotationPrefix = "flannel.alpha.coreos.com"

// typedNodeListWatch builds a ListerWatcher on the typed Nodes client. The
// fake clientset returns a nil RESTClient, so cache.NewListWatchFromClient
// cannot be used in tests; the typed List/Watch methods are fully faked.
func typedNodeListWatch(client kubernetes.Interface) cache.ListerWatcher {
	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return client.CoreV1().Nodes().List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return client.CoreV1().Nodes().Watch(context.Background(), options)
		},
	}
}

func newTestSubnetManager(t *testing.T, client kubernetes.Interface) *kubeSubnetManager {
	t.Helper()
	sm, err := newKubeSubnetManagerWithListerWatcher(
		context.Background(), client, testSubnetConfig(), "node-self", testAnnotationPrefix,
		func() cache.ListerWatcher { return typedNodeListWatch(client) })
	if err != nil {
		t.Fatalf("newKubeSubnetManager: %v", err)
	}
	return sm
}

func mustIP4Net(s string) ip.IP4Net {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ip.FromIPNet(n)
}

func mustIP4(s string) ip.IP4 {
	a, err := ip.ParseIP4(s)
	if err != nil {
		panic(err)
	}
	return a
}

func testSubnetConfig() *subnet.Config {
	return &subnet.Config{
		EnableIPv4: true,
		Network:    mustIP4Net("10.244.0.0/16"),
		SubnetLen:  24,
		SubnetMin:  mustIP4("10.244.1.0"),
		SubnetMax:  mustIP4("10.244.254.0"),
	}
}

func managedNode(name, podCIDR, publicIP string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				testAnnotationPrefix + "/kube-subnet-manager": "true",
				testAnnotationPrefix + "/backend-type":        "vxlan",
				testAnnotationPrefix + "/backend-data":        `{"VNI":1,"VtepMAC":"aa:bb:cc:dd:ee:01"}`,
				testAnnotationPrefix + "/public-ip":           publicIP,
			},
		},
		Spec: v1.NodeSpec{PodCIDR: podCIDR, PodCIDRs: []string{podCIDR}},
	}
}

func waitEvent(t *testing.T, ch chan lease.Event, timeout time.Duration) (lease.Event, bool) {
	t.Helper()
	select {
	case evt := <-ch:
		return evt, true
	case <-time.After(timeout):
		return lease.Event{}, false
	}
}

func assertNoEvent(t *testing.T, ch chan lease.Event, within time.Duration) {
	t.Helper()
	select {
	case evt := <-ch:
		t.Fatalf("unexpected event: %v subnet %s", evt.Type, evt.Lease.Subnet)
	case <-time.After(within):
	}
}

// TestInformerInitialSyncAndLifecycle drives the real informer against a fake
// API server and verifies the full required lifecycle:
//  1. existing nodes are listed at startup and emitted as added leases,
//  2. a newly managed node arrives as an incremental event without waiting
//     for the resync period,
//  3. a deleted node emits a removal event so its subnet is released,
//  4. unmanaged nodes never produce events.
func TestInformerInitialSyncAndLifecycle(t *testing.T) {
	existing := managedNode("node-existing", "10.244.1.0/24", "192.0.2.1")
	unmanaged := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-unmanaged"},
		Spec:       v1.NodeSpec{PodCIDR: "10.244.9.0/24", PodCIDRs: []string{"10.244.9.0/24"}},
	}
	client := fake.NewSimpleClientset(existing, unmanaged)

	sm := newTestSubnetManager(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sm.Run(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sm.nodeController.HasSynced() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sm.nodeController.HasSynced() {
		t.Fatal("informer never synced")
	}

	// 1. initial list produces exactly one added lease (unmanaged is skipped)
	evt, ok := waitEvent(t, sm.events, 5*time.Second)
	if !ok {
		t.Fatal("no event for existing managed node")
	}
	if evt.Type != lease.EventAdded || evt.Lease.Subnet.String() != "10.244.1.0/24" {
		t.Fatalf("unexpected initial event: %v subnet %s", evt.Type, evt.Lease.Subnet)
	}
	assertNoEvent(t, sm.events, 300*time.Millisecond)

	// 2. incremental add of a newly managed node
	newNode := managedNode("node-new", "10.244.2.0/24", "192.0.2.2")
	if _, err := client.CoreV1().Nodes().Create(ctx, newNode, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	evt, ok = waitEvent(t, sm.events, 5*time.Second)
	if !ok {
		t.Fatal("no event for newly created node")
	}
	if evt.Type != lease.EventAdded || evt.Lease.Subnet.String() != "10.244.2.0/24" {
		t.Fatalf("unexpected add event: %v subnet %s", evt.Type, evt.Lease.Subnet)
	}

	// 3. deleting the node releases its subnet
	if err := client.CoreV1().Nodes().Delete(ctx, "node-new", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	evt, ok = waitEvent(t, sm.events, 5*time.Second)
	if !ok {
		t.Fatal("no removal event for deleted node")
	}
	if evt.Type != lease.EventRemoved || evt.Lease.Subnet.String() != "10.244.2.0/24" {
		t.Fatalf("unexpected remove event: %v subnet %s", evt.Type, evt.Lease.Subnet)
	}
}

// TestInformerManagedTransition verifies a node that exists before flannel
// starts managing it still produces an add event as soon as the managed
// annotation appears, rather than waiting for the resync period.
func TestInformerManagedTransition(t *testing.T) {
	unmanaged := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-late"},
		Spec:       v1.NodeSpec{PodCIDR: "10.244.5.0/24", PodCIDRs: []string{"10.244.5.0/24"}},
	}
	client := fake.NewSimpleClientset(unmanaged)

	sm := newTestSubnetManager(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sm.Run(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sm.nodeController.HasSynced() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sm.nodeController.HasSynced() {
		t.Fatal("informer never synced")
	}
	assertNoEvent(t, sm.events, 300*time.Millisecond)

	managed := managedNode("node-late", "10.244.5.0/24", "192.0.2.5")
	if _, err := client.CoreV1().Nodes().Update(ctx, managed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	evt, ok := waitEvent(t, sm.events, 5*time.Second)
	if !ok {
		t.Fatal("no event when node became flannel-managed")
	}
	if evt.Type != lease.EventAdded || evt.Lease.Subnet.String() != "10.244.5.0/24" {
		t.Fatalf("unexpected transition event: %v subnet %s", evt.Type, evt.Lease.Subnet)
	}
}
