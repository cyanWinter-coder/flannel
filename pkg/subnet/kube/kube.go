// Copyright 2016 flannel authors
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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	log "k8s.io/klog/v2"
)

var (
	ErrUnimplemented = errors.New("unimplemented")
)

const (
	resyncPeriod              = 5 * time.Minute
	nodeControllerSyncTimeout = 10 * time.Minute

	// patchMaxAttempts bounds the retries when writing flannel annotations
	// (the node "configuration") back to the API server.
	patchMaxAttempts = 5
	// patchInitialBackoff / patchMaxBackoff drive exponential backoff between
	// patch attempts.
	patchInitialBackoff = 500 * time.Millisecond
	patchMaxBackoff     = 15 * time.Second
	// patchOverallTimeout caps the whole retry loop regardless of attempts.
	patchOverallTimeout = 2 * time.Minute
)

type subnetFileInfo struct {
	path   string
	ipMask bool
	sn     ip.IP4Net
	IPv6sn ip.IP6Net
	mtu    int
}

type kubeSubnetManager struct {
	enableIPv4       bool
	enableIPv6       bool
	annotations      annotations
	annotationPrefix string
	client           clientset.Interface
	nodeName         string
	nodeStore        cache.Store
	nodeController   cache.Controller
	// listerWatcherFactory builds the node ListerWatcher; overridable in
	// tests so the informer can run against clients (e.g. fake clientset)
	// that do not provide a working RESTClient.
	listerWatcherFactory      func() cache.ListerWatcher
	subnetConf                *subnet.Config
	events                    chan lease.Event
	eventQueue                *nodeEventQueue
	clusterCIDRController     cache.Controller
	setNodeNetworkUnavailable bool
	disableNodeInformer       bool
	snFileInfo                *subnetFileInfo

	// patchStats tracks node annotation write failures so that retry counts
	// and reasons are observable via logs and the NodePatchStats accessor.
	patchStatsMu sync.Mutex
	patchStats   map[string]*nodePatchStats

	// patchBackoff / patchTimeout drive retries when writing flannel
	// annotations. They default to the package-level constants but are kept
	// as fields so tests can shrink the delays.
	patchBackoff wait.Backoff
	patchTimeout time.Duration
}

// nodePatchStats accumulates node configuration (annotation patch) write
// attempts for one node. Counters are safe to read while the manager runs.
type nodePatchStats struct {
	Attempts    int
	Failures    int
	LastError   string
	LastAttempt time.Time
}

func NewSubnetManager(ctx context.Context, apiUrl, kubeconfig, prefix, netConfPath string, setNodeNetworkUnavailable bool) (subnet.Manager, error) {
	var cfg *rest.Config
	var err error
	// Try to build kubernetes config from a master url or a kubeconfig filepath. If neither masterUrl
	// or kubeconfigPath are passed in we fall back to inClusterConfig. If inClusterConfig fails,
	// we fallback to the default config.
	cfg, err = clientcmd.BuildConfigFromFlags(apiUrl, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("fail to create kubernetes config: %v", err)
	}

	c, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize client: %v", err)
	}

	// The kube subnet mgr needs to know the k8s node name that it's running on so it can annotate it.
	// If we're running as a pod then the POD_NAME and POD_NAMESPACE will be populated and can be used to find the node
	// name. Otherwise, the environment variable NODE_NAME can be passed in.
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		podName := os.Getenv("POD_NAME")
		podNamespace := os.Getenv("POD_NAMESPACE")
		if podName == "" || podNamespace == "" {
			return nil, fmt.Errorf("env variables POD_NAME and POD_NAMESPACE must be set")
		}

		pod, err := c.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error retrieving pod spec for '%s/%s': %v", podNamespace, podName, err)
		}
		nodeName = pod.Spec.NodeName
		if nodeName == "" {
			return nil, fmt.Errorf("node name not present in pod spec '%s/%s'", podNamespace, podName)
		}
	}

	netConf, err := os.ReadFile(netConfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read net conf: %v", err)
	}

	sc, err := subnet.ParseConfig(string(netConf))
	if err != nil {
		return nil, fmt.Errorf("error parsing subnet config: %s", err)
	}

	sm, err := newKubeSubnetManager(ctx, c, sc, nodeName, prefix)
	if err != nil {
		return nil, fmt.Errorf("error creating network manager: %s", err)
	}
	sm.setNodeNetworkUnavailable = setNodeNetworkUnavailable

	if sm.disableNodeInformer {
		log.Infof("Node controller skips sync")
	} else {
		go sm.Run(ctx)

		log.Infof("Waiting %s for node controller to sync", nodeControllerSyncTimeout)
		err = wait.PollUntilContextTimeout(ctx, time.Second, nodeControllerSyncTimeout, true, func(context.Context) (bool, error) {
			ch := make(chan bool, 1)
			go func() {
				// HasSynced() is a blocking call waiting on
				// the DeltaFIFO mutex that's also used by other
				// cache controller callbacks calling wait or Update
				// use a channel/select to not block the main thread
				ch <- sm.nodeController.HasSynced()
			}()
			select {
			case synced := <-ch:
				return synced, nil
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(time.Second):
				return false, nil // or error to break
			}
		})

		if err != nil {
			log.Errorf("Node controller sync not completed within 1s: %v", err)
			return sm, fmt.Errorf("error waiting for nodeController to sync state: %w", err)
		}
		log.Infof("Node controller sync successful")
	}

	return sm, nil
}

// newKubeSubnetManager fills the kubeSubnetManager. The most important part is the controller which will
// watch for kubernetes node updates
func newKubeSubnetManager(ctx context.Context, c clientset.Interface, sc *subnet.Config, nodeName, prefix string) (*kubeSubnetManager, error) {
	return newKubeSubnetManagerWithListerWatcher(ctx, c, sc, nodeName, prefix, nil)
}

// newKubeSubnetManagerWithListerWatcher is the same as newKubeSubnetManager but
// allows injecting a custom node ListerWatcher (used by tests that run the
// informer against a fake clientset, whose RESTClient is nil).
func newKubeSubnetManagerWithListerWatcher(ctx context.Context, c clientset.Interface, sc *subnet.Config, nodeName, prefix string, lwFactory func() cache.ListerWatcher) (*kubeSubnetManager, error) {
	var err error
	var ksm kubeSubnetManager
	ksm.annotationPrefix = prefix
	ksm.annotations, err = newAnnotations(prefix)
	if err != nil {
		return nil, err
	}
	ksm.enableIPv4 = sc.EnableIPv4
	ksm.enableIPv6 = sc.EnableIPv6
	ksm.client = c
	ksm.nodeName = nodeName
	ksm.listerWatcherFactory = lwFactory
	ksm.subnetConf = sc
	scale := 5000
	scaleStr := os.Getenv("EVENT_QUEUE_DEPTH")
	if scaleStr != "" {
		n, err := strconv.Atoi(scaleStr)
		if err != nil {
			return nil, fmt.Errorf("env EVENT_QUEUE_DEPTH=%s format error: %v", scaleStr, err)
		}
		if n > 0 {
			scale = n
		}
	}
	ksm.events = make(chan lease.Event, scale)
	ksm.eventQueue = newNodeEventQueue(ksm.events)
	ksm.patchStats = make(map[string]*nodePatchStats)
	ksm.patchBackoff = wait.Backoff{
		Duration: patchInitialBackoff,
		Factor:   2.0,
		Jitter:   0.1,
		Steps:    patchMaxAttempts,
		Cap:      patchMaxBackoff,
	}
	ksm.patchTimeout = patchOverallTimeout
	// when backend type is alloc, someone else (e.g. cloud-controller-managers) is taking care of the routing, thus we do not need informer
	// See https://github.com/flannel-io/flannel/issues/1617
	if sc.BackendType == "alloc" {
		ksm.disableNodeInformer = true
	}
	if !ksm.disableNodeInformer {
		listerWatcher := newLoggingListWatch(ksm.nodeListerWatcher())

		handler := cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ksm.handleAddLeaseEvent(ctx, lease.EventAdded, obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				ksm.handleUpdateLeaseEvent(ctx, oldObj, newObj)
			},
			DeleteFunc: func(obj interface{}) {
				// We can get DeletedFinalStateUnknown instead of *v1.Node here
				// when the watch missed the actual deletion; unwrap it so the
				// subnet can still be released from the last known state.
				node, ok := obj.(*v1.Node)
				if !ok {
					deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						log.Errorf("Error received unexpected object: %v", obj)
						return
					}
					node, ok = deletedState.Obj.(*v1.Node)
					if !ok {
						log.Errorf("Error deletedFinalStateUnknown contained non-Node object: %v", deletedState.Obj)
						return
					}
				}
				ksm.handleDeleteLeaseEvent(ctx, node)
			},
		}
		store, controller := cache.NewInformerWithOptions(cache.InformerOptions{
			ListerWatcher: listerWatcher,
			ObjectType:    &v1.Node{},
			ResyncPeriod:  resyncPeriod,
			Handler:       handler,
			Indexers:      cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		})

		ksm.nodeController = controller
		ksm.nodeStore = store
	}

	return &ksm, nil
}

// nodeListerWatcher returns the ListerWatcher backing the node informer.
// Production uses the RESTClient-backed list/watch; tests can inject a factory
// built on the typed client (which works with fake clientsets).
func (ksm *kubeSubnetManager) nodeListerWatcher() cache.ListerWatcher {
	if ksm.listerWatcherFactory != nil {
		return ksm.listerWatcherFactory()
	}
	return cache.NewListWatchFromClient(
		ksm.client.CoreV1().RESTClient(),
		"nodes",
		"",
		fields.Everything())
}

// enqueueLeaseEvent hands an event to the per-node ordered queue. The queue
// guarantees serialization for the node named in the event while different
// nodes proceed concurrently, and applies backpressure instead of dropping or
// reordering events when the downstream channel is saturated.
func (ksm *kubeSubnetManager) enqueueLeaseEvent(ctx context.Context, evt lease.Event, nodeName string) {
	ksm.eventQueue.enqueue(ctx, nodeName, evt)
}

func (ksm *kubeSubnetManager) handleAddLeaseEvent(ctx context.Context, et lease.EventType, obj interface{}) {
	n := obj.(*v1.Node)
	if s, ok := n.Annotations[ksm.annotations.SubnetKubeManaged]; !ok || s != "true" {
		// Nodes that are not flannel-managed yet carry no subnet lease; when
		// they become managed handleUpdateLeaseEvent will emit the first event.
		return
	}

	l, err := ksm.nodeToLease(*n)
	if err != nil {
		log.Infof("Error turning node %q to lease: %v", n.Name, err)
		return
	}
	log.V(2).Infof("Node %q lease event %v for subnet %s", n.Name, et, l.Subnet)
	ksm.enqueueLeaseEvent(ctx, lease.Event{Type: et, Lease: l}, n.Name)
}

// handleDeleteLeaseEvent releases the subnet of a removed node. The informer
// may redeliver the deletion after a relist or as a DeletedFinalStateUnknown
// tombstone, and downstream LeaseWatcher removal is already idempotent; keep
// the conversion failures here non-fatal and log at info level so repeated
// deletions do not generate misleading error noise.
func (ksm *kubeSubnetManager) handleDeleteLeaseEvent(ctx context.Context, n *v1.Node) {
	if s, ok := n.Annotations[ksm.annotations.SubnetKubeManaged]; !ok || s != "true" {
		return
	}

	l, err := ksm.nodeToLease(*n)
	if err != nil {
		log.Infof("Error turning deleted node %q to lease: %v", n.Name, err)
		return
	}
	log.Infof("Node %q deleted, releasing subnet %s", n.Name, l.Subnet)
	ksm.enqueueLeaseEvent(ctx, lease.Event{Type: lease.EventRemoved, Lease: l}, n.Name)
}

// handleUpdateLeaseEvent verifies if anything relevant changed in the node object: either
// ksm.annotations.BackendData, ksm.annotations.BackendType or ksm.annotations.BackendPublicIP,
// or the flannel-managed marker flipping to "true" for a newly registered node.
func (ksm *kubeSubnetManager) handleUpdateLeaseEvent(ctx context.Context, oldObj, newObj interface{}) {
	o := oldObj.(*v1.Node)
	n := newObj.(*v1.Node)

	oldManaged := o.Annotations[ksm.annotations.SubnetKubeManaged] == "true"
	newManaged := n.Annotations[ksm.annotations.SubnetKubeManaged] == "true"
	if !newManaged {
		return
	}

	var changed = false
	// The node just became flannel-managed: its initial lease (including the
	// PodCIDR assigned by the controller) must be emitted even if no backend
	// annotation differs, otherwise the subnet is invisible until the next
	// periodic resync (up to resyncPeriod, minutes later on large clusters).
	if !oldManaged {
		changed = true
	}

	if ksm.enableIPv4 && (o.Annotations[ksm.annotations.BackendData] != n.Annotations[ksm.annotations.BackendData] ||
		o.Annotations[ksm.annotations.BackendType] != n.Annotations[ksm.annotations.BackendType] ||
		o.Annotations[ksm.annotations.BackendPublicIP] != n.Annotations[ksm.annotations.BackendPublicIP]) {
		changed = true
	}

	if ksm.enableIPv6 && (o.Annotations[ksm.annotations.BackendV6Data] != n.Annotations[ksm.annotations.BackendV6Data] ||
		o.Annotations[ksm.annotations.BackendType] != n.Annotations[ksm.annotations.BackendType] ||
		o.Annotations[ksm.annotations.BackendPublicIPv6] != n.Annotations[ksm.annotations.BackendPublicIPv6]) {
		changed = true
	}

	if !changed {
		return // No change to lease
	}

	l, err := ksm.nodeToLease(*n)
	if err != nil {
		log.Infof("Error turning node %q to lease: %v", n.Name, err)
		return
	}
	ksm.enqueueLeaseEvent(ctx, lease.Event{Type: lease.EventAdded, Lease: l}, n.Name)
}

// recordPatchAttempt updates the per-node counters of node configuration
// writes. A nil error counts as a successful attempt only; every failure
// reason is retained in LastError for diagnostics.
func (ksm *kubeSubnetManager) recordPatchAttempt(nodeName string, attempt int, err error) {
	ksm.patchStatsMu.Lock()
	defer ksm.patchStatsMu.Unlock()

	stats, ok := ksm.patchStats[nodeName]
	if !ok {
		stats = &nodePatchStats{}
		ksm.patchStats[nodeName] = stats
	}
	stats.Attempts = attempt
	stats.LastAttempt = time.Now()
	if err != nil {
		stats.Failures++
		stats.LastError = err.Error()
	} else {
		stats.LastError = ""
	}
}

// NodePatchStats returns a snapshot of the node configuration write statistics
// keyed by node name, intended for diagnostic/observability consumers.
func (ksm *kubeSubnetManager) NodePatchStats() map[string]nodePatchStats {
	ksm.patchStatsMu.Lock()
	defer ksm.patchStatsMu.Unlock()

	out := make(map[string]nodePatchStats, len(ksm.patchStats))
	for name, stats := range ksm.patchStats {
		out[name] = *stats
	}
	return out
}

// patchNodeWithRetry writes the flannel node annotations (the node
// "configuration") with bounded exponential backoff. Every attempt is logged
// with its attempt number and failure reason and recorded in the per-node
// patch statistics so retry counts and causes stay observable.
//
// A conflict (HTTP 409) means the node changed since the patch was computed.
// A strategic merge patch only touches the flannel annotation keys, so after
// the backoff delay the same patch can simply be retried against the newer
// object without recomputing it; the informer cache converges in parallel.
func (ksm *kubeSubnetManager) patchNodeWithRetry(ctx context.Context, patchBytes []byte) error {
	// Copy the backoff: Step() mutates Steps/Duration, and this method may be
	// called more than once over the manager's lifetime.
	bo := ksm.patchBackoff
	deadlineCtx, cancel := context.WithTimeout(ctx, ksm.patchTimeout)
	defer cancel()

	var lastErr error
	attempt := 0
	for {
		attempt++
		_, err := ksm.client.CoreV1().Nodes().Patch(deadlineCtx, ksm.nodeName,
			types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}, "status")
		if err == nil {
			ksm.recordPatchAttempt(ksm.nodeName, attempt, nil)
			if attempt > 1 {
				log.Infof("Successfully patched node %q after %d attempts", ksm.nodeName, attempt)
			}
			return nil
		}
		lastErr = err
		ksm.recordPatchAttempt(ksm.nodeName, attempt, err)
		log.Warningf("Failed to patch node %q (attempt %d/%d): %v",
			ksm.nodeName, attempt, ksm.patchBackoff.Steps, err)

		// Step returns the delay before the next try and decrements the
		// remaining steps; zero steps means the budget is exhausted.
		next := bo.Step()
		if bo.Steps == 0 {
			break
		}
		select {
		case <-deadlineCtx.Done():
			return fmt.Errorf("failed to patch node %q after %s: last error: %v",
				ksm.nodeName, ksm.patchTimeout, lastErr)
		case <-time.After(next):
		}
	}

	return fmt.Errorf("failed to patch node %q after %d attempts, last error: %v",
		ksm.nodeName, ksm.patchBackoff.Steps, lastErr)
}

func (ksm *kubeSubnetManager) GetNetworkConfig(ctx context.Context) (*subnet.Config, error) {
	return ksm.subnetConf, nil
}

// AcquireLease adds the flannel specific node annotations (defined in the struct LeaseAttrs) and returns a lease
// with important information for the backend, such as the subnet. This function is called once by the backend when
// registering
func (ksm *kubeSubnetManager) AcquireLease(ctx context.Context, attrs *lease.LeaseAttrs) (*lease.Lease, error) {
	var cachedNode *v1.Node
	waitErr := wait.PollUntilContextTimeout(ctx, 3*time.Second, 30*time.Second, true, func(context.Context) (done bool, err error) {
		if ksm.disableNodeInformer {
			cachedNode, err = ksm.client.CoreV1().Nodes().Get(ctx, ksm.nodeName, metav1.GetOptions{ResourceVersion: "0"})
			if err != nil {
				log.V(2).Infof("Failed to get node %q: %v", ksm.nodeName, err)
				return false, nil
			}
		} else {
			nodeIface, exists, err := ksm.nodeStore.GetByKey(ksm.nodeName)
			if err != nil {
				log.V(2).Infof("failed to get node %q: %v", ksm.nodeName, err)
				return false, nil
			} else if !exists {
				log.V(2).Infof("node %q does not exist ", ksm.nodeName)
				return false, nil
			}
			cachedNode = nodeIface.(*v1.Node)
		}
		return true, nil
	})
	if waitErr != nil {
		return nil, fmt.Errorf("timeout contacting kube-api, failed to patch node %q. Error: %v", ksm.nodeName, waitErr)
	}

	n := cachedNode.DeepCopy()
	if n.Spec.PodCIDR == "" {
		return nil, fmt.Errorf("node %q pod cidr not assigned", ksm.nodeName)
	}

	var bd, v6Bd []byte
	bd, err := attrs.BackendData.MarshalJSON()
	if err != nil {
		return nil, err
	}

	v6Bd, err = attrs.BackendV6Data.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var cidr, ipv6Cidr *net.IPNet
	switch {
	case len(n.Spec.PodCIDRs) == 0:
		_, parseCidr, err := net.ParseCIDR(n.Spec.PodCIDR)
		if err != nil {
			return nil, err
		}
		if len(parseCidr.IP) == net.IPv4len {
			cidr = parseCidr
		} else if len(parseCidr.IP) == net.IPv6len {
			ipv6Cidr = parseCidr
		}
	case len(n.Spec.PodCIDRs) < 3:
		for _, podCidr := range n.Spec.PodCIDRs {
			_, parseCidr, err := net.ParseCIDR(podCidr)
			if err != nil {
				return nil, err
			}
			if len(parseCidr.IP) == net.IPv4len {
				cidr = parseCidr
			} else if len(parseCidr.IP) == net.IPv6len {
				ipv6Cidr = parseCidr
			}
		}
	default:
		return nil, fmt.Errorf("node %q pod cidrs should be IPv4/IPv6 only or dualstack", ksm.nodeName)
	}

	if (n.Annotations[ksm.annotations.BackendData] != string(bd) ||
		n.Annotations[ksm.annotations.BackendType] != attrs.BackendType ||
		n.Annotations[ksm.annotations.BackendPublicIP] != attrs.PublicIP.String() ||
		n.Annotations[ksm.annotations.SubnetKubeManaged] != "true" ||
		(n.Annotations[ksm.annotations.BackendPublicIPOverwrite] != "" && n.Annotations[ksm.annotations.BackendPublicIPOverwrite] != attrs.PublicIP.String())) ||
		(attrs.PublicIPv6 != nil &&
			(n.Annotations[ksm.annotations.BackendV6Data] != string(v6Bd) ||
				n.Annotations[ksm.annotations.BackendType] != attrs.BackendType ||
				n.Annotations[ksm.annotations.BackendPublicIPv6] != attrs.PublicIPv6.String() ||
				n.Annotations[ksm.annotations.SubnetKubeManaged] != "true" ||
				(n.Annotations[ksm.annotations.BackendPublicIPv6Overwrite] != "" && n.Annotations[ksm.annotations.BackendPublicIPv6Overwrite] != attrs.PublicIPv6.String()))) {
		n.Annotations[ksm.annotations.BackendType] = attrs.BackendType

		//TODO -i only vxlan and host-gw backends support dual stack now.
		if (attrs.BackendType == "vxlan" && string(bd) != "null") || (attrs.BackendType == "wireguard" && string(bd) != "null") || attrs.BackendType != "vxlan" {
			n.Annotations[ksm.annotations.BackendData] = string(bd)
			if n.Annotations[ksm.annotations.BackendPublicIPOverwrite] != "" {
				if n.Annotations[ksm.annotations.BackendPublicIP] != n.Annotations[ksm.annotations.BackendPublicIPOverwrite] {
					log.Infof("Overriding public ip with '%s' from node annotation '%s'",
						n.Annotations[ksm.annotations.BackendPublicIPOverwrite],
						ksm.annotations.BackendPublicIPOverwrite)
					n.Annotations[ksm.annotations.BackendPublicIP] = n.Annotations[ksm.annotations.BackendPublicIPOverwrite]
				}
			} else {
				n.Annotations[ksm.annotations.BackendPublicIP] = attrs.PublicIP.String()
			}
		}

		if (attrs.BackendType == "vxlan" && string(v6Bd) != "null") ||
			(attrs.BackendType == "wireguard" && string(v6Bd) != "null" && attrs.PublicIPv6 != nil) ||
			(attrs.BackendType == "host-gw" && attrs.PublicIPv6 != nil) ||
			(attrs.BackendType == "extension" && attrs.PublicIPv6 != nil) {
			n.Annotations[ksm.annotations.BackendV6Data] = string(v6Bd)
			if n.Annotations[ksm.annotations.BackendPublicIPv6Overwrite] != "" {
				if n.Annotations[ksm.annotations.BackendPublicIPv6] != n.Annotations[ksm.annotations.BackendPublicIPv6Overwrite] {
					log.Infof("Overriding public ipv6 with '%s' from node annotation '%s'",
						n.Annotations[ksm.annotations.BackendPublicIPv6Overwrite],
						ksm.annotations.BackendPublicIPv6Overwrite)
					n.Annotations[ksm.annotations.BackendPublicIPv6] = n.Annotations[ksm.annotations.BackendPublicIPv6Overwrite]
				}
			} else {
				n.Annotations[ksm.annotations.BackendPublicIPv6] = attrs.PublicIPv6.String()
			}
		}
		n.Annotations[ksm.annotations.SubnetKubeManaged] = "true"

		oldData, err := json.Marshal(cachedNode)
		if err != nil {
			return nil, err
		}

		newData, err := json.Marshal(n)
		if err != nil {
			return nil, err
		}

		patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, v1.Node{})
		if err != nil {
			return nil, fmt.Errorf("failed to create patch for node %q: %v", ksm.nodeName, err)
		}

		if err := ksm.patchNodeWithRetry(ctx, patchBytes); err != nil {
			return nil, err
		}
	}

	lease := &lease.Lease{
		Attrs:      *attrs,
		Expiration: time.Now().Add(24 * time.Hour),
	}
	if cidr != nil && ksm.enableIPv4 {
		if ksm.subnetConf.Network.Empty() || !containsCIDR(ksm.subnetConf.Network.ToIPNet(), cidr) {
			return nil, fmt.Errorf("subnet %q specified in the flannel net config doesn't contain %q PodCIDR of the %q node", ksm.subnetConf.Network, cidr, ksm.nodeName)
		}

		lease.Subnet = ip.FromIPNet(cidr)
	}
	if ipv6Cidr != nil && ksm.enableIPv6 {
		if ksm.subnetConf.IPv6Network.Empty() || !containsCIDR(ksm.subnetConf.IPv6Network.ToIPNet(), ipv6Cidr) {
			return nil, fmt.Errorf("subnet %q specified in the flannel net config doesn't contain %q IPv6 PodCIDR of the %q node", ksm.subnetConf.IPv6Network, ipv6Cidr, ksm.nodeName)
		}

		lease.IPv6Subnet = ip.FromIP6Net(ipv6Cidr)
	}
	//TODO - only vxlan, host-gw and wireguard backends support dual stack now.
	if attrs.BackendType != "vxlan" && attrs.BackendType != "host-gw" && attrs.BackendType != "wireguard" {
		lease.EnableIPv4 = true
		lease.EnableIPv6 = false
	}
	return lease, nil
}

// WatchLeases waits for the kubeSubnetManager to provide an event in case something relevant changed in the node data
func (ksm *kubeSubnetManager) WatchLeases(ctx context.Context, receiver chan []lease.LeaseWatchResult) error {
	for {
		select {
		case event := <-ksm.events:
			receiver <- []lease.LeaseWatchResult{
				{
					Events: []lease.Event{event},
				}}
		case <-ctx.Done():
			close(receiver)
			return ctx.Err()
		}
	}
}

func (ksm *kubeSubnetManager) Run(ctx context.Context) {
	log.Infof("Starting kube subnet manager")
	ksm.nodeController.Run(ctx.Done())
}

// nodeToLease updates the lease with information fetch from the node, e.g. PodCIDR
func (ksm *kubeSubnetManager) nodeToLease(n v1.Node) (l lease.Lease, err error) {
	if ksm.enableIPv4 {
		l.Attrs.PublicIP, err = ip.ParseIP4(n.Annotations[ksm.annotations.BackendPublicIP])
		if err != nil {
			return l, err
		}
		l.Attrs.BackendData = json.RawMessage(n.Annotations[ksm.annotations.BackendData])

		var cidr *net.IPNet
		switch {
		case len(n.Spec.PodCIDRs) == 0:
			_, parseCidr, err := net.ParseCIDR(n.Spec.PodCIDR)
			if err != nil {
				return l, err
			}
			if parseCidr.IP.To4() != nil {
				cidr = parseCidr
			}
		case len(n.Spec.PodCIDRs) < 3:
			log.Infof("Creating the node lease for IPv4. This is the n.Spec.PodCIDRs: %v", n.Spec.PodCIDRs)
			for _, podCidr := range n.Spec.PodCIDRs {
				_, parseCidr, err := net.ParseCIDR(podCidr)
				if err != nil {
					return l, err
				}
				if parseCidr.IP.To4() != nil {
					cidr = parseCidr
					break
				}
			}
		default:
			return l, fmt.Errorf("node %q pod cidrs should be IPv4/IPv6 only or dualstack", ksm.nodeName)
		}
		if cidr == nil {
			return l, fmt.Errorf("missing IPv4 address on n.Spec.PodCIDRs")
		}
		l.Subnet = ip.FromIPNet(cidr)
		l.EnableIPv4 = ksm.enableIPv4
	}

	if ksm.enableIPv6 {
		l.Attrs.PublicIPv6, err = ip.ParseIP6(n.Annotations[ksm.annotations.BackendPublicIPv6])
		if err != nil {
			return l, err
		}
		l.Attrs.BackendV6Data = json.RawMessage(n.Annotations[ksm.annotations.BackendV6Data])

		var ipv6Cidr *net.IPNet
		switch {
		case len(n.Spec.PodCIDRs) == 0:
			_, parseCidr, err := net.ParseCIDR(n.Spec.PodCIDR)
			if err != nil {
				return l, err
			}
			if parseCidr.IP.To4() == nil {
				ipv6Cidr = parseCidr
			}
		case len(n.Spec.PodCIDRs) < 3:
			log.Infof("Creating the node lease for IPv6. This is the n.Spec.PodCIDRs: %v", n.Spec.PodCIDRs)
			for _, podCidr := range n.Spec.PodCIDRs {
				_, parseCidr, err := net.ParseCIDR(podCidr)
				if err != nil {
					return l, err
				}
				if parseCidr.IP.To4() == nil {
					ipv6Cidr = parseCidr
					break
				}
			}
		default:
			return l, fmt.Errorf("node %q pod cidrs should be IPv4/IPv6 only or dualstack", ksm.nodeName)
		}
		if ipv6Cidr == nil {
			return l, fmt.Errorf("missing IPv6 address on n.Spec.PodCIDRs")
		}
		l.IPv6Subnet = ip.FromIP6Net(ipv6Cidr)
		l.EnableIPv6 = ksm.enableIPv6
	}
	l.Attrs.BackendType = n.Annotations[ksm.annotations.BackendType]
	return l, nil
}

// RenewLease: unimplemented
func (ksm *kubeSubnetManager) RenewLease(ctx context.Context, lease *lease.Lease) error {
	return ErrUnimplemented
}

func (ksm *kubeSubnetManager) WatchLease(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net, receiver chan []lease.LeaseWatchResult) error {
	return ErrUnimplemented
}

func (ksm *kubeSubnetManager) Name() string {
	return fmt.Sprintf("Kubernetes Subnet Manager - %s", ksm.nodeName)
}

// CompleteLease Set Kubernetes NodeNetworkUnavailable to false when starting
// https://kubernetes.io/docs/concepts/architecture/nodes/#condition
func (ksm *kubeSubnetManager) CompleteLease(ctx context.Context, lease *lease.Lease, wg *sync.WaitGroup) error {
	if ksm.clusterCIDRController != nil {
		//start clusterController after all subnet manager has been fully initialized
		log.Info("starting clusterCIDR controller...")
		go ksm.clusterCIDRController.Run(ctx.Done())

		log.Infof("Waiting %s for clusterCIDR controller to sync...", nodeControllerSyncTimeout)
		err := wait.PollUntilContextTimeout(ctx, time.Second, nodeControllerSyncTimeout, true, func(context.Context) (bool, error) {
			return ksm.clusterCIDRController.HasSynced(), nil
		})

		if err != nil {
			return fmt.Errorf("error waiting for clusterCIDR to sync state: %v", err)
		}
		log.Infof("clusterCIDR controller sync successful")
	}
	if !ksm.setNodeNetworkUnavailable {
		// not set NodeNetworkUnavailable NodeCondition
		return nil
	}

	condition := v1.NodeCondition{
		Type:               v1.NodeNetworkUnavailable,
		Status:             v1.ConditionFalse,
		Reason:             "FlannelIsUp",
		Message:            "Flannel is running on this node",
		LastTransitionTime: metav1.Now(),
		LastHeartbeatTime:  metav1.Now(),
	}
	raw, err := json.Marshal(&[]v1.NodeCondition{condition})
	if err != nil {
		return err
	}
	patch := []byte(fmt.Sprintf(`{"status":{"conditions":%s}}`, raw))
	_, err = ksm.client.CoreV1().Nodes().PatchStatus(ctx, ksm.nodeName, patch)
	return err
}

func containsCIDR(ipnet1, ipnet2 *net.IPNet) bool {
	ones1, _ := ipnet1.Mask.Size()
	ones2, _ := ipnet2.Mask.Size()
	return ones1 <= ones2 && ipnet1.Contains(ipnet2.IP)
}

// HandleSubnetFile writes the configuration file used by the CNI flannel plugin
// and stores the immutable data in a dedicated struct of the subnet manager
// so that we can update the file later when a clustercidr resource is created.
func (m *kubeSubnetManager) HandleSubnetFile(path string, config *subnet.Config, ipMasq bool, sn ip.IP4Net, ipv6sn ip.IP6Net, mtu int) error {
	m.snFileInfo = &subnetFileInfo{
		path:   path,
		ipMask: ipMasq,
		sn:     sn,
		IPv6sn: ipv6sn,
		mtu:    mtu,
	}
	return subnet.WriteSubnetFile(path, config, ipMasq, sn, ipv6sn, mtu)
}

// GetStoredMacAddresses reads MAC addresses from node annotations when flannel restarts
func (ksm *kubeSubnetManager) GetStoredMacAddresses(ctx context.Context) (string, string) {
	var macv4, macv6 string
	// get mac info from Name func.
	node, err := ksm.client.CoreV1().Nodes().Get(ctx, ksm.nodeName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Failed to get node for backend data: %v", err)
		return "", ""
	}

	// node backend data format: `{"VNI":1,"VtepMAC":"12:c6:65:89:b4:e3"}`
	// and we will return only mac addr str like 12:c6:65:89:b4:e3
	if node != nil && node.Annotations != nil {
		log.Infof("List of node(%s) annotations: %#+v", ksm.nodeName, node.Annotations)
		backendData, ok := node.Annotations[fmt.Sprintf("%s/backend-data", ksm.annotationPrefix)]
		if ok {
			macStr := strings.Trim(backendData, "\"}")
			macInfoSlice := strings.Split(macStr, ":\"")
			if len(macInfoSlice) == 2 {
				macv4 = macInfoSlice[1]
			}
		}
		backendDatav6, okv6 := node.Annotations[fmt.Sprintf("%s/backend-v6-data", ksm.annotationPrefix)]
		if okv6 {
			macStr := strings.Trim(backendDatav6, "\"}")
			macInfoSlice := strings.Split(macStr, ":\"")
			if len(macInfoSlice) == 2 {
				macv6 = macInfoSlice[1]
			}
		}
		return macv4, macv6
	}

	return "", ""
}

// GetStoredPublicIP reads if there are any public IP configured as annotation when flannel starts
func (ksm *kubeSubnetManager) GetStoredPublicIP(ctx context.Context) (string, string) {
	// get mac info from Name func.
	node, err := ksm.client.CoreV1().Nodes().Get(ctx, ksm.nodeName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Failed to get node for backend data: %v", err)
		return "", ""
	}

	if node != nil && node.Annotations != nil {
		log.Infof("List of node(%s) annotations: %#+v", ksm.nodeName, node.Annotations)
		publicIP := node.Annotations[ksm.annotations.BackendNodePublicIP]
		publicIPv6 := node.Annotations[ksm.annotations.BackendNodePublicIPv6]
		return publicIP, publicIPv6
	}

	return "", ""
}
