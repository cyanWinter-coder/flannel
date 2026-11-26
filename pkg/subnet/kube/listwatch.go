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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	log "k8s.io/klog/v2"
)

// loggingListWatch wraps the node informer's ListerWatcher so every full list
// and watch (re)connection is logged together with the resource version it
// resumes from. The reflector already resumes a watch from the last observed
// resource version and only falls back to a full relist when that version is
// gone from the API server's history; these logs make that behaviour
// observable when clusters report "watch disconnected and reconnected".
//
// It deliberately does not wrap the returned watch.Interface or its event
// channel: an intermediate forwarding goroutine would add backpressure and a
// second lifecycle that the reflector does not control. Disconnect reasons are
// already emitted by the reflector's own watch error handler.
type loggingListWatch struct {
	delegate cache.ListerWatcher
}

func newLoggingListWatch(delegate cache.ListerWatcher) cache.ListerWatcher {
	return &loggingListWatch{delegate: delegate}
}

func (lw *loggingListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	return lw.ListWithContext(context.Background(), options)
}

func (lw *loggingListWatch) ListWithContext(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
	log.Infof("Listing nodes (resourceVersion=%q)", options.ResourceVersion)
	lwCtx := cache.ToListerWatcherWithContext(lw.delegate)
	obj, err := lwCtx.ListWithContext(ctx, options)
	if err != nil {
		log.Errorf("Failed to list nodes: %v", err)
		return nil, err
	}
	log.Infof("Node list completed (requested resourceVersion=%q)", options.ResourceVersion)
	return obj, nil
}

func (lw *loggingListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return lw.WatchWithContext(context.Background(), options)
}

func (lw *loggingListWatch) WatchWithContext(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
	log.Infof("Starting node watch from resourceVersion=%q", options.ResourceVersion)
	lwCtx := cache.ToListerWatcherWithContext(lw.delegate)
	w, err := lwCtx.WatchWithContext(ctx, options)
	if err != nil {
		log.Errorf("Failed to start node watch from resourceVersion=%q: %v",
			options.ResourceVersion, err)
		return nil, err
	}
	return w, nil
}

// Compile-time guarantees that the wrapper stays interface-compatible with
// both the legacy and context-aware ListerWatcher contracts.
var (
	_ cache.ListerWatcher            = (*loggingListWatch)(nil)
	_ cache.ListerWatcherWithContext = (*loggingListWatch)(nil)
)
