package main

import (
	"context"
	"sync"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apiserver"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/registry/challengepayload"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/rest"
)

// ChallengePayloadList exists solely so the webhook can advertise LIST on the
// ChallengePayload resource. kube-controller-manager's garbage collector
// LISTs every discovered resource every ~50s; without this, each call returns
// 405 and floods the logs.
type ChallengePayloadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []v1alpha1.ChallengePayload `json:"items"`
}

func (l *ChallengePayloadList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := &ChallengePayloadList{
		TypeMeta: l.TypeMeta,
		ListMeta: *l.ListMeta.DeepCopy(),
	}
	if l.Items != nil {
		out.Items = make([]v1alpha1.ChallengePayload, len(l.Items))
		for i := range l.Items {
			l.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
	return out
}

func init() {
	apiserver.Scheme.AddKnownTypes(v1alpha1.SchemeGroupVersion, &ChallengePayloadList{})
}

// listableREST wraps challengepayload.REST so the generic apiserver also
// registers GET (list) routes for the resource. List always returns an empty
// collection — ChallengePayload is a synthetic RPC-style resource with no
// actual storage, so there is nothing to enumerate.
type listableREST struct {
	*challengepayload.REST
	tableConvertor rest.TableConvertor
}

func newListableREST(inner *challengepayload.REST, resource string) *listableREST {
	return &listableREST{
		REST: inner,
		tableConvertor: rest.NewDefaultTableConvertor(
			schema.GroupResource{Group: v1alpha1.SchemeGroupVersion.Group, Resource: resource},
		),
	}
}

func (r *listableREST) NewList() runtime.Object {
	return &ChallengePayloadList{}
}

func (r *listableREST) List(_ context.Context, _ *metainternalversion.ListOptions) (runtime.Object, error) {
	return &ChallengePayloadList{Items: []v1alpha1.ChallengePayload{}}, nil
}

func (r *listableREST) ConvertToTable(ctx context.Context, object runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return r.tableConvertor.ConvertToTable(ctx, object, tableOptions)
}

// Watch returns a watcher that never emits events. Informers (used by
// kube-controller-manager's garbage collector) will try to WATCH after a
// successful LIST; without this they would log 405s in place of the old LIST
// errors. The watcher blocks until the request context is cancelled.
func (r *listableREST) Watch(ctx context.Context, _ *metainternalversion.ListOptions) (watch.Interface, error) {
	return newBlockingWatcher(ctx), nil
}

type blockingWatcher struct {
	result   chan watch.Event
	stop     chan struct{}
	stopOnce sync.Once
}

func newBlockingWatcher(ctx context.Context) *blockingWatcher {
	w := &blockingWatcher{
		result: make(chan watch.Event),
		stop:   make(chan struct{}),
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-w.stop:
		}
		close(w.result)
	}()
	return w
}

func (w *blockingWatcher) Stop() {
	w.stopOnce.Do(func() { close(w.stop) })
}

func (w *blockingWatcher) ResultChan() <-chan watch.Event {
	return w.result
}
