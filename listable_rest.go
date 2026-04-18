package main

import (
	"context"
	"reflect"
	"sync"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apiserver"
	cmopenapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/openapi"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/registry/challengepayload"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/validation/spec"
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

// registerListTypes registers ChallengePayloadList and common metav1 types
// (including WatchEvent) under the webhook's runtime-configured SolverGroup.
// The apiserver installer resolves the versioned list/watch types against the
// endpoint's GroupVersion (the SolverGroup), not against the static
// cert-manager scheme group, so registration must happen after GROUP_NAME is
// read.
func registerListTypes(gv schema.GroupVersion) {
	apiserver.Scheme.AddKnownTypes(gv, &ChallengePayloadList{})
	metav1.AddToGroupVersion(apiserver.Scheme, gv)
}

// challengePayloadListTypeName returns the key the kube-openapi builder uses
// to look up the OpenAPI definition for ChallengePayloadList (PkgPath.Name).
// Deriving it via reflection avoids hard-coding "main.ChallengePayloadList",
// which changes if the type moves packages.
func challengePayloadListTypeName() string {
	t := reflect.TypeOf(ChallengePayloadList{})
	return t.PkgPath() + "." + t.Name()
}

// getOpenAPIDefinitions wraps the cert-manager-generated OpenAPI definitions
// and adds one for ChallengePayloadList. Without it the aggregated apiserver
// fails to build its OpenAPI spec at startup.
func getOpenAPIDefinitions(ref common.ReferenceCallback) map[string]common.OpenAPIDefinition {
	defs := cmopenapi.GetOpenAPIDefinitions(ref)
	defs[challengePayloadListTypeName()] = common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "ChallengePayloadList is a list of ChallengePayload objects. The webhook never stores any, so the list is always empty; it exists only so the aggregated API advertises LIST.",
				Type:        []string{"object"},
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents.",
							Type:        []string{"string"},
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object.",
							Type:        []string{"string"},
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Default: map[string]interface{}{},
							Ref:     ref("k8s.io/apimachinery/pkg/apis/meta/v1.ListMeta"),
						},
					},
					"items": {
						SchemaProps: spec.SchemaProps{
							Type: []string{"array"},
							Items: &spec.SchemaOrArray{
								Schema: &spec.Schema{
									SchemaProps: spec.SchemaProps{
										Default: map[string]interface{}{},
										Ref:     ref("github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1.ChallengePayload"),
									},
								},
							},
						},
					},
				},
				Required: []string{"items"},
			},
		},
		Dependencies: []string{
			"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1.ChallengePayload",
			"k8s.io/apimachinery/pkg/apis/meta/v1.ListMeta",
		},
	}
	return defs
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
