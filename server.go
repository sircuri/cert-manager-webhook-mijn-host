package main

import (
	"context"
	"fmt"
	"net"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apiserver"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/registry/challengepayload"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	basecompatibility "k8s.io/component-base/compatibility"
	"k8s.io/component-base/logs"
	ctrl "sigs.k8s.io/controller-runtime"
)

// runWebhookServer replicates cert-manager's cmd.RunWebhookServer but installs
// a listable REST handler so the APIService advertises LIST in addition to
// CREATE. Without this, kube-controller-manager's garbage collector LISTs every
// discovered resource roughly once per minute and produces 405 spam in the logs.
func runWebhookServer(ctx context.Context, groupName string, solver webhook.Solver) error {
	logs.InitLogs()
	defer logs.FlushLogs()
	ctrl.SetLogger(logf.Log)
	ctx = logf.NewContext(ctx, logf.Log, "acme-dns-webhook")

	loggingOpts := logs.NewOptions()
	recommended := genericoptions.NewRecommendedOptions(
		"<UNUSED>",
		apiserver.Codecs.LegacyCodec(whapi.SchemeGroupVersion),
	)
	recommended.Etcd = nil
	recommended.Admission = nil
	recommended.Features.EnablePriorityAndFairness = false

	cmd := &cobra.Command{
		Short: "Launch an ACME solver API server",
		Long:  "Launch an ACME solver API server",
		RunE: func(c *cobra.Command, _ []string) error {
			if err := logf.ValidateAndApply(loggingOpts); err != nil {
				return err
			}
			if errs := recommended.Validate(); len(errs) > 0 {
				return fmt.Errorf("error validating recommended options: %v", errs)
			}
			return runAPIServer(c.Context(), recommended, groupName, solver)
		},
	}
	flags := cmd.Flags()
	logf.AddFlags(loggingOpts, flags)
	recommended.AddFlags(flags)

	return cmd.ExecuteContext(ctx)
}

func runAPIServer(ctx context.Context, opts *genericoptions.RecommendedOptions, groupName string, solver webhook.Solver) error {
	if err := opts.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := opts.ApplyTo(serverConfig); err != nil {
		return err
	}

	serverConfig.EffectiveVersion = basecompatibility.NewEffectiveVersionFromString("1.1", "", "")
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(getOpenAPIDefinitions, openapi.NewDefinitionNamer(apiserver.Scheme))
	serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(getOpenAPIDefinitions, openapi.NewDefinitionNamer(apiserver.Scheme))

	restClientConfig := serverConfig.ClientConfig
	completed := serverConfig.Complete()

	genericServer, err := completed.New("challenge-server", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}

	gv := schema.GroupVersion{Group: groupName, Version: "v1alpha1"}
	registerListTypes(gv)
	challengeHandler := newListableREST(challengepayload.NewREST(solver), solver.Name())

	apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions: []schema.GroupVersion{gv},
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{
			gv.Version: {
				solver.Name(): challengeHandler,
			},
		},
		OptionsExternalVersion: &schema.GroupVersion{Version: "v1"},
		Scheme:                 apiserver.Scheme,
		ParameterCodec:         metav1.ParameterCodec,
		NegotiatedSerializer:   apiserver.Codecs,
	}
	if err := genericServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return fmt.Errorf("error installing APIGroup for solver: %w", err)
	}

	genericServer.AddPostStartHookOrDie(
		fmt.Sprintf("solver-%s-init", solver.Name()),
		func(pctx genericapiserver.PostStartHookContext) error {
			return solver.Initialize(restClientConfig, pctx.Done())
		},
	)

	return genericServer.PrepareRun().RunWithContext(ctx)
}
