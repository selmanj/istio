package analyzers

import (
	"fmt"
	"strings"

	"istio.io/api/networking/v1alpha3"

	"cuelang.org/go/cue"
	"cuelang.org/go/encoding/gocode/gocodec"
	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/processor/metadata"
	"istio.io/istio/galley/pkg/config/resource"
)

// CueSampleAnalyzer is a sample analyzer
type CueSampleAnalyzer struct {
}

var _ analysis.Analyzer = &SampleAnalyzer{}

// Name implements SampleAnalyzer
func (s *CueSampleAnalyzer) Name() string {
	return "cue_sample"
}

// Analyze implements SampleAnalyzer
func (s *CueSampleAnalyzer) Analyze(c analysis.Context) {

	var r cue.Runtime

	codec := gocodec.New(&r, &gocodec.Config{})
	// relevantTypes is the set of things we want to make assertions about
	relevantTypes := relevantTypes{
		VirtualService: make(map[string]*annotatedVirtualService),
		Gateway:        make(map[string]*v1alpha3.Gateway),
	}

	// Load up our rule - specifically, every GatewayRef must point to an existing Gateway
	instance, err := r.Compile("hardcoded", `
		Gateway <name>: {}
		VirtualService <name> GatewayRefs: [or([k for k, v in Gateway])] `)

	if err != nil {
		panic(err)
	}

	// Now built up our relevant types, annotating as we go
	c.ForEach(metadata.IstioNetworkingV1Alpha3Virtualservices, func(r *resource.Entry) bool {
		vs := r.Item.(*v1alpha3.VirtualService)
		ns, _ := r.Metadata.Name.InterpretAsNamespaceAndName()

		avs := annotatedVirtualService{VirtualService: vs}
		for _, gw := range vs.GetGateways() {
			var ref string
			if strings.Contains(gw, "/") {
				// It's already a global ref
				ref = gw
			} else {
				ref = ns + "/" + gw
			}
			// Annotate the Gateway with a reference
			avs.GatewayRefs = append(avs.GatewayRefs, ref)
		}

		relevantTypes.VirtualService[r.Metadata.Name.String()] = &avs
		return true
	})

	c.ForEach(metadata.IstioNetworkingV1Alpha3Gateways, func(r *resource.Entry) bool {
		gw := r.Item.(*v1alpha3.Gateway)

		relevantTypes.Gateway[r.Metadata.Name.String()] = gw
		return true
	})

	err = codec.Validate(instance.Value(), relevantTypes)
	// To be explicit that this is working, always print directly to stdout
	if err == nil {
		fmt.Printf("[CUE-EVAL] Successfully validated constraints.\n")
	} else {
		fmt.Printf("[CUE-EVAL] Error validating constraints: %v\n", err)
	}
}

type annotatedVirtualService struct {
	*v1alpha3.VirtualService
	// This is just a gateway reference but always includes the namespace
	GatewayRefs []string
}

type relevantTypes struct {
	VirtualService map[string]*annotatedVirtualService
	Gateway        map[string]*v1alpha3.Gateway
}
