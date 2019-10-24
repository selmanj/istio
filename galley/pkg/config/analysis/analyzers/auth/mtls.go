// Copyright 2019 Istio Authors
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

package auth

import (
	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/meta/metadata"
	"istio.io/istio/galley/pkg/config/meta/schema/collection"
	"istio.io/istio/galley/pkg/config/resource"
	"istio.io/istio/security/proto/authentication/v1alpha1"
)

// MTLSAnalyzer checks the validity of mTLS policy.
type MTLSAnalyzer struct{}

var _ analysis.Analyzer = &MTLSAnalyzer{}

// Metadata implements Analyzer
func (s *MTLSAnalyzer) Metadata() analysis.Metadata {
	return analysis.Metadata{
		Name: "auth.MTLSAnalyzer",
		Inputs: collection.Names{
			metadata.IstioAuthenticationV1Alpha1Meshpolicies,
		},
	}
}

// Analyze implements Analyzer
func (s *MTLSAnalyzer) Analyze(ctx analysis.Context) {
	// To analyze, we need to build up the entire context/ordering for security
	// policies.
	//
	// See istio.io/istio/pilot/pkg/model.AuthenticationPolicyForWorkload for
	// reference for how auth policy is resolved in practice.

	if r := ctx.Find(metadata.IstioAuthenticationV1Alpha1Meshpolicies, resource.NewName("", "default")); r != nil {
		meshPolicy := r.Item.(*v1alpha1.Policy)
		globalMTLSPolicy = CheckPolicyEnforcesMTLS(r.Metadata, meshPolicy)
	}

	// Now collect all policies
	var policies []*v1alpha1.Policy
	ctx.ForEach(metadata.IstioAuthenticationV1Alpha1Policies, func(r *resource.Entry) bool {

		return true
	})
}

type mTLSWorkload struct {
	name string
	port uint32
}

type mTLSPolicyChecker struct {
	// meshHasStrictMTLSPolicy tracks whether or not mTLS is strictly enforced on the mesh.
	meshHasStrictMTLSPolicy bool

	namespaceHasStrictMTLSPolicy map[string]bool
	workloadHasMTLSPolicy        map[mTLSWorkload]bool
}

func (pc *mTLSPolicyChecker) AddMeshPolicy(p *v1alpha1.Policy) {
	pc.meshHasStrictMTLSPolicy = DoesPolicyEnforceMTLS(p)
}

func (pc *mTLSPolicyChecker) AddPolicy(m resource.Metadata, p *v1alpha1.Policy) {
	if !DoesPolicyEnforceMTLS(p) {
		return
	}

	// Discover the targetted workload and take note. Should normalize.

}

func DoesPolicyEnforceMTLS(p *v1alpha1.Policy) bool {
	if p.PeerIsOptional {
		// Connection can still occur.
		return false
	}
	hasStrictMTLSPolicy := false
	for _, peer := range p.Peers {
		mtlsParams, ok := peer.Params.(*v1alpha1.PeerAuthenticationMethod_Mtls)
		if !ok {
			// Only looking for mtls methods
			continue
		}
		// Check to see if it's permissive.
		if mtlsParams.Mtls.AllowTls || mtlsParams.Mtls.Mode == v1alpha1.MutualTls_PERMISSIVE {
			continue
		}

		hasStrictMTLSPolicy = true
		break
	}

	return hasStrictMTLSPolicy
}
