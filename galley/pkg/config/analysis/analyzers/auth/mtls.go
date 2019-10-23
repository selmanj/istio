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
	"fmt"

	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/analysis/analyzers/util"
	"istio.io/istio/galley/pkg/config/meta/metadata"
	"istio.io/istio/galley/pkg/config/meta/schema/collection"
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
	//
	// For a given service/port combination, we need to figure out two things.
	// 1) Is there an authn policy that enforces strict MTLS on this service?
	// 2) If yes, is there a destination rule (or lack of rule) that does not enforce
	// strict MTLS on this service?
	//
	// To calculate 1, we must resolve which policy applies to the service by
	// looking at policies that target services, namespaces, and the mesh (in
	// that order). The first match found is the policy that is enforced.
	//
	// To calculate 2, we must also resolve which destination rule takes effect.
	// The ordering for resolving a matching destination rule is:
	// 1) Destination rules in the source namespace
	// 2) Destination rules in the destination namespace
	// 3) Destination rules in istio-system

	// if r := ctx.Find(metadata.IstioAuthenticationV1Alpha1Meshpolicies, resource.NewName("", "default")); r != nil {
	// 	meshPolicy := r.Item.(*v1alpha1.Policy)
	// }

	// // Now collect all policies
	// var policies []*v1alpha1.Policy
	// ctx.ForEach(metadata.IstioAuthenticationV1Alpha1Policies, func(r *resource.Entry) bool {

	// 	return true
	// })
}

type workload struct {
	fqdn string

	// Both portNumber and portName cannot both be non-default values.
	portNumber uint32
	portName   string
}

func newWorkloadWithPortNumber(fqdn string, portNumber uint32) workload {
	return workload{fqdn: fqdn, portNumber: portNumber}
}

func newWorkloadWithPortName(fqdn, portName string) workload {
	return workload{fqdn: fqdn, portName: portName}
}

func newWorkload(fqdn string) workload {
	return workload{fqdn: fqdn}
}

type mTLSPolicyChecker struct {
	// meshHasStrictMTLSPolicy tracks whether or not mTLS is strictly enforced on the mesh.
	meshHasStrictMTLSPolicy bool

	namespaceHasStrictMTLSPolicy map[string]bool
	workloadHasMTLSPolicy        map[workload]bool
}

func newMTLSPolicyChecker() *mTLSPolicyChecker {
	return &mTLSPolicyChecker{
		namespaceHasStrictMTLSPolicy: make(map[string]bool),
		workloadHasMTLSPolicy:        make(map[workload]bool),
	}
}

func (pc *mTLSPolicyChecker) addMeshPolicy(p *v1alpha1.Policy) {
	pc.meshHasStrictMTLSPolicy = doesPolicyEnforceMTLS(p)
}

func (pc *mTLSPolicyChecker) addPolicy(namespace string, p *v1alpha1.Policy) error {
	if !doesPolicyEnforceMTLS(p) {
		return nil
	}

	if len(p.Targets) == 0 {
		// Rule targets the namespace.
		pc.namespaceHasStrictMTLSPolicy[namespace] = true
		return nil
	}
	// Discover the targeted workload and take note. Should normalize.
	for _, target := range p.Targets {
		fqdn := util.ConvertHostToFQDN(namespace, target.Name)

		if len(target.Ports) == 0 {
			// Policy targets all ports on workload
			pc.workloadHasMTLSPolicy[newWorkload(fqdn)] = true
		}

		for _, port := range target.Ports {
			if port.GetName() != "" {
				pc.workloadHasMTLSPolicy[newWorkloadWithPortName(fqdn, port.GetName())] = true
			} else if port.GetNumber() != 0 {
				pc.workloadHasMTLSPolicy[newWorkloadWithPortNumber(fqdn, port.GetNumber())] = true
			} else {
				// Unhandled case!
				return fmt.Errorf("policy has a port with no name/number for target %s", target.Name)
			}
		}
	}

	return nil
}

func (pc *mTLSPolicyChecker) isServiceMTLSEnforced(namespace string, w workload) bool {
	if pc.workloadHasMTLSPolicy[w] {
		return true
	}
	// Try checking if its enforced on any ports
	workloadNoPort := newWorkload(w.fqdn)
	if pc.workloadHasMTLSPolicy[workloadNoPort] {
		return true
	}
	// Check if enforced on namespace
	// TODO consider using namespace in fqdn?
	if pc.namespaceHasStrictMTLSPolicy[namespace] {
		return true
	}
	// Finally, defer to mesh level policy
	return pc.meshHasStrictMTLSPolicy
}

func doesPolicyEnforceMTLS(p *v1alpha1.Policy) bool {
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
