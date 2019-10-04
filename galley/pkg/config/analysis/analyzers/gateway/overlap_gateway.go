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

package gateway

import (
	"strings"

	"istio.io/api/networking/v1alpha3"
	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/analysis/msg"
	"istio.io/istio/galley/pkg/config/meta/metadata"
	"istio.io/istio/galley/pkg/config/meta/schema/collection"
	"istio.io/istio/galley/pkg/config/resource"
)

// OverlappingAnalyzer checks if any Gateways overlap in the set of
// hosts that they match.
type OverlappingAnalyzer struct{}

// (compile-time check that we implement the interface)
var _ analysis.Analyzer = &OverlappingAnalyzer{}

// Metadata implements analysis.Analyzer
func (*OverlappingAnalyzer) Metadata() analysis.Metadata {
	return analysis.Metadata{
		Name: "gateway.OverlappingGatewayAnalyzer",
		Inputs: collection.Names{
			metadata.IstioNetworkingV1Alpha3Gateways,
			// metadata.K8SCoreV1Pods,
		},
	}
}

type stubServer struct {
	Port uint32
	// Note that hosts is normalized, which makes checking easier
	Hosts []string
}

type stubGateway struct {
	Resource *resource.Entry
	Selector map[string]string
	Servers  []stubServer
}

// Analyze implements analysis.Analyzer
func (s *OverlappingAnalyzer) Analyze(c analysis.Context) {
	var gateways []*resource.Entry
	c.ForEach(metadata.IstioNetworkingV1Alpha3Gateways, func(r *resource.Entry) bool {
		gateways = append(gateways, r)
		return true
	})

	// Iterate over every gateway pair and check for overlap
	for i := 0; i < len(gateways); i++ {
		for j := i + 1; j < len(gateways); j++ {
			r1 := gateways[i]
			r2 := gateways[j]

			gw1 := r1.Item.(*v1alpha3.Gateway)
			gw2 := r2.Item.(*v1alpha3.Gateway)

			ns1, _ := r1.Metadata.Name.InterpretAsNamespaceAndName()
			ns2, _ := r2.Metadata.Name.InterpretAsNamespaceAndName()

			// TODO It would be ideal if we could look at actual workloads instead of comparing the selector.
			if !areMapsEqual(gw1.Selector, gw2.Selector) {
				continue
			}
			// TODO should check if servers overlap on the same resource? or is that caught by single-object validation?
			for _, sv1 := range gw1.Servers {
				for _, sv2 := range gw2.Servers {
					if sv1.Port.GetNumber() != sv2.Port.GetNumber() {
						continue
					}
					// At this point the selector and port is the same. Check each hosts field for overlap
					for _, h1 := range sv1.Hosts {
						for _, h2 := range sv2.Hosts {
							if doHostsOverlap(ns1, h1, ns2, h2) {
								// Complain about both!
								c.Report(metadata.IstioNetworkingV1Alpha3Gateways,
									msg.NewGatewayOverlaps(r1, sv1.Port.GetNumber(), h1, "Gateway/"+r2.Metadata.Name.String(), h2))
								c.Report(metadata.IstioNetworkingV1Alpha3Gateways,
									msg.NewGatewayOverlaps(r2, sv2.Port.GetNumber(), h2, "Gateway/"+r1.Metadata.Name.String(), h1))
							}
						}
					}
				}
			}

		}
	}
}

// Assume host field is normalized
func doHostsOverlap(resourceNamespace1, host1, resourceNamespace2, host2 string) bool {
	namespace1, dnsName1 := normalizeHost(resourceNamespace1, host1)
	namespace2, dnsName2 := normalizeHost(resourceNamespace2, host2)

	// Bail early if namespace doesn't overlap
	if namespace1 != namespace2 && namespace1 != "*" && namespace2 != "*" {
		return false
	}

	if dnsName1 == "*" || dnsName2 == "*" {
		return true
	}

	// The actual service can only have a wildcard character in the left most
	// component. This means we can check for overlap in linear time by
	// reversing the host string and checking character by character until
	// none are left (or a * is encountered).
	i := len(dnsName1) - 1
	j := len(dnsName2) - 1
	for i >= 0 && j >= 0 {
		if (i == 0 && dnsName1[i] == '*') || (j == 0 && dnsName2[j] == '*') {
			// counts as a match
			return true
		}
		if dnsName1[i] != dnsName2[j] {
			return false
		}
		i--
		j--
	}

	if len(dnsName1) == len(dnsName2) {
		return true
	} else if len(dnsName1)-len(dnsName2) == 1 && dnsName1[0] == '*' {
		// Handle the edge case where we have something like '*example.com' and 'example.com'
		return true
	} else if len(dnsName2)-len(dnsName1) == 1 && dnsName2[0] == '*' {
		return true
	} else {
		return false
	}
}

func areMapsEqual(m1, m2 map[string]string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for k, v := range m1 {
		if m2[k] != v {
			return false
		}
	}
	return true
}

func normalizeHost(namespace, host string) (string, string) {
	parts := strings.SplitN(host, "/", 2)
	if len(parts) == 1 {
		// No namespace was specified, so explicitly use the implicit '*/' prefix
		return "*", parts[0]
	}
	// If '.' is used as the namespace and we know the actual namespace the
	// resource is in, fill it in.
	if len(parts) == 2 && parts[0] == "." && namespace != "" {
		return namespace, parts[1]
	}

	return parts[0], parts[1]
}
