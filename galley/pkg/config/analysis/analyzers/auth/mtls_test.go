package auth

import (
	"testing"

	"istio.io/istio/security/proto/authentication/v1alpha1"
)

func TestMTLSPolicyChecker(t *testing.T) {
	tests := map[string]struct {
		policies []struct {
			namespace string
			policy    *v1alpha1.Policy
		}
		namespace string
		workload  workload
		want      bool
	}{
		"no policies means no strict mtls": {
			// Note no policies specified
			namespace: "my-namespace",
			workload:  newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:      false,
		},
		"workload specific policy": {
			policies: []struct {
				namespace string
				policy    *v1alpha1.Policy
			}{
				{
					namespace: "my-namespace",
					policy: &v1alpha1.Policy{
						Targets: []*v1alpha1.TargetSelector{
							{
								Name: "foobar.my-namespace.svc.cluster.local",
								Ports: []*v1alpha1.PortSelector{
									{
										Port: &v1alpha1.PortSelector_Number{Number: 8080},
									},
								},
							},
						},
						Peers: []*v1alpha1.PeerAuthenticationMethod{
							{
								Params: &v1alpha1.PeerAuthenticationMethod_Mtls{
									Mtls: &v1alpha1.MutualTls{
										Mode: v1alpha1.MutualTls_STRICT,
									},
								},
							},
						},
					},
				},
			},
			workload: newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:     true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pc := newMTLSPolicyChecker()
			for _, p := range tc.policies {
				pc.addPolicy(p.namespace, p.policy)
			}

			got := pc.isServiceMTLSEnforced(tc.namespace, tc.workload)
			if got != tc.want {
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
		})
	}
}
