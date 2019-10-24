package auth

import (
	"bytes"
	"testing"

	"github.com/ghodss/yaml"

	"github.com/golang/protobuf/jsonpb"

	"istio.io/istio/security/proto/authentication/v1alpha1"
)

func TestMTLSPolicyChecker(t *testing.T) {
	tests := map[string]struct {
		policies []struct {
			namespace string
			policy    string
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
				policy    string
			}{
				{
					namespace: "my-namespace",
					policy: `
targets:
- name: foobar
  ports:
  - number: 8080
peers:
- mtls:
`,
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
				js, err := yaml.YAMLToJSON([]byte(p.policy))
				if err != nil {
					t.Fatalf("expected %v, got err parsing yaml: %v", tc.want, err)
				}
				var pb v1alpha1.Policy
				err = jsonpb.Unmarshal(bytes.NewReader(js), &pb)
				if err != nil {
					t.Fatalf("expected %v, got err unmarshalling json: %v", tc.want, err)
				}

				pc.addPolicy(p.namespace, &pb)
			}

			got := pc.isServiceMTLSEnforced(tc.namespace, tc.workload)
			if got != tc.want {
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
		})
	}
}
