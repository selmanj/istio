package auth

import (
	"bytes"
	"testing"

	"github.com/golang/protobuf/jsonpb"
	"sigs.k8s.io/yaml"

	"istio.io/istio/security/proto/authentication/v1alpha1"
)

func TestMTLSPolicyChecker(t *testing.T) {
	type PolicyResource struct {
		namespace string
		policy    string
	}

	tests := map[string]struct {
		meshPolicy string
		policies   []PolicyResource
		workload   workload
		want       bool
	}{
		"no policies means no strict mtls": {
			// Note no policies specified
			workload: newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:     false,
		},
		"workload specific policy": {
			policies: []PolicyResource{
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
		"non-matching host workload specific policy": {
			policies: []PolicyResource{
				{
					namespace: "my-namespace",
					policy: `
targets:
- name: baz
  ports:
  - number: 8080
peers:
- mtls:
`,
				},
			},
			workload: newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:     false,
		},
		"non-matching namespace workload specific policy": {
			policies: []PolicyResource{
				{
					namespace: "my-other-namespace",
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
			want:     false,
		},
		"policy matches workload but is not strict": {
			policies: []PolicyResource{
				{
					namespace: "my-namespace",
					policy: `
targets:
- name: foobar
  ports:
  - number: 8080
peers:
- mtls:
    mode: PERMISSIVE
`,
				},
			},
			workload: newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:     false,
		},
		"policy matches every port on service": {
			policies: []PolicyResource{
				{
					namespace: "my-namespace",
					policy: `
targets:
- name: foobar
peers:
- mtls:
`,
				},
			},
			workload: newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:     true,
		},
		"policy matches every service in namespace": {
			policies: []PolicyResource{
				{
					namespace: "my-namespace",
					policy: `
peers:
- mtls:
`,
				},
			},
			workload: newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:     true,
		},
		"policy matches entire mesh": {
			meshPolicy: `
peers:
- mtls:
`,
			workload: newWorkloadWithPortNumber("foobar.my-namespace.svc.cluster.local", 8080),
			want:     true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pc := newMTLSPolicyChecker()
			// Add mesh policy, if it exists.
			meshpb, err := yAMLToPolicy(tc.meshPolicy)
			if err != nil {
				t.Fatalf("expected: %v, got error when parsing yaml: %v", tc.want, err)
			}
			pc.addMeshPolicy(meshpb)

			// Add in all other policies
			for _, p := range tc.policies {
				pb, err := yAMLToPolicy(p.policy)
				if err != nil {
					t.Fatalf("expected: %v, got error when parsing yaml: %v", tc.want, err)
				}
				pc.addPolicy(p.namespace, pb)
			}

			got, err := pc.isServiceMTLSEnforced(tc.workload)
			if err != nil {
				t.Fatalf("expected: %v, got error: %v", tc.want, err)
			}
			if got != tc.want {
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
		})
	}
}

func yAMLToPolicy(yml string) (*v1alpha1.Policy, error) {
	js, err := yaml.YAMLToJSON([]byte(yml))
	if err != nil {
		return nil, err
	}
	var pb v1alpha1.Policy
	err = jsonpb.Unmarshal(bytes.NewReader(js), &pb)
	if err != nil {
		return nil, err
	}

	return &pb, nil
}
