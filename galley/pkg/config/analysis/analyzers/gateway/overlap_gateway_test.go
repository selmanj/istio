package gateway

import (
	"testing"
)

func TestNormalizeHosts(t *testing.T) {
	var tests = map[string]struct {
		ns       string
		host     string
		wantNs   string
		wantHost string
	}{
		"adds implicit star":             {ns: "", host: "myhost", wantNs: "*", wantHost: "myhost"},
		"accepts explicit host":          {ns: "", host: "foobar/baz", wantNs: "foobar", wantHost: "baz"},
		"uses dot if no namespace":       {ns: "", host: "./myhost", wantNs: ".", wantHost: "myhost"},
		"uses namespace in place of dot": {ns: "mynamespace", host: "./myhost", wantNs: "mynamespace", wantHost: "myhost"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			gotNs, gotHost := normalizeHost(tt.ns, tt.host)
			if gotNs != tt.wantNs || gotHost != tt.wantHost {
				t.Errorf("normalizeHost(%s, %s) = (%s, %s), want (%s, %s)", tt.ns, tt.host, gotNs, gotHost, tt.wantNs, tt.wantHost)
			}
		})
	}
}

func TestDoHostsOverlap(t *testing.T) {
	var tests = map[string]struct {
		ns1   string
		host1 string
		ns2   string
		host2 string
		want  bool
	}{
		"basic":                  {host1: "*/host", host2: "*/host", want: true},
		"basic no match":         {host1: "*/host", host2: "*/differenthost", want: false},
		"diff namespace":         {host1: "a/host", host2: "b/host", want: false},
		"star namespace":         {host1: "a/host", host2: "*/host", want: true},
		"star host":              {host1: "a/*", host2: "a/example.com", want: true},
		"star prefix":            {host1: "a/*.example.com", host2: "a/*mple.com", want: true},
		"star prefix no overlap": {host1: "a/*.b.example.com", host2: "a/*.a.example.com", want: false},
		"star prefix edgecase":   {host1: "a/*example.com", host2: "a/example.com", want: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := doHostsOverlap(tt.ns1, tt.host1, tt.ns2, tt.host2)
			if got != tt.want {
				t.Errorf("doHostsOverlap(%v, %v) = %v, want %v", tt.host1, tt.host2, got, tt.want)
			}
		})
	}
}
