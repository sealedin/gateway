// Package egress forwards OpenAI-compatible requests to upstream TEE instances verified against the measured policy.
package egress

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sealedin/gateway/internal/egress/chutes"
	"github.com/sealedin/gateway/internal/egress/near"
)

// Policy is egress/policy.yaml: the upstream hosts, the re-attestation interval and the measurement allowlists.
type Policy struct {
	Provider string `yaml:"provider"`
	Hosts    struct {
		API     string `yaml:"api"`
		Catalog string `yaml:"catalog"`
	} `yaml:"hosts"`
	ReattestInterval time.Duration `yaml:"reattest_interval"`
	Upstream         chutes.Policy `yaml:",inline"`
	// Near is the optional second family; without it every model goes to the provider above.
	Near *NearPolicy `yaml:"near"`
}

// NearPolicy names the models routed to the provider's gateway and what that gateway must attest to.
type NearPolicy struct {
	near.Policy `yaml:",inline"`

	Models []string `yaml:"models"`
}

// LoadPolicy decodes and validates a policy; a policy that fails here must not start the egress.
func LoadPolicy(r io.Reader) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("egress: policy: %w", err)
	}
	return p, p.Validate()
}

// Validate checks the shape: a known provider, https hosts, a positive interval, and allowlists that pin something.
func (p Policy) Validate() error {
	if p.Provider != "chutes" {
		return fmt.Errorf("egress: policy provider %q unsupported", p.Provider)
	}
	for name, host := range map[string]string{"api": p.Hosts.API, "catalog": p.Hosts.Catalog} {
		u, err := url.Parse(host)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.String() != "https://"+u.Host {
			return fmt.Errorf("egress: policy host %s %q must be a bare https origin", name, host)
		}
	}
	if p.ReattestInterval <= 0 {
		return errors.New("egress: policy reattest_interval must be positive")
	}
	if p.Near != nil {
		if len(p.Near.Models) == 0 {
			return errors.New("egress: policy near block routes no model")
		}
		if err := p.Near.Validate(); err != nil {
			return err
		}
	}
	return p.Upstream.Validate()
}
