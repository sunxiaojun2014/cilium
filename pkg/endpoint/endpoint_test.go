// Copyright 2016-2017 Authors of Cilium
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

package endpoint

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/comparator"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

var (
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointSuite struct{}

var _ = Suite(&EndpointSuite{})

func (s *EndpointSuite) TestEndpointID(c *C) {
	e := Endpoint{
		ID:     IPv6Addr.EndpointID(),
		IPv6:   IPv6Addr,
		IPv4:   IPv4Addr,
		Status: NewEndpointStatus(),
	}
	c.Assert(e.ID, Equals, uint16(4370)) //"0x1112"
	c.Assert(bytes.Compare(e.IPv6, IPv6Addr) == 0, Equals, true)
	c.Assert(bytes.Compare(e.IPv4, IPv4Addr) == 0, Equals, true)
}

func (s *EndpointSuite) TestOrderEndpointAsc(c *C) {
	eps := []*models.Endpoint{
		{ID: 5},
		{ID: 1000},
		{ID: 1},
		{ID: 3},
		{ID: 2},
	}
	epsWant := []*models.Endpoint{
		{ID: 1},
		{ID: 2},
		{ID: 3},
		{ID: 5},
		{ID: 1000},
	}
	OrderEndpointAsc(eps)
	c.Assert(eps, comparator.DeepEquals, epsWant)
}

func (s *EndpointSuite) TestEndpointStatus(c *C) {
	eps := NewEndpointStatus()

	c.Assert(eps.String(), Equals, "OK")

	sts := &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "BPF Program compiled",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "OK")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "BPF Program failed to compile",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	// An OK message with priority Other can't hide a High Failure message.
	for i := 0; i <= maxLogs; i++ {
		st := &statusLogMsg{
			Status: Status{
				Code: OK,
				Msg:  "Other thing compiled",
				Type: Other,
			},
			Timestamp: time.Now(),
		}
		eps.addStatusLog(st)
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "BPF Program compiled",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	// BPF might be ok but the policy is still in fail mode.
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "OK")
}

func (s *EndpointSuite) TestEndpointUpdateLabels(c *C) {
	e := Endpoint{
		ID:     IPv6Addr.EndpointID(),
		IPv6:   IPv6Addr,
		IPv4:   IPv4Addr,
		Status: NewEndpointStatus(),
		OpLabels: pkgLabels.OpLabels{
			Custom:                pkgLabels.Labels{},
			Disabled:              pkgLabels.Labels{},
			OrchestrationIdentity: pkgLabels.Labels{},
			OrchestrationInfo:     pkgLabels.Labels{},
		},
	}
	e.UnconditionalLock()
	e.SetDefaultOpts(nil)
	e.Unlock()

	// Test that inserting identity labels works
	rev := e.replaceIdentityLabels(pkgLabels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(rev, Not(Equals), 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Test that nothing changes
	rev = e.replaceIdentityLabels(pkgLabels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(rev, Equals, 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Remove one label, change the source and value of the other.
	rev = e.replaceIdentityLabels(pkgLabels.Map2Labels(map[string]string{"foo": "zop"}, "nginx"))
	c.Assert(rev, Not(Equals), 0)
	c.Assert(string(e.OpLabels.OrchestrationIdentity.SortedList()), Equals, "nginx:foo=zop;")

	// Test that inserting information labels works
	e.replaceInformationLabels(pkgLabels.Map2Labels(map[string]string{"foo": "bar", "zip": "zop"}, "cilium"))
	c.Assert(string(e.OpLabels.OrchestrationInfo.SortedList()), Equals, "cilium:foo=bar;cilium:zip=zop;")
	// Remove one label, change the source and value of the other.
	e.replaceInformationLabels(pkgLabels.Map2Labels(map[string]string{"foo": "zop"}, "nginx"))
	c.Assert(string(e.OpLabels.OrchestrationInfo.SortedList()), Equals, "nginx:foo=zop;")
}

func (s *EndpointSuite) TestWaitForPolicyRevision(c *C) {
	e := &Endpoint{policyRevision: 0}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1*time.Second))

	<-e.WaitForPolicyRevision(ctx, 0)
	// shouldn't get a timeout when waiting for policy revision already reached
	c.Assert(ctx.Err(), IsNil)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithTimeout(context.Background(), time.Duration(1*time.Second))

	<-e.WaitForPolicyRevision(ctx, 0)
	// shouldn't get a timeout when waiting for policy revision already reached
	c.Assert(ctx.Err(), IsNil)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithCancel(context.Background())

	ch := e.WaitForPolicyRevision(ctx, 2)
	cancel()
	// context was prematurely closed on purpose the error should be nil
	c.Assert(ctx.Err(), Equals, context.Canceled)

	e.setPolicyRevision(3)

	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since the wanted policy revision was reached")
	}

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)

	e.state = StateDisconnected

	ctx, cancel = context.WithCancel(context.Background())
	ch = e.WaitForPolicyRevision(ctx, 99)
	cancel()
	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since the endpoint is in disconnected state")
	}

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)

	e.state = StateCreating
	ctx, cancel = context.WithCancel(context.Background())
	ch = e.WaitForPolicyRevision(ctx, 99)

	e.cleanPolicySignals()

	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since all policy signals were closed")
	}
	cancel()

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)
}

func (s *EndpointSuite) TestProxyID(c *C) {
	e := &Endpoint{ID: 123, policyRevision: 0}

	id := e.ProxyID(&policy.L4Filter{Port: 8080, Protocol: api.ProtoTCP, Ingress: true})
	endpointID, ingress, protocol, port, err := policy.ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(123))
	c.Assert(ingress, Equals, true)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(8080))
	c.Assert(err, IsNil)
}
