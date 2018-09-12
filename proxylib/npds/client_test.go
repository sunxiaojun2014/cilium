// Copyright 2018 Authors of Cilium
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

package npds

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/proxylib/test"

	log "github.com/sirupsen/logrus"
	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	check.TestingT(t)
}

type ServerSuite struct{}

var _ = check.Suite(&ServerSuite{})

const (
	TestTimeout      = 10 * time.Second
	CacheUpdateDelay = 250 * time.Millisecond
)

var resources = []*cilium.NetworkPolicy{
	{Name: "resource0"},
	{Name: "resource1"},
	{Name: "resource2"},
}

func ackCallback() {
	log.Info("ACK Callback called")
}

// UpsertNetworkPolicy must only be used for testing!
func UpsertNetworkPolicy(s *envoy.XDSServer, p *cilium.NetworkPolicy) {
	c := completion.NewCallback(context.Background(), ackCallback)
	s.NetworkPolicyMutator.Upsert(envoy.NetworkPolicyTypeURL, p.Name, p, []string{"127.0.0.1"}, c)
}

func (s *ServerSuite) TestRequestAllResources(c *check.C) {
	xdsPath := filepath.Join(test.Tmpdir, "xds.sock")
	StartClient(xdsPath, "sidecar~127.0.0.1~v0.default~default.svc.cluster.local")

	// Start another client, which will never connect
	xdsPath2 := filepath.Join(test.Tmpdir, "xds.sock2")
	StartClient(xdsPath2, "sidecar~127.0.0.2~v0.default~default.svc.cluster.local")

	// Start third client on the same path as the first, should return immediately without connecting again
	StartClient(xdsPath, "sidecar~127.0.0.1~v0.default~default.svc.cluster.local")

	// Some wait before server is made available
	time.Sleep(500 * time.Millisecond)
	xdsServer := envoy.StartXDSServer(test.Tmpdir)
	time.Sleep(500 * time.Millisecond)

	// Create version 1 with resource 0.
	UpsertNetworkPolicy(xdsServer, resources[0])

	time.Sleep(DialDelay * BackOffLimit)
}
