// Copyright 2016-2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/buildqueue"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// BuildQueue is the endpoint build queue. It is also used to build
	// base programs
	BuildQueue = buildqueue.NewBuildQueue("endpoint-builder")
)

type endpointBuild struct {
	endpoint *Endpoint
	context  *RegenerationContext
	owner    Owner
}

type buildStatus struct {
	// initialSuccessful is true after the first build has been successful.
	// This includes builds using an init identity.
	initialSuccessful bool

	// lastFailed is true when the last attempt to regenerate failed
	lastFailed bool

	// building is true while the endpoint is being built
	building bool

	// numWaiting is the number of builds of this endpoint waiting to be
	// built. If an endpoint is requested to be regenerated while a
	// regeneration is already queued up, this variable counts the number
	// of builds that have piled up. The build queue itself may decide to
	// fold builds together and fullfil multiple regeneration requests with
	// a single build. In that case, this variable still accounts for all
	// individual build requests and the variable gets decremented with the
	// number of folded builds as soon as the build completes.
	numWaiting int
}

func (e *Endpoint) newEndpointBuild(owner Owner, context *RegenerationContext) *endpointBuild {
	context.Stats.totalTime.Start()
	context.Stats.queueWait.Start()
	return &endpointBuild{
		endpoint: e,
		owner:    owner,
		context:  context,
	}
}

func (b *endpointBuild) GetUUID() string {
	return b.endpoint.UUID
}

func (b *endpointBuild) BuildQueued() {
	e := b.endpoint
	e.UnconditionalLock()
	e.buildStatus.numWaiting++
	e.updateState()
	e.Unlock()
}

func (b *endpointBuild) BuildsDequeued(nbuilds int, cancelled bool) {
	e := b.endpoint
	e.UnconditionalLock()
	e.buildStatus.numWaiting -= nbuilds
	e.updateState()
	e.Unlock()
}

func (b *endpointBuild) Build() error {
	e := b.endpoint

	b.context.Stats.queueWait.End()

	err := e.regenerate(b.owner, b.context)

	scopedLog := e.Logger()
	repr, reprerr := monitor.EndpointRegenRepr(e, err)
	if reprerr != nil {
		scopedLog.WithError(reprerr).Warn("Notifying monitor about endpoint regeneration failed")
	}

	if err != nil {
		scopedLog.WithError(err).Warn("Regeneration of endpoint program failed")
		e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
		if reprerr == nil && !option.Config.DryMode {
			b.owner.SendNotification(monitor.AgentNotifyEndpointRegenerateFail, repr)
		}
	} else {
		e.LogStatusOK(BPF, "Successfully regenerated endpoint program due to "+b.context.Reason)
		if reprerr == nil && !option.Config.DryMode {
			b.owner.SendNotification(monitor.AgentNotifyEndpointRegenerateSuccess, repr)
		}
	}

	if err := e.LockAlive(); err == nil {
		if err == nil {
			e.buildStatus.initialSuccessful = true
		}

		e.buildStatus.building = false
		e.buildStatus.lastFailed = err != nil
		e.updateState()
		e.Unlock()
	}

	return err
}

// DrainAllBuilds waits until any ongoing current build has completed and
// removes all scheduled builds from the build queue.  The endpoint must NOT be
// locked.
func (e *Endpoint) DrainAllBuilds() {
	BuildQueue.Drain(e)
}
