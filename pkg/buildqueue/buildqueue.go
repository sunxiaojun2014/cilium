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

package buildqueue

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// minWorkerThreads is the minimum number of worker threads to use
	// regardless of the number of cores available in the system
	minWorkerThreads = 2

	// buildQueueSize is the maximum number of builds that can be queued
	// before Enqueue() starts blocking
	buildQueueSize = 4096
)

// buildStatusMap contains the build status of all queued builders
type buildStatusMap map[string]*buildStatus

// buildGroup is a logical grouping of builds
type buildGroup struct {
	// running is the number of builds running of this group
	running int

	// waiting is the number of builds currently blocked in
	// waitForBuildCondition(), waiting for their build condition to be
	// met.
	waiting int

	// condition is the condition that must be met throughout the build.
	// The condition function is called with q.mutex held.
	condition func(q *BuildQueue) bool
}

// waitForBuildCondition is called by a build which has been dequeued and
// assigned to a worker and will block until the build condition associated
// with the builder is being met, e.g. the exclusive build condition will block
// until all currently running regular builds have completed.
func (b *buildGroup) waitForBuildCondition(q *BuildQueue) {
	metric := metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName:  q.name,
		metrics.LabelBuildQueueState: metrics.BuildQueueBlocked,
	})

	q.mutex.Lock()
	b.waiting++
	metric.Inc()
	for !b.condition(q) {
		q.waitingBuilders.Wait()
	}

	metric.Dec()
	b.waiting--
	b.running++
	q.mutex.Unlock()
}

// finish signals that a build of this buildGroup has completed
func (b *buildGroup) finish(q *BuildQueue) {
	q.mutex.Lock()
	b.running--
	q.mutex.Unlock()

	q.waitingBuilders.Broadcast()
}

// BuildQueue is a queueing system for builds
type BuildQueue struct {
	// name is the name of the build queue
	name string

	// mutex protects access to the buildStatus map and for the
	// waitingBuilders sync.Condition in waitForBuildCondition()
	mutex lock.Mutex

	// buildStatus contains the status of all builders separated by UUID
	buildStatus buildStatusMap

	// workerBuildQueue is a buffered channel that contains all scheduled
	// builds
	workerBuildQueue chan Builder

	// stopWorker is used to stop worker threads when the build queue is
	// shutdown. Workers will run until this channel is closed.
	stopWorker chan struct{}

	// regularBuilds accounts for running regular builds
	regularBuilds *buildGroup

	// exclusiveBuilds accounts for running exclusive builds
	exclusiveBuilds *buildGroup

	// waitingBuilders is used to wake up builders waiting for their
	// condition to be met
	waitingBuilders *sync.Cond
}

// NewBuildQueue returns a new build queue
func NewBuildQueue(name string) *BuildQueue {
	q := &BuildQueue{
		name:             name,
		buildStatus:      buildStatusMap{},
		workerBuildQueue: make(chan Builder, buildQueueSize),
		stopWorker:       make(chan struct{}, 0),
		regularBuilds: &buildGroup{
			condition: func(q *BuildQueue) bool {
				return q.exclusiveBuilds.waiting == 0 && q.exclusiveBuilds.running == 0
			},
		},
		exclusiveBuilds: &buildGroup{
			condition: func(q *BuildQueue) bool {
				return q.exclusiveBuilds.running == 0 && q.regularBuilds.running == 0
			},
		},
	}

	q.waitingBuilders = sync.NewCond(&q.mutex)

	nWorkers := numWorkerThreads()
	for w := 0; w < nWorkers; w++ {
		go q.runWorker()
	}

	return q
}

// Stop stops the build queue and terminates all workers
func (q *BuildQueue) Stop() {
	close(q.stopWorker)

	waitForCleanup := sync.WaitGroup{}

	q.mutex.Lock()
	for _, status := range q.buildStatus {
		waitForCleanup.Add(1)
		go func(b Builder) {
			q.Drain(b)
			waitForCleanup.Done()
		}(status.builder)
	}
	q.mutex.Unlock()

	waitForCleanup.Wait()
}

// numWorkerThreads returns the number of worker threads to use
func numWorkerThreads() int {
	ncpu := runtime.NumCPU()

	if ncpu < minWorkerThreads {
		return minWorkerThreads
	}
	return ncpu
}

// Buildable is an object that is buildable
type Buildable interface {
	// GetUUID must return a unique UUID of the object
	GetUUID() string
}

// Builder is an object that can build itself. A builder must also be Buildable
type Builder interface {
	Buildable

	// Build must build object
	Build() error

	// BuildQueued is called every time a build has been scheduled to be
	// built
	BuildQueued()

	// BuildsDequeued is called when a scheduled built has been dequeued for
	// building or cancelled
	BuildsDequeued(nbuilds int, cancelled bool)
}

// BuildNotification is a channel to receive the status of a build. The channel
// will receive true if the build was successful. The channel is buffered and
// is guaranteed to only be written to exactly once and is then immediately
// closed. It is up to the caller of Enqueue() to decide whether to read on the
// channel or not.
type BuildNotification chan bool

func newBuildNotification() BuildNotification {
	return make(BuildNotification, 1)
}

// build is what is returned by Enqueue() to provide information about the
// build
type build struct {
	builder Builder

	// uuid is the UUID of the Buildable
	uuid string

	// notificationChannels is a list of a channels that should be notified
	// about the completion of the build
	notificationChannels []BuildNotification

	// internalNotification is used to notify
	internalNotification BuildNotification
}

// createAndAddNotificationChannel creates and adds a build notification
// channel. This function may only be called while the build is not yet in
// progress.
func (b *build) createAndAddNotificationChannel() BuildNotification {
	notify := newBuildNotification()
	b.notificationChannels = append(b.notificationChannels, notify)
	return notify
}

// reportStatus reports the status of a build to all notification channels.
// This function may only be called if the build is the currentBuild. It may
// never be called while the build is still assigned to nextBuild.
func (b *build) reportStatus(q *BuildQueue, success bool) {
	b.internalNotification <- success
	close(b.internalNotification)

	for _, notify := range b.notificationChannels {
		notify <- success
		close(notify)
	}
}

// cancel cancels a scheduled and not yet running build. q.mutex must be held.
func (b *build) cancelScheduled(q *BuildQueue) int {
	numBuilds := b.numFolded()

	metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName:  q.name,
		metrics.LabelBuildQueueState: metrics.BuildQueueWaiting,
	}).Sub(float64(numBuilds))

	b.reportStatus(q, false)

	return numBuilds
}

// numFolded returns the number of folded builds
func (b *build) numFolded() int {
	return len(b.notificationChannels)
}

func newBuild(b Builder, uuid string) *build {
	return &build{
		builder:              b,
		uuid:                 uuid,
		notificationChannels: []BuildNotification{},
		internalNotification: make(BuildNotification, 1),
	}
}

// buildStatus is the current status of a build
type buildStatus struct {
	builder Builder

	// curentBuild is the building information of any running build
	currentBuild *build

	// nextBuild is the building information of the next build for this
	// UUID
	nextBuild *build
}

func (q *BuildQueue) enqueueBuild(b Builder) (BuildNotification, bool) {
	build, enqueued := q.serializeBuild(b)
	notify := build.createAndAddNotificationChannel()

	metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName:  q.name,
		metrics.LabelBuildQueueState: metrics.BuildQueueWaiting,
	}).Inc()

	b.BuildQueued()

	return notify, enqueued
}

func (q *BuildQueue) serializeBuild(b Builder) (*build, bool) {
	uuid := b.GetUUID()
	build := newBuild(b, uuid)

	q.mutex.Lock()
	defer q.mutex.Unlock()

	if buildStatus, ok := q.buildStatus[uuid]; ok {
		// If the builder is currently being built, prepare the next
		// build and store it in the nextBuild field. When the current
		// build finishes, the next build will automatically be added
		// to the workerBuildQueue
		if buildStatus.currentBuild != nil && buildStatus.nextBuild == nil {
			buildStatus.nextBuild = build
			return build, false
		}

		// The builder is already in the queue but not being built, the
		// build request will be fulfilled when the queued build is
		// executed. The caller can be notified to skip the build.
		return buildStatus.nextBuild, false
	}

	q.buildStatus[uuid] = &buildStatus{
		builder:   b,
		nextBuild: build,
	}

	return build, true
}

// Enqueue schedules Builder for building. A channel is returned to provide the
// ability to wait for the build to complete and check for success or failure.
//
// A regular build fullfils the following build guarantees:
// * The same Buildable, i.e. the same UUID, will not be built in parallel on
//   multiple workers.
// * The order in which regular builds are enqueued is maintained in the build
//   order across different Buildables. If the same Buildable is enqueued
//   multiple times, the buils are automatically folded together until the
//   build is executed. This means in practise that a specific Buildable can only
//   be in the build queue once.
// * In the presence of preemptive, exclusive builds, regular builds get a fair
//   chance to run but preemptive builds always preempt any queued, not yet
//   running regular build.
func (q *BuildQueue) Enqueue(b Builder) BuildNotification {
	notify, enqueue := q.enqueueBuild(b)
	if enqueue {
		// This should be non-blocking unless there is contention beyond
		// queueBuildSize in which case this will block until a slot in the
		// queue becomes available.
		q.workerBuildQueue <- b
	}

	return notify
}

// Remove removes the builder from the queue.
func (q *BuildQueue) Remove(b Buildable) {
	uuid := b.GetUUID()
	q.mutex.Lock()
	if status, ok := q.buildStatus[uuid]; ok {
		delete(q.buildStatus, uuid)

		if status.nextBuild != nil {
			num := status.nextBuild.cancelScheduled(q)
			defer status.builder.BuildsDequeued(num, true)
		}
	}
	q.mutex.Unlock()
}

// Drain will drain the queue from any running or scheduled builds of a
// Buildable. If a build is running, the function will block for the build to
// complete. It is the responsibility of the caller that the Buildable does not
// get re-scheduled during the draining. Returns true if waiting was required.
func (q *BuildQueue) Drain(b Buildable) bool {
	uuid := b.GetUUID()

	q.mutex.Lock()
	status, ok := q.buildStatus[uuid]
	var currentBuild *build
	if ok {
		currentBuild = status.currentBuild
		delete(q.buildStatus, uuid)

		if status.nextBuild != nil {
			num := status.nextBuild.cancelScheduled(q)
			defer status.builder.BuildsDequeued(num, true)
		}
	}
	q.mutex.Unlock()

	// If a build is onging, block until build is complete
	if currentBuild != nil {
		<-currentBuild.internalNotification
		return true
	}

	return false
}

func (q *BuildQueue) build(b Builder) error {
	metric := metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName:  q.name,
		metrics.LabelBuildQueueState: metrics.BuildQueueRunning,
	})

	metric.Inc()
	err := b.Build()
	metric.Dec()

	return err
}

func (q *BuildQueue) runExclusiveBuild(b Builder) {
	uuid := b.GetUUID()

	for {
		currentBuild := q.nominateBuild(uuid)
		if currentBuild == nil {
			return
		}

		q.exclusiveBuilds.waitForBuildCondition(q)
		err := q.build(b)
		q.exclusiveBuilds.finish(q)

		currentBuild.reportStatus(q, err == nil)

		if !q.needToBuildAgain(uuid) {
			return
		}

		select {
		case <-q.stopWorker:
			return
		default:
		}
	}
}

// PreemptExclusive enqueues a build at the front of the queue and provides
// exclusive build access. All other builds enqueued via Enqueue()
// PreemptExclusive() have to finish before the exclusive build is executed.
// The exclusive build will then be the only build executed until it finishes.
//
// If an exclusive build for the same UUID is already enqueued but not yet
// running, the build will be folded into the already scheduled build but both
// notification channels will be notified.
func (q *BuildQueue) PreemptExclusive(b Builder) BuildNotification {
	notify, enqueue := q.enqueueBuild(b)
	if enqueue {
		go q.runExclusiveBuild(b)
	}

	return notify
}

// nominateBuild is called when a build has made it to the front of the build
// queue or the build is a preemptive build. nominateBuild will pull the
// build information from the buildStatus.nextBuild and nominate the build as
// buildStatus.currentBuild. nominateBuild() returns the build or nil if the
// build has since been cancelled.
func (q *BuildQueue) nominateBuild(uuid string) *build {
	q.mutex.Lock()

	buildStatus, ok := q.buildStatus[uuid]
	if !ok || buildStatus.nextBuild == nil {
		// The builder has been removed since the build was
		// scheduled. Cancel the build.
		q.mutex.Unlock()
		return nil
	}

	// Mark the scheduled build as building
	currentBuild := buildStatus.nextBuild
	buildStatus.currentBuild = currentBuild
	buildStatus.nextBuild = nil
	q.mutex.Unlock()

	num := currentBuild.numFolded()
	metrics.BuildQueueEntries.With(map[string]string{
		metrics.LabelBuildQueueName:  q.name,
		metrics.LabelBuildQueueState: metrics.BuildQueueWaiting,
	}).Sub(float64(num))

	buildStatus.builder.BuildsDequeued(num, false)

	return currentBuild
}

func (q *BuildQueue) needToBuildAgain(uuid string) bool {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	buildStatus, ok := q.buildStatus[uuid]
	var nextBuild *build
	if ok {
		buildStatus.currentBuild = nil
		nextBuild = buildStatus.nextBuild

		// If no next build is scheduled, the builder can be
		// removed from the build status entirely
		if nextBuild == nil {
			delete(q.buildStatus, uuid)
		}
	}

	return nextBuild != nil
}

func (q *BuildQueue) runWorker() {
	for b := range q.workerBuildQueue {
		uuid := b.GetUUID()

		currentBuild := q.nominateBuild(uuid)
		if currentBuild == nil {
			return
		}

		q.regularBuilds.waitForBuildCondition(q)
		err := q.build(b)
		q.regularBuilds.finish(q)

		currentBuild.reportStatus(q, err == nil)

		// If another build for the same builder is scheduled, queue it
		if q.needToBuildAgain(uuid) {
			q.workerBuildQueue <- b
		}

		select {
		case <-q.stopWorker:
			return
		default:
		}
	}
}

// checkBuildGuarantees reports errors when build guarantees are currently not
// being respected
func (q *BuildQueue) checkBuildGuarantees() error {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	buildCount := map[string]int{}

	for _, status := range q.buildStatus {
		if build := status.currentBuild; build != nil {
			buildCount[build.uuid]++
		}
	}

	switch {
	case q.exclusiveBuilds.running > 1:
		return fmt.Errorf("More than one exclusive build is running")
	case q.exclusiveBuilds.running > 0 && q.regularBuilds.running > 0:
		return fmt.Errorf("Exclusive build is running in parallel with regular build")
	default:
		for uuid, count := range buildCount {
			if count > 1 {
				return fmt.Errorf("UUID %s is being built in parallel", uuid)
			}
		}
	}

	return nil
}
